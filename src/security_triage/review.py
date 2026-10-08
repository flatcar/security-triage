"""Human-gated review-issue workflow for discovery and cleanup recommendations.

This module implements the two-stage, human-gated process described in
``.github/copilot-instructions.md`` and the review/apply design plan:

1. ``build_review_batch`` turns validated discovery/cleanup documents into one
   or more self-contained "review issue" parts. Each part renders evidence,
   exact proposed changes, and task-list checkboxes carrying machine-readable
   action IDs, plus a versioned JSON manifest embedded (base64-encoded) in a
   hidden HTML comment.
2. ``apply_review_issue`` re-fetches a closed review issue, validates the
   manifest, resolves which single action (if any) was approved per decision
   group, and executes only checked, conflict-free, schema-valid actions
   through ``GitHubActionRunner``.

GitHub task lists are an approval *interface*, not executable prose: only
action IDs that exist verbatim in the validated manifest ever reach a mutating
API call, and every mutation is re-validated against freshly fetched GitHub
state before it is applied.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import textwrap
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .actions import GitHubActionRunner
from .console import NullProgressLogger, ProgressLogger
from .debug import DebugLogger
from .feedback import (
    FEEDBACK_DECISIONS,
    FEEDBACK_KIND,
    build_feedback_payload,
    is_trusted_feedback_author,
    parse_feedback_summary,
    render_feedback_summary,
    validate_feedback_payload,
)
from .issue_updates import (
    append_field_values,
    ensure_issue_fields,
    set_field_if_placeholder,
    with_package_identity,
)
from .issues import (
    GitHubIssueClient,
    find_existing_issue_matches,
    is_package_update_issue,
    issue_from_api,
    issue_package_from_title,
    parse_issue_body,
)
from .records import Issue, ParsedIssue
from .rules import (
    REVIEW_APPLIED_LABEL,
    REVIEW_LABEL,
    cleanup_comment_body,
    is_gentoo_reference,
    issue_labels,
    neutralize_mentions,
    package_identities_match,
    render_issue_body,
    sanitize_single_line,
    severity_label,
    truncate_text,
    validate_repo_name,
)

REVIEW_SCHEMA_VERSION = "1.0"
REVIEW_FEEDBACK_LABEL = "security-triage/review-feedback"

#: Conservative ceiling for a single issue/part body, kept well below GitHub's
#: real ~65536 character issue-body limit so encoding overhead never trips it.
DEFAULT_MAX_PART_BODY_CHARS = 55000
#: Budget reserved for the header, footer, and manifest comment of each part;
#: the remainder is available to pack rendered decision-group sections into.
_RESERVED_OVERHEAD_CHARS = 6000
_MIN_GROUP_BUDGET_CHARS = 4000

_RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_ACTION_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# --- Action kinds -----------------------------------------------------------

DISCOVERY_KIND_CREATE = "discovery_create_issue"
DISCOVERY_KIND_UPDATE = "discovery_update_issue"
DISCOVERY_KIND_IGNORE = "discovery_ignore"
DISCOVERY_KIND_KERNEL = "discovery_kernel_routing"
DISCOVERY_KIND_MANUAL = "discovery_manual_review"

CLEANUP_KIND_COMMENT_ONLY = "cleanup_comment_only"
CLEANUP_KIND_COMMENT_AND_CLOSE = "cleanup_comment_and_close"
CLEANUP_KIND_KEEP_OPEN = "cleanup_keep_open"
CLEANUP_KIND_MANUAL = "cleanup_manual_review"

DISCOVERY_ACTION_KINDS = {
    DISCOVERY_KIND_CREATE,
    DISCOVERY_KIND_UPDATE,
    DISCOVERY_KIND_IGNORE,
    DISCOVERY_KIND_KERNEL,
    DISCOVERY_KIND_MANUAL,
}
CLEANUP_ACTION_KINDS = {
    CLEANUP_KIND_COMMENT_ONLY,
    CLEANUP_KIND_COMMENT_AND_CLOSE,
    CLEANUP_KIND_KEEP_OPEN,
    CLEANUP_KIND_MANUAL,
}
ALL_ACTION_KINDS = DISCOVERY_ACTION_KINDS | CLEANUP_ACTION_KINDS | {FEEDBACK_KIND}

#: Action kinds that never call a mutating GitHub API. Selecting one of these
#: only records an explicit human acknowledgement in the execution summary.
NON_MUTATING_KINDS = {
    DISCOVERY_KIND_IGNORE,
    DISCOVERY_KIND_KERNEL,
    DISCOVERY_KIND_MANUAL,
    CLEANUP_KIND_KEEP_OPEN,
    CLEANUP_KIND_MANUAL,
    FEEDBACK_KIND,
}

_DRY_RUN_BODY_MARKER = "<!-- security-triage:dry-run-body-start -->"


class ReviewConfigError(ValueError):
    """Raised for invalid, untrusted, or missing review run configuration."""


class ManifestCorruptionError(ValueError):
    """Raised when the embedded review manifest cannot be parsed or its digest
    does not match."""


class ManifestValidationError(ValueError):
    """Raised when a structurally valid manifest fails a trust/consistency check."""


# --- Domain model ------------------------------------------------------------


@dataclass(slots=True)
class ReviewContext:
    """Trusted run-level configuration used to build a review batch.

    Every value here is expected to come from CLI arguments, environment
    variables, or GitHub Actions workflow configuration -- never from
    editable issue prose -- but repository identifiers are still validated
    defensively.
    """

    advisory_repo: str
    review_repo: str
    run_id: str
    generated_at: str
    run_url: str = ""
    commit_sha: str = ""
    window_start: str | None = None
    window_end: str | None = None
    sbom_url: str | None = None
    sbom_metadata: dict[str, Any] = field(default_factory=dict)
    model_metadata: dict[str, Any] = field(default_factory=dict)
    discovery_report_url: str | None = None
    cleanup_report_url: str | None = None
    max_part_body_chars: int = DEFAULT_MAX_PART_BODY_CHARS
    review_detail: str = "full"
    include_go: bool = True
    include_rust: bool = True
    enable_feedback: bool = False

    def __post_init__(self) -> None:
        self.advisory_repo = validate_repo_name(self.advisory_repo)
        self.review_repo = validate_repo_name(self.review_repo)
        if self.review_detail not in {"compact", "full"}:
            raise ReviewConfigError("review_detail must be 'compact' or 'full'")
        if not _RUN_ID_RE.match(self.run_id or ""):
            raise ReviewConfigError(
                f"Invalid run id {self.run_id!r}; expected 1-128 characters "
                "from [A-Za-z0-9._-]"
            )


@dataclass(slots=True)
class ApplyContext:
    """Trusted repository configuration for the apply-on-close command."""

    advisory_repo: str
    review_repo: str

    def __post_init__(self) -> None:
        self.advisory_repo = validate_repo_name(self.advisory_repo)
        self.review_repo = validate_repo_name(self.review_repo)


@dataclass(slots=True)
class ActionCandidate:
    action_id: str
    group_id: str
    kind: str
    label: str
    payload: dict[str, Any]
    evidence_fingerprint: str


@dataclass(slots=True)
class DecisionGroup:
    group_id: str
    source: str  # "discovery" | "cleanup"
    record: dict[str, Any]
    candidates: list[ActionCandidate]


@dataclass(slots=True)
class ReviewPart:
    batch_id: str
    part_id: str
    part_index: int
    part_count: int
    title: str
    body: str
    manifest: dict[str, Any]
    group_ids: list[str]


@dataclass(slots=True)
class ReviewBatch:
    batch_id: str
    parts: list[ReviewPart]
    groups: list[DecisionGroup]
    omissions: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class PartCreationResult:
    part_id: str
    part_index: int
    part_count: int
    issue_number: int
    issue_url: str
    created: bool


@dataclass(slots=True)
class GroupResolution:
    group_id: str
    source: str
    outcome: str  # "selected" | "no_action" | "conflict"
    selected_action: dict[str, Any] | None
    checked_action_ids: list[str]


# --- Stable ID derivation -----------------------------------------------------


def _stable_hash(*parts: str, length: int = 20) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return digest[:length]


def discovery_action_id(
    record_id: str, kind: str, target_issue: int | None = None
) -> str:
    """Derive a stable action ID for a discovery action.

    Deterministic in the discovery record ID, the action kind, and the target
    issue number (when relevant) so the same evidence always yields the same
    ID across reruns, while different evidence yields a different ID.
    """
    return "disc-" + _stable_hash(
        "discovery", record_id, kind, "" if target_issue is None else str(target_issue)
    )


def cleanup_action_id(
    issue_number: int,
    kind: str,
    cves: list[Any],
    fixed_version_requirement: str | None,
    sbom_match: dict[str, Any] | None,
    evidence: list[Any],
) -> str:
    """Derive a stable action ID for a cleanup action.

    Deterministic in the issue number, action kind, CVEs, fixed-version
    requirement, SBOM match identity, and a hash of the supporting evidence.
    """
    sbom_key = (
        f"{(sbom_match or {}).get('name') or ''}:"
        f"{(sbom_match or {}).get('versionInfo') or ''}"
    )
    evidence_key = "|".join(sorted(str(item) for item in evidence))
    return "clean-" + _stable_hash(
        "cleanup",
        str(issue_number),
        kind,
        ",".join(sorted(str(cve).upper() for cve in cves)),
        fixed_version_requirement or "",
        sbom_key,
        evidence_key,
    )


def _group_id(*parts: str) -> str:
    return "grp-" + _stable_hash(*parts, length=16)


def _discovery_evidence_fingerprint(
    record: dict[str, Any], kind: str, target_issue: int | None
) -> str:
    extraction = record.get("llm_extraction") or {}
    parts = [
        kind,
        str(extraction.get("package_name") or ""),
        ",".join(sorted(str(cve).upper() for cve in extraction.get("cves") or [])),
        str(extraction.get("action_needed") or ""),
        str(target_issue or ""),
    ]
    return _stable_hash(*parts, length=16)


def _cleanup_evidence_fingerprint(record: dict[str, Any], kind: str) -> str:
    parts = [
        kind,
        str(record.get("package_from_issue") or ""),
        ",".join(
            sorted(str(cve).upper() for cve in record.get("cves_from_issue") or [])
        ),
        str(record.get("fixed_version_requirement") or ""),
    ]
    return _stable_hash(*parts, length=16)


# --- Canonicalization and manifest embedding ---------------------------------


def canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_digest(manifest_without_digest: dict[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json(manifest_without_digest).encode("utf-8")
    ).hexdigest()


def render_marker_block(
    batch_id: str, part_id: str, part_index: int, part_count: int
) -> str:
    lines = "\n".join(
        [
            f"batch_id={batch_id}",
            f"part_id={part_id}",
            f"part_index={part_index}",
            f"part_count={part_count}",
            f"schema_version={REVIEW_SCHEMA_VERSION}",
        ]
    )
    return f"<!-- security-triage:review-marker\n{lines}\n-->"


_MARKER_BLOCK_RE = re.compile(
    r"<!--\s*security-triage:review-marker\s*(?P<body>.*?)-->", re.DOTALL
)
_MANIFEST_BLOCK_RE = re.compile(
    r"<!--\s*security-triage:review-manifest:v1\s*(?P<body>.*?)-->", re.DOTALL
)
_FEEDBACK_SUMMARY_BLOCK_RE = re.compile(
    r"<!--\s*security-triage:review-feedback:v1\s+[A-Za-z0-9+/=\s]+?-->",
    re.DOTALL,
)
_ACTION_LINE_RE = re.compile(
    r"^\s*[-*]\s+\[(?P<mark>[ xX])\]\s+.*<!--\s*security-triage:action-id:"
    r"(?P<action_id>[A-Za-z0-9._-]+)\s*-->\s*$"
)


def find_batch_part_marker(body: str) -> tuple[str, str] | None:
    """Return ``(batch_id, part_id)`` from the hidden marker comment, if present.

    Fails closed (returns ``None``, the same as "no marker found") when more
    than one marker-shaped comment exists anywhere in the body. Untrusted
    upstream advisory text (package summaries, comments, proposed issue
    bodies) is rendered into this same body, and nothing prevents that text
    from containing a byte-for-byte valid-looking
    ``<!-- security-triage:review-marker ... -->`` comment. Silently taking
    the first match (as a plain ``re.search`` would) could pick an
    attacker-forged block instead of the pipeline's own, so any ambiguity is
    treated as untrustworthy rather than resolved by position.
    """
    matches = list(_MARKER_BLOCK_RE.finditer(body or ""))
    if len(matches) != 1:
        return None
    match = matches[0]
    fields: dict[str, str] = {}
    for line in match.group("body").strip().splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip()
    batch_id = fields.get("batch_id")
    part_id = fields.get("part_id")
    if not batch_id or not part_id:
        return None
    return batch_id, part_id


def _manifest_for_storage(manifest: dict[str, Any]) -> dict[str, Any]:
    """Store each feedback evidence snapshot once, addressed by its SHA256."""
    snapshots: dict[str, Any] = {}
    groups = []
    for group in manifest.get("groups", []):
        actions = []
        for action in group.get("actions", []):
            payload = action.get("payload") or {}
            snapshot = payload.get("evidence_snapshot")
            if action.get("kind") == FEEDBACK_KIND and isinstance(snapshot, dict):
                key = compute_digest(snapshot)
                snapshots[key] = snapshot
                payload = {
                    key: value
                    for key, value in payload.items()
                    if key != "evidence_snapshot"
                }
                payload["evidence_snapshot_ref"] = key
                action = {**action, "payload": payload}
            actions.append(action)
        groups.append({**group, "actions": actions})
    if not snapshots:
        return manifest
    return {**manifest, "groups": groups, "feedback_snapshots": snapshots}


def _expand_feedback_snapshots(manifest: dict[str, Any]) -> dict[str, Any]:
    if "feedback_snapshots" not in manifest:
        return manifest
    snapshots = manifest.pop("feedback_snapshots")
    if not isinstance(snapshots, dict) or any(
        not isinstance(snapshot, dict) or compute_digest(snapshot) != key
        for key, snapshot in snapshots.items()
    ):
        raise ManifestCorruptionError("Invalid feedback evidence snapshot table")
    referenced: set[str] = set()
    try:
        for group in manifest["groups"]:
            for action in group["actions"]:
                payload = action.get("payload") or {}
                if "evidence_snapshot_ref" not in payload:
                    continue
                key = payload.pop("evidence_snapshot_ref")
                if (
                    action.get("kind") != FEEDBACK_KIND
                    or "evidence_snapshot" in payload
                    or key not in snapshots
                ):
                    raise ManifestCorruptionError("Invalid feedback evidence reference")
                payload["evidence_snapshot"] = snapshots[key]
                referenced.add(key)
    except (KeyError, TypeError, AttributeError) as exc:
        raise ManifestCorruptionError("Malformed feedback snapshot references") from exc
    if referenced != set(snapshots):
        raise ManifestCorruptionError("Unreferenced feedback evidence snapshots")
    return manifest


def embed_manifest(manifest: dict[str, Any]) -> str:
    encoded = base64.b64encode(
        canonical_json(_manifest_for_storage(manifest)).encode("utf-8")
    ).decode("ascii")
    wrapped = "\n".join(textwrap.wrap(encoded, 200)) if encoded else ""
    return f"<!-- security-triage:review-manifest:v1\n{wrapped}\n-->"


def extract_manifest(body: str) -> dict[str, Any]:
    """Extract, decode, and integrity-check the review manifest from an issue body.

    The digest is an accidental-corruption check, not an authorization
    boundary: authorization still comes from who could edit/close the GitHub
    issue. Base64-encoding (rather than embedding raw JSON) guarantees the
    HTML comment stays well-formed regardless of any ``-->``-like substrings
    that sanitized upstream text might otherwise contain.

    Untrusted upstream advisory text is rendered elsewhere in this same body
    (proposed issue bodies, summaries, rationale quotes), and nothing stops
    that text from containing a fully valid, self-consistent forged
    ``<!-- security-triage:review-manifest:v1 ... -->`` comment -- a forged
    manifest's digest is trivially self-computable offline, so the digest
    alone cannot distinguish "genuine" from "forged". Because the pipeline's
    own manifest is always appended last (in the footer, after every
    upstream-influenced group section), requiring *exactly one* such comment
    in the whole body is what actually defeats a forged, earlier copy: a
    forged block makes this raise rather than silently resolving to either
    copy by position.
    """
    matches = list(_MANIFEST_BLOCK_RE.finditer(body or ""))
    if not matches:
        raise ManifestCorruptionError("No review manifest comment found in issue body")
    if len(matches) > 1:
        raise ManifestCorruptionError(
            f"Found {len(matches)} review manifest comments in the issue body; "
            "expected exactly one. "
            "This can happen if untrusted rendered content contains a "
            "forged manifest-shaped comment; "
            "refusing to guess which one is genuine."
        )
    match = matches[0]
    encoded = "".join(match.group("body").split())
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
        manifest = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ManifestCorruptionError(
            f"Review manifest is not valid base64 JSON: {exc}"
        ) from exc
    if not isinstance(manifest, dict):
        raise ManifestCorruptionError("Review manifest must be a JSON object")
    manifest = _expand_feedback_snapshots(manifest)
    digest = manifest.get("digest")
    without_digest = {key: value for key, value in manifest.items() if key != "digest"}
    if digest != compute_digest(without_digest):
        raise ManifestCorruptionError(
            "Review manifest digest does not match its content; the "
            "issue body may be corrupted"
        )
    return manifest


def validate_manifest_against_context(
    manifest: dict[str, Any], advisory_repo: str, review_repo: str
) -> None:
    """Validate manifest schema, internal batch/part identity, and repository equality.

    Raises ``ManifestValidationError`` with a human-readable reason on any
    failure; callers must treat that as "apply zero actions".
    """
    if manifest.get("schema_version") != REVIEW_SCHEMA_VERSION:
        raise ManifestValidationError(
            "Unsupported review manifest schema version: "
            f"{manifest.get('schema_version')!r}"
        )
    part_index = manifest.get("part_index")
    part_count = manifest.get("part_count")
    if (
        not isinstance(part_index, int)
        or not isinstance(part_count, int)
        or not (1 <= part_index <= part_count)
    ):
        raise ManifestValidationError(
            "Review manifest part_index/part_count is not internally consistent"
        )
    if not manifest.get("batch_id") or not manifest.get("part_id"):
        raise ManifestValidationError("Review manifest is missing batch_id/part_id")
    if not isinstance(manifest.get("groups"), list):
        raise ManifestValidationError("Review manifest is missing a groups list")

    manifest_advisory_repo = str(manifest.get("advisory_repo") or "")
    manifest_review_repo = str(manifest.get("review_repo") or "")
    try:
        expected_advisory = validate_repo_name(advisory_repo)
        expected_review = validate_repo_name(review_repo)
        actual_advisory = validate_repo_name(manifest_advisory_repo)
        actual_review = validate_repo_name(manifest_review_repo)
    except ValueError as exc:
        raise ManifestValidationError(
            f"Repository identifier failed validation: {exc}"
        ) from exc
    if actual_advisory != expected_advisory:
        raise ManifestValidationError(
            f"Configured advisory repository {advisory_repo!r} does not "
            "match the manifest's "
            f"{manifest_advisory_repo!r}"
        )
    if actual_review != expected_review:
        raise ManifestValidationError(
            f"Configured review repository {review_repo!r} does not match "
            f"the manifest's {manifest_review_repo!r}"
        )

    seen_action_ids: set[str] = set()
    seen_group_ids: set[str] = set()
    for group in manifest.get("groups", []):
        if (
            not isinstance(group, dict)
            or not group.get("group_id")
            or not isinstance(group.get("actions"), list)
        ):
            raise ManifestValidationError(
                "Review manifest contains a malformed decision group"
            )
        group_id = group["group_id"]
        if not isinstance(group_id, str) or group_id in seen_group_ids:
            raise ManifestValidationError("Duplicate or invalid decision group ID")
        seen_group_ids.add(group_id)
        if group.get("source") == "feedback" and not isinstance(
            group.get("feedback_for_group_id"), str
        ):
            raise ManifestValidationError(
                "Feedback group is missing its related decision group"
            )
        for action in group["actions"]:
            _validate_manifest_action(action)
            if (action["kind"] == FEEDBACK_KIND) != (group.get("source") == "feedback"):
                raise ManifestValidationError(
                    "Feedback must have its own non-mutating group"
                )
            if action["kind"] == FEEDBACK_KIND:
                try:
                    validate_feedback_payload(
                        action["payload"], advisory_repository=actual_advisory
                    )
                except ValueError as exc:
                    raise ManifestValidationError(str(exc)) from exc
            action_id = action["action_id"]
            if action_id in seen_action_ids:
                raise ManifestValidationError(
                    f"Duplicate action ID in manifest: {action_id!r}"
                )
            seen_action_ids.add(action_id)


def _validate_manifest_action(action: Any) -> None:
    if not isinstance(action, dict):
        raise ManifestValidationError("Review manifest action entry is not an object")
    action_id = action.get("action_id")
    kind = action.get("kind")
    if not isinstance(action_id, str) or not _ACTION_ID_RE.match(action_id):
        raise ManifestValidationError(f"Invalid action ID in manifest: {action_id!r}")
    if kind not in ALL_ACTION_KINDS:
        raise ManifestValidationError(f"Unsupported action kind in manifest: {kind!r}")
    payload = action.get("payload")
    if not isinstance(payload, dict):
        raise ManifestValidationError(
            f"Action {action_id!r} is missing a payload object"
        )
    if kind == DISCOVERY_KIND_CREATE:
        if (
            not payload.get("title")
            or not isinstance(payload.get("body"), str)
            or not isinstance(payload.get("labels"), list)
        ):
            raise ManifestValidationError(
                f"Action {action_id!r} payload is missing required create-issue fields"
            )
        parsed = parse_issue_body(payload["body"])
        if (
            not parsed.valid
            or not package_identities_match(payload.get("package_name"), parsed.name)
            or not package_identities_match(
                payload.get("package_identity") or payload.get("package_name"),
                parsed.identity,
            )
            or not package_identities_match(
                parsed.name, issue_package_from_title(str(payload["title"]))
            )
            or not all(isinstance(label, str) for label in payload["labels"])
            or not {"advisory", "security"}.issubset(payload["labels"])
        ):
            raise ManifestValidationError(
                f"Action {action_id!r} has inconsistent advisory package identity or labels"
            )
    elif kind == DISCOVERY_KIND_UPDATE:
        if type(payload.get("issue")) is not int or payload["issue"] <= 0:
            raise ManifestValidationError(
                f"Action {action_id!r} payload is missing an issue number"
            )
        additions = payload.get("field_additions", {})
        if not isinstance(additions, dict) or any(
            not isinstance(additions.get(key, []), list)
            or not all(isinstance(value, str) for value in additions.get(key, []))
            for key in ("cves", "cvss_scores", "gentoo_refs")
        ):
            raise ManifestValidationError(
                f"Action {action_id!r} has malformed additive fields"
            )
    elif kind in (CLEANUP_KIND_COMMENT_ONLY, CLEANUP_KIND_COMMENT_AND_CLOSE):
        if (
            type(payload.get("issue")) is not int
            or payload["issue"] <= 0
            or not isinstance(payload.get("comment_body"), str)
            or not payload["comment_body"]
        ):
            raise ManifestValidationError(
                f"Action {action_id!r} payload is missing an issue number "
                "or comment body"
            )
    elif kind == FEEDBACK_KIND:
        try:
            validate_feedback_payload(payload)
        except ValueError as exc:
            raise ManifestValidationError(str(exc)) from exc


# --- Checkbox rendering and parsing ------------------------------------------


def render_checkbox_line(action_id: str, text: str) -> str:
    return f"- [ ] {_md_escape(text)} <!-- security-triage:action-id:{action_id} -->"


def parse_checked_action_ids(body: str) -> set[str]:
    """Parse checked (``[x]``/``[X]``) task-list action IDs from an issue body.

    Only lines carrying the hidden ``action-id`` comment are recognized;
    unrelated checkboxes a maintainer might add elsewhere in the body are
    never mistaken for approvals.
    """
    checked: set[str] = set()
    for line in (body or "").splitlines():
        match = _ACTION_LINE_RE.match(line)
        if match and match.group("mark").lower() == "x":
            checked.add(match.group("action_id"))
    return checked


def resolve_review_selections(
    manifest: dict[str, Any], checked_ids: set[str]
) -> list[GroupResolution]:
    """Resolve each manifest decision group against the checked action IDs.

    Zero checked IDs in a group means no action; exactly one means that
    action is selected; more than one means the group fails closed as a
    conflict and is skipped.
    """
    resolutions: list[GroupResolution] = []
    for group in manifest.get("groups", []):
        actions = group.get("actions", [])
        action_ids_in_group = {action["action_id"] for action in actions}
        checked_in_group = sorted(action_ids_in_group & checked_ids)
        if len(checked_in_group) == 0:
            resolutions.append(
                GroupResolution(
                    group["group_id"], group.get("source", ""), "no_action", None, []
                )
            )
        elif len(checked_in_group) == 1:
            selected = next(
                action
                for action in actions
                if action["action_id"] == checked_in_group[0]
            )
            resolutions.append(
                GroupResolution(
                    group["group_id"],
                    group.get("source", ""),
                    "selected",
                    selected,
                    checked_in_group,
                )
            )
        else:
            resolutions.append(
                GroupResolution(
                    group["group_id"],
                    group.get("source", ""),
                    "conflict",
                    None,
                    checked_in_group,
                )
            )
    by_group = {resolution.group_id: resolution for resolution in resolutions}
    feedback_by_key: dict[str, list[GroupResolution]] = {}
    for group in manifest.get("groups", []):
        resolution = by_group[group["group_id"]]
        if group.get("source") == "feedback" and resolution.outcome == "conflict":
            related = by_group.get(group.get("feedback_for_group_id"))
            if (
                related is not None
                and related.selected_action is not None
                and related.selected_action.get("kind") not in NON_MUTATING_KINDS
            ):
                related.outcome, related.selected_action = "conflict", None
        action = resolution.selected_action
        if action is None or action.get("kind") != FEEDBACK_KIND:
            continue
        payload = action["payload"]
        feedback_by_key.setdefault(payload["feedback_key"], []).append(resolution)
        related = by_group.get(group.get("feedback_for_group_id"))
        if (
            related is not None
            and related.selected_action is not None
            and related.selected_action.get("kind") not in NON_MUTATING_KINDS
            and payload["decision"] != "revoke"
        ):
            related.outcome = resolution.outcome = "conflict"
            related.selected_action = resolution.selected_action = None
    for feedback_resolutions in feedback_by_key.values():
        decisions = {
            item.selected_action["payload"]["decision"]
            for item in feedback_resolutions
            if item.selected_action is not None
        }
        if len(decisions) > 1:
            for item in feedback_resolutions:
                item.outcome, item.selected_action = "conflict", None
    return resolutions


def unknown_checked_action_ids(
    manifest: dict[str, Any], checked_ids: set[str]
) -> list[str]:
    known: set[str] = set()
    for group in manifest.get("groups", []):
        for action in group.get("actions", []):
            known.add(action["action_id"])
    return sorted(checked_ids - known)


# --- Building decision groups from discovery/cleanup documents ---------------


_DISCOVERY_KIND_BY_ACTION = {
    "create_issue": DISCOVERY_KIND_CREATE,
    "update_existing_issue": DISCOVERY_KIND_UPDATE,
    "ignore": DISCOVERY_KIND_IGNORE,
    "kernel_regular_update_flow": DISCOVERY_KIND_KERNEL,
}
_CLEANUP_KIND_BY_ACTION = {
    "comment_only": CLEANUP_KIND_COMMENT_ONLY,
    "close_issue": CLEANUP_KIND_COMMENT_AND_CLOSE,
    "keep_open": CLEANUP_KIND_KEEP_OPEN,
}


def _unique_records(document: dict[str, Any], source: str) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for record in document.get("records", []):
        identity = str(
            record.get("record_id" if source == "discovery" else "issue") or ""
        )
        key = identity or compute_digest(record)
        if key in records and canonical_json(records[key]) != canonical_json(record):
            raise ManifestValidationError(
                f"Conflicting duplicate {source} record ID: {key}"
            )
        records.setdefault(key, record)
    return list(records.values())


def _evidence_bound_group(group: DecisionGroup) -> DecisionGroup:
    """Version new IDs without changing validation of already-published manifests."""
    fingerprint = compute_digest(group.record)
    for candidate in group.candidates:
        candidate.action_id = (
            candidate.action_id.split("-", 1)[0]
            + "-"
            + _stable_hash(
                "evidence-v2",
                candidate.action_id,
                fingerprint,
                canonical_json(candidate.payload),
            )
        )
        candidate.evidence_fingerprint = fingerprint
    return group


def _omission_reason(
    record: dict[str, Any], source: str, context: ReviewContext
) -> str | None:
    if source == "discovery":
        if record.get("source") == "go_vulndb" and not context.include_go:
            return "source_excluded:go_vulndb"
        if record.get("source") == "rustsec" and not context.include_rust:
            return "source_excluded:rustsec"
    if context.review_detail != "compact":
        return None
    if _is_suppressed(record):
        suppression = record["review_suppression"]
        decision = (
            suppression.get("decision") if isinstance(suppression, dict) else None
        )
        return "review_suppression:" + (
            decision if decision in FEEDBACK_DECISIONS else "recorded_feedback"
        )
    feedback = record.get("review_suppression") or {}
    if isinstance(feedback, dict) and feedback.get("decision") == "track_uncertain":
        return None
    decision = record.get("decision") or {}
    confidence = (
        decision.get("confidence")
        if source == "discovery"
        else record.get("confidence")
    )
    if record.get("manual_review_reasons") or confidence not in {"high", "medium"}:
        return None
    if source == "cleanup" and record.get("recommended_action") == "keep_open":
        if record.get("status") != "needs_manual_review":
            return "compact:cleanup_keep_open"
    activity = record.get("upstream_activity") or {}
    if (
        source == "discovery"
        and not any(
            activity.get(key)
            for key in (
                "requires_issue_update",
                "new_aliases",
                "new_references",
                "new_comments",
            )
        )
        and not record.get("upstream_new_comments")
    ):
        if decision.get("action") in {"ignore", "kernel_regular_update_flow"}:
            return "compact:" + str(decision["action"])
    return None


def _visible_records(
    document: dict[str, Any],
    source: str,
    context: ReviewContext | None,
    omissions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    visible = []
    for record in _unique_records(document, source):
        reason = _omission_reason(record, source, context) if context else None
        if reason:
            omissions.append(
                {
                    "source": source,
                    "record_id": str(
                        record.get("record_id" if source == "discovery" else "issue")
                        or compute_digest(record)
                    ),
                    "reason": reason,
                    "explanation": (
                        str(
                            (record.get("review_suppression") or {}).get("reason") or ""
                        )
                        if isinstance(record.get("review_suppression"), dict)
                        else ""
                    ),
                }
            )
        else:
            visible.append(record)
    return visible


def _is_suppressed(record: dict[str, Any]) -> bool:
    suppression = record.get("review_suppression")
    if isinstance(suppression, dict):
        return bool(suppression.get("suppressed", True))
    return bool(suppression)


def build_discovery_groups(
    document: dict[str, Any] | None,
    context: ReviewContext | None = None,
    *,
    omissions: list[dict[str, Any]] | None = None,
) -> list[DecisionGroup]:
    if not document:
        return []
    groups: list[DecisionGroup] = []
    for record in _visible_records(
        document, "discovery", context, omissions if omissions is not None else []
    ):
        action = (record.get("decision") or {}).get("action")
        if action == "needs_manual_review":
            groups.append(_discovery_manual_group(record))
        else:
            groups.append(_discovery_normal_group(record, action))
    for group in groups:
        if _is_suppressed(group.record):
            group.candidates = []
    return [_evidence_bound_group(group) for group in groups]


def build_cleanup_groups(
    document: dict[str, Any] | None,
    context: ReviewContext | None = None,
    *,
    omissions: list[dict[str, Any]] | None = None,
) -> list[DecisionGroup]:
    if not document:
        return []
    groups: list[DecisionGroup] = []
    for record in _visible_records(
        document, "cleanup", context, omissions if omissions is not None else []
    ):
        recommended = record.get("recommended_action")
        if recommended == "manual_review":
            groups.append(_cleanup_manual_group(record))
        else:
            groups.append(_cleanup_normal_group(record, recommended))
    for group in groups:
        if _is_suppressed(group.record):
            group.candidates = []
    return [_evidence_bound_group(group) for group in groups]


def _feedback_group(
    record: dict[str, Any], context: ReviewContext
) -> DecisionGroup | None:
    record_id = str(record.get("record_id") or compute_digest(record))
    group_id = _group_id("feedback", record_id)
    candidates = []
    decisions = (
        ("track_uncertain", "revoke") if _is_suppressed(record) else FEEDBACK_DECISIONS
    )
    for decision in decisions:
        try:
            payload = build_feedback_payload(
                record, decision, advisory_repository=context.advisory_repo
            )
        except ValueError:
            return None
        candidates.append(
            ActionCandidate(
                action_id="feedback-"
                + _stable_hash(group_id, payload["feedback_key"], decision),
                group_id=group_id,
                kind=FEEDBACK_KIND,
                label=f"Record reviewer feedback: {decision.replace('_', ' ')}",
                payload=payload,
                evidence_fingerprint=payload["feedback_key"],
            )
        )
    return DecisionGroup(group_id, "feedback", record, candidates)


def _dedupe_preserve_order(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text.upper() in {"TBD", "N/A", "NONE"}:
            continue
        key = text.upper()
        if key not in seen:
            seen.add(key)
            out.append(text)
    return out


def _create_payload(record: dict[str, Any]) -> dict[str, Any]:
    proposed = record.get("proposed_issue") or {}
    extraction = record.get("llm_extraction") or {}
    relevance = record.get("flatcar_relevance") or {}
    identity = (
        extraction.get("package_purl")
        or extraction.get("package_identity")
        or extraction.get("package_name")
    )
    confirmed_scopes = [
        "sdk-only" if entry["scope"] == "sdk_only" else "sysext"
        for entry in relevance.get("scope_evidence") or []
        if isinstance(entry, dict)
        and entry.get("validated") is True
        and str(entry.get("source") or "").strip()
        and entry.get("scope") in {"sdk_only", "sysext"}
        and (entry["scope"] != "sdk_only" or relevance.get("scope") != "production")
        and package_identities_match(identity, entry.get("package"))
    ]
    trusted_labels = issue_labels(
        extraction.get("cvss_scores"),
        relevance.get("scope")
        if relevance.get("scope") in {"sdk_only", "sysext"}
        else None,
        " ".join(confirmed_scopes),
    )
    if proposed:
        title = str(proposed.get("title") or "")
        body = str(proposed.get("body") or "")
        labels = list(proposed.get("labels") or [])
        labels = [
            label
            for label in labels
            if label not in {"advisory/only-sdk", "advisory/sysext"}
        ]
        labels.extend(
            label
            for label in trusted_labels
            if label in {"advisory/only-sdk", "advisory/sysext"}
        )
    else:
        package_name = str(extraction.get("package_name") or "")
        title = f"update: {package_name}"
        gentoo_ref = extraction.get("gentoo_ref")
        body = render_issue_body(
            package_name,
            extraction.get("cves") or [],
            extraction.get("cvss_scores") or [],
            extraction.get("action_needed"),
            extraction.get("summary"),
            gentoo_ref if is_gentoo_reference(gentoo_ref) else None,
        )
        labels = trusted_labels
    body = with_package_identity(body, identity)
    return {
        "title": title,
        "body": body,
        "labels": labels,
        "package_name": extraction.get("package_name"),
        "package_identity": extraction.get("package_purl")
        or extraction.get("package_identity")
        or extraction.get("package_name"),
        "cves": extraction.get("cves") or [],
    }


def _field_additions(
    extraction: dict[str, Any],
    upstream_activity: dict[str, Any],
    record: dict[str, Any],
) -> dict[str, Any]:
    cves = [
        *(extraction.get("cves") or []),
        *(upstream_activity.get("new_aliases") or []),
    ]
    upstream_metadata = record.get("upstream_metadata") or {}
    gentoo_candidates = [
        extraction.get("gentoo_ref"),
        record.get("source_url"),
        upstream_metadata.get("url"),
        *(upstream_metadata.get("see_also") or []),
        *(record.get("upstream_references") or []),
    ]
    return {
        "cves": _dedupe_preserve_order(cves),
        "cvss_scores": _dedupe_preserve_order(extraction.get("cvss_scores") or []),
        "gentoo_refs": _dedupe_preserve_order(
            [value for value in gentoo_candidates if is_gentoo_reference(value)]
        ),
        "action_needed": extraction.get("action_needed"),
        "summary": extraction.get("summary"),
    }


def _update_payload(record: dict[str, Any], target_issue: int) -> dict[str, Any]:
    extraction = record.get("llm_extraction") or {}
    upstream_activity = record.get("upstream_activity") or {}
    matches = record.get("existing_issue_matches") or []
    match: dict[str, Any] = next(
        (item for item in matches if int(item.get("issue", -1)) == target_issue),
        {},
    )
    proposed_update = record.get("proposed_update") or {}
    return {
        "issue": target_issue,
        "field_additions": _field_additions(extraction, upstream_activity, record),
        "comment_body": proposed_update.get("comment_body"),
        "expected_package": extraction.get("package_purl")
        or extraction.get("package_identity")
        or extraction.get("package_name"),
        "expected_cves": list(match.get("cves") or []),
    }


def _reliable_update_matches(record: dict[str, Any]) -> list[dict[str, Any]]:
    extraction = record.get("llm_extraction") or {}
    package = (
        extraction.get("package_purl")
        or extraction.get("package_identity")
        or extraction.get("package_name")
    )
    matches: dict[int, dict[str, Any]] = {}
    for match in record.get("existing_issue_matches") or []:
        if (
            package_identities_match(package, match.get("package"))
            and match.get("state", "open") == "open"
            and isinstance(match.get("issue"), int)
        ):
            number = match["issue"]
            if number in matches and matches[number] != match:
                return []
            matches[number] = match
    return list(matches.values())


def _has_unvalidated_claims(record: dict[str, Any]) -> bool:
    validation = (record.get("llm_extraction") or {}).get("evidence_validation")
    return isinstance(validation, dict) and (
        bool(validation.get("errors"))
        or validation.get("status") not in {None, "validated"}
    )


def _discovery_normal_group(
    record: dict[str, Any], action: str | None
) -> DecisionGroup:
    record_id = str(record.get("record_id") or compute_digest(record))
    kind = _DISCOVERY_KIND_BY_ACTION.get(action or "")
    group_id = _group_id("discovery", record_id)
    target_issue: int | None = None
    payload: dict[str, Any] = {}
    label = "Approve the recommended action"

    if kind in {
        DISCOVERY_KIND_CREATE,
        DISCOVERY_KIND_UPDATE,
    } and _has_unvalidated_claims(record):
        return _discovery_manual_group(record)
    if kind == DISCOVERY_KIND_CREATE and record.get("proposed_issue"):
        payload = _create_payload(record)
        label = f"Create new advisory issue: {payload['title']}"
    elif kind == DISCOVERY_KIND_UPDATE and record.get("proposed_update"):
        target_issue = int(record["proposed_update"]["issue"])
        matches = _reliable_update_matches(record)
        if len(matches) != 1 or matches[0]["issue"] != target_issue:
            return _discovery_manual_group(record)
        payload = _update_payload(record, target_issue)
        label = f"Update existing issue #{target_issue} with new upstream context"
    elif kind == DISCOVERY_KIND_IGNORE:
        label = "Acknowledge: no advisory action needed"
    elif kind == DISCOVERY_KIND_KERNEL:
        label = (
            "Acknowledge: routed to the regular kernel update flow (no advisory issue)"
        )
    else:
        # A recognized non-manual decision without the payload it requires is
        # a guardrail gap, not a safe automatable recommendation: fail closed
        # to the manual-review menu instead of rendering a broken checkbox.
        return _discovery_manual_group(record)

    candidate = ActionCandidate(
        action_id=discovery_action_id(record_id, kind, target_issue),
        group_id=group_id,
        kind=kind,
        label=label,
        payload=payload,
        evidence_fingerprint=_discovery_evidence_fingerprint(
            record, kind, target_issue
        ),
    )
    return DecisionGroup(
        group_id=group_id, source="discovery", record=record, candidates=[candidate]
    )


def _discovery_manual_group(record: dict[str, Any]) -> DecisionGroup:
    record_id = str(record.get("record_id") or compute_digest(record))
    group_id = _group_id("discovery", record_id)
    candidates: list[ActionCandidate] = []

    extraction = record.get("llm_extraction") or {}
    package_name = str(extraction.get("package_name") or "").strip()
    cves = [cve for cve in (extraction.get("cves") or []) if str(cve).strip()]
    summary = str(extraction.get("summary") or "").strip()
    grounded = not _has_unvalidated_claims(record)
    if grounded and package_name and (cves or (summary and summary.upper() != "TBD")):
        payload = _create_payload(record)
        candidates.append(
            ActionCandidate(
                action_id=discovery_action_id(record_id, DISCOVERY_KIND_CREATE, None),
                group_id=group_id,
                kind=DISCOVERY_KIND_CREATE,
                label=f"Create new advisory issue: {payload['title']}",
                payload=payload,
                evidence_fingerprint=_discovery_evidence_fingerprint(
                    record, DISCOVERY_KIND_CREATE, None
                ),
            )
        )

    existing_matches = _reliable_update_matches(record)
    if grounded and len(existing_matches) == 1:
        target_issue = int(existing_matches[0]["issue"])
        payload = _update_payload(record, target_issue)
        candidates.append(
            ActionCandidate(
                action_id=discovery_action_id(
                    record_id, DISCOVERY_KIND_UPDATE, target_issue
                ),
                group_id=group_id,
                kind=DISCOVERY_KIND_UPDATE,
                label=(
                    f"Update existing issue #{target_issue} with new upstream context"
                ),
                payload=payload,
                evidence_fingerprint=_discovery_evidence_fingerprint(
                    record, DISCOVERY_KIND_UPDATE, target_issue
                ),
            )
        )

    candidates.append(
        ActionCandidate(
            action_id=discovery_action_id(record_id, DISCOVERY_KIND_IGNORE, None),
            group_id=group_id,
            kind=DISCOVERY_KIND_IGNORE,
            label="No advisory action (ignore/defer)",
            payload={},
            evidence_fingerprint=_discovery_evidence_fingerprint(
                record, DISCOVERY_KIND_IGNORE, None
            ),
        )
    )
    candidates.append(
        ActionCandidate(
            action_id=discovery_action_id(record_id, DISCOVERY_KIND_MANUAL, None),
            group_id=group_id,
            kind=DISCOVERY_KIND_MANUAL,
            label="Manual handling outside the pipeline",
            payload={},
            evidence_fingerprint=_discovery_evidence_fingerprint(
                record, DISCOVERY_KIND_MANUAL, None
            ),
        )
    )
    return DecisionGroup(
        group_id=group_id, source="discovery", record=record, candidates=candidates
    )


def _cleanup_payload(record: dict[str, Any], issue_number: int) -> dict[str, Any]:
    matches = record.get("sbom_package_matches") or []
    comment_body = record.get("comment_body") or ""
    if not comment_body and matches and record.get("fixed_version_requirement"):
        comment_body = cleanup_comment_body(
            record.get("package_from_issue") or "unknown",
            record.get("cves_from_issue") or [],
            record.get("fixed_version_requirement"),
            matches[0],
        )
    return {
        "issue": issue_number,
        "comment_body": comment_body,
        "expected_package": record.get("package_from_issue"),
        "expected_cves": record.get("cves_from_issue") or [],
        "expected_issue_body_sha256": record.get("issue_body_sha256"),
        "expected_scope_labels": sorted(
            set(record.get("labels") or []) & {"advisory/only-sdk", "advisory/sysext"}
        ),
    }


def _cleanup_normal_group(
    record: dict[str, Any], recommended: str | None
) -> DecisionGroup:
    issue_number = int(record["issue"])
    kind = _CLEANUP_KIND_BY_ACTION.get(recommended or "")
    group_id = _group_id("cleanup", str(issue_number))
    matches = record.get("sbom_package_matches") or []

    if kind in (
        CLEANUP_KIND_COMMENT_ONLY,
        CLEANUP_KIND_COMMENT_AND_CLOSE,
    ) and record.get("comment_body"):
        payload = _cleanup_payload(record, issue_number)
        label = (
            f"Post remediation comment on #{issue_number}"
            if kind == CLEANUP_KIND_COMMENT_ONLY
            else f"Post remediation comment and close #{issue_number}"
        )
    elif kind == CLEANUP_KIND_KEEP_OPEN:
        payload = {}
        label = f"Acknowledge: keep #{issue_number} open"
    else:
        return _cleanup_manual_group(record)

    candidate = ActionCandidate(
        action_id=cleanup_action_id(
            issue_number,
            kind,
            record.get("cves_from_issue") or [],
            record.get("fixed_version_requirement"),
            matches[0] if matches else None,
            record.get("evidence") or [],
        ),
        group_id=group_id,
        kind=kind,
        label=label,
        payload=payload,
        evidence_fingerprint=_cleanup_evidence_fingerprint(record, kind),
    )
    return DecisionGroup(
        group_id=group_id, source="cleanup", record=record, candidates=[candidate]
    )


def _cleanup_manual_group(record: dict[str, Any]) -> DecisionGroup:
    issue_number = int(record["issue"])
    group_id = _group_id("cleanup", str(issue_number))
    candidates: list[ActionCandidate] = []
    matches = record.get("sbom_package_matches") or []
    fixed_version = record.get("fixed_version_requirement")
    sbom_match = matches[0] if matches else None

    if matches and fixed_version:
        payload = _cleanup_payload(record, issue_number)
        for kind, label in (
            (CLEANUP_KIND_COMMENT_ONLY, f"Post remediation comment on #{issue_number}"),
            (
                CLEANUP_KIND_COMMENT_AND_CLOSE,
                f"Post remediation comment and close #{issue_number}",
            ),
        ):
            candidates.append(
                ActionCandidate(
                    action_id=cleanup_action_id(
                        issue_number,
                        kind,
                        record.get("cves_from_issue") or [],
                        fixed_version,
                        sbom_match,
                        record.get("evidence") or [],
                    ),
                    group_id=group_id,
                    kind=kind,
                    label=label,
                    payload=payload,
                    evidence_fingerprint=_cleanup_evidence_fingerprint(record, kind),
                )
            )

    candidates.append(
        ActionCandidate(
            action_id=cleanup_action_id(
                issue_number,
                CLEANUP_KIND_KEEP_OPEN,
                record.get("cves_from_issue") or [],
                fixed_version,
                sbom_match,
                record.get("evidence") or [],
            ),
            group_id=group_id,
            kind=CLEANUP_KIND_KEEP_OPEN,
            label=f"Keep #{issue_number} open",
            payload={},
            evidence_fingerprint=_cleanup_evidence_fingerprint(
                record, CLEANUP_KIND_KEEP_OPEN
            ),
        )
    )
    candidates.append(
        ActionCandidate(
            action_id=cleanup_action_id(
                issue_number,
                CLEANUP_KIND_MANUAL,
                record.get("cves_from_issue") or [],
                fixed_version,
                sbom_match,
                record.get("evidence") or [],
            ),
            group_id=group_id,
            kind=CLEANUP_KIND_MANUAL,
            label="Manual handling outside the pipeline",
            payload={},
            evidence_fingerprint=_cleanup_evidence_fingerprint(
                record, CLEANUP_KIND_MANUAL
            ),
        )
    )
    return DecisionGroup(
        group_id=group_id, source="cleanup", record=record, candidates=candidates
    )


# --- Rendering ---------------------------------------------------------------

_HTML_COMMENT_OPEN_RE = re.compile(r"<!--")
_HTML_COMMENT_CLOSE_RE = re.compile(r"--!?>")


def _neutralize_html_comments(text: str) -> str:
    """Break literal HTML comment delimiters in untrusted display text.

    Defense in depth on top of the "exactly one manifest/marker comment"
    requirement enforced by ``find_batch_part_marker``/``extract_manifest``:
    that check is what actually prevents a forged manifest from being parsed
    instead of the genuine one, but untrusted upstream text (advisory
    summaries, rationale, proposed issue bodies) should also never be able to
    render as a real HTML comment in the first place. Applied only to
    *display* copies embedded in the rendered issue body; the manifest
    payload used to actually create/update a GitHub issue at apply time is
    never touched by this function.
    """
    if not text:
        return text
    neutralized = _HTML_COMMENT_OPEN_RE.sub("<!\u2011\u2011", text)
    return _HTML_COMMENT_CLOSE_RE.sub("\u2011\u2011>", neutralized)


def _md_escape(text: Any) -> str:
    return _neutralize_html_comments(
        neutralize_mentions(sanitize_single_line(str(text or "")))
    )


def _quote(text: Any) -> str:
    return _md_escape(text).replace("\n", " ")


def _truncate_md(text: Any, limit: int = 400) -> str:
    return truncate_text(_md_escape(text), limit)


def _display_body(text: Any) -> str:
    """Neutralize an untrusted multi-line body/comment for the *preview only*.

    Unlike ``_md_escape``, this preserves newlines and does not collapse
    whitespace (the code-fenced preview should show the real proposed issue
    body/comment layout), but still breaks literal HTML comment delimiters so
    the preview itself can never smuggle a forged manifest-shaped comment.
    """
    return _neutralize_html_comments(str(text or ""))


def _render_candidate_preview(candidate: ActionCandidate) -> str:
    payload = candidate.payload
    if candidate.kind == DISCOVERY_KIND_CREATE and payload:
        labels = ", ".join(payload.get("labels") or [])
        return (
            "<details><summary>Exact proposed issue for action <code>"
            f"{candidate.action_id}</code></summary>\n\n"
            f"Title: `{payload.get('title')}`\n\n"
            "```text\n" + _display_body(payload.get("body")) + "\n```\n\n"
            f"Labels: {labels}\n"
            "</details>\n"
        )
    if candidate.kind == DISCOVERY_KIND_UPDATE and payload:
        additions = payload.get("field_additions") or {}
        add_lines = []
        if additions.get("cves"):
            add_lines.append(f"- Add CVEs: {', '.join(additions['cves'])}")
        if additions.get("cvss_scores"):
            add_lines.append(f"- Add CVSSs: {', '.join(additions['cvss_scores'])}")
        if additions.get("gentoo_refs"):
            add_lines.append(
                f"- Add refmap.gentoo: {', '.join(additions['gentoo_refs'])}"
            )
        if additions.get("action_needed"):
            add_lines.append(
                "- Action Needed (only applied if missing or currently TBD): "
                f"{_truncate_md(additions['action_needed'], 200)}"
            )
        if additions.get("summary"):
            add_lines.append(
                "- Summary (only applied if missing or currently TBD): "
                f"{_truncate_md(additions['summary'])}"
            )
        body = (
            "\n".join(add_lines)
            or "- No additive field changes detected; only the comment below "
            "(if any) would be posted."
        )
        preview = (
            "<details><summary>Proposed additive update for action <code>"
            f"{candidate.action_id}</code> "
            f"(issue #{payload.get('issue')})"
            f"</summary>\n\n{body}\n"
        )
        if payload.get("comment_body"):
            preview += (
                "\nComment to post:\n\n```text\n"
                + _display_body(payload["comment_body"])
                + "\n```\n"
            )
        preview += (
            "\nThis update is re-applied against the issue's current body at "
            "apply time and never removes existing content. Missing official fields "
            "are added; existing human prose is preserved.\n</details>\n"
        )
        return preview
    if (
        candidate.kind in (CLEANUP_KIND_COMMENT_ONLY, CLEANUP_KIND_COMMENT_AND_CLOSE)
        and payload
    ):
        closing_note = (
            " and then closes the issue"
            if candidate.kind == CLEANUP_KIND_COMMENT_AND_CLOSE
            else ""
        )
        return (
            "<details><summary>Exact comment for action <code>"
            f"{candidate.action_id}</code> "
            f"(issue #{payload.get('issue')}{closing_note})</summary>\n\n"
            "```text\n"
            + _display_body(payload.get("comment_body"))
            + "\n```\n</details>\n"
        )
    return ""


def _render_discovery_group(group: DecisionGroup, index: int) -> str:
    record = group.record
    extraction = record.get("llm_extraction") or {}
    relevance = record.get("flatcar_relevance") or {}
    decision = record.get("decision") or {}
    package_name = (
        extraction.get("package_name") or record.get("raw_advisory_id") or "unknown"
    )
    cves = extraction.get("cves") or []
    cvss = extraction.get("cvss_scores") or []

    lines = [
        (
            f"### Group {index}: {_md_escape(package_name)} "
            f"(discovery, source: {_md_escape(record.get('source'))})"
        ),
        "",
        f"- Source URL: `{_md_escape(record.get('source_url') or 'n/a')}`",
        "- CVEs / upstream IDs: "
        + (
            _md_escape(", ".join(cves))
            if cves
            else _md_escape(record.get("raw_advisory_id")) or "n/a"
        ),
        f"- CVSS: {_md_escape(', '.join(cvss)) if cvss else 'n/a'}",
        (
            f"- Flatcar relevance: **{_md_escape(relevance.get('status'))}** "
            f"(scope: {_md_escape(relevance.get('scope'))})"
        ),
        (
            f"- Recommendation: **{_md_escape(decision.get('action'))}** "
            f"(confidence: {_md_escape(decision.get('confidence'))})"
        ),
    ]
    sbom_matches = record.get("sbom_package_matches") or []
    if sbom_matches:
        lines.append(
            "- SBOM matches: "
            + "; ".join(
                (
                    f"{_md_escape(match.get('name'))} {_md_escape(match.get('versionInfo'))} "
                    f"({_md_escape(match.get('match_type'))})"
                )
                for match in sbom_matches
            )
        )
    else:
        lines.append("- SBOM matches: none")
    issue_matches = record.get("existing_issue_matches") or []
    if issue_matches:
        lines.append(
            "- Existing issue matches: "
            + "; ".join(
                (
                    f"#{_md_escape(match.get('issue'))} ({_md_escape(match.get('state'))}): "
                    f"{_md_escape(match.get('title'))}"
                )
                for match in issue_matches
            )
        )
    else:
        lines.append("- Existing issue matches: none")

    rationale = decision.get("reason") or relevance.get("llm_decision")
    if rationale:
        lines.extend(["", f"> {_quote(rationale)}"])
    manual_reasons = record.get("manual_review_reasons") or []
    if manual_reasons:
        lines.extend(
            [
                "",
                (
                    "- Safety/ambiguity notes: "
                    f"{_md_escape('; '.join(str(reason) for reason in manual_reasons))}"
                ),
            ]
        )
    if _has_unvalidated_claims(record):
        lines.extend(
            [
                "",
                "Advisory mutations are withheld because source-grounding validation failed. "
                "Unsupported claims remain in the original report for investigation.",
            ]
        )

    lines.append("")
    for candidate in group.candidates:
        preview = _render_candidate_preview(candidate)
        if preview:
            lines.append(preview)

    lines.extend(
        [
            (
                "Choose at most one (leave all unchecked to take no action "
                "for this group):"
            ),
            "",
        ]
    )
    for candidate in group.candidates:
        lines.append(render_checkbox_line(candidate.action_id, candidate.label))
    lines.append("")
    return "\n".join(lines)


def _render_cleanup_group(group: DecisionGroup, index: int) -> str:
    record = group.record
    issue_number = record.get("issue")
    lines = [
        (
            f"### Group {index}: #{issue_number} "
            f"{_md_escape(record.get('title'))} (cleanup)"
        ),
        "",
        f"- Package: {_md_escape(record.get('package_from_issue') or 'unknown')}",
        f"- CVEs: {_md_escape(', '.join(record.get('cves_from_issue') or []) or 'n/a')}",
        (
            "- Required fixed version (Action Needed): "
            f"{_md_escape(record.get('fixed_version_requirement') or 'unparsed')}"
        ),
        (
            f"- Status: **{_md_escape(record.get('status'))}** "
            f"(confidence: {_md_escape(record.get('confidence'))})"
        ),
        "- Current issue state (at report time): open",
        f"- Issue link: {_md_escape(record.get('issue_url'))}",
    ]
    matches = record.get("sbom_package_matches") or []
    if matches:
        lines.append(
            "- SBOM matches: "
            + "; ".join(
                (
                    f"{_md_escape(match.get('name'))} {_md_escape(match.get('versionInfo'))} "
                    f"({_md_escape(match.get('match_type'))})"
                )
                for match in matches
            )
        )
    else:
        lines.append("- SBOM matches: none")
    evidence = record.get("evidence") or []
    if evidence:
        lines.append(
            f"- Evidence: {_md_escape('; '.join(str(item) for item in evidence))}"
        )

    lines.append("")
    for candidate in group.candidates:
        preview = _render_candidate_preview(candidate)
        if preview:
            lines.append(preview)

    lines.extend(
        [
            (
                "Choose at most one (leave all unchecked to take no action "
                "for this group):"
            ),
            "",
        ]
    )
    for candidate in group.candidates:
        lines.append(render_checkbox_line(candidate.action_id, candidate.label))
    lines.append("")
    return "\n".join(lines)


def _render_group(group: DecisionGroup, index: int) -> str:
    if group.source == "feedback":
        package = (group.record.get("llm_extraction") or {}).get(
            "package_name"
        ) or "unknown"
        lines = [
            "<details><summary>Optional reviewer feedback — "
            f"{_md_escape(package)}</summary>",
            "",
            "Optional, independent feedback for this exact evidence. It does not mutate advisory issues. "
            "Leave every box unchecked unless explicitly recording a decision. "
            "Wrong package / not shipped / already addressed / deferred suppress unchanged future findings; "
            "track uncertain keeps them visible; revoke restores tracking. "
            "Feedback conflicting with a selected advisory mutation is ignored along with that mutation.",
            "",
        ]
        lines.extend(
            render_checkbox_line(candidate.action_id, candidate.label)
            for candidate in group.candidates
        )
        lines.extend(["", "</details>"])
        return "\n".join(lines) + "\n"
    if _is_suppressed(group.record):
        return (
            f"### Group {index}: suppressed\n\n"
            f"{_md_escape(group.record.get('review_suppression'))}\n\n"
            "No advisory actions are offered for this suppressed decision.\n"
        )
    if group.source == "discovery":
        return _render_discovery_group(group, index)
    return _render_cleanup_group(group, index)


def _group_confidence(group: DecisionGroup) -> str:
    if group.source == "discovery":
        return str((group.record.get("decision") or {}).get("confidence") or "unknown")
    return str(group.record.get("confidence") or "unknown")


def _group_severity(group: DecisionGroup) -> str:
    if group.source != "discovery":
        return "n/a"
    scores = (group.record.get("llm_extraction") or {}).get("cvss_scores") or []
    label = severity_label(scores)
    return label.replace("cvss/", "") if label else "n/a"


def _render_counts_table(groups: list[DecisionGroup]) -> list[str]:
    groups = [group for group in groups if group.source != "feedback"]
    if not groups:
        return ["", "(no decision groups)"]
    kind_counts = Counter(
        str((group.record.get("decision") or {}).get("action") or "needs_manual_review")
        if group.source == "discovery"
        else str(group.record.get("recommended_action") or "manual_review")
        for group in groups
    )
    confidence_counts = Counter(_group_confidence(group) for group in groups)
    severity_counts = Counter(_group_severity(group) for group in groups)
    lines = ["", "| Recommendation | Count |", "| --- | --- |"]
    lines.extend(
        f"| {_md_escape(kind)} | {count} |"
        for kind, count in sorted(kind_counts.items())
    )
    lines.extend(["", "| Confidence | Count |", "| --- | --- |"])
    lines.extend(
        f"| {_md_escape(level)} | {count} |"
        for level, count in sorted(confidence_counts.items())
    )
    lines.extend(["", "| Severity | Count |", "| --- | --- |"])
    lines.extend(
        f"| {level} | {count} |" for level, count in sorted(severity_counts.items())
    )
    return lines


def render_review_title(generated_at: str, part_index: int, part_count: int) -> str:
    date = (generated_at or "")[:10] or "unknown-date"
    return f"Security triage review: {date} (part {part_index}/{part_count})"


def _render_header(
    context: ReviewContext,
    part_index: int,
    part_count: int,
    part_groups: list[DecisionGroup],
    all_groups: list[DecisionGroup],
) -> str:
    part_note = f", part {part_index} of {part_count}" if part_count > 1 else ""
    lines = [
        (
            "Automated Flatcar security-triage review batch "
            f"`{context.run_id}`{part_note}."
        ),
        "",
        "## Run metadata",
        "",
        f"- Analyzed (advisory) repository: `{context.advisory_repo}`",
        f"- Review repository: `{context.review_repo}`",
        f"- Workflow run: {context.run_url or 'n/a'}",
        f"- Commit: `{context.commit_sha or 'n/a'}`",
        f"- Generated at: {context.generated_at}",
    ]
    if context.window_start or context.window_end:
        lines.append(
            f"- Analysis period: {context.window_start or 'n/a'} to "
            f"{context.window_end or 'n/a'}"
        )
    if context.sbom_url:
        meta_bits = ", ".join(
            f"{key}={value}"
            for key, value in (context.sbom_metadata or {}).items()
            if value
        )
        lines.append(
            f"- Production SBOM: `{context.sbom_url}`"
            + (f" ({meta_bits})" if meta_bits else "")
        )
    if context.model_metadata:
        meta_bits = ", ".join(
            f"{key}={value}" for key, value in context.model_metadata.items() if value
        )
        if meta_bits:
            lines.append(f"- Model: {meta_bits}")
    if context.discovery_report_url:
        lines.append(f"- Discovery report artifact: {context.discovery_report_url}")
    if context.cleanup_report_url:
        lines.append(f"- Cleanup report artifact: {context.cleanup_report_url}")

    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"This part contains {sum(group.source != 'feedback' for group in part_groups)} decision group(s).",
        ]
    )
    lines.extend(_render_counts_table(part_groups))
    if part_count > 1:
        lines.extend(
            [
                "",
                (
                    f"Whole batch: {sum(group.source != 'feedback' for group in all_groups)} decision group(s) "
                    f"across {part_count} part(s)."
                ),
            ]
        )
        lines.extend(_render_counts_table(all_groups))

    lines.extend(
        [
            "",
            "## How to use this review",
            "",
            (
                "- Check exactly one box per group to approve that action; "
                "leave a group fully unchecked to take no action for it."
            ),
            (
                "- Checking more than one box in the same group cancels "
                "that group: it is skipped and reported as a conflict."
            ),
            (
                "- Close this issue with reason **Completed** to apply "
                "every checked, conflict-free action."
            ),
            (
                "- Close this issue as **Not planned** (or leave it open) "
                "to take no automated action at all."
            ),
            (
                "- Do not edit the hidden HTML comments below the decision "
                "groups; they carry the machine-readable manifest this "
                "automation depends on."
            ),
            "",
            "## Decision groups",
            "",
        ]
    )
    return "\n".join(lines)


def _render_footer(marker_block: str, manifest_block: str) -> str:
    return "\n".join(
        [
            "---",
            "",
            (
                "<sub>This section is machine-readable metadata used by "
                "the apply automation. It is safe to ignore while "
                "reviewing.</sub>"
            ),
            "",
            marker_block,
            manifest_block,
            "",
        ]
    )


def _manifest_group(group: DecisionGroup) -> dict[str, Any]:
    result = {
        "group_id": group.group_id,
        "source": group.source,
        "package": (group.record.get("llm_extraction") or {}).get("package_name")
        or group.record.get("package_from_issue"),
        "target_issue": group.record.get("issue")
        if group.source == "cleanup"
        else None,
        "actions": [
            {
                "action_id": candidate.action_id,
                "kind": candidate.kind,
                "payload": candidate.payload,
                "evidence_fingerprint": candidate.evidence_fingerprint,
            }
            for candidate in group.candidates
        ],
    }
    if group.source == "feedback":
        result["feedback_for_group_id"] = _group_id(
            "discovery",
            str(group.record.get("record_id") or compute_digest(group.record)),
        )
    return result


#: Hard ceiling GitHub enforces on issue bodies. `DEFAULT_MAX_PART_BODY_CHARS`
#: already budgets well below this; it exists as a final safety check after
#: packing/rendering, not as the primary splitting budget.
GITHUB_ISSUE_BODY_HARD_LIMIT = 65536

#: Base64 inflates encoded bytes by 4/3; this adds extra margin for the
#: line-wrapping newlines `embed_manifest` inserts every 200 characters and
#: for the JSON object/array punctuation shared across a part's groups, so
#: the packing budget does not undercount the manifest's real contribution.
_MANIFEST_SIZE_SAFETY_FACTOR = 1.5


def _pack_groups(
    rendered_groups: list[tuple[DecisionGroup, str, int]], max_group_chars: int
) -> list[list[tuple[DecisionGroup, str, int]]]:
    if not rendered_groups:
        return []
    packed: list[list[tuple[DecisionGroup, str, int]]] = []
    current: list[tuple[DecisionGroup, str, int]] = []
    current_len = 0
    units: list[list[tuple[DecisionGroup, str, int]]] = []
    for item in rendered_groups:
        group = item[0]
        if (
            group.source == "feedback"
            and units
            and units[-1][-1][0].source == "discovery"
            and units[-1][-1][0].record is group.record
        ):
            units[-1].append(item)
        else:
            units.append([item])
    for unit in units:
        item_len = sum(item[2] for item in unit)
        # A single group larger than the budget still gets its own part
        # rather than being split mid-group or dropped.
        if current and current_len + item_len > max_group_chars:
            packed.append(current)
            current = []
            current_len = 0
        current.extend(unit)
        current_len += item_len
    if current:
        packed.append(current)
    return packed


def _omission_summary(omissions: list[dict[str, Any]]) -> dict[str, Any]:
    categories: dict[str, dict[str, Any]] = {}
    for item in omissions:
        reason = str(item["reason"])
        category = categories.setdefault(
            reason,
            {
                "reason": reason,
                "count": 0,
                "examples": [],
                "explanation": str(item.get("explanation") or "")[:160],
            },
        )
        category["count"] += 1
        if len(category["examples"]) < 3:
            category["examples"].append(str(item["record_id"])[:80])
    return {
        "total_records": len(omissions),
        "categories": [categories[key] for key in sorted(categories)],
    }


def _finalize_part(
    context: ReviewContext,
    part_index: int,
    part_count: int,
    group_slice: list[tuple[DecisionGroup, str, int]],
    all_groups: list[DecisionGroup],
    omissions: list[dict[str, Any]] | None = None,
) -> ReviewPart:
    groups = [group for group, _, _ in group_slice]
    group_text = "\n".join(text for _, text, _ in group_slice)
    header = _render_header(context, part_index, part_count, groups, all_groups)
    omission_summary = _omission_summary(omissions or [])
    if omissions:
        audit_lines = [
            "## Omitted decisions audit",
            "",
            f"Omitted records: {len(omissions)}",
        ]
        for category in omission_summary["categories"]:
            audit_lines.append(
                f"- {_md_escape(category['reason'])}: {category['count']}; "
                f"examples: {_md_escape(', '.join(category['examples']))}"
                + (
                    f" — {_md_escape(category['explanation'])}"
                    if category["explanation"]
                    else ""
                )
            )
        audit_lines.extend(
            [
                "",
                "Full omitted IDs, reasons, and evidence remain in the discovery/cleanup JSON reports "
                "and the local review audit JSON; this issue contains bounded examples only.",
                f"Report artifacts: {_md_escape(context.discovery_report_url or context.cleanup_report_url or context.run_url or 'the reports supplied to this review run')}",
            ]
        )
        header += "\n\n" + "\n".join(audit_lines) + "\n"
    part_id = f"{context.run_id}-part-{part_index}"
    manifest_without_digest: dict[str, Any] = {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "batch_id": context.run_id,
        "run_id": context.run_id,
        "run_url": context.run_url,
        "commit_sha": context.commit_sha,
        "part_id": part_id,
        "part_index": part_index,
        "part_count": part_count,
        "generated_at": context.generated_at,
        "advisory_repo": context.advisory_repo,
        "review_repo": context.review_repo,
        "groups": [_manifest_group(group) for group in groups],
        "omission_summary": omission_summary,
    }
    digest = compute_digest(manifest_without_digest)
    manifest = {**manifest_without_digest, "digest": digest}
    validate_manifest_against_context(
        manifest, context.advisory_repo, context.review_repo
    )
    marker_block = render_marker_block(context.run_id, part_id, part_index, part_count)
    manifest_block = embed_manifest(manifest)
    footer = _render_footer(marker_block, manifest_block)
    title = render_review_title(context.generated_at, part_index, part_count)
    body = "\n".join([header, group_text, footer])
    if len(body) > GITHUB_ISSUE_BODY_HARD_LIMIT:
        # `build_review_batch`'s packing budget already accounts for the
        # manifest's contribution; reaching this means a *single* group
        # (which is never split) plus its own manifest entry and the shared
        # header/footer overhead exceeds GitHub's hard limit on its own.
        # Fail loudly here rather than silently attempt to create/update an
        # issue body the API will reject.
        raise ReviewConfigError(
            f"Review part {part_id!r} body is {len(body)} characters, "
            "exceeding GitHub's "
            f"{GITHUB_ISSUE_BODY_HARD_LIMIT}-character issue body limit "
            "even as a single part; "
            "reduce --max-part-body-chars is not sufficient here because "
            "at least one decision "
            "group's own content is too large to split further."
        )
    return ReviewPart(
        batch_id=context.run_id,
        part_id=part_id,
        part_index=part_index,
        part_count=part_count,
        title=title,
        body=body,
        manifest=manifest,
        group_ids=[group.group_id for group in groups],
    )


def build_review_batch(
    context: ReviewContext,
    discovery_document: dict[str, Any] | None = None,
    cleanup_document: dict[str, Any] | None = None,
) -> ReviewBatch:
    """Build a complete, self-contained review batch without any GitHub calls.

    Shared by the ``review create`` (mutating) and ``review render`` (local
    dry-run) commands so both produce byte-identical part titles/bodies for
    the same inputs.
    """
    omissions: list[dict[str, Any]] = []
    all_groups = [
        *build_discovery_groups(discovery_document, context, omissions=omissions),
        *build_cleanup_groups(cleanup_document, context, omissions=omissions),
    ]
    if context.enable_feedback and discovery_document:
        # Full reviews expose suppressed records for explicit correction/revocation.
        # Compact summaries never re-expand omitted records into feedback menus.
        for record in _unique_records(discovery_document, "discovery"):
            if (record.get("source") == "go_vulndb" and not context.include_go) or (
                record.get("source") == "rustsec" and not context.include_rust
            ):
                continue
            related_index = next(
                (
                    index
                    for index, group in enumerate(all_groups)
                    if group.record is record and group.source == "discovery"
                ),
                None,
            )
            if related_index is None:
                continue
            group = _feedback_group(record, context)
            if group is not None:
                all_groups.insert(related_index + 1, group)
    validation_manifest = {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "batch_id": context.run_id,
        "part_id": context.run_id,
        "part_index": 1,
        "part_count": 1,
        "advisory_repo": context.advisory_repo,
        "review_repo": context.review_repo,
        "groups": [_manifest_group(group) for group in all_groups],
    }
    validate_manifest_against_context(
        validation_manifest, context.advisory_repo, context.review_repo
    )
    rendered_groups: list[tuple[DecisionGroup, str, int]] = []
    index = 0
    for group in all_groups:
        if group.source != "feedback":
            index += 1
        text = _render_group(group, index)
        # Packing must weigh both the human-readable rendered text *and* this
        # group's contribution to the base64-encoded manifest embedded in the
        # footer -- the manifest re-serializes the same proposed
        # titles/bodies/comments, so ignoring it would let a part's real
        # rendered size silently exceed the configured (and GitHub's hard)
        # body-size limit.
        manifest_json_len = len(
            canonical_json(_manifest_for_storage({"groups": [_manifest_group(group)]}))
        )
        combined_len = len(text) + int(manifest_json_len * _MANIFEST_SIZE_SAFETY_FACTOR)
        rendered_groups.append((group, text, combined_len))
    audit_budget = (
        int(len(canonical_json(_omission_summary(omissions))) * 3) if omissions else 0
    )
    max_group_chars = max(
        context.max_part_body_chars - _RESERVED_OVERHEAD_CHARS - audit_budget,
        _MIN_GROUP_BUDGET_CHARS,
    )
    packed = _pack_groups(rendered_groups, max_group_chars)
    slices = packed or [[]]
    part_count = len(slices)
    parts = [
        _finalize_part(
            context,
            part_index,
            part_count,
            group_slice,
            all_groups,
            omissions if part_index == 1 else [],
        )
        for part_index, group_slice in enumerate(slices, start=1)
    ]
    return ReviewBatch(
        batch_id=context.run_id, parts=parts, groups=all_groups, omissions=omissions
    )


# --- Local dry-run rendering (no GitHub calls) -------------------------------


def render_dry_run_document(part: ReviewPart, review_repo: str) -> str:
    """Render the exact would-be issue title/body as a single local Markdown document.

    Everything after ``_DRY_RUN_BODY_MARKER`` is byte-for-byte identical to
    ``part.body``, which is exactly what ``review create`` would submit as
    the issue body for this part.
    """
    header_lines = [
        (
            "<!-- security-triage dry-run review output: no GitHub "
            "mutation was performed -->"
        ),
        f"<!-- title: {part.title} -->",
        f"<!-- labels: {REVIEW_LABEL} -->",
        f"<!-- would_create_in_repo: {review_repo} -->",
        f"<!-- batch_id: {part.batch_id} -->",
        f"<!-- part_id: {part.part_id} -->",
        f"<!-- part_index: {part.part_index} -->",
        f"<!-- part_count: {part.part_count} -->",
        _DRY_RUN_BODY_MARKER,
    ]
    return "\n".join(header_lines) + "\n" + part.body


def parse_dry_run_document(text: str) -> tuple[dict[str, str], str]:
    """Inverse of ``render_dry_run_document``: returns (metadata, exact body)."""
    if _DRY_RUN_BODY_MARKER not in text:
        raise ValueError("Not a security-triage dry-run review document")
    header_text, _, body = text.partition(_DRY_RUN_BODY_MARKER)
    body = body[1:] if body.startswith("\n") else body
    metadata: dict[str, str] = {}
    for line in header_text.splitlines():
        match = re.match(r"<!--\s*([a-zA-Z_]+):\s*(.*?)\s*-->", line.strip())
        if match:
            metadata[match.group(1)] = match.group(2)
    return metadata, body


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-") or "part"


def _render_dry_run_summary(
    batch: ReviewBatch, review_repo: str, part_paths: list[Path]
) -> str:
    lines = [
        "# Security triage review dry run",
        "",
        f"Batch ID: `{batch.batch_id}`",
        f"Would create in repository: `{review_repo}`",
        f"Parts: {len(batch.parts)}",
        f"Total decision groups: {sum(group.source != 'feedback' for group in batch.groups)}",
        "",
        "No GitHub API calls were made while generating this output.",
        "",
        "| Part | Title | File | Decision groups |",
        "| --- | --- | --- | --- |",
    ]
    for part, path in zip(batch.parts, part_paths, strict=True):
        decision_count = sum(
            group["source"] != "feedback" for group in part.manifest["groups"]
        )
        lines.append(
            f"| {part.part_index}/{part.part_count} | {part.title} | "
            f"`{path.name}` | {decision_count} |"
        )
    if batch.omissions:
        lines.extend(["", "Complete omitted-record audit: `review-audit.json`."])
    return "\n".join(lines) + "\n"


def write_dry_run_batch(
    batch: ReviewBatch, output_dir: str | Path, review_repo: str
) -> list[Path]:
    """Write each part's exact would-be issue contents to a local Markdown file.

    Performs no GitHub API calls and requires no token. Returns the list of
    written paths (one per part, plus a trailing summary file).
    """
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    part_paths: list[Path] = []
    for part in batch.parts:
        path = directory / f"{_slug(part.part_id)}.md"
        path.write_text(render_dry_run_document(part, review_repo), encoding="utf-8")
        part_paths.append(path)
    summary_path = directory / "dry-run-summary.md"
    summary_path.write_text(
        _render_dry_run_summary(batch, review_repo, part_paths), encoding="utf-8"
    )
    if batch.omissions:
        (directory / "review-audit.json").write_text(
            canonical_json({"batch_id": batch.batch_id, "omissions": batch.omissions})
            + "\n",
            encoding="utf-8",
        )
    return [*part_paths, summary_path]


def render_dry_run(
    context: ReviewContext,
    output_dir: str | Path,
    discovery_document: dict[str, Any] | None = None,
    cleanup_document: dict[str, Any] | None = None,
) -> tuple[ReviewBatch, list[Path]]:
    """Build a review batch and write it to local Markdown files (no GitHub calls)."""
    batch = build_review_batch(context, discovery_document, cleanup_document)
    paths = write_dry_run_batch(batch, output_dir, context.review_repo)
    return batch, paths


# --- Review issue creation (idempotent) --------------------------------------


def ensure_review_label(client: GitHubIssueClient) -> None:
    client.ensure_label_exists(
        REVIEW_LABEL,
        color="5319e7",
        description="Security-triage generated review issue (approval required)",
    )


def create_review_batch(
    client: GitHubIssueClient, batch: ReviewBatch
) -> list[PartCreationResult]:
    """Create (or find) each part's review issue, idempotent per batch/part marker.

    Uses the Issues List API (label filter, ``state=all``) instead of GitHub
    Search so a rerun of the same Actions run reliably finds an issue it just
    created moments earlier, even though the Search index is only eventually
    consistent.
    """
    # Validate every part before even creating labels: never publish half a batch
    # only to discover a corrupt/duplicate action in a later part.
    seen_ids: set[str] = set()
    seen_parts: set[str] = set()
    seen_groups: set[str] = set()
    for part in batch.parts:
        manifest = extract_manifest(part.body)
        validate_manifest_against_context(
            manifest, str(part.manifest.get("advisory_repo") or ""), client.repo
        )
        if manifest != part.manifest or find_batch_part_marker(part.body) != (
            part.batch_id,
            part.part_id,
        ):
            raise ManifestValidationError("Review part body and metadata disagree")
        if part.part_id in seen_parts:
            raise ManifestValidationError("Duplicate review part ID")
        seen_parts.add(part.part_id)
        for group in manifest["groups"]:
            if group["group_id"] in seen_groups:
                raise ManifestValidationError(
                    "Duplicate decision group ID across review parts"
                )
            seen_groups.add(group["group_id"])
            for action in group["actions"]:
                if action["action_id"] in seen_ids:
                    raise ManifestValidationError(
                        "Duplicate action ID across review parts"
                    )
                seen_ids.add(action["action_id"])
    ensure_review_label(client)
    existing_by_part_id: dict[str, Issue] = {}
    for issue in client.list_issues_by_label(REVIEW_LABEL, state="all"):
        marker = find_batch_part_marker(issue.body)
        if marker and marker[1] in seen_parts:
            if marker[1] in existing_by_part_id:
                raise ManifestValidationError(
                    "Multiple review issues carry the same part ID"
                )
            existing_by_part_id.setdefault(marker[1], issue)

    results: list[PartCreationResult] = []
    for part in batch.parts:
        existing = existing_by_part_id.get(part.part_id)
        if existing is not None:
            results.append(
                PartCreationResult(
                    part.part_id,
                    part.part_index,
                    part.part_count,
                    existing.number,
                    existing.html_url,
                    created=False,
                )
            )
            continue
        response = client.create_issue(part.title, part.body, [REVIEW_LABEL])
        results.append(
            PartCreationResult(
                part_id=part.part_id,
                part_index=part.part_index,
                part_count=part.part_count,
                issue_number=int(response.get("number", 0)),
                issue_url=str(response.get("html_url") or ""),
                created=True,
            )
        )
    return results


def render_create_job_summary(results: list[PartCreationResult]) -> str:
    lines = ["## Security-triage review issues", ""]
    if not results:
        lines.append(
            "No decision groups were produced by this run; no review issue was created."
        )
        return "\n".join(lines) + "\n"
    for result in results:
        verb = "Created" if result.created else "Already exists (idempotent rerun)"
        lines.append(
            f"- Part {result.part_index}/{result.part_count}: {verb} — "
            f"{result.issue_url or f'#{result.issue_number}'}"
        )
    return "\n".join(lines) + "\n"


# --- Apply-on-close execution -------------------------------------------------


def _with_action_marker(body: str, action_id: str) -> str:
    return f"{body}\n\n<!-- security-triage:action-id:{action_id} -->"


def _has_marker_comment(comments: list[dict[str, Any]], action_id: str) -> bool:
    marker = f"<!-- security-triage:action-id:{action_id} -->"
    return any(marker in str(comment.get("body") or "") for comment in comments)


def _identity_matches(
    parsed: ParsedIssue, expected_package: Any, expected_cves: list[Any]
) -> bool:
    """Verify a live issue still looks like the package/CVE the review
    was generated for.

    Fails closed (returns False) whenever there is nothing concrete to
    confirm identity against, rather than assuming an untouched match.
    """
    return package_identities_match(str(expected_package or ""), parsed.identity)


def _translate_guarded_result(result: dict[str, Any]) -> dict[str, Any]:
    outcome = result.get("outcome")
    response = result.get("result") or {}
    return {
        "outcome": "skipped" if outcome == "blocked" else outcome,
        "reason": result.get("reason"),
        "operation": result.get("action"),
        "issue": response.get("number"),
        "issue_url": response.get("html_url"),
        "result": response,
    }


def _combine_results(*results: dict[str, Any] | None) -> dict[str, Any]:
    translated = [
        _translate_guarded_result(result) for result in results if result is not None
    ]
    outcomes = {item["outcome"] for item in translated}
    if not translated:
        return {"outcome": "no_op", "reason": None, "details": []}
    if "failed" in outcomes:
        outcome = "failed"
    elif "applied" in outcomes:
        outcome = "applied"
    elif "skipped" in outcomes:
        outcome = "skipped"
    else:
        outcome = "no_op"
    reasons = [item["reason"] for item in translated if item.get("reason")]
    return {
        "outcome": outcome,
        "reason": "; ".join(reasons) if reasons else None,
        "details": translated,
    }


def _execute_discovery_create(
    action_id: str,
    payload: dict[str, Any],
    client: GitHubIssueClient,
    runner: GitHubActionRunner,
) -> dict[str, Any]:
    try:
        current_issues = client.list_issues(state="all")
        current_issues.extend(issue_from_api(item) for item in runner.created_issues)
        current_issues = list(
            {issue.number: issue for issue in current_issues}.values()
        )
    except Exception as exc:  # noqa: BLE001 - surfaced as a failed outcome, not raised
        return {
            "outcome": "failed",
            "reason": (
                "Could not list current issues for the fresh "
                f"duplicate check ({type(exc).__name__})"
            ),
        }
    marker = f"<!-- security-triage:action-id:{action_id} -->"
    created = [
        issue
        for issue in current_issues
        if REVIEW_LABEL not in issue.labels
        and marker in issue.body.splitlines()
        and package_identities_match(
            payload.get("package_identity") or payload.get("package_name"),
            parse_issue_body(issue.body).identity,
        )
    ]
    if len(created) > 1:
        return {
            "outcome": "failed",
            "reason": "Multiple issues carry this create action ID; manual review required",
        }
    if created:
        return {
            "outcome": "no_op",
            "reason": "This action already created an issue",
            "issue": created[0].number,
            "issue_url": created[0].html_url,
        }
    duplicate_matches = find_existing_issue_matches(
        {
            "package_name": payload.get("package_name"),
            "package_identity": payload.get("package_identity"),
            "cves": payload.get("cves") or [],
        },
        [
            issue
            for issue in current_issues
            if issue.state == "open" and REVIEW_LABEL not in issue.labels
        ],
    )
    if not duplicate_matches and payload.get("package_identity"):
        # An ambiguous bare-name issue is not authority to update a namespaced
        # package, but it is enough to withhold a potentially duplicate create.
        duplicate_matches = find_existing_issue_matches(
            {"package_name": payload.get("package_name")},
            [issue for issue in current_issues if issue.state == "open"],
        )
    if duplicate_matches:
        return {
            "outcome": "skipped",
            "reason": (
                "A matching package update issue now exists "
                f"({', '.join('#' + str(match['issue']) for match in duplicate_matches)}); skipping create "
                "to avoid a duplicate"
            ),
            "issue": duplicate_matches[0]["issue"]
            if len(duplicate_matches) == 1
            else None,
            "issue_url": duplicate_matches[0]["issue_url"]
            if len(duplicate_matches) == 1
            else None,
        }
    result = runner.create_issue_guarded(
        action_id,
        str(payload.get("title") or ""),
        _with_action_marker(str(payload.get("body") or ""), action_id),
        list(payload.get("labels") or []),
    )
    return _translate_guarded_result(result)


def _execute_discovery_update(
    action_id: str,
    payload: dict[str, Any],
    client: GitHubIssueClient,
    runner: GitHubActionRunner,
) -> dict[str, Any]:
    issue_number = int(payload["issue"])
    try:
        current_issue = client.get_issue(issue_number)
    except Exception as exc:  # noqa: BLE001
        return {
            "outcome": "failed",
            "reason": f"Could not fetch issue #{issue_number} ({type(exc).__name__})",
        }
    if current_issue.state != "open":
        return {
            "outcome": "skipped",
            "reason": f"Issue #{issue_number} is no longer open",
        }
    if not is_package_update_issue(current_issue):
        return {
            "outcome": "skipped",
            "reason": f"Issue #{issue_number} is no longer a package update or advisory issue",
        }
    parsed = parse_issue_body(current_issue.body)
    if parsed.name is None:
        parsed.name = issue_package_from_title(current_issue.title)
    if not _identity_matches(
        parsed, payload.get("expected_package"), payload.get("expected_cves") or []
    ):
        return {
            "outcome": "skipped",
            "reason": (
                f"Issue #{issue_number} package/CVE identity changed "
                "since the review was generated"
            ),
        }

    additions = payload.get("field_additions") or {}
    updated_body = ensure_issue_fields(current_issue.body, str(parsed.name or ""))
    updated_body = append_field_values(
        updated_body, "CVEs", additions.get("cves") or []
    )
    updated_body = append_field_values(
        updated_body, "CVSSs", additions.get("cvss_scores") or []
    )
    updated_body = append_field_values(
        updated_body, "refmap.gentoo", additions.get("gentoo_refs") or []
    )
    updated_body = set_field_if_placeholder(
        updated_body, "Action Needed", additions.get("action_needed")
    )
    updated_body = set_field_if_placeholder(
        updated_body, "Summary", additions.get("summary")
    )
    body_result = runner.update_issue_body_guarded(
        action_id, issue_number, current_issue.body, updated_body
    )

    comment_body = payload.get("comment_body")
    comment_result = None
    if comment_body:
        try:
            already_posted = _has_marker_comment(
                client.list_comments(issue_number), action_id
            )
            comment_result = runner.post_comment_guarded(
                action_id,
                issue_number,
                _with_action_marker(str(comment_body), action_id),
                required_permission="update_existing_issues",
                already_posted=already_posted,
            )
        except Exception as exc:
            comment_result = {
                "action": "post_comment",
                "outcome": "failed",
                "reason": f"Could not check comment history ({type(exc).__name__})",
            }

    return _combine_results(body_result, comment_result)


def _execute_cleanup_comment(
    action_id: str,
    kind: str,
    payload: dict[str, Any],
    client: GitHubIssueClient,
    runner: GitHubActionRunner,
) -> dict[str, Any]:
    issue_number = int(payload["issue"])
    try:
        current_issue = client.get_issue(issue_number)
    except Exception as exc:  # noqa: BLE001
        return {
            "outcome": "failed",
            "reason": f"Could not fetch issue #{issue_number} ({type(exc).__name__})",
        }
    if current_issue.state != "open":
        return {
            "outcome": "skipped",
            "reason": f"Issue #{issue_number} is already closed; taking no action",
        }
    expected_body_digest = payload.get("expected_issue_body_sha256")
    expected_scope_labels = payload.get("expected_scope_labels")
    if (
        expected_body_digest
        and hashlib.sha256(current_issue.body.encode("utf-8")).hexdigest()
        != expected_body_digest
    ) or (
        expected_scope_labels is not None
        and sorted(set(current_issue.labels) & {"advisory/only-sdk", "advisory/sysext"})
        != expected_scope_labels
    ):
        return {
            "outcome": "skipped",
            "reason": f"Issue #{issue_number} body or scope changed since review generation",
        }
    parsed = parse_issue_body(current_issue.body)
    if not _identity_matches(
        parsed, payload.get("expected_package"), payload.get("expected_cves") or []
    ) or {str(cve).strip().upper() for cve in payload.get("expected_cves") or []} != {
        cve.strip().upper() for cve in parsed.cves
    }:
        return {
            "outcome": "skipped",
            "reason": (
                f"Issue #{issue_number} package/CVE identity changed "
                "since the review was generated"
            ),
        }

    comment_body = str(payload.get("comment_body") or "")
    already_posted = _has_marker_comment(client.list_comments(issue_number), action_id)
    comment_result = runner.post_comment_guarded(
        action_id,
        issue_number,
        _with_action_marker(comment_body, action_id),
        required_permission="post_cleanup_comments",
        already_posted=already_posted,
    )
    if kind == CLEANUP_KIND_COMMENT_AND_CLOSE and comment_result.get("outcome") in {
        "applied",
        "no_op",
    }:
        close_result = runner.close_issue_guarded(
            action_id, issue_number, already_closed=False
        )
        return _combine_results(comment_result, close_result)
    return _combine_results(comment_result)


def _execute_action(
    action: dict[str, Any], client: GitHubIssueClient, runner: GitHubActionRunner
) -> dict[str, Any]:
    kind = action.get("kind")
    action_id = action["action_id"]
    payload = action.get("payload") or {}
    if kind == FEEDBACK_KIND:
        return {
            "outcome": "no_op",
            "reason": "Explicit reviewer feedback recorded; no advisory mutation",
            "status": "feedback_recorded",
            "feedback": validate_feedback_payload(
                payload, advisory_repository=client.repo
            ),
        }
    if kind in NON_MUTATING_KINDS:
        return {"outcome": "no_op", "reason": f"{kind} performs no GitHub mutation"}
    if kind == DISCOVERY_KIND_CREATE:
        return _execute_discovery_create(action_id, payload, client, runner)
    if kind == DISCOVERY_KIND_UPDATE:
        return _execute_discovery_update(action_id, payload, client, runner)
    if kind in (CLEANUP_KIND_COMMENT_ONLY, CLEANUP_KIND_COMMENT_AND_CLOSE):
        return _execute_cleanup_comment(action_id, kind, payload, client, runner)
    return {"outcome": "failed", "reason": f"Unrecognized action kind: {kind!r}"}


def _render_execution_summary(
    execution_results: list[dict[str, Any]],
    unknown_ids: list[str],
    selected_ids: list[str] | None = None,
) -> str:
    lines = ["## Security-triage review apply summary", ""]
    lines.append(
        "Selected action IDs at execution time: "
        + (", ".join(f"`{item}`" for item in selected_ids or []) or "(none)")
    )
    lines.append("")
    counts = Counter(result["outcome"] for result in execution_results)
    lines.append(
        ", ".join(f"{outcome}: {count}" for outcome, count in sorted(counts.items()))
        if counts
        else "No decision groups were present."
    )
    lines.append("")
    for result in execution_results:
        line = f"- Group `{result['group_id']}`: {result['outcome']}"
        if result.get("action_id"):
            line += f" (action `{result['action_id']}`)"
        if result.get("kind"):
            line += f" — {_md_escape(result['kind'])}"
        if result.get("package"):
            line += f" — package: {_md_escape(result['package'])}"
        if result.get("issue_url"):
            line += f" — target/result: {_md_escape(result['issue_url'])}"
        reason = result.get("reason")
        if reason:
            line += f" — {_quote(reason)}"
        lines.append(line)
        for detail in result.get("details") or []:
            lines.append(
                f"  - {_md_escape(detail.get('operation'))}: "
                f"{_md_escape(detail.get('outcome'))}"
                + (f" — {_quote(detail['reason'])}" if detail.get("reason") else "")
            )
    if unknown_ids:
        lines.extend(
            ["", f"Unrecognized checked action ID(s) ignored: {', '.join(unknown_ids)}"]
        )
    lines.extend(
        [
            "",
            (
                "This is the execution-time selection snapshot, not the current "
                "checkbox state. Failed attempts remain retryable; an already-applied "
                "review is a no-op."
            ),
        ]
    )
    return "\n".join(lines)


def _publish_execution_summary(
    client: GitHubIssueClient,
    issue_number: int,
    summary: str,
    *,
    advisory_repository: str | None = None,
) -> dict[str, Any]:
    marker_id = f"review-summary-{issue_number}"
    marker = f"<!-- security-triage:action-id:{marker_id} -->"
    existing = [
        comment
        for comment in client.list_comments(issue_number)
        if marker in str(comment.get("body") or "")
        and is_trusted_feedback_author(comment)
    ]
    if len(existing) > 1:
        raise ManifestValidationError("Multiple bot execution summaries found")
    if existing and not _FEEDBACK_SUMMARY_BLOCK_RE.search(summary):
        prior_blocks = _FEEDBACK_SUMMARY_BLOCK_RE.findall(
            str(existing[0].get("body") or "")
        )
        if prior_blocks:
            if len(prior_blocks) != 1 or not parse_feedback_summary(
                client.get_issue(issue_number),
                existing[0],
                advisory_repository=advisory_repository or client.repo,
                review_repository=client.repo,
            ):
                raise ManifestValidationError(
                    "Cannot overwrite unverifiable prior feedback"
                )
            summary += (
                "\n\nPreviously confirmed feedback is retained from its original execution snapshot; "
                "unchecked boxes do not revoke it.\n\n" + prior_blocks[0]
            )
    body = _with_action_marker(summary, marker_id)
    if existing:
        if existing[0].get("body") != body:
            return client.update_comment(int(existing[0]["id"]), body)
        return existing[0]
    return client.post_comment(issue_number, body)


def _persist_feedback_receipt(
    client: GitHubIssueClient,
    issue: Issue,
    manifest: dict[str, Any],
    checked_ids: set[str],
    execution_results: list[dict[str, Any]],
    apply_context: ApplyContext,
) -> bool:
    """Persist immutable feedback independently of the replaceable execution summary."""
    confirmed = []
    for comment in client.list_comments(issue.number):
        confirmed.extend(
            parse_feedback_summary(
                issue,
                comment,
                advisory_repository=apply_context.advisory_repo,
                review_repository=apply_context.review_repo,
            )
        )
    feedback_results = [
        result
        for result in execution_results
        if result.get("status") == "feedback_recorded"
    ]
    if not feedback_results:
        return bool(confirmed)
    existing = {(item["action_id"], item["manifest_digest"]) for item in confirmed}
    # A retry of the same feedback action is not a new reviewer decision.
    # Unrelated checkbox changes must not refresh its timestamp past a revocation.
    feedback_results = [
        result
        for result in feedback_results
        if (result["action_id"], manifest["digest"]) not in existing
    ]
    if not feedback_results:
        return True
    desired = {(result["action_id"], manifest["digest"]) for result in feedback_results}
    lines = [
        "## Security-triage reviewer feedback receipt",
        "",
        "This immutable receipt records the original Completed apply selection. "
        "Later checkbox edits do not revoke it; use an explicit revoke decision.",
        "",
    ]
    lines.extend(
        f"- {_md_escape(result.get('package'))}: "
        f"{_md_escape(result['feedback']['decision'])} (`{result['action_id']}`)"
        for result in feedback_results
    )
    lines.extend(
        [
            "",
            render_feedback_summary(
                manifest,
                checked_ids,
                feedback_results,
                review_issue_number=issue.number,
            ),
        ]
    )
    response = client.post_comment(issue.number, "\n".join(lines))
    persisted = parse_feedback_summary(
        issue,
        response,
        advisory_repository=apply_context.advisory_repo,
        review_repository=apply_context.review_repo,
    )
    if not desired <= {
        (item["action_id"], item["manifest_digest"]) for item in persisted
    }:
        raise ManifestValidationError(
            "Feedback receipt was not durably persisted by trusted automation"
        )
    return True


def _gate_result(outcome: str, reason: str, issue_number: int) -> dict[str, Any]:
    return {"outcome": outcome, "reason": reason, "issue": issue_number, "groups": []}


def apply_review_issue(
    review_client: GitHubIssueClient,
    advisory_client: GitHubIssueClient,
    runner: GitHubActionRunner,
    issue_number: int,
    apply_context: ApplyContext,
    progress_logger: ProgressLogger | None = None,
    debug_logger: DebugLogger | None = None,
) -> dict[str, Any]:
    """Apply a closed review issue's checked, conflict-free actions.

    Always re-fetches the issue fresh (never trusts a webhook payload) and
    performs the ordered safety gate described in the design plan: dedicated
    label + manifest marker present; close reason exactly ``completed``; not
    already applied; manifest schema/digest/identity/repository valid; then
    resolves and executes only checked, unambiguous, schema-valid actions.
    Returns without any GitHub mutation for every other close reason.
    """
    progress = progress_logger or NullProgressLogger()
    debug = debug_logger or DebugLogger()
    issue = review_client.get_issue(issue_number)
    debug.log(
        "review_apply_fetched_issue",
        issue=issue_number,
        state=issue.state,
        state_reason=issue.state_reason,
        labels=issue.labels,
    )

    if REVIEW_LABEL not in issue.labels:
        return _gate_result(
            "skipped",
            f"Issue #{issue_number} does not carry the {REVIEW_LABEL!r} label",
            issue_number,
        )
    if find_batch_part_marker(issue.body) is None:
        return _gate_result(
            "skipped",
            f"Issue #{issue_number} has no review batch/part marker",
            issue_number,
        )
    if issue.state != "closed" or issue.state_reason != "completed":
        return _gate_result(
            "skipped",
            f"Issue #{issue_number} close reason is {issue.state_reason!r} "
            f"(state {issue.state!r}); only state_reason=='completed' "
            "applies actions",
            issue_number,
        )
    if REVIEW_APPLIED_LABEL in issue.labels:
        return _gate_result(
            "no_op",
            f"Issue #{issue_number} was already applied; no action taken",
            issue_number,
        )

    if (
        review_client.repo != apply_context.review_repo
        or advisory_client.repo != apply_context.advisory_repo
        or runner.client.repo != apply_context.advisory_repo
    ):
        return _gate_result(
            "failed", "Configured clients do not match apply repositories", issue_number
        )

    try:
        manifest = extract_manifest(issue.body)
        validate_manifest_against_context(
            manifest, apply_context.advisory_repo, apply_context.review_repo
        )
        if find_batch_part_marker(issue.body) != (
            manifest["batch_id"],
            manifest["part_id"],
        ):
            raise ManifestValidationError(
                "Review marker and manifest identity disagree"
            )
    except (ManifestCorruptionError, ManifestValidationError) as exc:
        result = _gate_result(
            "failed", f"Review manifest failed validation: {exc}", issue_number
        )
        try:
            _publish_execution_summary(
                review_client,
                issue_number,
                "## Security-triage review apply summary\n\n"
                "Validation failed; no advisory actions were executed. No applied label was added.\n\n"
                + _quote(result["reason"]),
                advisory_repository=apply_context.advisory_repo,
            )
        except Exception:
            result["summary_error"] = "Could not publish the validation failure summary"
        return result

    checked_ids = parse_checked_action_ids(issue.body)
    unknown_ids = unknown_checked_action_ids(manifest, checked_ids)
    resolutions = resolve_review_selections(manifest, checked_ids)
    selected_count = sum(
        1 for resolution in resolutions if resolution.outcome == "selected"
    )
    progress.info(
        f"Applying review issue #{issue_number}: {len(resolutions)} "
        f"group(s), {selected_count} selected action(s)"
    )

    # Defense in depth: restrict the runner to exactly the action IDs this
    # apply run legitimately resolved from the (now verified-unambiguous,
    # digest-valid) manifest. This does not by itself decide *which* actions
    # are legitimate -- that already happened above -- but it ensures no
    # other code path can ever cause a mutation for an action ID that this
    # resolution step did not select.
    runner.allowed_action_ids = {
        resolution.selected_action["action_id"]
        for resolution in resolutions
        if resolution.outcome == "selected" and resolution.selected_action is not None
    }
    selected_ids = sorted(runner.allowed_action_ids)
    group_metadata = {group["group_id"]: group for group in manifest["groups"]}

    execution_results: list[dict[str, Any]] = []
    all_terminal = True
    for resolution in resolutions:
        if resolution.outcome == "no_action":
            execution_results.append(
                {
                    "group_id": resolution.group_id,
                    "outcome": "no_action",
                    "action_id": None,
                    "reason": None,
                }
            )
            continue
        if resolution.outcome == "conflict":
            execution_results.append(
                {
                    "group_id": resolution.group_id,
                    "outcome": "conflict",
                    "action_id": None,
                    "reason": (
                        "Conflicting selected alternatives or mutation/feedback choices: "
                        f"{', '.join(resolution.checked_action_ids)}"
                    ),
                }
            )
            continue
        action = resolution.selected_action
        assert action is not None
        progress.info(
            f"Executing action {action['action_id']} ({action['kind']}) "
            f"for group {resolution.group_id}"
        )
        try:
            result = _execute_action(action, advisory_client, runner)
        except Exception as exc:
            result = {
                "outcome": "failed",
                "reason": f"Action failed ({type(exc).__name__}); retry is safe",
            }
        debug.log(
            "review_apply_action_result",
            action_id=action["action_id"],
            kind=action["kind"],
            result=result,
        )
        payload = action.get("payload") or {}
        metadata = group_metadata[resolution.group_id]
        target_issue = (
            result.get("issue") or payload.get("issue") or metadata.get("target_issue")
        )
        issue_url = (
            f"https://github.com/{apply_context.advisory_repo}/issues/{target_issue}"
            if target_issue
            else result.get("issue_url")
        )
        execution_results.append(
            {
                "group_id": resolution.group_id,
                "outcome": result["outcome"],
                "action_id": action["action_id"],
                "reason": result.get("reason"),
                "kind": action["kind"],
                "package": payload.get("package_name")
                or payload.get("expected_package")
                or metadata.get("package"),
                "issue": target_issue,
                "issue_url": issue_url,
                "details": result.get("details") or [],
                "status": result.get("status"),
                "feedback": result.get("feedback"),
            }
        )
        if result["outcome"] == "failed":
            all_terminal = False

    persistence_reason = None
    try:
        has_feedback = _persist_feedback_receipt(
            review_client,
            issue,
            manifest,
            checked_ids,
            execution_results,
            apply_context,
        )
    except Exception:
        has_feedback = False
        all_terminal = False
        persistence_reason = "Could not persist the trusted feedback receipt; retry is safe and no applied label was added"
        for result in execution_results:
            if result.get("status") == "feedback_recorded":
                result.update(
                    outcome="failed",
                    status="feedback_persistence_failed",
                    reason=persistence_reason,
                )
    outcome = "applied" if all_terminal else "partial_failure"
    summary_comment = _render_execution_summary(
        execution_results, unknown_ids, selected_ids
    )
    if persistence_reason:
        summary_comment += "\n\n" + persistence_reason
    try:
        _publish_execution_summary(
            review_client,
            issue_number,
            summary_comment,
            advisory_repository=apply_context.advisory_repo,
        )
    except Exception:
        return {
            "outcome": "partial_failure",
            "issue": issue_number,
            "reason": "Could not persist execution summary; no applied label was added",
            "groups": execution_results,
            "selected_action_ids": selected_ids,
            "unknown_checked_action_ids": unknown_ids,
        }
    if has_feedback:
        try:
            if REVIEW_FEEDBACK_LABEL not in issue.labels:
                review_client.ensure_label_exists(
                    REVIEW_FEEDBACK_LABEL,
                    color="5319e7",
                    description="Internal index of confirmed security-triage reviewer feedback",
                )
                review_client.add_labels(issue_number, [REVIEW_FEEDBACK_LABEL])
        except Exception:
            all_terminal = False
            outcome = "partial_failure"
            persistence_reason = "Could not persist the trusted feedback index label; retry is safe and no applied label was added"
            try:
                _publish_execution_summary(
                    review_client,
                    issue_number,
                    summary_comment + "\n\n" + persistence_reason,
                    advisory_repository=apply_context.advisory_repo,
                )
            except Exception:
                pass
    if all_terminal:
        if REVIEW_APPLIED_LABEL not in issue.labels:
            try:
                review_client.ensure_label_exists(
                    REVIEW_APPLIED_LABEL,
                    color="0e8a16",
                    description="Security-triage review actions have been applied",
                )
                review_client.add_labels(issue_number, [REVIEW_APPLIED_LABEL])
            except Exception:
                outcome = "partial_failure"
                try:
                    _publish_execution_summary(
                        review_client,
                        issue_number,
                        summary_comment
                        + "\n\nCould not persist the applied label; retry is safe.",
                        advisory_repository=apply_context.advisory_repo,
                    )
                except Exception:
                    pass

    return {
        "outcome": outcome,
        "reason": persistence_reason,
        "issue": issue_number,
        "unknown_checked_action_ids": unknown_ids,
        "selected_action_ids": selected_ids,
        "groups": execution_results,
    }
