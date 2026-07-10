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
action IDs that exist verbatim in the signed-for manifest ever reach a mutating
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
from .issue_updates import append_field_values, set_field_if_placeholder
from .issues import GitHubIssueClient, find_existing_issue_matches, parse_issue_body
from .records import Issue, ParsedIssue
from .rules import (
    REVIEW_APPLIED_LABEL,
    REVIEW_LABEL,
    cleanup_comment_body,
    is_gentoo_reference,
    issue_labels,
    neutralize_mentions,
    normalize_name,
    render_issue_body,
    sanitize_single_line,
    severity_label,
    truncate_text,
    validate_repo_name,
)

REVIEW_SCHEMA_VERSION = "1.0"

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
ALL_ACTION_KINDS = DISCOVERY_ACTION_KINDS | CLEANUP_ACTION_KINDS

#: Action kinds that never call a mutating GitHub API. Selecting one of these
#: only records an explicit human acknowledgement in the execution summary.
NON_MUTATING_KINDS = {
    DISCOVERY_KIND_IGNORE,
    DISCOVERY_KIND_KERNEL,
    DISCOVERY_KIND_MANUAL,
    CLEANUP_KIND_KEEP_OPEN,
    CLEANUP_KIND_MANUAL,
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

    def __post_init__(self) -> None:
        self.advisory_repo = validate_repo_name(self.advisory_repo)
        self.review_repo = validate_repo_name(self.review_repo)
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


def embed_manifest(manifest: dict[str, Any]) -> str:
    encoded = base64.b64encode(canonical_json(manifest).encode("utf-8")).decode("ascii")
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
    for group in manifest.get("groups", []):
        if (
            not isinstance(group, dict)
            or not group.get("group_id")
            or not isinstance(group.get("actions"), list)
        ):
            raise ManifestValidationError(
                "Review manifest contains a malformed decision group"
            )
        for action in group["actions"]:
            _validate_manifest_action(action)
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
    elif kind == DISCOVERY_KIND_UPDATE:
        if not isinstance(payload.get("issue"), int):
            raise ManifestValidationError(
                f"Action {action_id!r} payload is missing an issue number"
            )
    elif kind in (CLEANUP_KIND_COMMENT_ONLY, CLEANUP_KIND_COMMENT_AND_CLOSE):
        if not isinstance(payload.get("issue"), int) or not payload.get("comment_body"):
            raise ManifestValidationError(
                f"Action {action_id!r} payload is missing an issue number "
                "or comment body"
            )


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


def build_discovery_groups(document: dict[str, Any] | None) -> list[DecisionGroup]:
    if not document:
        return []
    groups: list[DecisionGroup] = []
    for record in document.get("records", []):
        action = (record.get("decision") or {}).get("action")
        if action == "needs_manual_review":
            groups.append(_discovery_manual_group(record))
        else:
            groups.append(_discovery_normal_group(record, action))
    return groups


def build_cleanup_groups(document: dict[str, Any] | None) -> list[DecisionGroup]:
    if not document:
        return []
    groups: list[DecisionGroup] = []
    for record in document.get("records", []):
        recommended = record.get("recommended_action")
        if recommended == "manual_review":
            groups.append(_cleanup_manual_group(record))
        else:
            groups.append(_cleanup_normal_group(record, recommended))
    return groups


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
    if proposed:
        title = str(proposed.get("title") or "")
        body = str(proposed.get("body") or "")
        labels = list(proposed.get("labels") or [])
    else:
        relevance = record.get("flatcar_relevance") or {}
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
        labels = issue_labels(
            extraction.get("cvss_scores"),
            relevance.get("scope"),
            extraction.get("scope_assessment"),
        )
    return {
        "title": title,
        "body": body,
        "labels": labels,
        "package_name": extraction.get("package_name"),
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
    match = next(
        (item for item in matches if int(item.get("issue", -1)) == target_issue),
        matches[0] if matches else {},
    )
    proposed_update = record.get("proposed_update") or {}
    return {
        "issue": target_issue,
        "field_additions": _field_additions(extraction, upstream_activity, record),
        "comment_body": proposed_update.get("comment_body"),
        "expected_package": match.get("package") or extraction.get("package_name"),
        "expected_cves": list(match.get("cves") or []),
    }


def _discovery_normal_group(
    record: dict[str, Any], action: str | None
) -> DecisionGroup:
    record_id = str(record.get("record_id") or "")
    kind = _DISCOVERY_KIND_BY_ACTION.get(action or "")
    group_id = _group_id("discovery", record_id)
    target_issue: int | None = None
    payload: dict[str, Any] = {}
    label = "Approve the recommended action"

    if kind == DISCOVERY_KIND_CREATE and record.get("proposed_issue"):
        payload = _create_payload(record)
        label = f"Create new advisory issue: {payload['title']}"
    elif kind == DISCOVERY_KIND_UPDATE and record.get("proposed_update"):
        target_issue = int(record["proposed_update"]["issue"])
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
    record_id = str(record.get("record_id") or "")
    group_id = _group_id("discovery", record_id)
    candidates: list[ActionCandidate] = []

    extraction = record.get("llm_extraction") or {}
    package_name = str(extraction.get("package_name") or "").strip()
    cves = [cve for cve in (extraction.get("cves") or []) if str(cve).strip()]
    summary = str(extraction.get("summary") or "").strip()
    if package_name and (cves or (summary and summary.upper() != "TBD")):
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

    existing_matches = record.get("existing_issue_matches") or []
    if existing_matches:
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
_HTML_COMMENT_CLOSE_RE = re.compile(r"-->")


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
                "- Action Needed (only applied if currently TBD): "
                f"{_truncate_md(additions['action_needed'], 200)}"
            )
        if additions.get("summary"):
            add_lines.append(
                "- Summary (only applied if currently TBD): "
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
            "apply time and never removes existing content.\n</details>\n"
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
        f"- Source URL: `{record.get('source_url') or 'n/a'}`",
        "- CVEs / upstream IDs: "
        + (
            ", ".join(cves)
            if cves
            else _md_escape(record.get("raw_advisory_id")) or "n/a"
        ),
        f"- CVSS: {', '.join(cvss) if cvss else 'n/a'}",
        (
            f"- Flatcar relevance: **{relevance.get('status')}** "
            f"(scope: {relevance.get('scope')})"
        ),
        (
            f"- Recommendation: **{decision.get('action')}** "
            f"(confidence: {decision.get('confidence')})"
        ),
    ]
    sbom_matches = record.get("sbom_package_matches") or []
    if sbom_matches:
        lines.append(
            "- SBOM matches: "
            + "; ".join(
                (
                    f"{match.get('name')} {match.get('versionInfo')} "
                    f"({match.get('match_type')})"
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
                    f"#{match.get('issue')} ({match.get('state')}): "
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
        f"- Package: {record.get('package_from_issue') or 'unknown'}",
        f"- CVEs: {', '.join(record.get('cves_from_issue') or []) or 'n/a'}",
        (
            "- Required fixed version (Action Needed): "
            f"{record.get('fixed_version_requirement') or 'unparsed'}"
        ),
        (
            f"- Status: **{record.get('status')}** "
            f"(confidence: {record.get('confidence')})"
        ),
        "- Current issue state (at report time): open",
        f"- Issue link: {record.get('issue_url')}",
    ]
    matches = record.get("sbom_package_matches") or []
    if matches:
        lines.append(
            "- SBOM matches: "
            + "; ".join(
                (
                    f"{match.get('name')} {match.get('versionInfo')} "
                    f"({match.get('match_type')})"
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
    if not groups:
        return ["", "(no decision groups)"]
    kind_counts = Counter(
        group.candidates[0].kind if group.candidates else "unknown" for group in groups
    )
    confidence_counts = Counter(_group_confidence(group) for group in groups)
    severity_counts = Counter(_group_severity(group) for group in groups)
    lines = ["", "| Recommendation | Count |", "| --- | --- |"]
    lines.extend(f"| {kind} | {count} |" for kind, count in sorted(kind_counts.items()))
    lines.extend(["", "| Confidence | Count |", "| --- | --- |"])
    lines.extend(
        f"| {level} | {count} |" for level, count in sorted(confidence_counts.items())
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
            f"This part contains {len(part_groups)} decision group(s).",
        ]
    )
    lines.extend(_render_counts_table(part_groups))
    if part_count > 1:
        lines.extend(
            [
                "",
                (
                    f"Whole batch: {len(all_groups)} decision group(s) "
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
    return {
        "group_id": group.group_id,
        "source": group.source,
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
    for item in rendered_groups:
        _, _, item_len = item
        # A single group larger than the budget still gets its own part
        # rather than being split mid-group or dropped.
        if current and current_len + item_len > max_group_chars:
            packed.append(current)
            current = []
            current_len = 0
        current.append(item)
        current_len += item_len
    if current:
        packed.append(current)
    return packed


def _finalize_part(
    context: ReviewContext,
    part_index: int,
    part_count: int,
    group_slice: list[tuple[DecisionGroup, str, int]],
    all_groups: list[DecisionGroup],
) -> ReviewPart:
    groups = [group for group, _, _ in group_slice]
    group_text = "\n".join(text for _, text, _ in group_slice)
    header = _render_header(context, part_index, part_count, groups, all_groups)
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
    }
    digest = compute_digest(manifest_without_digest)
    manifest = {**manifest_without_digest, "digest": digest}
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
    all_groups = [
        *build_discovery_groups(discovery_document),
        *build_cleanup_groups(cleanup_document),
    ]
    rendered_groups: list[tuple[DecisionGroup, str, int]] = []
    for index, group in enumerate(all_groups):
        text = _render_group(group, index + 1)
        # Packing must weigh both the human-readable rendered text *and* this
        # group's contribution to the base64-encoded manifest embedded in the
        # footer -- the manifest re-serializes the same proposed
        # titles/bodies/comments, so ignoring it would let a part's real
        # rendered size silently exceed the configured (and GitHub's hard)
        # body-size limit.
        manifest_json_len = len(canonical_json(_manifest_group(group)))
        combined_len = len(text) + int(manifest_json_len * _MANIFEST_SIZE_SAFETY_FACTOR)
        rendered_groups.append((group, text, combined_len))
    max_group_chars = max(
        context.max_part_body_chars - _RESERVED_OVERHEAD_CHARS, _MIN_GROUP_BUDGET_CHARS
    )
    packed = _pack_groups(rendered_groups, max_group_chars)
    slices = packed or [[]]
    part_count = len(slices)
    parts = [
        _finalize_part(context, part_index, part_count, group_slice, all_groups)
        for part_index, group_slice in enumerate(slices, start=1)
    ]
    return ReviewBatch(batch_id=context.run_id, parts=parts, groups=all_groups)


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
        f"Total decision groups: {len(batch.groups)}",
        "",
        "No GitHub API calls were made while generating this output.",
        "",
        "| Part | Title | File | Decision groups |",
        "| --- | --- | --- | --- |",
    ]
    for part, path in zip(batch.parts, part_paths, strict=True):
        lines.append(
            f"| {part.part_index}/{part.part_count} | {part.title} | "
            f"`{path.name}` | {len(part.group_ids)} |"
        )
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
    ensure_review_label(client)
    existing_by_part_id: dict[str, Issue] = {}
    for issue in client.list_issues_by_label(REVIEW_LABEL, state="all"):
        marker = find_batch_part_marker(issue.body)
        if marker:
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
    expected_name = normalize_name(str(expected_package or ""))
    current_name = normalize_name(parsed.name or "")
    if expected_name and current_name and expected_name == current_name:
        return True
    expected_cve_set = {str(cve).upper() for cve in expected_cves if str(cve).strip()}
    current_cve_set = {cve.upper() for cve in parsed.cves}
    if expected_cve_set and current_cve_set and expected_cve_set & current_cve_set:
        return True
    return False


def _translate_guarded_result(result: dict[str, Any]) -> dict[str, Any]:
    outcome = result.get("outcome")
    if outcome == "blocked":
        return {"outcome": "skipped", "reason": result.get("reason")}
    if outcome == "no_op":
        return {"outcome": "no_op", "reason": result.get("reason")}
    return {"outcome": "applied", "reason": None}


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
        current_issues = client.fetch_open_advisory_issues()
    except Exception as exc:  # noqa: BLE001 - surfaced as a failed outcome, not raised
        return {
            "outcome": "failed",
            "reason": (
                "Could not fetch current advisory issues for the fresh "
                f"duplicate check: {exc}"
            ),
        }
    duplicate_matches = find_existing_issue_matches(
        {
            "package_name": payload.get("package_name"),
            "cves": payload.get("cves") or [],
        },
        current_issues,
    )
    if duplicate_matches:
        return {
            "outcome": "skipped",
            "reason": (
                "A matching advisory issue now exists "
                f"(#{duplicate_matches[0]['issue']}); skipping create "
                "to avoid a duplicate"
            ),
        }
    result = runner.create_issue_guarded(
        action_id,
        str(payload.get("title") or ""),
        str(payload.get("body") or ""),
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
            "reason": f"Could not fetch issue #{issue_number}: {exc}",
        }
    if current_issue.state != "open":
        return {
            "outcome": "skipped",
            "reason": f"Issue #{issue_number} is no longer open",
        }
    parsed = parse_issue_body(current_issue.body)
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
    updated_body = current_issue.body
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
            "reason": f"Could not fetch issue #{issue_number}: {exc}",
        }
    if current_issue.state != "open":
        return {
            "outcome": "skipped",
            "reason": f"Issue #{issue_number} is already closed; taking no action",
        }
    parsed = parse_issue_body(current_issue.body)
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

    comment_body = str(payload.get("comment_body") or "")
    already_posted = _has_marker_comment(client.list_comments(issue_number), action_id)
    comment_result = runner.post_comment_guarded(
        action_id,
        issue_number,
        _with_action_marker(comment_body, action_id),
        required_permission="post_cleanup_comments",
        already_posted=already_posted,
    )
    if (
        kind == CLEANUP_KIND_COMMENT_AND_CLOSE
        and comment_result.get("outcome") != "blocked"
    ):
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
    execution_results: list[dict[str, Any]], unknown_ids: list[str]
) -> str:
    lines = ["## Security-triage review apply summary", ""]
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
        reason = result.get("reason")
        if reason:
            line += f" — {_quote(reason)}"
        lines.append(line)
    if unknown_ids:
        lines.extend(
            ["", f"Unrecognized checked action ID(s) ignored: {', '.join(unknown_ids)}"]
        )
    lines.extend(
        [
            "",
            (
                "This comment is posted once per applied review part; "
                "re-running apply on an already-applied issue is a no-op."
            ),
        ]
    )
    return "\n".join(lines)


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

    try:
        manifest = extract_manifest(issue.body)
        validate_manifest_against_context(
            manifest, apply_context.advisory_repo, apply_context.review_repo
        )
    except (ManifestCorruptionError, ManifestValidationError) as exc:
        return _gate_result(
            "failed", f"Review manifest failed validation: {exc}", issue_number
        )

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
                        "Multiple checked alternatives: "
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
        result = _execute_action(action, advisory_client, runner)
        debug.log(
            "review_apply_action_result",
            action_id=action["action_id"],
            kind=action["kind"],
            result=result,
        )
        execution_results.append(
            {
                "group_id": resolution.group_id,
                "outcome": result["outcome"],
                "action_id": action["action_id"],
                "reason": result.get("reason"),
            }
        )
        if result["outcome"] == "failed":
            all_terminal = False

    outcome = "applied" if all_terminal else "partial_failure"
    if all_terminal:
        summary_action_id = f"applied-summary-{manifest['part_id']}"
        summary_comment = _render_execution_summary(execution_results, unknown_ids)
        if not _has_marker_comment(
            review_client.list_comments(issue_number), summary_action_id
        ):
            review_client.post_comment(
                issue_number, _with_action_marker(summary_comment, summary_action_id)
            )
        if REVIEW_APPLIED_LABEL not in issue.labels:
            review_client.ensure_label_exists(
                REVIEW_APPLIED_LABEL,
                color="0e8a16",
                description="Security-triage review actions have been applied",
            )
            review_client.add_labels(issue_number, [REVIEW_APPLIED_LABEL])

    return {
        "outcome": outcome,
        "reason": None,
        "issue": issue_number,
        "unknown_checked_action_ids": unknown_ids,
        "groups": execution_results,
    }
