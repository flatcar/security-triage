from __future__ import annotations

import re
from typing import Any

SCHEMA_VERSION = "1.0"
PROMPT_VERSION = "security-triage-2026-04-29"
TARGET_REPO = "flatcar/Flatcar"
FLATCAR_PRODUCTION_SBOM_URL = "https://alpha.release.flatcar-linux.net/amd64-usr/current/flatcar_production_image_sbom.json"
REVIEW_LABEL = "security-triage/review"
REVIEW_APPLIED_LABEL = "security-triage/review-applied"

REQUIRED_LABELS = {"advisory", "security"}
ALLOWED_LABELS = {
    "advisory",
    "security",
    "advisory/only-sdk",
    "advisory/sysext",
    "cvss/CRITICAL",
    "cvss/HIGH",
    "cvss/MEDIUM",
}
ALLOWED_CONFIDENCE = {"high", "medium", "low"}
DISCOVERY_ACTIONS = {
    "create_issue",
    "update_existing_issue",
    "ignore",
    "kernel_regular_update_flow",
    "needs_manual_review",
}
RELEVANCE_STATUSES = {
    "relevant",
    "not_relevant",
    "needs_manual_review",
    "kernel_regular_update_flow",
}
RELEVANCE_SCOPES = {
    "production",
    "sdk_only",
    "sysext",
    "build_only",
    "not_shipped",
    "unknown",
}
SBOM_MATCH_ASSESSMENT_STATUSES = {
    "confirmed_match",
    "plausible_match",
    "unrelated_matches",
    "no_matches",
    "needs_manual_review",
}
CLEANUP_STATUSES = {
    "remediated_in_current_production_sbom",
    "not_remediated_in_current_production_sbom",
    "needs_manual_review",
}
CLEANUP_RECOMMENDATIONS = {"comment_only", "close_issue", "keep_open", "manual_review"}

MAX_ACTION_NEEDED_LENGTH = 300
MAX_SUMMARY_LENGTH = 2000
MAX_PACKAGE_NAME_LENGTH = 200
MAX_GENTOO_REF_LENGTH = 400

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")
_MENTION_RE = re.compile(
    r"(^|[^\w`])@([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:/[A-Za-z0-9._-]+)?)"
)
_CVSS_RE = re.compile(r"(?<!\d)(10(?:\.0)?|[0-9](?:\.\d)?)(?!\d)")
_KERNEL_RE = re.compile(
    r"\b(linux|linux-kernel|kernel|sys-kernel|kernel-cve)\b", re.IGNORECASE
)
_STRIKETHROUGH_RE = re.compile(r"(?:~~.*?~~|~[^~]*~)", re.DOTALL)
_GENTOO_REF_MARKERS = ("bugs.gentoo.org", "glsa.gentoo.org", "security.gentoo.org/glsa")
_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
_REPO_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_REPO_FORBIDDEN_CHARS = frozenset(" \t\r\n?#@\\\"'<>|*")


class SchemaValidationError(ValueError):
    pass


class RepositoryValidationError(SchemaValidationError):
    """Raised when a configured GitHub repository identifier is missing or unsafe.

    Target repositories always come from trusted CLI arguments, environment
    variables, or workflow configuration -- never from editable issue prose --
    but every value is still validated defensively before use in an API path
    or search query.
    """


def validate_repo_name(value: str | None) -> str:
    """Validate and normalize a GitHub ``owner/repo`` identifier.

    Rejects empty values, control characters, whitespace, and query/fragment
    style characters, and requires exactly one ``/``-delimited owner/repo pair
    using the character set GitHub allows in login and repository slugs.
    """
    text = (value or "").strip()
    if not text:
        raise RepositoryValidationError("Repository name must not be empty")
    if _CONTROL_CHARS_RE.search(text) or any(
        char in _REPO_FORBIDDEN_CHARS for char in text
    ):
        raise RepositoryValidationError(
            f"Repository name contains invalid characters: {value!r}"
        )
    parts = text.split("/")
    if len(parts) != 2:
        raise RepositoryValidationError(
            f"Repository name must be 'owner/repo': {value!r}"
        )
    owner, repo = parts
    if not owner or len(owner) > 39 or not _OWNER_RE.match(owner):
        raise RepositoryValidationError(f"Invalid repository owner: {owner!r}")
    if (
        not repo
        or len(repo) > 100
        or repo in {".", ".."}
        or not _REPO_NAME_RE.match(repo)
    ):
        raise RepositoryValidationError(f"Invalid repository name: {repo!r}")
    return f"{owner}/{repo}"


def advisory_issue_query(repo: str, *, exclude_review_label: bool = True) -> str:
    """Build the advisory-issue search query for ``repo``.

    Parameterized so battle testing in ``flatcar/security-triage`` and a later
    production rollout to ``flatcar/Flatcar`` only change configuration, never
    the query-building logic. The dedicated review label is excluded as
    defense in depth even though review issues never receive the ``advisory``
    or ``security`` labels.
    """
    validated = validate_repo_name(repo)
    query = f"repo:{validated} is:issue is:open label:advisory label:security"
    if exclude_review_label:
        query += f' -label:"{REVIEW_LABEL}"'
    return query


def review_issue_label_query(repo: str) -> str:
    """Build a diagnostic search query for review issues in any state.

    The review pipeline's own duplicate/idempotency checks use the Issues
    List API (label filter with ``state=all``) instead of this search query
    because GitHub's search index is only eventually consistent, and a rerun
    of the same Actions run needs an immediately consistent duplicate check.
    """
    validated = validate_repo_name(repo)
    return f'repo:{validated} is:issue label:"{REVIEW_LABEL}"'


def is_gentoo_reference(value: Any) -> bool:
    """Return True when ``value`` looks like a real Gentoo Bugzilla/GLSA reference.

    Used to keep ``refmap.gentoo`` restricted to genuine Gentoo URLs instead of
    an arbitrary upstream link that untrusted source text might suggest.
    """
    text = str(value or "").strip()
    if not text or text.upper() in {"TBD", "N/A", "NONE"}:
        return False
    return any(marker in text for marker in _GENTOO_REF_MARKERS)


def sanitize_single_line(value: str | None) -> str:
    """Collapse control characters (newlines, tabs, etc.) to single spaces.

    Advisory fields are rendered into a line-oriented issue body such as
    ``Action Needed: <value>``. Without this, a value that contains a newline
    could inject additional ``Field: value`` lines that downstream issue parsing
    and cleanup automation would trust (for example a forged low fixed-version
    that makes a still-vulnerable package look remediated).
    """
    if not value:
        return ""
    return _CONTROL_CHARS_RE.sub(" ", value).strip()


def extract_cves(text: str | None) -> list[str]:
    if not text:
        return []
    seen: set[str] = set()
    cves: list[str] = []
    for match in _CVE_RE.findall(text):
        cve = match.upper()
        if cve not in seen:
            cves.append(cve)
            seen.add(cve)
    return cves


def neutralize_mentions(text: str | None) -> str:
    """Wrap @mentions in code spans so upstream-controlled text cannot ping GitHub users or teams."""
    if not text:
        return ""
    return _MENTION_RE.sub(lambda match: f"{match.group(1)}`@{match.group(2)}`", text)


def truncate_text(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3].rstrip() + "..."


def active_markdown_text(text: str | None) -> str:
    if not text:
        return ""
    active = _STRIKETHROUGH_RE.sub("", text)
    lines = [line.strip(" \t,;") for line in active.splitlines()]
    return "\n".join(line for line in lines if line).strip()


def normalize_name(value: str | None) -> str:
    if not value:
        return ""
    text = value.strip().lower()
    if ":" in text and text.startswith("pkg:"):
        text = text.rsplit("/", 1)[-1].split("@", 1)[0]
    if "/" in text:
        text = text.rsplit("/", 1)[-1]
    return re.sub(r"[^a-z0-9.+_-]+", "-", text).strip("-")


def parse_cvss_scores(values: list[Any] | str | None) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        raw_values = re.split(r"[,\s]+", values)
    else:
        raw_values = [str(value) for value in values]
    scores: list[str] = []
    for raw in raw_values:
        text = raw.strip()
        if not text or text.lower() == "n/a":
            continue
        match = _CVSS_RE.search(text)
        if not match:
            continue
        score = match.group(1)
        if score not in scores:
            scores.append(score)
    return scores


def severity_label(cvss_scores: list[Any] | str | None) -> str | None:
    parsed = parse_cvss_scores(cvss_scores)
    if not parsed:
        return None
    highest = max(float(score) for score in parsed)
    if highest >= 9:
        return "cvss/CRITICAL"
    if highest > 7:
        return "cvss/HIGH"
    if highest >= 4:
        return "cvss/MEDIUM"
    return None


def scope_labels(scope: str | None, scope_assessment: str | None = None) -> list[str]:
    labels: list[str] = []
    text = f"{scope or ''} {scope_assessment or ''}".lower()
    if scope == "sdk_only" or "sdk-only" in text or "sdk only" in text:
        labels.append("advisory/only-sdk")
    if scope == "sysext" or "sysext" in text or "system extension" in text:
        labels.append("advisory/sysext")
    return labels


def issue_labels(
    cvss_scores: list[Any] | str | None,
    scope: str | None,
    scope_assessment: str | None = None,
) -> list[str]:
    labels = ["advisory", "security"]
    labels.extend(scope_labels(scope, scope_assessment))
    label = severity_label(cvss_scores)
    if label:
        labels.append(label)
    return sanitize_labels(labels)


def sanitize_labels(labels: list[str]) -> list[str]:
    ordered: list[str] = []
    for label in ["advisory", "security", *labels]:
        if label in ALLOWED_LABELS and label not in ordered:
            ordered.append(label)
    return ordered


def render_issue_body(
    package_name: str,
    cves: list[str],
    cvss_scores: list[str] | None,
    action_needed: str | None,
    summary: str | None,
    gentoo_ref: str | None,
) -> str:
    cve_text = ", ".join(sanitize_single_line(cve) for cve in cves) if cves else "TBD"
    cvss_text = (
        ", ".join(sanitize_single_line(score) for score in cvss_scores or [])
        if cvss_scores
        else "n/a"
    )
    return (
        f"Name: {sanitize_single_line(package_name)}\n"
        f"CVEs: {cve_text}\n"
        f"CVSSs: {cvss_text}\n"
        f"Action Needed: {sanitize_single_line(action_needed) or 'TBD'}\n"
        f"Summary: {sanitize_single_line(summary) or 'TBD'}\n\n"
        f"refmap.gentoo: {sanitize_single_line(gentoo_ref) or 'TBD'}"
    )


def is_kernel_advisory(package_name: str | None, title: str | None = None) -> bool:
    text = " ".join(part for part in [package_name, title] if part)
    if not text:
        return False
    normalized = normalize_name(package_name)
    return normalized in {
        "linux",
        "kernel",
        "linux-kernel",
        "sys-kernel",
        "gentoo-kernel",
    } or bool(_KERNEL_RE.search(text))


def coerce_confidence(value: Any, default: str = "low") -> str:
    text = str(value or default).lower()
    return text if text in ALLOWED_CONFIDENCE else default


def coerce_extraction(data: dict[str, Any] | None) -> dict[str, Any]:
    source = data or {}
    cves = [
        sanitize_single_line(str(cve).upper())
        for cve in source.get("cves", [])
        if str(cve).strip()
    ]
    if not cves:
        cves = extract_cves(
            " ".join(
                str(source.get(key, "")) for key in ("summary", "raw_text", "title")
            )
        )
    cvss_scores = parse_cvss_scores(source.get("cvss_scores", []))
    fixed_versions = [
        sanitize_single_line(str(item))
        for item in source.get("fixed_versions", [])
        if str(item).strip()
    ]
    action_needed = sanitize_single_line(str(source.get("action_needed") or "")) or None
    if not action_needed and fixed_versions:
        action_needed = f"update to >= {fixed_versions[0]}"
    return {
        "package_name": sanitize_single_line(str(source.get("package_name") or ""))[
            :MAX_PACKAGE_NAME_LENGTH
        ],
        "cves": cves,
        "cvss_scores": cvss_scores,
        "affected_versions": [
            sanitize_single_line(str(item))
            for item in source.get("affected_versions", [])
            if str(item).strip()
        ],
        "fixed_versions": fixed_versions,
        "action_needed": truncate_text(
            neutralize_mentions(action_needed or "TBD"), MAX_ACTION_NEEDED_LENGTH
        ),
        "summary": truncate_text(
            neutralize_mentions(
                sanitize_single_line(str(source.get("summary") or "")) or "TBD"
            ),
            MAX_SUMMARY_LENGTH,
        ),
        "gentoo_ref": (
            sanitize_single_line(str(source.get("gentoo_ref") or "")) or "TBD"
        )[:MAX_GENTOO_REF_LENGTH],
        "scope_assessment": str(source.get("scope_assessment") or "unknown").strip(),
        "confidence": coerce_confidence(source.get("confidence")),
    }


def coerce_relevance(data: dict[str, Any] | None) -> dict[str, Any]:
    source = data or {}
    status = str(source.get("status") or "needs_manual_review")
    scope = str(source.get("scope") or "unknown")
    return {
        "status": status if status in RELEVANCE_STATUSES else "needs_manual_review",
        "scope": scope if scope in RELEVANCE_SCOPES else "unknown",
        "llm_decision": str(source.get("llm_decision") or source.get("decision") or ""),
        "reasons": _string_list(source.get("reasons")),
        "evidence": _string_list(source.get("evidence")),
        "sbom_match_assessment": coerce_sbom_match_assessment(
            source.get("sbom_match_assessment")
        ),
    }


def coerce_sbom_match_assessment(data: Any) -> dict[str, Any]:
    source = data if isinstance(data, dict) else {}
    status = str(source.get("status") or "needs_manual_review")
    return {
        "status": status
        if status in SBOM_MATCH_ASSESSMENT_STATUSES
        else "needs_manual_review",
        "reason": str(source.get("reason") or ""),
        "related_matches": _string_list(source.get("related_matches")),
        "unrelated_matches": _string_list(source.get("unrelated_matches")),
    }


def coerce_discovery_decision(data: dict[str, Any] | None) -> dict[str, Any]:
    source = data or {}
    action = str(source.get("action") or "needs_manual_review")
    return {
        "action": action if action in DISCOVERY_ACTIONS else "needs_manual_review",
        "confidence": coerce_confidence(source.get("confidence")),
        "reason": str(source.get("reason") or ""),
    }


def coerce_cleanup_review(data: dict[str, Any] | None) -> dict[str, Any]:
    source = data or {}
    decision = str(source.get("decision") or "needs_manual_review")
    return {
        "decision": decision if decision in CLEANUP_STATUSES else "needs_manual_review",
        "confidence": coerce_confidence(source.get("confidence")),
        "reasons": _string_list(source.get("reasons")),
    }


def apply_discovery_guardrails(
    extraction: dict[str, Any],
    relevance: dict[str, Any],
    decision: dict[str, Any],
    sbom_matches: list[dict[str, Any]],
    issue_matches: list[dict[str, Any]],
    source_title: str,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    manual_reasons: list[str] = []
    package_name = extraction.get("package_name") or ""
    sbom_match_assessment = relevance.get("sbom_match_assessment") or {}
    unrelated_weak_sbom_matches = (
        sbom_match_assessment.get("status") == "unrelated_matches"
        and _only_weak_sbom_matches(sbom_matches)
        and not issue_matches
    )

    if is_kernel_advisory(package_name, source_title):
        relevance = {
            "status": "kernel_regular_update_flow",
            "scope": "production",
            "llm_decision": relevance.get("llm_decision")
            or "Kernel CVEs use the regular Flatcar kernel update flow.",
            "reasons": [
                *relevance.get("reasons", []),
                "Kernel advisory routed away from normal advisory issues.",
            ],
            "evidence": relevance.get("evidence", []),
        }
        return (
            relevance,
            {
                "action": "kernel_regular_update_flow",
                "confidence": "high",
                "reason": "Kernel CVEs are not tracked as normal Flatcar advisory issues.",
            },
            [],
        )

    if unrelated_weak_sbom_matches:
        assessment_reason = (
            sbom_match_assessment.get("reason")
            or "LLM judged the weak SBOM substring matches unrelated to the advisory package."
        )
        relevance = {
            **relevance,
            "status": "not_relevant",
            "scope": "not_shipped",
            "llm_decision": relevance.get("llm_decision")
            or "Weak SBOM matches are unrelated; no Flatcar package evidence remains.",
            "reasons": [
                *relevance.get("reasons", []),
                "LLM judged weak SBOM substring matches unrelated to the advisory package.",
            ],
            "evidence": [*relevance.get("evidence", []), assessment_reason],
        }
        decision = {
            "action": "ignore",
            "confidence": "medium",
            "reason": "LLM judged the only SBOM matches unrelated; treat this as strong not-shipped evidence.",
        }

    if not package_name:
        manual_reasons.append(
            "LLM extraction did not identify a package or component name."
        )
    if decision["action"] not in DISCOVERY_ACTIONS:
        manual_reasons.append(f"Invalid discovery action: {decision['action']}")
    if relevance["status"] == "needs_manual_review":
        manual_reasons.append("LLM relevance decision requested manual review.")
    if decision["action"] == "create_issue" and issue_matches:
        decision = {
            "action": "update_existing_issue",
            "confidence": min_confidence(decision.get("confidence"), "medium"),
            "reason": "Existing Flatcar issue match found; recommend updating it instead of creating a duplicate.",
        }
    if decision["action"] == "update_existing_issue" and not issue_matches:
        manual_reasons.append(
            "LLM recommended updating an existing issue but no existing issue match was found."
        )
    if (
        decision["action"] in {"create_issue", "update_existing_issue"}
        and relevance["status"] != "relevant"
    ):
        manual_reasons.append(
            "Issue mutation recommendation requires a relevant Flatcar status."
        )
    if decision["action"] == "create_issue" and not (
        extraction.get("cves") or extraction.get("summary") != "TBD"
    ):
        manual_reasons.append(
            "Create recommendation lacks CVE IDs or an upstream security issue summary."
        )
    if decision["action"] == "create_issue" and not (
        sbom_matches or relevance.get("evidence")
    ):
        manual_reasons.append(
            "Create recommendation lacks SBOM match or other explicit Flatcar relevance evidence."
        )

    if manual_reasons:
        relevance = {**relevance, "status": "needs_manual_review"}
        decision = {
            "action": "needs_manual_review",
            "confidence": "low",
            "reason": "; ".join(manual_reasons),
        }
    elif relevance["status"] == "not_relevant":
        decision = {
            "action": "ignore",
            "confidence": decision.get("confidence", "medium"),
            "reason": decision.get("reason")
            or "LLM decision found the advisory not relevant to Flatcar tracking rules.",
        }
    return relevance, decision, manual_reasons


def _only_weak_sbom_matches(sbom_matches: list[dict[str, Any]]) -> bool:
    if not sbom_matches:
        return True
    return all(
        match.get("match_type") in {"unique_substring", "ambiguous_substring"}
        for match in sbom_matches
    )


def min_confidence(left: str | None, right: str | None) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    left_text = coerce_confidence(left)
    right_text = coerce_confidence(right)
    return left_text if order[left_text] <= order[right_text] else right_text


def validate_discovery_document(document: dict[str, Any]) -> None:
    _require_root(
        document,
        [
            "schema_version",
            "workflow",
            "generated_at",
            "target_repo",
            "processing_window",
            "sources",
            "model",
            "records",
            "errors",
        ],
    )
    if document["workflow"] != "new_vulnerability_discovery":
        raise SchemaValidationError("Invalid discovery workflow name")
    for record in document.get("records", []):
        _require_root(
            record,
            [
                "record_id",
                "source",
                "source_url",
                "raw_advisory_id",
                "llm_extraction",
                "flatcar_relevance",
                "decision",
                "manual_review_reasons",
                "evidence",
            ],
        )
        action = record["decision"].get("action")
        if action not in DISCOVERY_ACTIONS:
            raise SchemaValidationError(f"Invalid discovery action {action}")
        status = record["flatcar_relevance"].get("status")
        if status not in RELEVANCE_STATUSES:
            raise SchemaValidationError(f"Invalid relevance status {status}")
        proposed_issue = record.get("proposed_issue")
        if proposed_issue:
            labels = set(proposed_issue.get("labels", []))
            if not REQUIRED_LABELS.issubset(labels):
                raise SchemaValidationError(
                    "Proposed issue is missing required advisory/security labels"
                )
            unknown = labels - ALLOWED_LABELS
            if unknown:
                raise SchemaValidationError(
                    f"Proposed issue contains unsupported labels: {sorted(unknown)}"
                )


def validate_cleanup_document(document: dict[str, Any]) -> None:
    _require_root(
        document,
        [
            "schema_version",
            "workflow",
            "generated_at",
            "target_repo",
            "sbom_url",
            "issue_query",
            "records",
            "errors",
        ],
    )
    if document["workflow"] != "advisory_cleanup_recommendation":
        raise SchemaValidationError("Invalid cleanup workflow name")
    for record in document.get("records", []):
        _require_root(
            record,
            [
                "issue",
                "issue_url",
                "title",
                "package_from_issue",
                "labels",
                "sbom_url",
                "cves_from_issue",
                "fixed_version_requirement",
                "sbom_package_matches",
                "llm_review",
                "status",
                "confidence",
                "evidence",
                "recommended_action",
                "comment_body",
            ],
        )
        if record["status"] not in CLEANUP_STATUSES:
            raise SchemaValidationError(f"Invalid cleanup status {record['status']}")
        if record["recommended_action"] not in CLEANUP_RECOMMENDATIONS:
            raise SchemaValidationError(
                f"Invalid cleanup recommendation {record['recommended_action']}"
            )


#: Backward-compatible default query for ``TARGET_REPO``. New code should call
#: ``advisory_issue_query(repo)`` with an explicit, configured repository
#: instead of relying on this module-level constant.
ADVISORY_ISSUE_QUERY = advisory_issue_query(TARGET_REPO)


def cleanup_comment_body(
    package: str, cves: list[str], action_needed: str | None, match: dict[str, Any]
) -> str:
    cve_text = ", ".join(cves) if cves else "n/a"
    return (
        "This advisory appears to be remediated in the current Flatcar production SBOM.\n\n"
        "Evidence:\n"
        f"- SBOM: {FLATCAR_PRODUCTION_SBOM_URL}\n"
        f"- Issue package: {package}\n"
        f"- Issue CVEs: {cve_text}\n"
        f"- Required action from issue: {action_needed or 'TBD'}\n"
        f"- SBOM package match: {match.get('name') or 'unknown'}\n"
        f"- SBOM versionInfo: {match.get('versionInfo') or 'unknown'}\n\n"
        "Pipeline recommendation: close as fixed/remediated."
    )


def _require_root(document: dict[str, Any], fields: list[str]) -> None:
    missing = [field for field in fields if field not in document]
    if missing:
        raise SchemaValidationError(f"Missing required field(s): {', '.join(missing)}")


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str):
        return [value] if value.strip() else []
    return [str(value)]
