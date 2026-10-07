"""Evidence-scoped reviewer decisions persisted in trusted review apply summaries.

Hashes provide correlation, not authorization. Only an execution summary from
the configured automation identity, correlated with its checked review manifest,
can supply a durable decision. Upstream text and ordinary comments cannot.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .io_utils import load_structured_file
from .rules import package_identity, sanitize_single_line, validate_repo_name

FEEDBACK_SCHEMA_VERSION = "1.0"
FEEDBACK_KIND = "discovery_feedback"
FEEDBACK_LABEL = "security-triage/review-feedback"
FEEDBACK_DECISIONS = (
    "wrong_package",
    "not_shipped",
    "already_addressed",
    "deferred",
    "track_uncertain",
    "revoke",
)
SUPPRESSING_DECISIONS = frozenset(FEEDBACK_DECISIONS[:4])
DEFAULT_REASONS = {
    "wrong_package": "Reviewer confirmed that this finding targets a different package.",
    "not_shipped": "Reviewer confirmed that this package is not shipped in the assessed scope.",
    "already_addressed": "Reviewer confirmed that this exact evidence is already addressed.",
    "deferred": "Reviewer deferred this exact evidence until a meaningful evidence change or revocation.",
    "track_uncertain": "Reviewer requested continued tracking because evidence remains uncertain.",
    "revoke": "Reviewer revoked the previous decision for this exact evidence.",
}
TRUSTED_BOT_LOGINS = frozenset({"github-actions[bot]"})
GITHUB_ACTIONS_BOT_ID = 41898282
DEFAULT_MAX_REVIEW_ISSUES = 200
DEFAULT_MAX_COMMENTS_PER_ISSUE = 200
DEFAULT_MAX_TOTAL_COMMENTS = 2000
_KEY_RE = re.compile(r"^security-triage:feedback:v1:[0-9a-f]{64}$")
_SUMMARY_RE = re.compile(
    r"<!-- security-triage:review-feedback:v1\s+([A-Za-z0-9+/=\s]+?)\s*-->",
    re.DOTALL,
)
_HOUSEKEEPING_RE = re.compile(
    r"^(?:\*{0,2}\s*)?(?:"
    r"(?:last[ _-]?(?:modified|updated)|updated[ _-]?at|creation[ _-]?time|"
    r"assigned[ _-]?to|assignee|cc|whiteboard|last[ _-]?change[ _-]?time)\s*:"
    r"|(?:added|removed|adding|removing)\s+(?:myself|.+?\s+to\s+cc)\b"
    r"|(?:thanks|thank you)[.! ]*$"
    r"|(?:bump|ping|cc me)[.! ]*$"
    r"|severity\s*:\s*(?:normal|unspecified)\s*$"
    r")",
    re.IGNORECASE,
)


class _ConfirmedFeedback(dict[str, Any]):
    """In-process provenance: produced only after validating API envelopes."""


class FeedbackLoadResult(list[dict[str, Any]]):
    """List-compatible confirmed feedback plus explicit scan completeness."""

    def __init__(self) -> None:
        super().__init__()
        self.coverage: dict[str, Any] = {
            "complete": True,
            "review_issues_scanned": 0,
            "comments_scanned": 0,
            "warnings": [],
        }

    def incomplete(self, warning: str) -> None:
        self.coverage["complete"] = False
        self.coverage["warnings"].append(warning)
        # A later, unseen revocation may supersede any decision already loaded.
        self.clear()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def meaningful_text(value: Any) -> str:
    """Discard only recognized housekeeping lines; unfamiliar prose resurfaces."""
    return " ".join(
        " ".join(line.split())
        for line in str(value or "").splitlines()
        if line.strip() and not _HOUSEKEEPING_RE.match(line.strip())
    )


def _strings(values: Any, *, upper: bool = False) -> list[str]:
    if not isinstance(values, (list, tuple)):
        values = [values] if values else []
    return sorted(
        {
            str(value).strip().upper() if upper else str(value).strip()
            for value in values
            if value is not None and str(value).strip()
        }
    )


def _scope_snapshot(item: dict[str, Any]) -> dict[str, Any]:
    evidence = item.get("evidence")
    if isinstance(evidence, dict):
        evidence = {
            key: value
            for key, value in evidence.items()
            if key
            not in {
                "snapshot_sha256",
                "documentNamespace",
                "creationInfo",
                "generated_at",
                "fetched_at",
                "retrieved_at",
                "updated_at",
                "created_at",
            }
        }
    return {
        "package": package_identity(item.get("package")),
        "scope": item.get("scope"),
        "source": item.get("source"),
        "validated": item.get("validated"),
        "discovery_only": bool(item.get("discovery_only")),
        "versionInfo": item.get("versionInfo"),
        "sbom_package": item.get("sbom_package"),
        "purls": _strings(item.get("purls")),
        "evidence": evidence,
    }


def evidence_snapshot(record: dict[str, Any]) -> dict[str, Any]:
    extraction = record.get("llm_extraction") or {}
    metadata = record.get("upstream_metadata") or {}
    severity = str(metadata.get("severity") or "").strip().lower()
    comments = (
        record.get("upstream_comments") or record.get("upstream_new_comments") or []
    )
    source = record.get("source_content", record.get("raw_source_excerpt"))
    if record.get("upstream_description") is not None:
        source = str(source or "").split("\nNew comments in processing window:", 1)[0]
    source_facts = {
        "title": meaningful_text(record.get("source_title")),
        "text": meaningful_text(source),
        "description": meaningful_text(record.get("upstream_description")),
        "comments": sorted(
            {
                text
                for comment in comments
                if isinstance(comment, dict)
                and (text := meaningful_text(comment.get("text")))
            }
        ),
    }
    issues = [
        {
            "issue": match.get("issue"),
            "package": package_identity(str(match.get("package") or "")),
            "state": match.get("state"),
            "labels": [
                label
                for label in _strings(match.get("labels"))
                if label
                in {"advisory", "security", "advisory/only-sdk", "advisory/sysext"}
                or label.startswith("cvss/")
            ],
            "body_digest": _digest(meaningful_text(match.get("body"))),
        }
        for match in record.get("existing_issue_matches") or []
    ]
    packages = [
        {
            "name": str(match.get("name") or ""),
            "version": match.get("versionInfo"),
            "purls": _strings(match.get("purls")),
            "scope": match.get("scope"),
        }
        for match in record.get("sbom_package_matches") or []
    ]
    return {
        "package": package_identity(
            extraction.get("package_identity") or extraction.get("package_name")
        ),
        "package_identity": str(
            extraction.get("package_identity") or extraction.get("package_name") or ""
        )
        .strip()
        .lower(),
        "package_purl": extraction.get("package_purl"),
        "ecosystem": extraction.get("ecosystem"),
        "source": str(record.get("source") or ""),
        "source_url": str(record.get("source_url") or ""),
        "advisory_id": str(record.get("raw_advisory_id") or ""),
        "cves": _strings(extraction.get("cves"), upper=True),
        "aliases": _strings(metadata.get("alias"), upper=True),
        "source_severity": severity
        if severity not in {"", "normal", "unspecified"}
        else None,
        "affected_versions": extraction.get("affected_versions"),
        "fixed_versions": extraction.get("fixed_versions"),
        "fixed_version_semantics": extraction.get("fixed_version_semantics"),
        "action_needed": meaningful_text(extraction.get("action_needed")),
        "cvss_scores": _strings(extraction.get("cvss_scores")),
        "scope": (record.get("flatcar_relevance") or {}).get("scope"),
        "scope_assessment": extraction.get("scope_assessment"),
        "scope_evidence": sorted(
            [
                _scope_snapshot(item)
                for item in record.get("scope_evidence") or []
                if isinstance(item, dict)
            ],
            key=_canonical,
        ),
        "use_flags": extraction.get("use_flags"),
        "evidence_validation": {
            key: (extraction.get("evidence_validation") or {}).get(key)
            for key in ("status", "errors")
        },
        "source_facts_digest": _digest(source_facts),
        "references": _strings(record.get("upstream_references")),
        "sbom_packages": sorted(packages, key=_canonical),
        "existing_issues": sorted(issues, key=_canonical),
    }


def feedback_key(record: dict[str, Any]) -> str:
    return "security-triage:feedback:v1:" + _digest(evidence_snapshot(record))


def build_feedback_payload(
    record: dict[str, Any],
    decision: str,
    *,
    advisory_repository: str,
    reason: str = "",
) -> dict[str, Any]:
    snapshot = evidence_snapshot(record)
    payload = {
        "schema_version": FEEDBACK_SCHEMA_VERSION,
        "advisory_repository": validate_repo_name(advisory_repository),
        "feedback_key": "security-triage:feedback:v1:" + _digest(snapshot),
        "decision": decision,
        "reason": sanitize_single_line(reason or DEFAULT_REASONS.get(decision, "")),
        "evidence_snapshot": snapshot,
    }
    return validate_feedback_payload(payload)


def validate_feedback_payload(
    payload: Any, *, advisory_repository: str | None = None
) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "advisory_repository",
        "feedback_key",
        "decision",
        "reason",
        "evidence_snapshot",
    }:
        raise ValueError("Feedback must have exactly the supported payload fields")
    if payload.get("schema_version") != FEEDBACK_SCHEMA_VERSION:
        raise ValueError("Unsupported feedback schema")
    repo = validate_repo_name(payload.get("advisory_repository"))
    if (
        advisory_repository is not None
        and repo.lower() != validate_repo_name(advisory_repository).lower()
    ):
        raise ValueError("Feedback advisory repository mismatch")
    if payload.get("decision") not in FEEDBACK_DECISIONS:
        raise ValueError("Unsupported feedback decision")
    reason = payload.get("reason")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
        raise ValueError("Feedback needs a bounded explicit reason")
    snapshot = payload.get("evidence_snapshot")
    if (
        not isinstance(snapshot, dict)
        or not snapshot.get("package")
        or not snapshot.get("source_url")
    ):
        raise ValueError("Feedback requires a package and source identity")
    if not snapshot.get("cves") and not snapshot.get("advisory_id"):
        raise ValueError("Feedback requires an advisory identity")
    key = payload.get("feedback_key")
    if not isinstance(key, str) or not _KEY_RE.fullmatch(key):
        raise ValueError("Invalid feedback key")
    if key != "security-triage:feedback:v1:" + _digest(snapshot):
        raise ValueError("Feedback key does not match the evidence snapshot")
    return payload


def render_feedback_summary(
    manifest: dict[str, Any],
    checked_ids: list[str] | set[str],
    execution_results: list[dict[str, Any]],
    *,
    review_issue_number: int,
) -> str:
    """Append to the bot execution summary, not to user-editable source prose."""
    checked = sorted(set(checked_ids))
    summary = {
        "schema_version": FEEDBACK_SCHEMA_VERSION,
        "applied_state": "closed",
        "applied_state_reason": "completed",
        "advisory_repository": manifest["advisory_repo"],
        "review_repository": manifest["review_repo"],
        "review_issue_number": review_issue_number,
        "manifest_digest": manifest["digest"],
        "manifest_snapshot": base64.b64encode(
            zlib.compress(_canonical(manifest).encode("utf-8"))
        ).decode("ascii"),
        "checked_action_ids": checked,
        "selection_digest": _digest(checked),
        "results": execution_results,
    }
    encoded = base64.b64encode(_canonical(summary).encode("utf-8")).decode("ascii")
    return f"<!-- security-triage:review-feedback:v1\n{encoded}\n-->"


def is_trusted_feedback_author(raw: dict[str, Any]) -> bool:
    """Check the API-returned issue/comment author against the automation identity."""
    if not isinstance(raw, dict):
        return False
    author = raw.get("user") or {}
    return (
        isinstance(author, dict)
        and author.get("type") == "Bot"
        and author.get("login") in TRUSTED_BOT_LOGINS
        and author.get("id", GITHUB_ACTIONS_BOT_ID) == GITHUB_ACTIONS_BOT_ID
    )


def parse_feedback_summary(
    issue: Any,
    comment: dict[str, Any],
    *,
    advisory_repository: str,
    review_repository: str,
) -> list[dict[str, Any]]:
    """Return confirmed decisions or nothing; labels and close state are insufficient."""
    from .review import (
        compute_digest,
        resolve_review_selections,
        validate_manifest_against_context,
    )

    advisory_repository = validate_repo_name(advisory_repository)
    review_repository = validate_repo_name(review_repository)
    if not is_trusted_feedback_author(issue.raw) or not is_trusted_feedback_author(
        comment
    ):
        return []
    expected_url = f"https://github.com/{review_repository}/issues/{issue.number}"
    if issue.html_url.lower() != expected_url.lower():
        return []
    comment_id = comment.get("id")
    if type(comment_id) is not int or comment_id <= 0:
        return []
    comment_url = f"{expected_url}#issuecomment-{comment_id}"
    if str(comment.get("html_url") or "").lower() != comment_url.lower():
        return []
    try:
        matches = _SUMMARY_RE.findall(str(comment.get("body") or ""))
        if len(matches) != 1:
            return []
        summary = json.loads(
            base64.b64decode("".join(matches[0].split()), validate=True)
        )
        if (
            summary.get("applied_state") != "closed"
            or summary.get("applied_state_reason") != "completed"
        ):
            return []
        compressed = base64.b64decode(
            summary.get("manifest_snapshot", ""), validate=True
        )
        inflater = zlib.decompressobj()
        raw_manifest = inflater.decompress(compressed, 1_000_001)
        if len(raw_manifest) > 1_000_000 or not inflater.eof or inflater.unused_data:
            return []
        manifest = json.loads(raw_manifest)
        if not isinstance(manifest, dict) or manifest.get("digest") != compute_digest(
            {key: value for key, value in manifest.items() if key != "digest"}
        ):
            return []
        validate_manifest_against_context(
            manifest, advisory_repository, review_repository
        )
        if summary.get("schema_version") != FEEDBACK_SCHEMA_VERSION:
            return []
        if (
            summary.get("advisory_repository") != manifest["advisory_repo"]
            or summary.get("review_repository") != manifest["review_repo"]
            or summary.get("review_issue_number") != issue.number
            or summary.get("manifest_digest") != manifest["digest"]
        ):
            return []
        checked = summary.get("checked_action_ids")
        if not isinstance(checked, list) or not all(
            isinstance(item, str) for item in checked
        ):
            return []
        if checked != sorted(set(checked)) or summary.get(
            "selection_digest"
        ) != _digest(checked):
            return []
        selected = {
            resolution.selected_action["action_id"]: resolution.selected_action
            for resolution in resolve_review_selections(manifest, set(checked))
            if resolution.outcome == "selected" and resolution.selected_action
        }
        created_at = str(comment.get("updated_at") or comment.get("created_at") or "")
        timestamp = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            return []
        records: list[dict[str, Any]] = []
        results = summary.get("results")
        if not isinstance(results, list):
            return []
        for result in results:
            if (
                not isinstance(result, dict)
                or result.get("status") != "feedback_recorded"
            ):
                continue
            action = selected.get(result.get("action_id"))
            if not action or action.get("kind") != FEEDBACK_KIND:
                continue
            payload = validate_feedback_payload(
                action.get("payload"), advisory_repository=advisory_repository
            )
            if result.get("feedback") != payload:
                continue
            records.append(
                _ConfirmedFeedback(
                    {
                        **payload,
                        "confirmed": True,
                        "review_repository": review_repository,
                        "review_issue_number": issue.number,
                        "review_issue_url": expected_url,
                        "comment_id": comment_id,
                        "comment_url": comment_url,
                        "confirmed_at": timestamp.astimezone(UTC).isoformat(),
                        "action_id": action["action_id"],
                        "manifest_digest": manifest["digest"],
                        "selection_digest": summary["selection_digest"],
                    }
                )
            )
        return records
    except (ValueError, TypeError, KeyError, AttributeError, zlib.error):
        return []


def load_review_feedback(
    client: Any,
    *,
    advisory_repository: str | None = None,
    max_review_issues: int = DEFAULT_MAX_REVIEW_ISSUES,
    max_comments_per_issue: int = DEFAULT_MAX_COMMENTS_PER_ISSUE,
    max_total_comments: int = DEFAULT_MAX_TOTAL_COMMENTS,
) -> FeedbackLoadResult:
    """Read bounded review history; incomplete coverage never suppresses findings."""
    from .issues import GitHubIssueClient

    review_repo = validate_repo_name(client.repo)
    advisory_repo = validate_repo_name(advisory_repository or review_repo)
    if any(
        type(limit) is not int or limit <= 0
        for limit in (max_review_issues, max_comments_per_issue, max_total_comments)
    ):
        raise ValueError("Feedback scan limits must be positive integers")
    records = FeedbackLoadResult()
    records.coverage.update(
        {
            "review_repository": review_repo,
            "advisory_repository": advisory_repo,
            "review_label": FEEDBACK_LABEL,
            "max_review_issues": max_review_issues,
            "max_comments_per_issue": max_comments_per_issue,
            "max_total_comments": max_total_comments,
        }
    )
    page_reader = getattr(client, "list_issues_page", None)
    if isinstance(client, GitHubIssueClient) and (
        not callable(page_reader)
        or not callable(getattr(client, "list_comments_page", None))
    ):
        records.incomplete(
            "Bounded GitHub history pagination is unavailable; feedback suppression is disabled."
        )
        return records
    issues: list[Any] = []
    page = 1
    try:
        while True:
            items = (
                page_reader(
                    state="all",
                    label=FEEDBACK_LABEL,
                    page=page,
                    per_page=100,
                )
                if callable(page_reader)
                else client.list_issues_by_label(FEEDBACK_LABEL, state="all")
            )
            remaining = max_review_issues - len(issues)
            issues.extend(items[:remaining])
            records.coverage["review_issues_scanned"] = len(issues)
            if len(items) > remaining or (
                callable(page_reader)
                and len(items) == 100
                and len(issues) >= max_review_issues
            ):
                records.incomplete(
                    "Review issue scan limit reached; feedback suppression is disabled."
                )
                return records
            if not callable(page_reader) or len(items) < 100:
                break
            page += 1
    except Exception as exc:
        records.incomplete(
            f"Review issue history could not be read ({type(exc).__name__}); feedback suppression is disabled."
        )
        return records
    for issue in issues:
        if not is_trusted_feedback_author(issue.raw):
            continue
        comment_reader = getattr(client, "list_comments_page", None)
        page = 1
        issue_comments = 0
        try:
            while True:
                comments = (
                    comment_reader(issue.number, page=page, per_page=100)
                    if callable(comment_reader)
                    else client.list_comments(issue.number)
                )
                remaining = min(
                    max_comments_per_issue - issue_comments,
                    max_total_comments - records.coverage["comments_scanned"],
                )
                consumed = comments[:remaining]
                issue_comments += len(consumed)
                records.coverage["comments_scanned"] += len(consumed)
                if len(comments) > remaining or (
                    callable(comment_reader)
                    and len(comments) == 100
                    and (
                        issue_comments >= max_comments_per_issue
                        or records.coverage["comments_scanned"] >= max_total_comments
                    )
                ):
                    records.incomplete(
                        f"Comment scan limit reached at review #{issue.number}; feedback suppression is disabled."
                    )
                    return records
                for comment in consumed:
                    parsed = parse_feedback_summary(
                        issue,
                        comment,
                        advisory_repository=advisory_repo,
                        review_repository=review_repo,
                    )
                    if (
                        not parsed
                        and is_trusted_feedback_author(comment)
                        and "security-triage:review-feedback:v1"
                        in str(comment.get("body") or "")
                    ):
                        records.incomplete(
                            f"An unverifiable feedback summary exists on review #{issue.number}; feedback suppression is disabled."
                        )
                        return records
                    records.extend(parsed)
                if not callable(comment_reader) or len(comments) < 100:
                    break
                page += 1
        except Exception as exc:
            records.incomplete(
                f"Comments for review #{issue.number} could not be read ({type(exc).__name__}); feedback suppression is disabled."
            )
            return records
    return records


def load_feedback_fixture(
    path: str | Path, *, advisory_repository: str, review_repository: str | None = None
) -> FeedbackLoadResult:
    """Offline replay of API envelopes through the same trust checks as GitHub."""
    from .issues import issue_from_api

    document = load_structured_file(path)
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != FEEDBACK_SCHEMA_VERSION
    ):
        raise ValueError("Feedback fixture requires a versioned review API envelope")
    repo = validate_repo_name(review_repository or document.get("review_repository"))
    if document.get("review_repository") != repo:
        raise ValueError("Feedback fixture review repository mismatch")
    reviews = document.get("reviews")
    if not isinstance(reviews, list):
        raise ValueError("Feedback fixture reviews must be a list")
    issues = []
    comments_by_issue = {}
    for review in reviews:
        if not isinstance(review, dict) or not isinstance(review.get("issue"), dict):
            raise ValueError("Feedback fixture requires issue/comment API records")
        issue = issue_from_api(review["issue"])
        comments = review.get("comments", [])
        if not isinstance(comments, list):
            raise ValueError("Feedback fixture comments must be a list")
        if issue.number in comments_by_issue:
            raise ValueError("Feedback fixture contains duplicate review issues")
        issues.append(issue)
        comments_by_issue[issue.number] = comments

    class FixtureClient:
        def __init__(self) -> None:
            self.repo = repo

        def list_issues_by_label(self, label: str, state: str) -> list[Any]:
            return issues

        def list_comments(self, issue_number: int) -> list[dict[str, Any]]:
            return comments_by_issue[issue_number]

    return load_review_feedback(
        FixtureClient(), advisory_repository=advisory_repository
    )


def annotate_review_feedback(
    record: dict[str, Any], feedback: list[dict[str, Any]], *, advisory_repository: str
) -> None:
    key = feedback_key(record)
    record["feedback_key"] = key
    record["evidence_snapshot_id"] = key.replace(":feedback:", ":evidence:")
    eligible = []
    payload_fields = {
        "schema_version",
        "advisory_repository",
        "feedback_key",
        "decision",
        "reason",
        "evidence_snapshot",
    }
    for item in feedback:
        if (
            not isinstance(item, _ConfirmedFeedback)
            or item.get("confirmed") is not True
            or item.get("feedback_key") != key
        ):
            continue
        try:
            validate_feedback_payload(
                {field: item[field] for field in payload_fields},
                advisory_repository=advisory_repository,
            )
            if (
                not item.get("comment_url")
                or not item.get("manifest_digest")
                or not item.get("selection_digest")
            ):
                continue
            timestamp = datetime.fromisoformat(
                str(item["confirmed_at"]).replace("Z", "+00:00")
            )
            if timestamp.tzinfo is None:
                continue
            eligible.append((timestamp, int(item["comment_id"]), item))
        except (ValueError, TypeError, KeyError):
            continue
    if not eligible:
        return
    _, _, latest = max(eligible, key=lambda candidate: candidate[:2])
    record["review_suppression"] = {
        "suppressed": latest["decision"] in SUPPRESSING_DECISIONS,
        "decision": latest["decision"],
        "reason": latest["reason"],
        "feedback_key": key,
        "review_issue_url": latest.get("review_issue_url"),
        "comment_url": latest["comment_url"],
        "confirmed_at": latest["confirmed_at"],
    }
