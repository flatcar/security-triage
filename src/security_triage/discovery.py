from __future__ import annotations

import difflib
import hashlib
from typing import Any

from .console import NullProgressLogger, ProgressLogger
from .debug import DebugLogger
from .issue_updates import (
    append_field_values,
    removal_guard_violations,
    set_field_if_placeholder,
)
from .issues import find_existing_issue_matches
from .models import BaseModelClient
from .reasoning import build_discovery_evidence_bundle
from .records import Issue, SourceEntry
from .rules import (
    SCHEMA_VERSION,
    TARGET_REPO,
    apply_discovery_guardrails,
    coerce_discovery_decision,
    coerce_extraction,
    coerce_relevance,
    extract_cves,
    issue_labels,
    neutralize_mentions,
    render_issue_body,
    validate_discovery_document,
)
from .sbom import SBOMIndex
from .time_utils import iso_now


class DiscoveryWorkflow:
    def __init__(
        self,
        model_client: BaseModelClient,
        sbom_index: SBOMIndex,
        issues: list[Issue],
        debug_logger: DebugLogger | None = None,
        progress_logger: ProgressLogger | None = None,
    ) -> None:
        self.model_client = model_client
        self.sbom_index = sbom_index
        self.issues = issues
        self.debug_logger = debug_logger or DebugLogger()
        self.progress_logger = progress_logger or NullProgressLogger()

    def run(
        self, entries: list[SourceEntry], window_start: str, window_end: str
    ) -> dict[str, Any]:
        records: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        total = len(entries)
        self.progress_logger.info(
            f"Processing {total} upstream source entr{'y' if total == 1 else 'ies'}"
        )
        for index, entry in enumerate(entries, start=1):
            record_id = _record_id(entry)
            self.progress_logger.info(
                f"[{index}/{total}] Processing {entry.source} entry {entry.entry_id}: {entry.title[:100]}"
            )
            self.debug_logger.log(
                "discovery_source_entry",
                record_id=record_id,
                source=entry.source,
                raw_entry=entry.raw,
                content=entry.content,
            )
            try:
                record = self._process_entry(record_id, entry)
            except Exception as exc:
                self.progress_logger.info(
                    f"[{index}/{total}] Entry {entry.entry_id} failed; recording manual review: {exc}"
                )
                errors.append(
                    {"record_id": record_id, "source": entry.source, "error": str(exc)}
                )
                record = self._manual_record(record_id, entry, str(exc))
            records.append(record)
            decision = record.get("decision", {})
            package_name = (
                record.get("llm_extraction", {}).get("package_name") or "unknown"
            )
            self.progress_logger.info(
                f"[{index}/{total}] Finished {package_name}: {decision.get('action')} ({decision.get('confidence')})"
            )
            self.debug_logger.log(
                "discovery_final_record", record_id=record_id, record=record
            )

        document = {
            "schema_version": SCHEMA_VERSION,
            "workflow": "new_vulnerability_discovery",
            "generated_at": iso_now(),
            "target_repo": TARGET_REPO,
            "processing_window": {
                "start": window_start,
                "end": window_end,
                "timezone": "UTC",
            },
            "sources": _sources_summary(entries),
            "model": self.model_client.metadata(),
            "records": records,
            "errors": errors,
        }
        validate_discovery_document(document)
        return document

    def _process_entry(self, record_id: str, entry: SourceEntry) -> dict[str, Any]:
        self.progress_logger.info(f"Extracting advisory fields for {entry.entry_id}")
        extraction = coerce_extraction(self.model_client.extract_advisory(entry))
        self.progress_logger.info(
            f"Extracted package {extraction.get('package_name') or 'unknown'} with {len(extraction.get('cves') or [])} CVE(s)"
        )
        sbom_matches = self.sbom_index.match_package(extraction.get("package_name"))
        self.progress_logger.info(f"Found {len(sbom_matches)} SBOM package match(es)")
        existing_issue_matches = find_existing_issue_matches(extraction, self.issues)
        self.progress_logger.info(
            f"Found {len(existing_issue_matches)} existing issue match(es)"
        )
        covered_match = _already_covered_by_existing_issue(
            extraction, existing_issue_matches
        )
        upstream_activity = _upstream_activity(
            entry, extraction, existing_issue_matches
        )
        if covered_match and not upstream_activity["requires_issue_update"]:
            self.progress_logger.info(
                f"Existing issue #{covered_match.get('issue')} already covers extracted advisory IDs; skipping relevance model call"
            )
            return _already_tracked_record(
                record_id,
                entry,
                extraction,
                sbom_matches,
                existing_issue_matches,
                covered_match,
                upstream_activity,
            )
        evidence_bundle = build_discovery_evidence_bundle(
            record_id, entry, extraction, sbom_matches, existing_issue_matches
        )
        self.debug_logger.log(
            "discovery_evidence_bundle", record_id=record_id, bundle=evidence_bundle
        )
        self.progress_logger.info("Requesting Flatcar relevance decision")
        model_decision = self.model_client.decide_relevance(evidence_bundle)
        relevance = coerce_relevance(model_decision.get("flatcar_relevance"))
        decision = coerce_discovery_decision(model_decision.get("decision"))
        relevance, decision, manual_review_reasons = apply_discovery_guardrails(
            extraction,
            relevance,
            decision,
            sbom_matches,
            existing_issue_matches,
            entry.title,
        )
        if (
            upstream_activity["requires_issue_update"]
            and existing_issue_matches
            and decision["action"] == "ignore"
        ):
            relevance = {**relevance, "status": "relevant"}
            decision = {
                "action": "update_existing_issue",
                "confidence": "medium",
                "reason": "Gentoo Bugzilla changed for an already tracked advisory; recommend updating the existing issue.",
            }
        proposed_issue = None
        proposed_update = None
        if decision["action"] == "create_issue":
            proposed_issue = _proposed_issue(extraction, relevance)
        elif decision["action"] == "update_existing_issue":
            proposed_update = _proposed_update(
                entry, extraction, existing_issue_matches, upstream_activity
            )

        return {
            "record_id": record_id,
            "source": entry.source,
            "source_url": entry.source_url,
            "raw_advisory_id": entry.entry_id,
            "source_entry_published_at": entry.published_at,
            "source_entry_updated_at": entry.updated_at,
            "upstream_references": _upstream_references(entry),
            **_source_detail_fields(entry, upstream_activity),
            "raw_source_excerpt": entry.excerpt(),
            "llm_extraction": extraction,
            "flatcar_relevance": relevance,
            "sbom_package_matches": sbom_matches,
            "existing_issue_matches": existing_issue_matches,
            "decision": decision,
            "proposed_issue": proposed_issue,
            "proposed_update": proposed_update,
            "manual_review_reasons": manual_review_reasons,
            "evidence": _record_evidence(
                relevance, sbom_matches, existing_issue_matches
            ),
        }

    def _manual_record(
        self, record_id: str, entry: SourceEntry, reason: str
    ) -> dict[str, Any]:
        return {
            "record_id": record_id,
            "source": entry.source,
            "source_url": entry.source_url,
            "raw_advisory_id": entry.entry_id,
            "source_entry_published_at": entry.published_at,
            "source_entry_updated_at": entry.updated_at,
            "upstream_references": _upstream_references(entry),
            **_source_detail_fields(entry, _empty_upstream_activity()),
            "raw_source_excerpt": entry.excerpt(),
            "llm_extraction": coerce_extraction({}),
            "flatcar_relevance": {
                "status": "needs_manual_review",
                "scope": "unknown",
                "llm_decision": "Workflow processing failed before a valid decision was produced.",
                "reasons": [reason],
                "evidence": [],
            },
            "sbom_package_matches": [],
            "existing_issue_matches": [],
            "decision": {
                "action": "needs_manual_review",
                "confidence": "low",
                "reason": reason,
            },
            "proposed_issue": None,
            "proposed_update": None,
            "manual_review_reasons": [reason],
            "evidence": [],
        }


def _record_id(entry: SourceEntry) -> str:
    digest = hashlib.sha256(
        f"{entry.source}:{entry.entry_id}:{entry.source_url}".encode()
    ).hexdigest()[:16]
    return f"{entry.source}:{digest}"


def _sources_summary(entries: list[SourceEntry]) -> list[dict[str, Any]]:
    summary: dict[str, dict[str, Any]] = {}
    for entry in entries:
        source = summary.setdefault(
            entry.source, {"source": entry.source, "urls": [], "entry_count": 0}
        )
        source["entry_count"] += 1
        if entry.source_url and entry.source_url not in source["urls"]:
            source["urls"].append(entry.source_url)
    return list(summary.values())


def _upstream_references(entry: SourceEntry) -> list[str]:
    references: list[str] = []
    for reference in [entry.source_url, *entry.references]:
        if reference and reference not in references:
            references.append(reference)
    return references


def _proposed_issue(
    extraction: dict[str, Any], relevance: dict[str, Any]
) -> dict[str, Any]:
    package_name = extraction["package_name"]
    labels = issue_labels(
        extraction.get("cvss_scores"),
        relevance.get("scope"),
        extraction.get("scope_assessment"),
    )
    gentoo_ref = extraction.get("gentoo_ref")
    if not _is_gentoo_ref(gentoo_ref):
        gentoo_ref = None
    return {
        "title": f"update: {package_name}",
        "body": render_issue_body(
            package_name,
            extraction.get("cves") or [],
            extraction.get("cvss_scores") or [],
            extraction.get("action_needed"),
            extraction.get("summary"),
            gentoo_ref,
        ),
        "labels": labels,
        "assignees": [],
        "milestone": None,
    }


def _proposed_update(
    entry: SourceEntry,
    extraction: dict[str, Any],
    matches: list[dict[str, Any]],
    upstream_activity: dict[str, Any],
) -> dict[str, Any] | None:
    if not matches:
        return None
    cves = extraction.get("cves") or []
    additions: list[str] = []
    new_cves = _new_cves_for_issue(cves, matches[0])
    if new_cves:
        additions.append(f"Add CVEs: {', '.join(new_cves)}")
    if upstream_activity.get("new_aliases"):
        additions.append(
            f"Add Gentoo aliases/CVEs: {', '.join(upstream_activity['new_aliases'])}"
        )
    action_needed = extraction.get("action_needed")
    if (
        action_needed
        and action_needed != "TBD"
        and _value_missing_from_issue(action_needed, matches[0])
    ):
        additions.append(f"Review Action Needed: {action_needed}")
    summary = extraction.get("summary")
    if summary and summary != "TBD" and _value_missing_from_issue(summary, matches[0]):
        additions.append(f"Add upstream context: {summary}")
    additions.extend(upstream_activity.get("recommended_additions") or [])
    updated_body = _updated_issue_body(entry, extraction, matches[0], upstream_activity)
    comment_body = _upstream_update_comment_body(entry, upstream_activity, additions)
    body_diff = _body_diff(matches[0].get("body"), updated_body)
    return {
        "issue": matches[0]["issue"],
        "issue_url": matches[0]["issue_url"],
        "title": matches[0]["title"],
        "update_reason": _update_reason(upstream_activity, new_cves),
        "detected_changes": _detected_changes(upstream_activity, new_cves),
        "recommended_additions": additions,
        "body_update_mode": "additive_guarded" if updated_body else None,
        "updated_body": updated_body,
        "updated_body_diff": body_diff,
        "comment_body": comment_body,
        "matched_existing_issue": matches[0],
    }


def _already_covered_by_existing_issue(
    extraction: dict[str, Any], matches: list[dict[str, Any]]
) -> dict[str, Any] | None:
    extracted_ids = {
        str(item).strip().upper()
        for item in extraction.get("cves") or []
        if str(item).strip()
    }
    if not extracted_ids:
        return None
    for match in matches:
        issue_ids = {
            str(item).strip().upper()
            for item in match.get("cves") or []
            if str(item).strip()
        }
        if extracted_ids and extracted_ids.issubset(issue_ids):
            return match
    return None


def _already_tracked_record(
    record_id: str,
    entry: SourceEntry,
    extraction: dict[str, Any],
    sbom_matches: list[dict[str, Any]],
    existing_issue_matches: list[dict[str, Any]],
    covered_match: dict[str, Any],
    upstream_activity: dict[str, Any],
) -> dict[str, Any]:
    relevance = {
        "status": "relevant",
        "scope": "unknown",
        "llm_decision": "An existing open Flatcar advisory already contains every extracted advisory ID.",
        "reasons": [
            "Existing issue already covers the extracted CVE or upstream advisory IDs."
        ],
        "evidence": [
            f"Existing issue #{covered_match.get('issue')}: {covered_match.get('title')}"
        ],
    }
    decision = {
        "action": "ignore",
        "confidence": "high",
        "reason": f"Already tracked by existing issue #{covered_match.get('issue')}.",
    }
    return {
        "record_id": record_id,
        "source": entry.source,
        "source_url": entry.source_url,
        "raw_advisory_id": entry.entry_id,
        "source_entry_published_at": entry.published_at,
        "source_entry_updated_at": entry.updated_at,
        "upstream_references": _upstream_references(entry),
        **_source_detail_fields(entry, upstream_activity),
        "raw_source_excerpt": entry.excerpt(),
        "llm_extraction": extraction,
        "flatcar_relevance": relevance,
        "sbom_package_matches": sbom_matches,
        "existing_issue_matches": existing_issue_matches,
        "decision": decision,
        "proposed_issue": None,
        "proposed_update": None,
        "manual_review_reasons": [],
        "evidence": _record_evidence(relevance, sbom_matches, existing_issue_matches),
    }


def _source_detail_fields(
    entry: SourceEntry, upstream_activity: dict[str, Any]
) -> dict[str, Any]:
    return {
        "upstream_metadata": entry.metadata,
        "upstream_description": entry.description,
        "upstream_comments": entry.comments,
        "upstream_new_comments": entry.new_comments,
        "upstream_activity": upstream_activity,
    }


def _empty_upstream_activity() -> dict[str, Any]:
    return {
        "requires_issue_update": False,
        "new_aliases": [],
        "new_references": [],
        "new_comments": [],
        "recommended_additions": [],
    }


def _upstream_activity(
    entry: SourceEntry, extraction: dict[str, Any], matches: list[dict[str, Any]]
) -> dict[str, Any]:
    if not matches:
        activity = _empty_upstream_activity()
        activity["new_comments"] = entry.new_comments
        return activity

    match = matches[0]
    existing_body = str(match.get("body") or "")
    existing_cves = {str(cve).upper() for cve in match.get("cves") or []}
    aliases = [
        str(alias) for alias in entry.metadata.get("alias", []) if str(alias).strip()
    ]
    alias_cves = extract_cves(" ".join(aliases))
    new_aliases = [cve for cve in alias_cves if cve not in existing_cves]
    new_references = [
        reference
        for reference in _activity_references(entry)
        if reference and reference not in existing_body
    ]
    recommended_additions: list[str] = []

    severity = entry.metadata.get("severity")
    if severity and str(severity) not in existing_body:
        source = entry.metadata.get("url")
        source_text = f" (source: {source})" if source else ""
        recommended_additions.append(f"Review Gentoo severity: {severity}{source_text}")
    if new_references:
        recommended_additions.append(
            f"Review upstream references: {', '.join(new_references[:5])}"
        )
    if entry.description and _compact(entry.description) not in _compact(existing_body):
        recommended_additions.append(
            f"Review Bugzilla description: {_truncate(neutralize_mentions(entry.description), 300)}"
        )
    for comment in entry.new_comments:
        recommended_additions.append(_comment_addition(comment))

    extracted_new_cves = _new_cves_for_issue(extraction.get("cves") or [], match)
    requires_issue_update = bool(
        new_aliases or extracted_new_cves or recommended_additions
    )
    return {
        "requires_issue_update": requires_issue_update,
        "new_aliases": new_aliases,
        "new_references": new_references,
        "new_comments": entry.new_comments,
        "severity": severity,
        "severity_source_url": entry.metadata.get("url"),
        "recommended_additions": recommended_additions,
    }


def _new_cves_for_issue(cves: list[Any], match: dict[str, Any]) -> list[str]:
    issue_cves = {str(cve).upper() for cve in match.get("cves") or []}
    new_cves: list[str] = []
    for cve in cves:
        normalized = str(cve).upper()
        if (
            normalized
            and normalized != "TBD"
            and normalized not in issue_cves
            and normalized not in new_cves
        ):
            new_cves.append(normalized)
    return new_cves


def _update_reason(upstream_activity: dict[str, Any], new_cves: list[str]) -> str:
    if new_cves or upstream_activity.get("new_aliases"):
        return "Upstream Bugzilla data introduced advisory IDs not present in the existing issue."
    if upstream_activity.get("new_comments"):
        return "New Bugzilla comments in the processing window should be reviewed against the existing issue."
    if upstream_activity.get("new_references"):
        return "Upstream Bugzilla references changed and should be reviewed against the existing issue."
    if upstream_activity.get("recommended_additions"):
        return "Upstream Bugzilla metadata changed and should be reviewed against the existing issue."
    return "Existing issue matched this advisory; review whether upstream context should be reflected there."


def _detected_changes(
    upstream_activity: dict[str, Any], new_cves: list[str]
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    if new_cves:
        changes.append(
            {
                "kind": "new_extracted_cves",
                "values": new_cves,
                "reason": "Extracted CVEs are missing from the matched issue.",
            }
        )
    if upstream_activity.get("new_aliases"):
        changes.append(
            {
                "kind": "new_bugzilla_aliases",
                "values": upstream_activity["new_aliases"],
                "reason": "Bugzilla aliases include CVEs missing from the matched issue.",
            }
        )
    if upstream_activity.get("new_references"):
        changes.append(
            {
                "kind": "new_references",
                "values": upstream_activity["new_references"],
                "reason": "Bugzilla URL, see_also, or source references are missing from the matched issue.",
            }
        )
    if upstream_activity.get("severity"):
        changes.append(
            {
                "kind": "bugzilla_severity",
                "value": upstream_activity.get("severity"),
                "source_url": upstream_activity.get("severity_source_url"),
                "reason": "Bugzilla severity metadata should be reviewed for advisory context.",
            }
        )
    for comment in upstream_activity.get("new_comments") or []:
        changes.append(
            {
                "kind": "new_bugzilla_comment",
                "count": comment.get("count"),
                "creator": comment.get("creator"),
                "creation_time": comment.get("creation_time"),
                "is_creator": comment.get("is_creator"),
                "excerpt": _truncate(str(comment.get("text") or ""), 500),
                "reason": "Comment was added during the processing window.",
            }
        )
    return changes


def _activity_references(entry: SourceEntry) -> list[str]:
    references: list[str] = []
    for reference in [
        entry.metadata.get("url"),
        *entry.metadata.get("see_also", []),
        *entry.references,
    ]:
        if (
            reference
            and reference != entry.source_url
            and str(reference) not in references
        ):
            references.append(str(reference))
    return references


def _updated_issue_body(
    entry: SourceEntry,
    extraction: dict[str, Any],
    match: dict[str, Any],
    upstream_activity: dict[str, Any],
) -> str | None:
    parsed = match.get("parsed_issue") or {}
    existing_body = str(match.get("body") or "")
    package_name = (
        parsed.get("name")
        or extraction.get("package_name")
        or match.get("package")
        or ""
    )
    if not package_name:
        return None
    if not existing_body.strip():
        cves = _dedupe_strings(
            [
                *(parsed.get("cves") or []),
                *(extraction.get("cves") or []),
                *(upstream_activity.get("new_aliases") or []),
            ],
            upper=True,
        )
        cvss_scores = _dedupe_strings(
            [*(parsed.get("cvss_scores") or []), *(extraction.get("cvss_scores") or [])]
        )
        updated = render_issue_body(
            package_name,
            cves,
            cvss_scores,
            extraction.get("action_needed"),
            extraction.get("summary"),
            extraction.get("gentoo_ref"),
        )
        return updated

    updated = existing_body
    updated = append_field_values(
        updated,
        "CVEs",
        [
            *(extraction.get("cves") or []),
            *(upstream_activity.get("new_aliases") or []),
        ],
    )
    updated = append_field_values(updated, "CVSSs", extraction.get("cvss_scores") or [])
    updated = append_field_values(
        updated, "refmap.gentoo", _gentoo_refs_for_update(entry, extraction)
    )
    updated = set_field_if_placeholder(
        updated, "Action Needed", extraction.get("action_needed")
    )
    updated = set_field_if_placeholder(updated, "Summary", extraction.get("summary"))
    if removal_guard_violations(existing_body, updated, parsed):
        return None
    return updated if updated.strip() != existing_body.strip() else None


def _gentoo_refs_for_update(
    entry: SourceEntry, extraction: dict[str, Any]
) -> list[str]:
    candidates = [
        extraction.get("gentoo_ref"),
        entry.source_url,
        entry.metadata.get("url"),
    ]
    candidates.extend(entry.metadata.get("see_also", []) or [])
    candidates.extend(entry.references)
    return _dedupe_strings(
        [candidate for candidate in candidates if _is_gentoo_ref(candidate)]
    )


def _is_gentoo_ref(value: Any) -> bool:
    text = str(value or "").strip()
    if not text or text.upper() in {"TBD", "N/A", "NONE"}:
        return False
    return (
        "bugs.gentoo.org" in text
        or "glsa.gentoo.org" in text
        or "security.gentoo.org/glsa" in text
    )


def _body_diff(existing_body: Any, updated_body: str | None) -> str | None:
    if not updated_body:
        return None
    existing_lines = str(existing_body or "").splitlines()
    updated_lines = updated_body.splitlines()
    return "\n".join(
        difflib.unified_diff(
            existing_lines,
            updated_lines,
            fromfile="existing_issue_body",
            tofile="proposed_issue_body",
            lineterm="",
        )
    )


def _upstream_update_comment_body(
    entry: SourceEntry, upstream_activity: dict[str, Any], additions: list[str]
) -> str | None:
    if not additions and not upstream_activity.get("new_comments"):
        return None
    lines = [
        "Gentoo Bugzilla has new or changed upstream context for this advisory.",
        "",
    ]
    if additions:
        lines.append("Recommended review items:")
        lines.extend(f"- {addition}" for addition in _dedupe_strings(additions))
        lines.append("")
    if upstream_activity.get("new_comments"):
        lines.append("New Bugzilla comments in the processing window:")
        for comment in upstream_activity["new_comments"][:10]:
            lines.append(f"- {_comment_addition(comment)}")
        lines.append("")
    lines.extend(
        [
            f"Source: {entry.source_url}",
            "",
            "This is a guarded automation recommendation; maintainers should review before editing the advisory body.",
        ]
    )
    return "\n".join(lines)


def _comment_addition(comment: dict[str, Any]) -> str:
    creator = neutralize_mentions(str(comment.get("creator") or "unknown"))
    created = comment.get("creation_time") or "unknown time"
    author_note = " (bug creator)" if comment.get("is_creator") else ""
    text = _truncate(neutralize_mentions(str(comment.get("text") or "")), 300)
    return f"Review Bugzilla comment #{comment.get('count')} by {creator}{author_note} at {created}: {text}"


def _value_missing_from_issue(value: str, match: dict[str, Any]) -> bool:
    return _compact(value) not in _compact(str(match.get("body") or ""))


def _dedupe_strings(values: list[Any], upper: bool = False) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text.upper() == "TBD":
            continue
        output = text.upper() if upper and text.upper().startswith("CVE-") else text
        key = output.upper()
        if key not in seen:
            deduped.append(output)
            seen.add(key)
    return deduped


def _compact(value: str) -> str:
    return " ".join(value.lower().split())


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3].rstrip() + "..."


def _record_evidence(
    relevance: dict[str, Any],
    sbom_matches: list[dict[str, Any]],
    issue_matches: list[dict[str, Any]],
) -> list[str]:
    evidence = list(relevance.get("evidence") or [])
    for match in sbom_matches:
        evidence.append(
            f"SBOM package match: {match.get('name')} {match.get('versionInfo')}"
        )
    for match in issue_matches:
        evidence.append(
            f"Existing issue match: #{match.get('issue')} {match.get('title')}"
        )
    return evidence
