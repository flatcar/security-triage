from __future__ import annotations

from pathlib import Path
from typing import Any

from .io_utils import write_json_file, write_yaml_file


def write_document(
    path: str | Path, document: dict[str, Any], output_format: str = "json"
) -> None:
    if output_format == "json":
        write_json_file(path, document)
        return
    if output_format == "yaml":
        write_yaml_file(path, document)
        return
    raise ValueError("output_format must be json or yaml")


def write_markdown(path: str | Path, content: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content, encoding="utf-8")


def render_discovery_markdown(document: dict[str, Any]) -> str:
    lines = [
        "# Flatcar Vulnerability Discovery Dry Run",
        "",
        f"Generated: {document.get('generated_at')}",
        f"Target repo: {document.get('target_repo')}",
        "",
        "## Decisions",
        "",
    ]
    if not document.get("records"):
        lines.append("No source entries were processed.")
    for record in document.get("records", []):
        decision = record.get("decision", {})
        extraction = record.get("llm_extraction", {})
        relevance = record.get("flatcar_relevance", {})
        lines.extend(
            [
                f"### {_discovery_record_title(record, extraction)}",
                "",
                f"- Source: {record.get('source')} ({record.get('source_url')})",
                f"- Created (updated): {record.get('source_entry_published_at') or 'n/a'} ({record.get('source_entry_updated_at') or 'n/a'})",
                f"- Package: {extraction.get('package_name') or 'unknown'}",
                f"- CVEs: {', '.join(extraction.get('cves') or []) or 'n/a'}",
                f"- Relevance: {relevance.get('status')} / {relevance.get('scope')}",
                f"- Action: {decision.get('action')} ({decision.get('confidence')})",
                f"- Reason: {decision.get('reason') or relevance.get('llm_decision') or 'n/a'}",
            ]
        )
        sbom_assessment = relevance.get("sbom_match_assessment") or {}
        if sbom_assessment.get("reason"):
            lines.append(
                f"- SBOM match assessment: {sbom_assessment.get('status')} - {sbom_assessment.get('reason')}"
            )
        if record.get("proposed_issue"):
            proposed = record["proposed_issue"]
            lines.extend(
                [
                    f"- Proposed issue: {proposed.get('title')}",
                    f"- Labels: {', '.join(proposed.get('labels') or [])}",
                ]
            )
        if record.get("proposed_update"):
            update = record["proposed_update"]
            lines.append(
                f"- Proposed update: #{update.get('issue')} {update.get('title')}"
            )
            if update.get("update_reason"):
                lines.append(f"- Update reason: {update.get('update_reason')}")
            changes = update.get("detected_changes") or []
            if changes:
                lines.extend(["", "Detected upstream changes:"])
                lines.extend(
                    f"- {_format_detected_change(change)}" for change in changes
                )
            additions = update.get("recommended_additions") or []
            if additions:
                lines.extend(["", "Recommended additions:"])
                lines.extend(f"- {addition}" for addition in additions)
            if update.get("comment_body"):
                lines.extend(
                    [
                        "",
                        "Comment preview:",
                        "",
                        "```markdown",
                        update["comment_body"],
                        "```",
                    ]
                )
            if update.get("body_update_mode") == "additive_guarded":
                lines.extend(
                    [
                        "",
                        "Proposed additive issue body update: existing issue content is preserved by guardrails.",
                    ]
                )
            elif update.get("updated_body_diff"):
                lines.extend(
                    [
                        "",
                        "Issue body diff:",
                        "",
                        "```diff",
                        update["updated_body_diff"],
                        "```",
                    ]
                )
        if record.get("manual_review_reasons"):
            lines.append(
                f"- Manual review: {'; '.join(record.get('manual_review_reasons') or [])}"
            )
        lines.append("")
    if document.get("errors"):
        lines.extend(["## Errors", ""])
        for error in document["errors"]:
            lines.append(f"- {error}")
    return "\n".join(lines).rstrip() + "\n"


def _discovery_record_title(record: dict[str, Any], extraction: dict[str, Any]) -> str:
    source = record.get("source") or "unknown"
    package_name = (
        extraction.get("package_name") or record.get("raw_advisory_id") or "unknown"
    )
    created = record.get("source_entry_published_at") or "n/a"
    return f"{source} {package_name} ({created})"


def _format_detected_change(change: dict[str, Any]) -> str:
    kind = change.get("kind") or "change"
    reason = change.get("reason") or "review recommended"
    if kind in {"new_extracted_cves", "new_bugzilla_aliases", "new_references"}:
        values = ", ".join(str(value) for value in change.get("values") or [])
        return f"{kind}: {values} ({reason})"
    if kind == "bugzilla_severity":
        source = (
            f"; source: {change.get('source_url')}" if change.get("source_url") else ""
        )
        return f"{kind}: {change.get('value')}{source} ({reason})"
    if kind == "new_bugzilla_comment":
        creator = change.get("creator") or "unknown"
        created = change.get("creation_time") or "unknown time"
        author_note = " by bug creator" if change.get("is_creator") else ""
        return f"Bugzilla comment #{change.get('count')} by {creator}{author_note} at {created}: {change.get('excerpt') or ''} ({reason})"
    return f"{kind}: {change}"


def render_cleanup_markdown(document: dict[str, Any]) -> str:
    lines = [
        "# Flatcar Advisory Cleanup Dry Run",
        "",
        f"Generated: {document.get('generated_at')}",
        f"SBOM: {document.get('sbom_url')}",
        "",
        "## Decisions",
        "",
    ]
    if not document.get("records"):
        lines.append("No advisory issues were processed.")
    for record in document.get("records", []):
        lines.extend(
            [
                f"### #{record.get('issue')} {record.get('title')}",
                "",
                f"- Package: {record.get('package_from_issue') or 'unknown'}",
                f"- CVEs: {', '.join(record.get('cves_from_issue') or []) or 'n/a'}",
                f"- Required version: {record.get('fixed_version_requirement') or 'unparsed'}",
                f"- Status: {record.get('status')} ({record.get('confidence')})",
                f"- Recommendation: {record.get('recommended_action')}",
            ]
        )
        matches = record.get("sbom_package_matches") or []
        if matches:
            match_text = "; ".join(
                f"{match.get('name')} {match.get('versionInfo')}" for match in matches
            )
            lines.append(f"- SBOM matches: {match_text}")
        if record.get("evidence"):
            lines.append(f"- Evidence: {'; '.join(record.get('evidence') or [])}")
        lines.append("")
    if document.get("errors"):
        lines.extend(["## Errors", ""])
        for error in document["errors"]:
            lines.append(f"- {error}")
    return "\n".join(lines).rstrip() + "\n"
