from __future__ import annotations

from typing import Any

from .records import Issue, SourceEntry
from .rules import FLATCAR_PRODUCTION_SBOM_URL


def build_discovery_evidence_bundle(
    record_id: str,
    entry: SourceEntry,
    extraction: dict[str, Any],
    sbom_matches: list[dict[str, Any]],
    existing_issue_matches: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "record_id": record_id,
        "source_entry": {
            "source": entry.source,
            "source_url": entry.source_url,
            "entry_id": entry.entry_id,
            "title": entry.title,
            "content": entry.content,
            "published_at": entry.published_at,
            "updated_at": entry.updated_at,
            "references": entry.references,
            "description": entry.description,
            "comments": entry.comments,
            "new_comments": entry.new_comments,
            "metadata": entry.metadata,
        },
        "llm_extraction": extraction,
        "sbom_package_matches": sbom_matches,
        "sbom_match_review": _sbom_match_review(sbom_matches),
        "existing_issue_matches": existing_issue_matches,
        "official_rules_summary": [
            "Track Flatcar-relevant server packages only.",
            "Do not track desktop stacks or unrelated Ruby/Node/application ecosystem issues without Flatcar evidence.",
            "Production SBOM evidence is strong production-image evidence; SDK and sysext scopes need labels and explicit evidence.",
            "Kernel CVEs must use kernel_regular_update_flow.",
            "Prefer needs_manual_review when Flatcar relevance, versions, or duplicate state are ambiguous.",
        ],
    }


def _sbom_match_review(sbom_matches: list[dict[str, Any]]) -> dict[str, Any]:
    weak_match_types = {"unique_substring", "ambiguous_substring"}
    weak_matches = [
        match for match in sbom_matches if match.get("match_type") in weak_match_types
    ]
    return {
        "requires_llm_judgement": bool(weak_matches),
        "weak_match_count": len(weak_matches),
        "instruction": (
            "If SBOM package candidates are weak substring matches, judge whether they are genuinely the same "
            "package/component/ecosystem as the extracted advisory package. Unrelated weak matches are strong "
            "evidence that the advisory package is not shipped in the production SBOM."
        ),
    }


def build_cleanup_evidence_bundle(
    issue: Issue,
    parsed_issue: dict[str, Any],
    fixed_version_requirement: str | None,
    fixed_version_requirements: list[str],
    sbom_matches: list[dict[str, Any]],
    preliminary_status: str,
    preliminary_reasons: list[str],
    version_comparison: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "issue": {
            "number": issue.number,
            "url": issue.html_url,
            "title": issue.title,
            "labels": issue.labels,
        },
        "parsed_issue": parsed_issue,
        "sbom_url": FLATCAR_PRODUCTION_SBOM_URL,
        "fixed_version_requirement": fixed_version_requirement,
        "fixed_version_requirements": fixed_version_requirements,
        "sbom_package_matches": sbom_matches,
        "version_comparison": version_comparison,
        "preliminary_status": preliminary_status,
        "preliminary_reasons": preliminary_reasons,
        "cleanup_safety_rules": [
            "Use only the current Flatcar production SBOM for cleanup evidence.",
            "Remediated requires fixed-version requirement, reliable SBOM match, clear simple version comparison at or above requirement, all CVEs covered, and no SDK/sysext-only uncertainty.",
            "SDK-only and sysext-only issues need explicit scope evidence before closure.",
            "Prefer needs_manual_review over false cleanup.",
        ],
    }
