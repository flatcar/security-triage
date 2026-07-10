from __future__ import annotations

from typing import Any

from .console import NullProgressLogger, ProgressLogger
from .debug import DebugLogger
from .issues import parse_issue_body, parsed_issue_to_dict
from .models import BaseModelClient
from .reasoning import build_cleanup_evidence_bundle
from .records import Issue
from .rules import (
    FLATCAR_PRODUCTION_SBOM_URL,
    SCHEMA_VERSION,
    TARGET_REPO,
    advisory_issue_query,
    cleanup_comment_body,
    coerce_cleanup_review,
    min_confidence,
    validate_cleanup_document,
    validate_repo_name,
)
from .sbom import (
    SBOMIndex,
    evaluate_fixed_version_requirements,
    extract_fixed_version_requirement,
    extract_fixed_version_requirements,
    fixed_version_requirements_are_alternatives,
)
from .time_utils import iso_now


class CleanupWorkflow:
    def __init__(
        self,
        model_client: BaseModelClient,
        sbom_index: SBOMIndex,
        issues: list[Issue],
        allow_close: bool = False,
        debug_logger: DebugLogger | None = None,
        progress_logger: ProgressLogger | None = None,
        target_repo: str = TARGET_REPO,
    ) -> None:
        self.model_client = model_client
        self.sbom_index = sbom_index
        self.issues = issues
        self.allow_close = allow_close
        self.debug_logger = debug_logger or DebugLogger()
        self.progress_logger = progress_logger or NullProgressLogger()
        self.target_repo = validate_repo_name(target_repo)

    def run(self) -> dict[str, Any]:
        records: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        total = len(self.issues)
        self.progress_logger.info(f"Processing {total} open advisory issue(s)")
        for index, issue in enumerate(self.issues, start=1):
            self.progress_logger.info(
                f"[{index}/{total}] Processing issue #{issue.number}: {issue.title[:100]}"
            )
            self.debug_logger.log(
                "cleanup_issue",
                issue=issue.raw or {"number": issue.number, "title": issue.title},
            )
            try:
                record = self._process_issue(issue)
            except Exception as exc:
                self.progress_logger.info(
                    f"[{index}/{total}] Issue #{issue.number} failed; recording manual review: {exc}"
                )
                errors.append({"issue": issue.number, "error": str(exc)})
                record = self._manual_record(issue, str(exc))
            records.append(record)
            self.progress_logger.info(
                f"[{index}/{total}] Finished issue #{issue.number}: {record.get('status')} -> {record.get('recommended_action')}"
            )
            self.debug_logger.log(
                "cleanup_final_record", issue=issue.number, record=record
            )
        document = {
            "schema_version": SCHEMA_VERSION,
            "workflow": "advisory_cleanup_recommendation",
            "generated_at": iso_now(),
            "target_repo": self.target_repo,
            "sbom_url": FLATCAR_PRODUCTION_SBOM_URL,
            "issue_query": advisory_issue_query(self.target_repo),
            "records": records,
            "errors": errors,
        }
        validate_cleanup_document(document)
        return document

    def _process_issue(self, issue: Issue) -> dict[str, Any]:
        self.progress_logger.info(f"Parsing advisory issue #{issue.number}")
        parsed_issue = _parse_or_normalize_issue(issue, self.model_client)
        package_name = parsed_issue.get("name")
        cves = parsed_issue.get("cves") or []
        self.progress_logger.info(
            f"Issue #{issue.number} package: {package_name or 'unknown'}; CVEs: {len(cves)}"
        )
        action_needed = parsed_issue.get("action_needed")
        fixed_versions = extract_fixed_version_requirements(action_needed)
        fixed_version = extract_fixed_version_requirement(action_needed)
        alternatives = fixed_version_requirements_are_alternatives(action_needed)
        if len(fixed_versions) > 1 and alternatives:
            self.progress_logger.info(
                f"Issue #{issue.number} fixed-version requirements (OR alternatives): {', '.join(fixed_versions)}"
            )
        elif len(fixed_versions) > 1 and fixed_version:
            self.progress_logger.info(
                f"Issue #{issue.number} fixed-version requirement: {fixed_version} selected from {len(fixed_versions)} active requirements"
            )
        else:
            self.progress_logger.info(
                f"Issue #{issue.number} fixed-version requirement: {fixed_version or 'unparsed'}"
            )
        sbom_matches = self.sbom_index.match_package(package_name)
        self.progress_logger.info(
            f"Issue #{issue.number} SBOM package matches: {len(sbom_matches)}"
        )
        preliminary_status, preliminary_reasons, version_comparison = (
            _preliminary_cleanup_status(
                issue.labels,
                fixed_versions,
                alternatives,
                sbom_matches,
            )
        )
        self.progress_logger.info(
            f"Issue #{issue.number} preliminary status: {preliminary_status}"
        )
        evidence_bundle = build_cleanup_evidence_bundle(
            issue,
            parsed_issue,
            fixed_version,
            fixed_versions,
            sbom_matches,
            preliminary_status,
            preliminary_reasons,
            version_comparison,
        )
        self.debug_logger.log(
            "cleanup_evidence_bundle", issue=issue.number, bundle=evidence_bundle
        )
        self.progress_logger.info(
            f"Requesting cleanup model review for issue #{issue.number}"
        )
        llm_review = coerce_cleanup_review(
            self.model_client.review_cleanup(evidence_bundle)
        )
        status, confidence, final_reasons = _finalize_cleanup_status(
            preliminary_status, preliminary_reasons, llm_review
        )
        recommended_action = _recommended_action(status, self.allow_close)
        comment_body = ""
        if status == "remediated_in_current_production_sbom" and sbom_matches:
            comment_body = cleanup_comment_body(
                package_name or "unknown", cves, action_needed, sbom_matches[0]
            )
        return {
            "issue": issue.number,
            "issue_url": issue.html_url,
            "title": issue.title,
            "package_from_issue": package_name,
            "labels": issue.labels,
            "sbom_url": FLATCAR_PRODUCTION_SBOM_URL,
            "cves_from_issue": cves,
            "fixed_version_requirement": fixed_version,
            "fixed_version_requirements": fixed_versions,
            "sbom_package_matches": sbom_matches,
            "llm_review": llm_review,
            "status": status,
            "confidence": confidence,
            "evidence": _cleanup_evidence(
                sbom_matches, version_comparison, final_reasons, fixed_versions
            ),
            "recommended_action": recommended_action,
            "comment_body": comment_body,
        }

    def _manual_record(self, issue: Issue, reason: str) -> dict[str, Any]:
        return {
            "issue": issue.number,
            "issue_url": issue.html_url,
            "title": issue.title,
            "package_from_issue": None,
            "labels": issue.labels,
            "sbom_url": FLATCAR_PRODUCTION_SBOM_URL,
            "cves_from_issue": [],
            "fixed_version_requirement": None,
            "sbom_package_matches": [],
            "llm_review": {
                "decision": "needs_manual_review",
                "confidence": "low",
                "reasons": [reason],
            },
            "status": "needs_manual_review",
            "confidence": "low",
            "evidence": [reason],
            "recommended_action": "manual_review",
            "comment_body": "",
        }


def _parse_or_normalize_issue(
    issue: Issue, model_client: BaseModelClient
) -> dict[str, Any]:
    parsed = parse_issue_body(issue.body)
    data = parsed_issue_to_dict(parsed)
    if parsed.valid and data.get("name"):
        return data
    normalized = model_client.normalize_issue(issue)
    merged = {
        "name": normalized.get("name") or data.get("name"),
        "cves": normalized.get("cves") or data.get("cves") or [],
        "cvss_scores": normalized.get("cvss_scores") or data.get("cvss_scores") or [],
        "action_needed": normalized.get("action_needed") or data.get("action_needed"),
        "summary": normalized.get("summary") or data.get("summary"),
        "gentoo_ref": normalized.get("gentoo_ref") or data.get("gentoo_ref"),
        "valid": bool(normalized.get("valid")) or parsed.valid,
        "missing_fields": normalized.get("missing_fields")
        or data.get("missing_fields")
        or [],
    }
    return merged


def _preliminary_cleanup_status(
    labels: list[str],
    fixed_versions: list[str],
    alternatives: bool,
    sbom_matches: list[dict[str, Any]],
) -> tuple[str, list[str], dict[str, Any] | None]:
    reasons: list[str] = []
    if "advisory/only-sdk" in labels:
        reasons.append(
            "Issue is SDK-only; production SBOM alone is insufficient cleanup evidence."
        )
    if "advisory/sysext" in labels:
        reasons.append(
            "Issue is sysext-scoped; production SBOM alone may not prove sysext remediation."
        )
    if not fixed_versions:
        reasons.append(
            "Action Needed does not contain a parseable fixed-version requirement."
        )
    if not sbom_matches:
        reasons.append("Package was not found in the Flatcar production SBOM.")
    reliable_matches = [
        match
        for match in sbom_matches
        if match.get("match_type") in {"exact_name", "exact_purl"}
    ]
    if sbom_matches and len(reliable_matches) != 1:
        reasons.append("SBOM package matching is ambiguous or not exact.")
    if reasons:
        return "needs_manual_review", reasons, None

    match = reliable_matches[0]
    comparison = evaluate_fixed_version_requirements(
        match.get("versionInfo"), fixed_versions, alternatives
    )
    comparison_dict = {"result": comparison.result, "reason": comparison.reason}
    if comparison.result == "at_or_above":
        return (
            "remediated_in_current_production_sbom",
            [comparison.reason],
            comparison_dict,
        )
    if comparison.result == "below":
        return (
            "not_remediated_in_current_production_sbom",
            [comparison.reason],
            comparison_dict,
        )
    return "needs_manual_review", [comparison.reason], comparison_dict


def _finalize_cleanup_status(
    preliminary_status: str,
    preliminary_reasons: list[str],
    llm_review: dict[str, Any],
) -> tuple[str, str, list[str]]:
    reasons = [*preliminary_reasons, *llm_review.get("reasons", [])]
    llm_decision = llm_review.get("decision")
    if preliminary_status == "needs_manual_review":
        if (
            llm_decision == "not_remediated_in_current_production_sbom"
            and llm_review.get("confidence") in {"high", "medium"}
            and _can_use_model_override_for_ambiguity(preliminary_reasons)
        ):
            return (
                "not_remediated_in_current_production_sbom",
                min_confidence("medium", llm_review.get("confidence")),
                reasons,
            )
        if (
            llm_decision == "remediated_in_current_production_sbom"
            and llm_review.get("confidence") in {"high", "medium", "low"}
            and _can_use_model_override_for_ambiguity(preliminary_reasons)
        ):
            return (
                "remediated_in_current_production_sbom",
                "low",
                [
                    *reasons,
                    "Model cleanup review affirmed remediation despite deterministic ambiguity; downgrade confidence to low.",
                ],
            )
        return "needs_manual_review", "low", reasons
    if preliminary_status == "remediated_in_current_production_sbom":
        if llm_decision == "remediated_in_current_production_sbom" and llm_review.get(
            "confidence"
        ) in {"high", "medium"}:
            return (
                preliminary_status,
                min_confidence("high", llm_review.get("confidence")),
                reasons,
            )
        return (
            "needs_manual_review",
            "low",
            [
                *reasons,
                "LLM cleanup review did not affirm high-confidence remediation.",
            ],
        )
    if preliminary_status == "not_remediated_in_current_production_sbom":
        if llm_decision in {
            "not_remediated_in_current_production_sbom",
            "needs_manual_review",
        }:
            confidence = (
                "high"
                if llm_decision == "not_remediated_in_current_production_sbom"
                else "medium"
            )
            return preliminary_status, confidence, reasons
    return "needs_manual_review", "low", reasons


def _can_use_model_override_for_ambiguity(preliminary_reasons: list[str]) -> bool:
    if not preliminary_reasons:
        return False
    hard_blocker_fragments = [
        "SDK-only",
        "sysext-scoped",
        "does not contain a parseable fixed-version requirement",
        "Package was not found",
    ]
    return not any(
        fragment in reason
        for reason in preliminary_reasons
        for fragment in hard_blocker_fragments
    )


def _recommended_action(status: str, allow_close: bool) -> str:
    if status == "remediated_in_current_production_sbom":
        return "close_issue" if allow_close else "comment_only"
    if status == "not_remediated_in_current_production_sbom":
        return "keep_open"
    return "manual_review"


def _cleanup_evidence(
    sbom_matches: list[dict[str, Any]],
    version_comparison: dict[str, Any] | None,
    reasons: list[str],
    fixed_version_requirements: list[str] | None = None,
) -> list[str]:
    evidence = list(reasons)
    if fixed_version_requirements and len(fixed_version_requirements) > 1:
        evidence.append(
            f"Active fixed-version requirements: {', '.join(fixed_version_requirements)}"
        )
    for match in sbom_matches:
        evidence.append(
            f"SBOM package match: {match.get('name')} {match.get('versionInfo')} ({match.get('match_type')})"
        )
    if version_comparison:
        evidence.append(f"Version comparison: {version_comparison.get('reason')}")
    return evidence
