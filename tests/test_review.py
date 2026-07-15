from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from security_triage import review
from security_triage.actions import ActionFlags, GitHubActionRunner
from security_triage.cleanup import CleanupWorkflow
from security_triage.discovery import DiscoveryWorkflow
from security_triage.issues import issue_from_api, load_issue_fixture
from security_triage.models import HeuristicModelClient
from security_triage.rules import RepositoryValidationError
from security_triage.sbom import load_sbom_fixture
from security_triage.sources import load_source_fixture

FIXTURES = Path(__file__).parent / "fixtures"
REPO = "flatcar/security-triage"


class FakeGitHubIssueClient:
    """In-memory stateful fake matching the GitHubIssueClient surface
    `review.py` depends on."""

    def __init__(self, repo: str = REPO) -> None:
        self.repo = repo
        self._issues: dict[int, dict[str, Any]] = {}
        self._comments: dict[int, list[dict[str, Any]]] = {}
        self._next_number = 1

    def seed_issue(
        self,
        number: int,
        title: str,
        body: str,
        labels: list[str],
        state: str = "open",
        state_reason: str | None = None,
    ) -> None:
        self._issues[number] = {
            "number": number,
            "title": title,
            "body": body,
            "labels": [{"name": label} for label in labels],
            "html_url": f"https://github.com/{self.repo}/issues/{number}",
            "state": state,
            "state_reason": state_reason,
        }
        self._comments.setdefault(number, [])
        self._next_number = max(self._next_number, number + 1)

    def set_body(self, issue_number: int, body: str) -> None:
        self._issues[issue_number]["body"] = body

    def close_as(self, issue_number: int, state_reason: str | None) -> None:
        self._issues[issue_number]["state"] = "closed"
        self._issues[issue_number]["state_reason"] = state_reason

    def reopen(self, issue_number: int) -> None:
        self._issues[issue_number]["state"] = "open"
        self._issues[issue_number]["state_reason"] = None

    # --- GitHubIssueClient surface ---

    def fetch_open_advisory_issues(self, query: str | None = None) -> list[Any]:
        return [
            issue_from_api(item)
            for item in self._issues.values()
            if item["state"] == "open"
        ]

    def get_issue(self, issue_number: int) -> Any:
        return issue_from_api(self._issues[issue_number])

    def list_issues_by_label(self, label: str, state: str = "all") -> list[Any]:
        out = []
        for item in self._issues.values():
            names = {entry["name"] for entry in item["labels"]}
            if label in names and (state == "all" or item["state"] == state):
                out.append(issue_from_api(item))
        return out

    def list_comments(self, issue_number: int) -> list[dict[str, Any]]:
        return list(self._comments.get(issue_number, []))

    def ensure_label_exists(
        self, name: str, color: str = "", description: str = ""
    ) -> None:
        return None

    def add_labels(self, issue_number: int, labels: list[str]) -> list[dict[str, Any]]:
        item = self._issues[issue_number]
        existing = {entry["name"] for entry in item["labels"]}
        for label in labels:
            if label not in existing:
                item["labels"].append({"name": label})
        return list(item["labels"])

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict[str, Any]:
        number = self._next_number
        self._next_number += 1
        self.seed_issue(number, title, body, labels, state="open")
        return {"number": number, "html_url": self._issues[number]["html_url"]}

    def update_issue_body(self, issue_number: int, body: str) -> dict[str, Any]:
        self._issues[issue_number]["body"] = body
        return {"number": issue_number}

    def post_comment(self, issue_number: int, body: str) -> dict[str, Any]:
        comment = {
            "id": len(self._comments.setdefault(issue_number, [])) + 1,
            "body": body,
        }
        self._comments[issue_number].append(comment)
        return comment

    def close_issue(self, issue_number: int) -> dict[str, Any]:
        self._issues[issue_number]["state"] = "closed"
        return {"number": issue_number}


def _check_action(body: str, action_id: str) -> str:
    marker = f"<!-- security-triage:action-id:{action_id} -->"
    lines = body.splitlines()
    for index, line in enumerate(lines):
        if marker in line and "[ ]" in line:
            lines[index] = line.replace("[ ]", "[x]")
    return "\n".join(lines)


def _action_ids_by_kind(manifest: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for group in manifest["groups"]:
        for action in group["actions"]:
            by_kind.setdefault(action["kind"], []).append(action)
    return by_kind


def _context(run_id: str = "42", **overrides: Any) -> review.ReviewContext:
    defaults: dict[str, Any] = {
        "advisory_repo": REPO,
        "review_repo": REPO,
        "run_id": run_id,
        "generated_at": "2026-07-10T06:00:00+00:00",
        "run_url": f"https://github.com/{REPO}/actions/runs/{run_id}",
        "commit_sha": "deadbeef",
    }
    defaults.update(overrides)
    return review.ReviewContext(**defaults)


def _discovery_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "record_id": "gentoo:abc123",
        "source": "gentoo",
        "source_url": "https://bugs.gentoo.org/1",
        "raw_advisory_id": "1",
        "source_entry_published_at": None,
        "source_entry_updated_at": None,
        "upstream_references": [],
        "upstream_metadata": {},
        "upstream_description": None,
        "upstream_comments": [],
        "upstream_new_comments": [],
        "upstream_activity": {
            "requires_issue_update": False,
            "new_aliases": [],
            "new_references": [],
            "new_comments": [],
            "recommended_additions": [],
        },
        "raw_source_excerpt": "excerpt",
        "llm_extraction": {
            "package_name": "widget",
            "cves": ["CVE-2026-9001"],
            "cvss_scores": ["7.5"],
            "affected_versions": [],
            "fixed_versions": ["1.2"],
            "action_needed": "update to >= 1.2",
            "summary": "widget issue",
            "gentoo_ref": "https://bugs.gentoo.org/1",
            "scope_assessment": "production",
            "confidence": "medium",
        },
        "flatcar_relevance": {
            "status": "relevant",
            "scope": "production",
            "llm_decision": "clear",
            "reasons": [],
            "evidence": ["evidence"],
            "sbom_match_assessment": {
                "status": "no_matches",
                "reason": "",
                "related_matches": [],
                "unrelated_matches": [],
            },
        },
        "sbom_package_matches": [],
        "existing_issue_matches": [],
        "decision": {"action": "create_issue", "confidence": "high", "reason": "clear"},
        "proposed_issue": {
            "title": "update: widget",
            "body": (
                "Name: widget\n"
                "CVEs: CVE-2026-9001\n"
                "CVSSs: 7.5\n"
                "Action Needed: update to >= 1.2\n"
                "Summary: widget issue\n\n"
                "refmap.gentoo: https://bugs.gentoo.org/1"
            ),
            "labels": ["advisory", "security", "cvss/HIGH"],
            "assignees": [],
            "milestone": None,
        },
        "proposed_update": None,
        "manual_review_reasons": [],
        "evidence": [],
    }
    record.update(overrides)
    return record


def _discovery_document(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "workflow": "new_vulnerability_discovery",
        "generated_at": "2026-07-10T00:00:00Z",
        "target_repo": REPO,
        "processing_window": {"start": "a", "end": "b", "timezone": "UTC"},
        "sources": [],
        "model": {},
        "records": records,
        "errors": [],
    }


def _cleanup_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "issue": 2088,
        "issue_url": f"https://github.com/{REPO}/issues/2088",
        "title": "update: libgcrypt",
        "package_from_issue": "libgcrypt",
        "labels": ["advisory", "security"],
        "sbom_url": "https://alpha.release.flatcar-linux.net/amd64-usr/current/flatcar_production_image_sbom.json",
        "cves_from_issue": ["CVE-2026-1200"],
        "fixed_version_requirement": "1.12.2",
        "fixed_version_requirements": ["1.12.2"],
        "sbom_package_matches": [
            {
                "name": "libgcrypt",
                "versionInfo": "1.12.2",
                "SPDXID": "SPDXRef-libgcrypt",
                "purls": [],
                "match_type": "exact_name",
            }
        ],
        "llm_review": {
            "decision": "remediated_in_current_production_sbom",
            "confidence": "high",
            "reasons": [],
        },
        "status": "remediated_in_current_production_sbom",
        "confidence": "high",
        "evidence": ["SBOM package match: libgcrypt 1.12.2 (exact_name)"],
        "recommended_action": "comment_only",
        "comment_body": (
            "This advisory appears to be remediated in the current "
            "Flatcar production SBOM."
        ),
    }
    record.update(overrides)
    return record


def _cleanup_document(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "workflow": "advisory_cleanup_recommendation",
        "generated_at": "2026-07-10T00:00:00Z",
        "target_repo": REPO,
        "sbom_url": "https://alpha.release.flatcar-linux.net/amd64-usr/current/flatcar_production_image_sbom.json",
        "issue_query": (
            "repo:flatcar/security-triage is:issue is:open "
            "label:advisory label:security"
        ),
        "records": records,
        "errors": [],
    }


# --- Stable ID determinism and evidence drift --------------------------------


def test_discovery_action_id_is_deterministic_and_drifts_with_evidence():
    first = review.discovery_action_id("gentoo:abc", review.DISCOVERY_KIND_CREATE)
    again = review.discovery_action_id("gentoo:abc", review.DISCOVERY_KIND_CREATE)
    different_kind = review.discovery_action_id(
        "gentoo:abc", review.DISCOVERY_KIND_UPDATE
    )
    different_record = review.discovery_action_id(
        "gentoo:xyz", review.DISCOVERY_KIND_CREATE
    )
    different_target = review.discovery_action_id(
        "gentoo:abc", review.DISCOVERY_KIND_UPDATE, target_issue=42
    )

    assert first == again
    assert first != different_kind
    assert first != different_record
    assert different_kind != different_target


def test_cleanup_action_id_is_deterministic_and_drifts_with_evidence():
    base_args = (
        2088,
        review.CLEANUP_KIND_COMMENT_ONLY,
        ["CVE-2026-1200"],
        "1.12.2",
        {"name": "libgcrypt", "versionInfo": "1.12.2"},
        ["evidence one"],
    )
    first = review.cleanup_action_id(*base_args)
    again = review.cleanup_action_id(*base_args)
    different_version = review.cleanup_action_id(
        2088,
        review.CLEANUP_KIND_COMMENT_ONLY,
        ["CVE-2026-1200"],
        "1.12.3",
        {"name": "libgcrypt", "versionInfo": "1.12.2"},
        ["evidence one"],
    )
    different_evidence = review.cleanup_action_id(
        2088,
        review.CLEANUP_KIND_COMMENT_ONLY,
        ["CVE-2026-1200"],
        "1.12.2",
        {"name": "libgcrypt", "versionInfo": "1.12.2"},
        ["evidence two"],
    )

    assert first == again
    assert first != different_version
    assert first != different_evidence


def test_action_ids_are_stable_across_two_independent_builds_of_the_same_document():
    document = _discovery_document([_discovery_record()])
    batch_a = review.build_review_batch(_context("run-a"), document, None)
    batch_b = review.build_review_batch(_context("run-b"), document, None)

    ids_a = sorted(
        action["action_id"]
        for group in batch_a.parts[0].manifest["groups"]
        for action in group["actions"]
    )
    ids_b = sorted(
        action["action_id"]
        for group in batch_b.parts[0].manifest["groups"]
        for action in group["actions"]
    )
    assert ids_a == ids_b, "action IDs must depend on evidence, not on the run/batch ID"


# --- Manifest canonicalization, round trip, corruption, and validation ------


def test_manifest_round_trips_through_embedding_and_extraction():
    document = _discovery_document([_discovery_record()])
    batch = review.build_review_batch(_context(), document, None)
    part = batch.parts[0]

    extracted = review.extract_manifest(part.body)

    assert extracted == part.manifest
    review.validate_manifest_against_context(extracted, REPO, REPO)


def test_extract_manifest_detects_digest_corruption():
    document = _discovery_document([_discovery_record()])
    batch = review.build_review_batch(_context(), document, None)
    body = batch.parts[0].body

    corrupted = body.replace(
        "security-triage:review-manifest:v1\n",
        "security-triage:review-manifest:v1\nAA",
        1,
    )

    with pytest.raises(review.ManifestCorruptionError):
        review.extract_manifest(corrupted)


def test_extract_manifest_requires_a_manifest_comment():
    with pytest.raises(review.ManifestCorruptionError):
        review.extract_manifest("no manifest here")


def test_validate_manifest_rejects_repository_mismatch():
    document = _discovery_document([_discovery_record()])
    batch = review.build_review_batch(_context(), document, None)
    manifest = batch.parts[0].manifest

    with pytest.raises(review.ManifestValidationError):
        review.validate_manifest_against_context(manifest, "someone/else", REPO)
    with pytest.raises(review.ManifestValidationError):
        review.validate_manifest_against_context(manifest, REPO, "someone/else")


def test_validate_manifest_rejects_bad_schema_version():
    document = _discovery_document([_discovery_record()])
    batch = review.build_review_batch(_context(), document, None)
    manifest = dict(batch.parts[0].manifest)
    manifest["schema_version"] = "9.9"

    with pytest.raises(review.ManifestValidationError):
        review.validate_manifest_against_context(manifest, REPO, REPO)


def test_validate_manifest_rejects_inconsistent_part_index():
    document = _discovery_document([_discovery_record()])
    batch = review.build_review_batch(_context(), document, None)
    manifest = dict(batch.parts[0].manifest)
    manifest["part_index"] = 5  # part_count is 1

    with pytest.raises(review.ManifestValidationError):
        review.validate_manifest_against_context(manifest, REPO, REPO)


def test_review_context_rejects_invalid_run_id():
    with pytest.raises(review.ReviewConfigError):
        _context(run_id="not a valid run id!!")


def test_review_context_rejects_invalid_repo():
    with pytest.raises(RepositoryValidationError):
        _context(advisory_repo="not-a-valid-repo")


# --- Checkbox parsing ---------------------------------------------------------


@pytest.mark.parametrize(
    "line,expected",
    [
        ("- [x] text <!-- security-triage:action-id:abc -->", {"abc"}),
        ("- [X] text <!-- security-triage:action-id:abc -->", {"abc"}),
        ("- [ ] text <!-- security-triage:action-id:abc -->", set()),
        ("-  [x]  text  <!-- security-triage:action-id:abc -->", {"abc"}),
        ("* [x] text <!-- security-triage:action-id:abc -->", {"abc"}),
        ("- [x] text with no marker comment", set()),
        ("plain text, not a checkbox", set()),
    ],
)
def test_parse_checked_action_ids_handles_case_and_spacing(line, expected):
    assert review.parse_checked_action_ids(line) == expected


def test_parse_checked_action_ids_ignores_unrelated_checkboxes():
    body = (
        "- [x] unrelated maintainer todo item\n"
        "- [x] text <!-- security-triage:action-id:real-id -->"
    )
    assert review.parse_checked_action_ids(body) == {"real-id"}


def test_resolve_review_selections_zero_one_and_many_checked():
    manifest = {
        "groups": [
            {
                "group_id": "g1",
                "source": "discovery",
                "actions": [{"action_id": "a1", "kind": "x", "payload": {}}],
            },
            {
                "group_id": "g2",
                "source": "discovery",
                "actions": [
                    {"action_id": "a2", "kind": "x", "payload": {}},
                    {"action_id": "a3", "kind": "x", "payload": {}},
                ],
            },
        ]
    }

    none_checked = review.resolve_review_selections(manifest, set())
    assert [r.outcome for r in none_checked] == ["no_action", "no_action"]

    one_checked = review.resolve_review_selections(manifest, {"a1"})
    assert one_checked[0].outcome == "selected"
    assert one_checked[0].selected_action["action_id"] == "a1"

    conflict = review.resolve_review_selections(manifest, {"a2", "a3"})
    assert conflict[1].outcome == "conflict"
    assert conflict[1].selected_action is None


def test_unknown_checked_action_ids_are_reported():
    manifest = {
        "groups": [
            {
                "group_id": "g1",
                "source": "discovery",
                "actions": [{"action_id": "a1", "kind": "x", "payload": {}}],
            }
        ]
    }
    assert review.unknown_checked_action_ids(manifest, {"a1", "not-real"}) == [
        "not-real"
    ]


# --- Building decision groups -------------------------------------------------


def test_discovery_create_group_has_single_approval_checkbox():
    document = _discovery_document([_discovery_record()])
    groups = review.build_discovery_groups(document)

    assert len(groups) == 1
    assert len(groups[0].candidates) == 1
    assert groups[0].candidates[0].kind == review.DISCOVERY_KIND_CREATE
    assert groups[0].candidates[0].payload["title"] == "update: widget"


def test_discovery_update_group_uses_field_additions_not_a_body_snapshot():
    record = _discovery_record(
        decision={
            "action": "update_existing_issue",
            "confidence": "medium",
            "reason": "existing match",
        },
        existing_issue_matches=[
            {
                "issue": 2109,
                "issue_url": "u",
                "title": "update: widget",
                "state": "open",
                "labels": ["advisory", "security"],
                "package": "widget",
                "cves": ["CVE-2026-0001"],
                "parsed_issue": {},
                "match_reasons": ["package_name"],
            }
        ],
        proposed_update={
            "issue": 2109,
            "issue_url": "u",
            "title": "update: widget",
            "update_reason": "r",
            "detected_changes": [],
            "recommended_additions": [],
            "body_update_mode": None,
            "updated_body": None,
            "updated_body_diff": None,
            "comment_body": "Upstream changed.",
            "matched_existing_issue": {"body": "old body"},
        },
        proposed_issue=None,
    )
    document = _discovery_document([record])
    groups = review.build_discovery_groups(document)

    payload = groups[0].candidates[0].payload
    assert payload["issue"] == 2109
    assert "body" not in payload
    assert payload["field_additions"]["cves"] == ["CVE-2026-9001"]
    assert payload["comment_body"] == "Upstream changed."
    assert payload["expected_package"] == "widget"


def test_discovery_ignore_and_kernel_groups_are_single_checkbox_no_payload():
    ignore_document = _discovery_document(
        [
            _discovery_record(
                decision={
                    "action": "ignore",
                    "confidence": "medium",
                    "reason": "not relevant",
                },
                proposed_issue=None,
            )
        ]
    )
    kernel_document = _discovery_document(
        [
            _discovery_record(
                decision={
                    "action": "kernel_regular_update_flow",
                    "confidence": "high",
                    "reason": "kernel",
                },
                proposed_issue=None,
            )
        ]
    )

    ignore_groups = review.build_discovery_groups(ignore_document)
    kernel_groups = review.build_discovery_groups(kernel_document)

    assert ignore_groups[0].candidates[0].kind == review.DISCOVERY_KIND_IGNORE
    assert ignore_groups[0].candidates[0].payload == {}
    assert kernel_groups[0].candidates[0].kind == review.DISCOVERY_KIND_KERNEL
    assert kernel_groups[0].candidates[0].payload == {}


def test_discovery_manual_review_offers_create_and_update_when_derivable():
    record = _discovery_record(
        decision={
            "action": "needs_manual_review",
            "confidence": "low",
            "reason": "ambiguous",
        },
        existing_issue_matches=[
            {
                "issue": 2109,
                "issue_url": "u",
                "title": "t",
                "state": "open",
                "labels": [],
                "package": "widget",
                "cves": [],
                "parsed_issue": {},
                "match_reasons": ["package_name"],
            }
        ],
        proposed_issue=None,
        proposed_update=None,
    )
    groups = review.build_discovery_groups(_discovery_document([record]))

    kinds = [candidate.kind for candidate in groups[0].candidates]
    assert kinds == [
        review.DISCOVERY_KIND_CREATE,
        review.DISCOVERY_KIND_UPDATE,
        review.DISCOVERY_KIND_IGNORE,
        review.DISCOVERY_KIND_MANUAL,
    ]
    assert len({candidate.action_id for candidate in groups[0].candidates}) == 4
    assert len({candidate.group_id for candidate in groups[0].candidates}) == 1


def test_discovery_manual_review_falls_back_to_ignore_when_nothing_derivable():
    record = _discovery_record(
        decision={
            "action": "needs_manual_review",
            "confidence": "low",
            "reason": "ambiguous",
        },
        llm_extraction={
            "package_name": "",
            "cves": [],
            "cvss_scores": [],
            "affected_versions": [],
            "fixed_versions": [],
            "action_needed": "TBD",
            "summary": "TBD",
            "gentoo_ref": "TBD",
            "scope_assessment": "unknown",
            "confidence": "low",
        },
        existing_issue_matches=[],
        proposed_issue=None,
        proposed_update=None,
    )
    groups = review.build_discovery_groups(_discovery_document([record]))

    kinds = [candidate.kind for candidate in groups[0].candidates]
    assert kinds == [review.DISCOVERY_KIND_IGNORE, review.DISCOVERY_KIND_MANUAL]


def test_cleanup_normal_groups_map_recommended_action_to_kind():
    comment_only = review.build_cleanup_groups(
        _cleanup_document([_cleanup_record(recommended_action="comment_only")])
    )
    comment_and_close = review.build_cleanup_groups(
        _cleanup_document([_cleanup_record(recommended_action="close_issue")])
    )
    keep_open = review.build_cleanup_groups(
        _cleanup_document(
            [
                _cleanup_record(
                    recommended_action="keep_open",
                    status="not_remediated_in_current_production_sbom",
                    comment_body="",
                )
            ]
        )
    )

    assert comment_only[0].candidates[0].kind == review.CLEANUP_KIND_COMMENT_ONLY
    assert (
        comment_and_close[0].candidates[0].kind == review.CLEANUP_KIND_COMMENT_AND_CLOSE
    )
    assert keep_open[0].candidates[0].kind == review.CLEANUP_KIND_KEEP_OPEN
    assert keep_open[0].candidates[0].payload == {}


def test_cleanup_manual_review_offers_comment_alternatives_when_derivable():
    record = _cleanup_record(
        recommended_action="manual_review",
        status="needs_manual_review",
        comment_body="",
    )
    groups = review.build_cleanup_groups(_cleanup_document([record]))

    kinds = [candidate.kind for candidate in groups[0].candidates]
    assert kinds == [
        review.CLEANUP_KIND_COMMENT_ONLY,
        review.CLEANUP_KIND_COMMENT_AND_CLOSE,
        review.CLEANUP_KIND_KEEP_OPEN,
        review.CLEANUP_KIND_MANUAL,
    ]


def test_cleanup_manual_review_offers_only_keep_open_and_manual_when_no_sbom_match():
    record = _cleanup_record(
        recommended_action="manual_review",
        status="needs_manual_review",
        comment_body="",
        sbom_package_matches=[],
        fixed_version_requirement=None,
    )
    groups = review.build_cleanup_groups(_cleanup_document([record]))

    kinds = [candidate.kind for candidate in groups[0].candidates]
    assert kinds == [review.CLEANUP_KIND_KEEP_OPEN, review.CLEANUP_KIND_MANUAL]


def test_build_review_batch_covers_fixture_backed_discovery_and_cleanup():
    entries = load_source_fixture(str(FIXTURES / "discovery_entries.json"))
    issues = load_issue_fixture(str(FIXTURES / "github_issues.json"))
    sbom = load_sbom_fixture(str(FIXTURES / "sbom.json"))
    discovery_document = DiscoveryWorkflow(
        HeuristicModelClient(), sbom, issues, target_repo=REPO
    ).run(entries, "2026-04-29T00:00:00Z", "2026-04-30T00:00:00Z")
    cleanup_document = CleanupWorkflow(
        HeuristicModelClient(), sbom, issues, target_repo=REPO
    ).run()

    batch = review.build_review_batch(_context(), discovery_document, cleanup_document)

    assert len(batch.parts) == 1
    assert len(batch.groups) == len(discovery_document["records"]) + len(
        cleanup_document["records"]
    )
    assert batch.parts[0].title == "Security triage review: 2026-07-10 (part 1/1)"
    assert (
        review.REVIEW_LABEL not in batch.parts[0].body
    )  # label is metadata for creation, not inline body text
    # The pipeline's own configured target repository must be the battle-test
    # repo. Fixture data legitimately references pre-existing flatcar/Flatcar
    # issue URLs (representing today's real advisory issues used for
    # duplicate matching), so this checks the *configured* repository fields
    # rather than a blanket substring search over the whole rendered body.
    assert f"Analyzed (advisory) repository: `{REPO}`" in batch.parts[0].body
    assert f"Review repository: `{REPO}`" in batch.parts[0].body
    assert batch.parts[0].manifest["advisory_repo"] == REPO
    assert batch.parts[0].manifest["review_repo"] == REPO


# --- Splitting -----------------------------------------------------------------


def test_build_review_batch_splits_at_group_boundaries_when_forced_small():
    records = [
        _discovery_record(
            record_id=f"gentoo:{i}",
            llm_extraction={
                **_discovery_record()["llm_extraction"],
                "package_name": f"pkg-{i}",
            },
        )
        for i in range(6)
    ]
    context = _context(max_part_body_chars=6500)

    batch = review.build_review_batch(context, _discovery_document(records), None)

    assert len(batch.parts) > 1
    total_groups = sum(len(part.group_ids) for part in batch.parts)
    assert total_groups == len(batch.groups) == 6
    # Every part must be self-contained and independently valid.
    for part in batch.parts:
        manifest = review.extract_manifest(part.body)
        review.validate_manifest_against_context(manifest, REPO, REPO)
        assert part.part_count == len(batch.parts)
        assert f"(part {part.part_index}/{part.part_count})" in part.title


def test_split_parts_never_divide_a_single_group():
    records = [_discovery_record(record_id=f"gentoo:{i}") for i in range(3)]
    batch = review.build_review_batch(
        _context(max_part_body_chars=6500), _discovery_document(records), None
    )

    seen_group_ids: set[str] = set()
    for part in batch.parts:
        for group_id in part.group_ids:
            assert group_id not in seen_group_ids, (
                "a group ID must not appear in more than one part"
            )
            seen_group_ids.add(group_id)


# --- Dry-run rendering ---------------------------------------------------------


def test_dry_run_document_round_trips_the_exact_body(tmp_path):
    document = _discovery_document([_discovery_record()])
    batch, paths = review.render_dry_run(_context(), tmp_path, document, None)

    assert len(paths) == 2  # one part + summary
    part_path = next(path for path in paths if path.name != "dry-run-summary.md")
    text = part_path.read_text(encoding="utf-8")
    metadata, body = review.parse_dry_run_document(text)

    assert body == batch.parts[0].body
    assert metadata["title"] == batch.parts[0].title
    assert metadata["would_create_in_repo"] == REPO
    assert metadata["batch_id"] == batch.batch_id


def test_write_dry_run_batch_never_touches_github_issue_client(tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError(
            "dry run must not construct a GitHubIssueClient or perform network I/O"
        )

    monkeypatch.setattr("security_triage.issues.GitHubIssueClient.__init__", boom)
    document = _discovery_document([_discovery_record()])

    batch, paths = review.render_dry_run(_context(), tmp_path, document, None)

    assert paths
    assert all(path.exists() for path in paths)


def test_dry_run_multi_part_writes_one_file_per_part_plus_summary(tmp_path):
    records = [_discovery_record(record_id=f"gentoo:{i}") for i in range(6)]
    batch, paths = review.render_dry_run(
        _context(max_part_body_chars=6500), tmp_path, _discovery_document(records), None
    )

    assert len(batch.parts) > 1
    assert len(paths) == len(batch.parts) + 1
    summary_text = (tmp_path / "dry-run-summary.md").read_text(encoding="utf-8")
    assert f"Parts: {len(batch.parts)}" in summary_text


def test_render_dry_run_with_no_documents_produces_an_empty_informational_part(
    tmp_path,
):
    batch, paths = review.render_dry_run(_context(), tmp_path, None, None)

    assert len(batch.parts) == 1
    assert batch.groups == []
    assert paths


# --- Idempotent creation -------------------------------------------------------


def test_create_review_batch_is_idempotent_for_the_same_run_but_not_across_runs():
    client = FakeGitHubIssueClient()
    document = _discovery_document([_discovery_record()])

    batch_run1 = review.build_review_batch(_context("run-1"), document, None)
    first = review.create_review_batch(client, batch_run1)
    assert first[0].created is True

    rerun = review.create_review_batch(client, batch_run1)
    assert rerun[0].created is False
    assert rerun[0].issue_number == first[0].issue_number
    assert len(client._issues) == 1

    batch_run2 = review.build_review_batch(_context("run-2"), document, None)
    second_run = review.create_review_batch(client, batch_run2)
    assert second_run[0].created is True
    assert second_run[0].issue_number != first[0].issue_number
    assert len(client._issues) == 2


def test_render_create_job_summary_handles_empty_and_nonempty():
    assert "No decision groups" in review.render_create_job_summary([])
    result = review.PartCreationResult("p", 1, 1, 5, "https://x/issues/5", created=True)
    summary = review.render_create_job_summary([result])
    assert "issues/5" in summary


# --- Apply gating order and safety ---------------------------------------------


def _apply_ctx() -> review.ApplyContext:
    return review.ApplyContext(advisory_repo=REPO, review_repo=REPO)


def _default_flags() -> ActionFlags:
    return ActionFlags(
        create_issues=True,
        update_existing_issues=True,
        post_cleanup_comments=True,
        close_issues=True,
    )


def test_apply_skips_issues_without_the_review_label():
    client = FakeGitHubIssueClient()
    client.seed_issue(
        1, "unrelated issue", "body", [], state="closed", state_reason="completed"
    )
    runner = GitHubActionRunner(client, _default_flags())

    result = review.apply_review_issue(client, client, runner, 1, _apply_ctx())

    assert result["outcome"] == "skipped"
    assert "does not carry" in result["reason"]


def test_apply_skips_review_issues_without_a_manifest_marker():
    client = FakeGitHubIssueClient()
    client.seed_issue(
        1,
        "t",
        "no marker here",
        [review.REVIEW_LABEL],
        state="closed",
        state_reason="completed",
    )
    runner = GitHubActionRunner(client, _default_flags())

    result = review.apply_review_issue(client, client, runner, 1, _apply_ctx())

    assert result["outcome"] == "skipped"
    assert "batch/part marker" in result["reason"]


@pytest.mark.parametrize(
    "state,state_reason",
    [
        ("open", None),
        ("closed", "not_planned"),
        ("closed", None),
        ("closed", "reopened"),
    ],
)
def test_apply_makes_zero_mutations_for_every_close_reason_except_completed(
    state, state_reason
):
    client = FakeGitHubIssueClient()
    document = _discovery_document([_discovery_record()])
    batch = review.build_review_batch(_context(), document, None)
    part = batch.parts[0]
    results = review.create_review_batch(client, batch)
    issue_number = results[0].issue_number
    action_id = part.manifest["groups"][0]["actions"][0]["action_id"]
    client.set_body(
        issue_number, _check_action(client._issues[issue_number]["body"], action_id)
    )
    client._issues[issue_number]["state"] = state
    client._issues[issue_number]["state_reason"] = state_reason

    runner = GitHubActionRunner(client, _default_flags())
    result = review.apply_review_issue(
        client, client, runner, issue_number, _apply_ctx()
    )

    assert result["outcome"] == "skipped"
    assert len(client._issues) == 1, (
        "no advisory mutation may happen for a non-completed close reason"
    )


def test_apply_completed_applies_only_checked_conflict_free_actions_end_to_end():
    review_client = FakeGitHubIssueClient()
    advisory_client = FakeGitHubIssueClient()
    issues = load_issue_fixture(str(FIXTURES / "github_issues.json"))
    for issue in issues:
        advisory_client.seed_issue(
            issue.number, issue.title, issue.body, issue.labels, state="open"
        )
    sbom = load_sbom_fixture(str(FIXTURES / "sbom.json"))
    entries = load_source_fixture(str(FIXTURES / "discovery_entries.json"))
    discovery_document = DiscoveryWorkflow(
        HeuristicModelClient(), sbom, issues, target_repo=REPO
    ).run(entries, "2026-04-29T00:00:00Z", "2026-04-30T00:00:00Z")
    cleanup_document = CleanupWorkflow(
        HeuristicModelClient(), sbom, issues, target_repo=REPO
    ).run()

    batch = review.build_review_batch(_context(), discovery_document, cleanup_document)
    part = batch.parts[0]
    results = review.create_review_batch(review_client, batch)
    issue_number = results[0].issue_number

    by_kind = _action_ids_by_kind(part.manifest)
    create_action = next(
        a
        for a in by_kind[review.DISCOVERY_KIND_CREATE]
        if a["payload"].get("package_name") == "openssl"
    )
    update_action = next(
        a
        for a in by_kind[review.DISCOVERY_KIND_UPDATE]
        if a["payload"].get("issue") == 2109
    )
    close_action = next(
        a
        for a in by_kind.get(review.CLEANUP_KIND_COMMENT_AND_CLOSE, [])
        if a["payload"].get("issue") == 2083
    )

    body = review_client._issues[issue_number]["body"]
    for action in (create_action, update_action, close_action):
        body = _check_action(body, action["action_id"])
    review_client.set_body(issue_number, body)
    review_client.close_as(issue_number, "completed")

    runner = GitHubActionRunner(advisory_client, _default_flags())
    result = review.apply_review_issue(
        review_client, advisory_client, runner, issue_number, _apply_ctx()
    )

    assert result["outcome"] == "applied"
    outcomes = {
        g["action_id"]: g["outcome"] for g in result["groups"] if g["action_id"]
    }
    assert outcomes[create_action["action_id"]] == "applied"
    assert outcomes[update_action["action_id"]] == "applied"
    assert outcomes[close_action["action_id"]] == "applied"

    created_numbers = [
        number
        for number in advisory_client._issues
        if number not in {issue.number for issue in issues}
    ]
    assert len(created_numbers) == 1
    assert advisory_client._issues[created_numbers[0]]["title"] == "update: openssl"

    updated_body = advisory_client._issues[2109]["body"]
    assert "CVE-2026-10001" in updated_body  # preserved
    assert "CVE-2026-30002" in updated_body  # additively appended

    assert advisory_client._issues[2083]["state"] == "closed"
    assert len(advisory_client._comments[2083]) == 1

    review_issue_labels = {
        entry["name"] for entry in review_client._issues[issue_number]["labels"]
    }
    assert review.REVIEW_APPLIED_LABEL in review_issue_labels

    # Re-running apply on an already-applied issue must be a no-op.
    rerun = review.apply_review_issue(
        review_client, advisory_client, runner, issue_number, _apply_ctx()
    )
    assert rerun["outcome"] == "no_op"
    assert len(advisory_client._issues) == len(issues) + 1
    assert len(advisory_client._comments[2083]) == 1
    assert len(review_client._comments[issue_number]) == 1

    # Reopening and re-closing as completed must not replay the batch.
    review_client.reopen(issue_number)
    review_client.close_as(issue_number, "completed")
    replay = review.apply_review_issue(
        review_client, advisory_client, runner, issue_number, _apply_ctx()
    )
    assert replay["outcome"] == "no_op"
    assert len(advisory_client._issues) == len(issues) + 1


def test_apply_conflicting_alternatives_skip_only_that_group():
    client = FakeGitHubIssueClient()
    record = _discovery_record(
        decision={
            "action": "needs_manual_review",
            "confidence": "low",
            "reason": "ambiguous",
        },
        existing_issue_matches=[
            {
                "issue": 500,
                "issue_url": "u",
                "title": "t",
                "state": "open",
                "labels": [],
                "package": "widget",
                "cves": [],
                "parsed_issue": {},
                "match_reasons": ["package_name"],
            }
        ],
        proposed_issue=None,
        proposed_update=None,
    )
    client.seed_issue(
        500,
        "update: widget",
        (
            "Name: widget\n"
            "CVEs: CVE-2026-9001\n"
            "CVSSs: n/a\n"
            "Action Needed: TBD\n"
            "Summary: s\n\n"
            "refmap.gentoo: TBD"
        ),
        ["advisory", "security"],
    )
    batch = review.build_review_batch(_context(), _discovery_document([record]), None)
    part = batch.parts[0]
    results = review.create_review_batch(client, batch)
    issue_number = results[0].issue_number

    action_ids = [
        action["action_id"] for action in part.manifest["groups"][0]["actions"]
    ]
    body = client._issues[issue_number]["body"]
    body = _check_action(body, action_ids[0])
    body = _check_action(body, action_ids[1])
    client.set_body(issue_number, body)
    client.close_as(issue_number, "completed")

    runner = GitHubActionRunner(client, _default_flags())
    result = review.apply_review_issue(
        client, client, runner, issue_number, _apply_ctx()
    )

    assert (
        result["outcome"] == "applied"
    )  # the run itself completes; the group is what fails closed
    assert result["groups"][0]["outcome"] == "conflict"
    assert client._issues[500]["body"] == (
        "Name: widget\n"
        "CVEs: CVE-2026-9001\n"
        "CVSSs: n/a\n"
        "Action Needed: TBD\n"
        "Summary: s\n\n"
        "refmap.gentoo: TBD"
    )


def test_apply_fresh_duplicate_check_blocks_stale_create():
    review_client = FakeGitHubIssueClient()
    advisory_client = FakeGitHubIssueClient()
    document = _discovery_document([_discovery_record()])
    batch = review.build_review_batch(_context(), document, None)
    part = batch.parts[0]
    results = review.create_review_batch(review_client, batch)
    issue_number = results[0].issue_number
    action_id = part.manifest["groups"][0]["actions"][0]["action_id"]
    review_client.set_body(
        issue_number,
        _check_action(review_client._issues[issue_number]["body"], action_id),
    )
    review_client.close_as(issue_number, "completed")

    # Someone else already created a matching advisory issue before apply ran.
    advisory_client.seed_issue(
        900,
        "update: widget",
        (
            "Name: widget\n"
            "CVEs: CVE-2026-9001\n"
            "CVSSs: 7.5\n"
            "Action Needed: update to >= 1.2\n"
            "Summary: s\n\n"
            "refmap.gentoo: TBD"
        ),
        ["advisory", "security"],
    )

    runner = GitHubActionRunner(advisory_client, _default_flags())
    result = review.apply_review_issue(
        review_client, advisory_client, runner, issue_number, _apply_ctx()
    )

    assert result["groups"][0]["outcome"] == "skipped"
    assert len(advisory_client._issues) == 1, (
        "must not create a duplicate advisory issue"
    )


def test_apply_skips_update_when_target_issue_is_no_longer_open():
    review_client = FakeGitHubIssueClient()
    advisory_client = FakeGitHubIssueClient()
    advisory_client.seed_issue(
        2109,
        "update: rust-openssl",
        (
            "Name: rust-openssl\n"
            "CVEs: CVE-2026-10001\n"
            "CVSSs: 8.1\n"
            "Action Needed: update to >= 0.10.78\n"
            "Summary: s\n\n"
            "refmap.gentoo: https://bugs.gentoo.org/10001"
        ),
        ["advisory", "security"],
        state="closed",
    )
    record = _discovery_record(
        llm_extraction={
            **_discovery_record()["llm_extraction"],
            "package_name": "rust-openssl",
        },
        decision={
            "action": "update_existing_issue",
            "confidence": "medium",
            "reason": "existing match",
        },
        existing_issue_matches=[
            {
                "issue": 2109,
                "issue_url": "u",
                "title": "update: rust-openssl",
                "state": "open",
                "labels": ["advisory", "security"],
                "package": "rust-openssl",
                "cves": ["CVE-2026-10001"],
                "parsed_issue": {},
                "match_reasons": ["package_name"],
            }
        ],
        proposed_issue=None,
        proposed_update={
            "issue": 2109,
            "issue_url": "u",
            "title": "update: rust-openssl",
            "update_reason": "r",
            "detected_changes": [],
            "recommended_additions": [],
            "body_update_mode": None,
            "updated_body": None,
            "updated_body_diff": None,
            "comment_body": None,
            "matched_existing_issue": {"body": "old"},
        },
    )
    batch = review.build_review_batch(_context(), _discovery_document([record]), None)
    part = batch.parts[0]
    results = review.create_review_batch(review_client, batch)
    issue_number = results[0].issue_number
    action_id = part.manifest["groups"][0]["actions"][0]["action_id"]
    review_client.set_body(
        issue_number,
        _check_action(review_client._issues[issue_number]["body"], action_id),
    )
    review_client.close_as(issue_number, "completed")

    runner = GitHubActionRunner(advisory_client, _default_flags())
    result = review.apply_review_issue(
        review_client, advisory_client, runner, issue_number, _apply_ctx()
    )

    assert result["groups"][0]["outcome"] == "skipped"
    assert "no longer open" in result["groups"][0]["reason"]


def test_apply_skips_when_target_identity_no_longer_matches():
    review_client = FakeGitHubIssueClient()
    advisory_client = FakeGitHubIssueClient()
    # The live issue now describes a completely different package/CVE
    # than the review was generated for.
    advisory_client.seed_issue(
        2109,
        "update: something-else",
        (
            "Name: something-else\n"
            "CVEs: CVE-2020-00000\n"
            "CVSSs: n/a\n"
            "Action Needed: TBD\n"
            "Summary: s\n\n"
            "refmap.gentoo: TBD"
        ),
        ["advisory", "security"],
    )
    record = _discovery_record(
        decision={
            "action": "update_existing_issue",
            "confidence": "medium",
            "reason": "existing match",
        },
        existing_issue_matches=[
            {
                "issue": 2109,
                "issue_url": "u",
                "title": "t",
                "state": "open",
                "labels": [],
                "package": "widget",
                "cves": ["CVE-2026-9001"],
                "parsed_issue": {},
                "match_reasons": ["package_name"],
            }
        ],
        proposed_issue=None,
        proposed_update={
            "issue": 2109,
            "issue_url": "u",
            "title": "t",
            "update_reason": "r",
            "detected_changes": [],
            "recommended_additions": [],
            "body_update_mode": None,
            "updated_body": None,
            "updated_body_diff": None,
            "comment_body": None,
            "matched_existing_issue": {"body": "old"},
        },
    )
    batch = review.build_review_batch(_context(), _discovery_document([record]), None)
    part = batch.parts[0]
    results = review.create_review_batch(review_client, batch)
    issue_number = results[0].issue_number
    action_id = part.manifest["groups"][0]["actions"][0]["action_id"]
    review_client.set_body(
        issue_number,
        _check_action(review_client._issues[issue_number]["body"], action_id),
    )
    review_client.close_as(issue_number, "completed")

    runner = GitHubActionRunner(advisory_client, _default_flags())
    result = review.apply_review_issue(
        review_client, advisory_client, runner, issue_number, _apply_ctx()
    )

    assert result["groups"][0]["outcome"] == "skipped"
    assert "identity changed" in result["groups"][0]["reason"]
    assert advisory_client._issues[2109]["body"] == (
        "Name: something-else\n"
        "CVEs: CVE-2020-00000\n"
        "CVSSs: n/a\n"
        "Action Needed: TBD\n"
        "Summary: s\n\n"
        "refmap.gentoo: TBD"
    )


def test_apply_rejects_tampered_manifest_with_zero_mutations():
    client = FakeGitHubIssueClient()
    advisory_client = FakeGitHubIssueClient()
    document = _discovery_document([_discovery_record()])
    batch = review.build_review_batch(_context(), document, None)
    results = review.create_review_batch(client, batch)
    issue_number = results[0].issue_number

    tampered = client._issues[issue_number]["body"].replace(
        "security-triage:review-manifest:v1\n",
        "security-triage:review-manifest:v1\nTAMPERED",
        1,
    )
    client.set_body(issue_number, tampered)
    client.close_as(issue_number, "completed")

    runner = GitHubActionRunner(advisory_client, _default_flags())
    result = review.apply_review_issue(
        client, advisory_client, runner, issue_number, _apply_ctx()
    )

    assert result["outcome"] == "failed"
    assert len(advisory_client._issues) == 0


def test_apply_rejects_repository_mismatch_with_zero_mutations():
    client = FakeGitHubIssueClient(repo=REPO)
    advisory_client = FakeGitHubIssueClient(repo=REPO)
    document = _discovery_document([_discovery_record()])
    batch = review.build_review_batch(_context(), document, None)
    results = review.create_review_batch(client, batch)
    issue_number = results[0].issue_number
    client.close_as(issue_number, "completed")

    runner = GitHubActionRunner(advisory_client, _default_flags())
    wrong_ctx = review.ApplyContext(advisory_repo="someone/else", review_repo=REPO)
    result = review.apply_review_issue(
        client, advisory_client, runner, issue_number, wrong_ctx
    )

    assert result["outcome"] == "failed"
    assert len(advisory_client._issues) == 0


def test_apply_ignores_unknown_checked_ids_but_still_applies_known_ones():
    client = FakeGitHubIssueClient()
    document = _discovery_document([_discovery_record()])
    batch = review.build_review_batch(_context(), document, None)
    part = batch.parts[0]
    results = review.create_review_batch(client, batch)
    issue_number = results[0].issue_number
    action_id = part.manifest["groups"][0]["actions"][0]["action_id"]
    body = client._issues[issue_number]["body"]
    body = _check_action(body, action_id)
    body += (
        "\n- [x] some unrelated maintainer checklist item "
        "<!-- security-triage:action-id:not-a-real-id -->\n"
    )
    client.set_body(issue_number, body)
    client.close_as(issue_number, "completed")

    runner = GitHubActionRunner(client, _default_flags())
    result = review.apply_review_issue(
        client, client, runner, issue_number, _apply_ctx()
    )

    assert result["outcome"] == "applied"
    assert result["unknown_checked_action_ids"] == ["not-a-real-id"]
    assert result["groups"][0]["outcome"] == "applied"


def test_apply_without_mutation_flags_blocks_the_mutation_but_still_reports_it():
    client = FakeGitHubIssueClient()
    document = _discovery_document([_discovery_record()])
    batch = review.build_review_batch(_context(), document, None)
    part = batch.parts[0]
    results = review.create_review_batch(client, batch)
    issue_number = results[0].issue_number
    action_id = part.manifest["groups"][0]["actions"][0]["action_id"]
    client.set_body(
        issue_number, _check_action(client._issues[issue_number]["body"], action_id)
    )
    client.close_as(issue_number, "completed")

    runner = GitHubActionRunner(client, ActionFlags())  # all mutation flags disabled
    result = review.apply_review_issue(
        client, client, runner, issue_number, _apply_ctx()
    )

    # No group ever reaches "failed" here (a disabled flag is a deliberate
    # skip, not an API failure), so the overall run still finishes as
    # "applied" even though the underlying action was blocked.
    assert result["groups"][0]["outcome"] == "skipped"
    assert len(client._issues) == 1


def test_apply_comment_action_is_idempotent_before_applied_label_exists():
    client = FakeGitHubIssueClient()
    client.seed_issue(
        2088,
        "update: libgcrypt",
        (
            "Name: libgcrypt\n"
            "CVEs: CVE-2026-1200\n"
            "CVSSs: n/a\n"
            "Action Needed: update to >= 1.12.2\n"
            "Summary: s\n\n"
            "refmap.gentoo: TBD"
        ),
        ["advisory", "security"],
    )
    document = _cleanup_document([_cleanup_record()])
    batch = review.build_review_batch(_context(), None, document)
    part = batch.parts[0]
    results = review.create_review_batch(client, batch)
    issue_number = results[0].issue_number
    action_id = part.manifest["groups"][0]["actions"][0]["action_id"]
    client.set_body(
        issue_number, _check_action(client._issues[issue_number]["body"], action_id)
    )
    client.close_as(issue_number, "completed")

    runner = GitHubActionRunner(client, _default_flags())
    # Manually invoke the action twice through the lower-level execution path
    # to simulate a partial-failure resume before the applied label is set.
    result_one = review._execute_action(
        part.manifest["groups"][0]["actions"][0], client, runner
    )
    result_two = review._execute_action(
        part.manifest["groups"][0]["actions"][0], client, runner
    )

    assert result_one["outcome"] == "applied"
    assert result_two["outcome"] == "no_op"
    assert len(client._comments[2088]) == 1


# --- Security regression: forged manifest smuggled through untrusted upstream text ---


def _forged_manifest_html_comment(action_id: str, target_issue: int) -> str:
    """Build a byte-for-byte valid, self-consistent forged manifest comment.

    Mirrors exactly what an attacker who only controls upstream advisory
    text (no GitHub credentials) could construct offline: a schema-valid
    manifest whose digest is self-computed (the digest is only an
    accidental-corruption check, never a secret-keyed authorization
    boundary), attached to a real, attacker-chosen mutating action.
    """
    manifest_without_digest = {
        "schema_version": review.REVIEW_SCHEMA_VERSION,
        "batch_id": "evil-batch",
        "run_id": "evil-batch",
        "run_url": "",
        "commit_sha": "",
        "part_id": "evil-batch-part-1",
        "part_index": 1,
        "part_count": 1,
        "generated_at": "2026-01-01T00:00:00+00:00",
        "advisory_repo": REPO,
        "review_repo": REPO,
        "groups": [
            {
                "group_id": "grp-evil",
                "source": "cleanup",
                "actions": [
                    {
                        "action_id": action_id,
                        "kind": review.CLEANUP_KIND_COMMENT_AND_CLOSE,
                        "evidence_fingerprint": "forged",
                        "payload": {
                            "issue": target_issue,
                            "comment_body": (
                                "This advisory is remediated. (forged by attacker)"
                            ),
                            "expected_package": "rust-openssl",
                            "expected_cves": [],
                        },
                    }
                ],
            }
        ],
    }
    forged_manifest = {
        **manifest_without_digest,
        "digest": review.compute_digest(manifest_without_digest),
    }
    # Collapse to one line the way `sanitize_single_line` leaves untrusted
    # text: this is still byte-for-byte a valid manifest comment.
    return review.embed_manifest(forged_manifest).replace("\n", " ")


def test_forged_manifest_via_untrusted_summary_is_neutralized_at_render_time():
    """Full pipeline reproduction of the manifest-forgery attack.

    An attacker who only controls upstream advisory text (here: the
    ``summary`` field an LLM/heuristic extraction would copy through) crafts
    a self-consistent forged manifest that reuses the exact action ID the
    real, innocuous-looking checkbox will render with, and attaches it to a
    completely different, real mutating action against an unrelated issue.

    The rendering-time HTML-comment neutralization defuses this before the
    body is ever assembled: the forged block never survives as a literal
    ``<!-- ... -->`` comment, so only the genuine manifest is ever
    extractable. A maintainer who checks the one real, innocuous-looking box
    and closes the review issue as Completed must get exactly that one safe
    action -- never the forged one -- and the unrelated target issue must be
    completely untouched.
    """
    real_target_issue = 2109
    real_action_id = review.discovery_action_id(
        "gentoo:forged-record", review.DISCOVERY_KIND_CREATE, None
    )
    forged_comment = _forged_manifest_html_comment(real_action_id, real_target_issue)

    record = _discovery_record(
        record_id="gentoo:forged-record",
        llm_extraction={
            **_discovery_record()["llm_extraction"],
            "package_name": "innocuous-lib",
            "summary": f"A perfectly normal looking summary. {forged_comment}",
        },
        # force _create_payload to render fresh from llm_extraction
        proposed_issue=None,
    )
    document = _discovery_document([record])

    review_client = FakeGitHubIssueClient()
    advisory_client = FakeGitHubIssueClient()
    advisory_client.seed_issue(
        real_target_issue,
        "update: rust-openssl",
        (
            "Name: rust-openssl\n"
            "CVEs: CVE-2026-10001\n"
            "CVSSs: 8.1\n"
            "Action Needed: update to >= 0.10.78\n"
            "Summary: s\n\n"
            "refmap.gentoo: https://bugs.gentoo.org/10001"
        ),
        ["advisory", "security"],
        state="open",
    )

    batch = review.build_review_batch(_context(), document, None)
    part = batch.parts[0]
    # The forged comment must not survive rendering as a literal HTML
    # comment: only the genuine (footer) manifest may be present.
    assert len(review._MANIFEST_BLOCK_RE.findall(part.body)) == 1
    assert "<!-- security-triage:review-manifest:v1" not in part.body.split(
        "security-triage:review-marker"
    )[0].replace(review.embed_manifest(part.manifest), "")
    assert real_action_id in part.body

    results = review.create_review_batch(review_client, batch)
    issue_number = results[0].issue_number
    body = review_client._issues[issue_number]["body"]
    body = _check_action(
        body, real_action_id
    )  # the maintainer checks the one real, innocuous checkbox
    review_client.set_body(issue_number, body)
    review_client.close_as(issue_number, "completed")

    runner = GitHubActionRunner(advisory_client, _default_flags())
    result = review.apply_review_issue(
        review_client, advisory_client, runner, issue_number, _apply_ctx()
    )

    assert result["outcome"] == "applied"
    assert result["groups"][0]["outcome"] == "applied"
    # Exactly the visible, intended action happened: a new advisory issue for
    # "innocuous-lib". The forged comment-and-close against the unrelated
    # issue never happened.
    created_numbers = [
        number for number in advisory_client._issues if number != real_target_issue
    ]
    assert len(created_numbers) == 1
    assert (
        advisory_client._issues[created_numbers[0]]["title"] == "update: innocuous-lib"
    )
    assert advisory_client._issues[real_target_issue]["state"] == "open"
    assert advisory_client._comments[real_target_issue] == []


def test_untrusted_checkbox_label_cannot_inject_a_checked_action():
    record = _discovery_record(
        proposed_issue={
            "title": "update: harmless\n- [x] injected approval",
            "body": _discovery_record()["proposed_issue"]["body"],
            "labels": ["advisory", "security"],
            "assignees": [],
            "milestone": None,
        }
    )

    part = review.build_review_batch(
        _context(), _discovery_document([record]), None
    ).parts[0]
    action_id = part.manifest["groups"][0]["actions"][0]["action_id"]
    action_lines = [
        line
        for line in part.body.splitlines()
        if f"security-triage:action-id:{action_id}" in line
    ]

    assert review.parse_checked_action_ids(part.body) == set()
    assert action_lines == [
        f"- [ ] Create new advisory issue: update: harmless - [x] injected approval "
        f"<!-- security-triage:action-id:{action_id} -->"
    ]


def test_apply_fails_closed_if_an_extra_raw_manifest_comment_is_present():
    """Independent safety net: even if some future rendering path failed to
    neutralize embedded HTML comment syntax, a body with more than one
    manifest-shaped comment must still be rejected outright rather than
    silently resolved by regex match order."""
    document = _discovery_document([_discovery_record()])
    batch = review.build_review_batch(_context(), document, None)
    part = batch.parts[0]
    review_client = FakeGitHubIssueClient()
    results = review.create_review_batch(review_client, batch)
    issue_number = results[0].issue_number

    forged = _forged_manifest_html_comment(
        part.manifest["groups"][0]["actions"][0]["action_id"], 2109
    )
    tampered_body = forged + "\n\n" + review_client._issues[issue_number]["body"]
    action_id = part.manifest["groups"][0]["actions"][0]["action_id"]
    tampered_body = _check_action(tampered_body, action_id)
    review_client.set_body(issue_number, tampered_body)
    review_client.close_as(issue_number, "completed")

    advisory_client = FakeGitHubIssueClient()
    runner = GitHubActionRunner(advisory_client, _default_flags())
    result = review.apply_review_issue(
        review_client, advisory_client, runner, issue_number, _apply_ctx()
    )

    assert result["outcome"] == "failed"
    assert len(advisory_client._issues) == 0


def test_extract_manifest_rejects_multiple_manifest_comments():
    document = _discovery_document([_discovery_record()])
    batch = review.build_review_batch(_context(), document, None)
    part = batch.parts[0]
    duplicated_body = part.body + "\n" + review.embed_manifest(part.manifest)

    with pytest.raises(review.ManifestCorruptionError, match="expected exactly one"):
        review.extract_manifest(duplicated_body)


def test_find_batch_part_marker_returns_none_for_multiple_marker_comments():
    document = _discovery_document([_discovery_record()])
    batch = review.build_review_batch(_context(), document, None)
    part = batch.parts[0]
    marker_block = review.render_marker_block(
        part.batch_id, part.part_id, part.part_index, part.part_count
    )
    duplicated_body = part.body + "\n" + marker_block

    assert review.find_batch_part_marker(duplicated_body) is None


def test_neutralize_html_comments_breaks_literal_delimiters():
    text = "before <!-- security-triage:review-manifest:v1 FAKE --> after"
    neutralized = review._neutralize_html_comments(text)

    assert "<!--" not in neutralized
    assert "-->" not in neutralized
    assert "security-triage:review-manifest:v1" in neutralized  # content stays readable


def test_rendered_group_preview_neutralizes_html_comment_delimiters_in_untrusted_body():
    record = _discovery_record(
        proposed_issue={
            "title": "update: widget",
            "body": (
                "Name: widget\n"
                "CVEs: CVE-2026-9001\n"
                "CVSSs: n/a\n"
                "Action Needed: TBD\n"
                "Summary: hi <!-- security-triage:review-manifest:v1 evil --> "
                "bye\n\n"
                "refmap.gentoo: TBD"
            ),
            "labels": ["advisory", "security"],
            "assignees": [],
            "milestone": None,
        }
    )
    groups = review.build_discovery_groups(_discovery_document([record]))
    rendered = review._render_candidate_preview(groups[0].candidates[0])

    assert "<!-- security-triage:review-manifest:v1 evil -->" not in rendered
    # The manifest payload itself (used for the real create_issue call) must
    # remain byte-for-byte the original content; only the rendered preview
    # copy is neutralized.
    assert groups[0].candidates[0].payload["body"] == record["proposed_issue"]["body"]


# --- Batch-size budget accounts for the embedded manifest's own size --------


def test_build_review_batch_packing_accounts_for_manifest_size():
    """The manifest re-serializes the same content as the rendered group text;
    packing must not undercount its (base64-inflated) contribution, or a
    part's real body could exceed both the configured and GitHub's hard
    issue-body size limit."""
    records = [
        _discovery_record(
            record_id=f"gentoo:{i}",
            llm_extraction={
                **_discovery_record()["llm_extraction"],
                "package_name": f"pkg-{i}",
                "summary": "S" * 1900,
                "action_needed": "update to >= 1.2.3",
            },
            proposed_issue={
                "title": f"update: pkg-{i}",
                "body": "B" * 3000,
                "labels": ["advisory", "security"],
                "assignees": [],
                "milestone": None,
            },
        )
        for i in range(8)
    ]
    batch = review.build_review_batch(
        _context(max_part_body_chars=review.DEFAULT_MAX_PART_BODY_CHARS),
        _discovery_document(records),
        None,
    )

    assert len(batch.parts) > 1, "large records must be split across more than one part"
    for part in batch.parts:
        assert len(part.body) <= review.GITHUB_ISSUE_BODY_HARD_LIMIT
        # Every part must still independently validate
        # (self-contained, single manifest).
        manifest = review.extract_manifest(part.body)
        review.validate_manifest_against_context(manifest, REPO, REPO)


def test_finalize_part_raises_when_a_single_group_exceeds_the_hard_limit():
    record = _discovery_record(
        proposed_issue={
            "title": "update: huge",
            "body": "B" * 70000,
            "labels": ["advisory", "security"],
            "assignees": [],
            "milestone": None,
        }
    )

    with pytest.raises(review.ReviewConfigError, match="exceeding GitHub's"):
        review.build_review_batch(_context(), _discovery_document([record]), None)
