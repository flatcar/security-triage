from __future__ import annotations

import base64
import json
from copy import deepcopy

import pytest
from test_review import (  # type: ignore[import-not-found]
    REPO,
    FakeGitHubIssueClient,
    _action_ids_by_kind,
    _apply_ctx,
    _check_action,
    _cleanup_document,
    _cleanup_record,
    _context,
    _default_flags,
    _discovery_document,
    _discovery_record,
)

from security_triage import review
from security_triage.actions import GitHubActionRunner
from security_triage.discovery import DiscoveryWorkflow
from security_triage.feedback import (
    FEEDBACK_KIND,
    annotate_review_feedback,
    load_review_feedback,
)
from security_triage.issue_updates import append_field_values, removal_guard_violations
from security_triage.issues import find_existing_issue_matches
from security_triage.models import HeuristicModelClient
from security_triage.records import SBOMPackage, SourceEntry
from security_triage.sbom import SBOMIndex


def _approve(client, batch, kinds=None):
    created = review.create_review_batch(client, batch)
    for part, result in zip(batch.parts, created, strict=True):
        body = part.body
        for group in part.manifest["groups"]:
            for action in group["actions"]:
                if kinds is None or action["kind"] in kinds:
                    body = _check_action(body, action["action_id"])
        client.set_body(result.issue_number, body)
        client.close_as(result.issue_number, "completed")
    return [item.issue_number for item in created]


def test_454_455_duplicate_records_are_deduped_before_manifest_publication():
    record = _discovery_record()
    batch = review.build_review_batch(
        _context(), _discovery_document([record, deepcopy(record)])
    )
    assert len(batch.groups) == 1
    review.validate_manifest_against_context(batch.parts[0].manifest, REPO, REPO)


@pytest.mark.parametrize("source", ["discovery", "cleanup"])
def test_conflicting_record_ids_fail_before_publication(source):
    record = _discovery_record() if source == "discovery" else _cleanup_record()
    changed = {**record, "evidence": ["different evidence"]}
    with pytest.raises(review.ManifestValidationError, match="Conflicting duplicate"):
        review.build_review_batch(
            _context(),
            _discovery_document([record, changed]) if source == "discovery" else None,
            _cleanup_document([record, changed]) if source == "cleanup" else None,
        )


def test_changed_references_and_comments_have_new_ids_but_legacy_ids_validate():
    before = _discovery_record()
    after = {**before, "upstream_references": ["https://example.org/new"]}
    batches = [
        review.build_review_batch(_context(), _discovery_document([record]))
        for record in (before, after)
    ]
    assert (
        batches[0].groups[0].candidates[0].action_id
        != batches[1].groups[0].candidates[0].action_id
    )
    manifest = deepcopy(batches[0].parts[0].manifest)
    manifest["groups"][0]["actions"][0]["action_id"] = review.discovery_action_id(
        before["record_id"], review.DISCOVERY_KIND_CREATE
    )
    review.validate_manifest_against_context(manifest, REPO, REPO)


def test_publication_revalidates_all_parts_before_any_writes():
    batch = review.build_review_batch(
        _context(), _discovery_document([_discovery_record()])
    )
    batch.parts[0].manifest["groups"][0]["actions"].append(
        deepcopy(batch.parts[0].manifest["groups"][0]["actions"][0])
    )
    client = FakeGitHubIssueClient()
    with pytest.raises(review.ManifestValidationError):
        review.create_review_batch(client, batch)
    assert not client._issues


@pytest.mark.parametrize("split", [False, True])
def test_430_431_two_creates_for_same_package_are_serially_deduplicated(split):
    records = [_discovery_record(record_id=f"gentoo:{number}") for number in (430, 431)]
    if split:
        for record in records:
            record["proposed_issue"]["body"] += "\n" + "More upstream evidence. " * 100
    batch = review.build_review_batch(
        _context(max_part_body_chars=7000 if split else 55000),
        _discovery_document(records),
    )
    review_client = FakeGitHubIssueClient()
    advisory_client = FakeGitHubIssueClient()
    advisory_client.fetch_open_advisory_issues = lambda *args: pytest.fail(
        "Search is not safe"
    )
    for number in _approve(review_client, batch):
        result = review.apply_review_issue(
            review_client,
            advisory_client,
            GitHubActionRunner(advisory_client, _default_flags()),
            number,
            _apply_ctx(),
        )
        assert result["outcome"] == "applied"
    assert len(advisory_client._issues) == 1
    assert len(batch.parts) == (2 if split else 1)


def test_unlabeled_package_update_blocks_create_and_exposes_target_link():
    batch = review.build_review_batch(
        _context(), _discovery_document([_discovery_record()])
    )
    client = FakeGitHubIssueClient()
    client.seed_issue(430, "update: widget", "Human tracking context", [])
    number = _approve(client, batch)[0]
    result = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["groups"][0]["outcome"] == "skipped"
    assert result["groups"][0]["issue_url"].endswith("/issues/430")
    assert len(client._issues) == 2


def test_75_cve_overlap_does_not_authorize_go_update_to_perl():
    client = FakeGitHubIssueClient()
    client.seed_issue(75, "update: perl", "Name: perl\nCVEs: CVE-2026-9001", [])
    assert not find_existing_issue_matches(
        {"package_name": "go", "cves": ["CVE-2026-9001"]}, [client.get_issue(75)]
    )
    record = _discovery_record(
        decision={"action": "update_existing_issue", "confidence": "high"},
        llm_extraction={**_discovery_record()["llm_extraction"], "package_name": "go"},
        proposed_issue=None,
        proposed_update={"issue": 75},
        existing_issue_matches=[
            {"issue": 75, "package": "perl", "cves": ["CVE-2026-9001"]}
        ],
    )
    batch = review.build_review_batch(_context(), _discovery_document([record]))
    assert review.DISCOVERY_KIND_UPDATE not in _action_ids_by_kind(
        batch.parts[0].manifest
    )
    parsed = review.parse_issue_body(client.get_issue(75).body)
    assert not review._identity_matches(parsed, "go", ["CVE-2026-9001"])


def test_ambiguous_package_matches_do_not_choose_first_update():
    record = _discovery_record(
        decision={"action": "update_existing_issue", "confidence": "high"},
        proposed_update={"issue": 1},
        existing_issue_matches=[
            {"issue": number, "package": "widget", "state": "open"} for number in (1, 2)
        ],
    )
    batch = review.build_review_batch(_context(), _discovery_document([record]))
    assert review.DISCOVERY_KIND_UPDATE not in _action_ids_by_kind(
        batch.parts[0].manifest
    )


def test_65_ghsa_and_reference_whitespace_is_idempotent_and_human_text_guarded():
    body = (
        "Name: widget\nCVEs: CVE-2026-9001,  GHSA-aaaa-bbbb-cccc\n"
        "CVSSs: 7.5\nAction Needed: TBD\nSummary: human summary\n\n"
        "refmap.gentoo: https://bugs.gentoo.org/1\nHuman footer: do not remove"
    )
    updated = append_field_values(
        body, "CVEs", [" GHSA-aaaa-bbbb-cccc ", "CVE-2026-9002"]
    )
    updated = append_field_values(
        updated, "refmap.gentoo", [" https://bugs.gentoo.org/1 "]
    )
    assert updated.count("GHSA-aaaa-bbbb-cccc") == 1
    assert updated.count("https://bugs.gentoo.org/1") == 1
    assert append_field_values(updated, "CVEs", ["CVE-2026-9002"]) == updated
    assert not removal_guard_violations(body, updated)
    assert removal_guard_violations(
        body, updated.replace("Human footer: do not remove", "")
    )


def test_approved_update_rebases_on_body_edited_after_review():
    client = FakeGitHubIssueClient()
    old_body = (
        "Name: widget\nCVEs: CVE-2026-0001\nCVSSs: n/a\n"
        "Action Needed: TBD\nSummary: original context\n\nrefmap.gentoo: TBD"
    )
    client.seed_issue(65, "update: widget", old_body, ["advisory", "security"])
    record = _discovery_record(
        decision={"action": "update_existing_issue", "confidence": "high"},
        existing_issue_matches=[
            {"issue": 65, "package": "widget", "state": "open", "body": old_body}
        ],
        proposed_issue=None,
        proposed_update={
            "issue": 65,
            "matched_existing_issue": {"body": old_body},
            "comment_body": "Upstream security evidence changed.",
        },
    )
    batch = review.build_review_batch(_context(), _discovery_document([record]))
    [number] = _approve(client, batch, {review.DISCOVERY_KIND_UPDATE})
    current_body = old_body.replace(
        "CVE-2026-0001", "CVE-2026-0001, CVE-2026-0002"
    ).replace("Action Needed: TBD", "Action Needed: update to >= 9.9.9")
    current_body += "\nHuman rollout notes: https://example.org/human-plan"
    client.set_body(65, current_body)

    result = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["groups"][0]["outcome"] == "applied"
    updated_body = client.get_issue(65).body
    assert not removal_guard_violations(current_body, updated_body)
    assert "CVE-2026-9001" in updated_body
    assert "CVE-2026-0002" in updated_body
    assert "Action Needed: update to >= 9.9.9" in updated_body
    assert "Human rollout notes: https://example.org/human-plan" in updated_body
    assert len(client.list_comments(65)) == 1


def test_146_summary_snapshots_selection_kind_package_url_and_distinct_operations():
    record = _discovery_record(
        decision={"action": "update_existing_issue", "confidence": "high"},
        proposed_update={"issue": 146, "comment_body": "New upstream context"},
        existing_issue_matches=[{"issue": 146, "package": "widget", "state": "open"}],
    )
    client = FakeGitHubIssueClient()
    client.seed_issue(
        146, "update: widget", _discovery_record()["proposed_issue"]["body"], []
    )
    batch = review.build_review_batch(_context(), _discovery_document([record]))
    number = _approve(client, batch)[0]
    result = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    summary = client._comments[number][0]["body"]
    assert "discovery_update_issue" in summary and "widget" in summary
    assert "/issues/146" in summary
    assert "update_issue_body: no_op" in summary and "post_comment: applied" in summary
    assert result["selected_action_ids"] == [batch.groups[0].candidates[0].action_id]
    client.set_body(number, client._issues[number]["body"].replace("[x]", "[ ]"))
    review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert client._comments[number][0]["body"] == summary


def test_partial_comment_failure_is_visible_and_retry_updates_one_bot_summary():
    record = _discovery_record(
        decision={"action": "update_existing_issue", "confidence": "high"},
        proposed_update={"issue": 65, "comment_body": "Upstream context"},
        existing_issue_matches=[{"issue": 65, "package": "widget", "state": "open"}],
    )
    advisory = FakeGitHubIssueClient()
    advisory.seed_issue(
        65,
        "update: widget",
        record["proposed_issue"]["body"].replace(
            "CVE-2026-9001", "GHSA-aaaa-bbbb-cccc"
        ),
        [],
    )
    reviews = FakeGitHubIssueClient()
    batch = review.build_review_batch(_context(), _discovery_document([record]))
    number = _approve(reviews, batch)[0]
    post_comment = advisory.post_comment

    def fail(*args):
        raise RuntimeError("sensitive upstream error text")

    advisory.post_comment = fail
    result = review.apply_review_issue(
        reviews,
        advisory,
        GitHubActionRunner(advisory, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["outcome"] == "partial_failure"
    assert review.REVIEW_APPLIED_LABEL not in reviews.get_issue(number).labels
    summary = reviews._comments[number][0]["body"]
    assert "update_issue_body: applied" in summary and "post_comment: failed" in summary
    assert "sensitive upstream" not in summary
    advisory.post_comment = post_comment
    result = review.apply_review_issue(
        reviews,
        advisory,
        GitHubActionRunner(advisory, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["outcome"] == "applied"
    assert len(reviews._comments[number]) == len(advisory._comments[65]) == 1
    assert advisory.get_issue(65).body.count("CVE-2026-9001") == 1


def test_invalid_manifest_posts_idempotent_failure_summary_without_applied_label():
    client = FakeGitHubIssueClient()
    batch = review.build_review_batch(
        _context(), _discovery_document([_discovery_record()])
    )
    number = _approve(client, batch)[0]
    client.set_body(
        number,
        client._issues[number]["body"].replace(
            "review-manifest:v1", "review-manifest:v2"
        ),
    )
    for _ in range(2):
        result = review.apply_review_issue(
            client,
            client,
            GitHubActionRunner(client, _default_flags()),
            number,
            _apply_ctx(),
        )
        assert result["outcome"] == "failed"
    assert len(client._comments[number]) == 1
    assert review.REVIEW_APPLIED_LABEL not in client.get_issue(number).labels
    assert len(client._issues) == 1


def test_compact_filters_exact_sources_and_unchanged_low_signal_with_audit():
    records = [
        _discovery_record(record_id="gentoo:go", source="gentoo"),
        _discovery_record(record_id="go:1", source="go_vulndb"),
        _discovery_record(record_id="rust:1", source="rustsec"),
        _discovery_record(
            record_id="gentoo:ignored",
            decision={"action": "ignore", "confidence": "high"},
        ),
        _discovery_record(
            record_id="gentoo:uncertain",
            decision={"action": "needs_manual_review", "confidence": "low"},
        ),
    ]
    batch = review.build_review_batch(
        _context(review_detail="compact", include_go=False, include_rust=False),
        _discovery_document(records),
    )
    assert {group.record["record_id"] for group in batch.groups} == {
        "gentoo:go",
        "gentoo:uncertain",
    }
    assert len(batch.omissions) == 3
    body = "\n".join(part.body for part in batch.parts)
    assert "source_excluded:go_vulndb" in body and "rust:1" in body
    assert "| needs_manual_review | 1 |" in body


@pytest.mark.parametrize("detail", ["compact", "full"])
def test_suppression_never_offers_mutation_and_empty_compact_audit_is_published(detail):
    record = _discovery_record(review_suppression={"reason": "wrong_package"})
    batch = review.build_review_batch(
        _context(review_detail=detail), _discovery_document([record])
    )
    assert len(batch.parts) == 1
    assert not _action_ids_by_kind(batch.parts[0].manifest)
    assert "wrong_package" in batch.parts[0].body
    assert len(review.create_review_batch(FakeGitHubIssueClient(), batch)) == 1


def test_large_omission_audit_is_bounded_with_complete_local_json(tmp_path):
    records = [
        _discovery_record(record_id=f"go:{number}", source="go_vulndb")
        for number in range(350)
    ]
    batch = review.build_review_batch(
        _context(include_go=False, max_part_body_chars=10000),
        _discovery_document(records),
    )
    assert len(batch.parts) == 1
    assert batch.parts[0].manifest["omission_summary"]["total_records"] == 350
    assert len(batch.parts[0].body) < 8000
    examples = batch.parts[0].manifest["omission_summary"]["categories"][0]["examples"]
    assert len(examples) == 3
    assert not batch.groups
    review.write_dry_run_batch(batch, tmp_path, REPO)
    audit = json.loads((tmp_path / "review-audit.json").read_text())
    assert len(audit["omissions"]) == 350
    assert audit["omissions"][-1]["record_id"] == "go:349"


def _select_feedback(client, batch, decisions, mutation=False):
    number = review.create_review_batch(client, batch)[0].issue_number
    part = batch.parts[0]
    body = part.body
    for group in part.manifest["groups"]:
        for action in group["actions"]:
            if (
                action["kind"] == FEEDBACK_KIND
                and action["payload"]["decision"] in decisions
            ) or (mutation and action["kind"] == review.DISCOVERY_KIND_CREATE):
                body = _check_action(body, action["action_id"])
    client.set_body(number, body)
    client.close_as(number, "completed")
    return number


def test_feedback_is_explicit_independent_durable_and_survives_checkbox_edits():
    record = _discovery_record()
    batch = review.build_review_batch(
        _context(enable_feedback=True), _discovery_document([record])
    )
    assert not review.parse_checked_action_ids(batch.parts[0].body)
    client = FakeGitHubIssueClient()
    number = _select_feedback(client, batch, {"wrong_package"})
    result = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["outcome"] == "applied"
    assert len(client._issues) == 1
    feedback = load_review_feedback(client, advisory_repository=REPO)
    assert len(feedback) == 1 and feedback[0]["decision"] == "wrong_package"
    client.set_body(number, client.get_issue(number).body.replace("[x]", "[ ]"))
    assert load_review_feedback(client, advisory_repository=REPO) == feedback


@pytest.mark.parametrize(
    "decisions,mutation",
    [
        ({"wrong_package", "deferred"}, False),
        ({"wrong_package", "deferred"}, True),
        ({"not_shipped"}, True),
        ({"track_uncertain"}, True),
    ],
)
def test_conflicting_feedback_cannot_persist_or_mutate(decisions, mutation):
    batch = review.build_review_batch(
        _context(enable_feedback=True), _discovery_document([_discovery_record()])
    )
    client = FakeGitHubIssueClient()
    number = _select_feedback(client, batch, decisions, mutation)
    result = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert any(group["outcome"] == "conflict" for group in result["groups"])
    assert len(client._issues) == 1
    assert load_review_feedback(client, advisory_repository=REPO) == []


def test_feedback_and_mutation_controls_never_split_across_parts():
    records = [_discovery_record(record_id=f"gentoo:{number}") for number in range(3)]
    batch = review.build_review_batch(
        _context(enable_feedback=True, max_part_body_chars=7000),
        _discovery_document(records),
    )
    assert len(batch.parts) > 1
    for part in batch.parts:
        ids = {group["group_id"] for group in part.manifest["groups"]}
        for group in part.manifest["groups"]:
            if group["source"] == "feedback":
                assert group["feedback_for_group_id"] in ids


@pytest.mark.parametrize("detail", ["compact", "full"])
def test_suppressed_record_offers_revoke_only_in_full_review(detail):
    record = _discovery_record(
        review_suppression={"suppressed": True, "reason": "explicit reviewer decision"}
    )
    batch = review.build_review_batch(
        _context(enable_feedback=True, review_detail=detail),
        _discovery_document([record]),
    )
    kinds = {candidate.kind for group in batch.groups for candidate in group.candidates}
    assert kinds == ({FEEDBACK_KIND} if detail == "full" else set())
    if detail == "full":
        assert any(
            candidate.payload["decision"] == "revoke"
            for group in batch.groups
            for candidate in group.candidates
        )
    else:
        assert not batch.groups


def test_revoked_or_uncertain_feedback_is_not_suppression():
    for decision in ("revoke", "track_uncertain"):
        record = _discovery_record(
            review_suppression={"suppressed": False, "decision": decision}
        )
        batch = review.build_review_batch(
            _context(review_detail="compact"), _discovery_document([record])
        )
        assert batch.groups[0].candidates[0].kind == review.DISCOVERY_KIND_CREATE


def test_track_uncertain_keeps_original_ignore_visible_without_authorizing_mutation():
    record = _discovery_record(
        decision={"action": "ignore", "confidence": "high"},
        review_suppression={"suppressed": False, "decision": "track_uncertain"},
    )
    batch = review.build_review_batch(
        _context(review_detail="compact"), _discovery_document([record])
    )
    assert len(batch.groups) == 1
    assert not batch.omissions
    assert batch.groups[0].candidates[0].kind == review.DISCOVERY_KIND_IGNORE


def test_cargo_identity_survives_create_rediscovery_and_guarded_update():
    client = FakeGitHubIssueClient()
    sbom = SBOMIndex(
        [SBOMPackage("tar", "1.2.2", "SPDXRef-crate", purls=["pkg:cargo/tar"])]
    )

    class QualifiedModel(HeuristicModelClient):
        def extract_advisory(self, entry):
            result = super().extract_advisory(entry)
            result["package_purl"] = "pkg:cargo/tar"
            return result

    def discover(cve):
        source = SourceEntry(
            source="rustsec",
            source_url="https://rustsec.org/advisories/RUSTSEC-2026-0001.html",
            entry_id=cve,
            title="tar: security advisory",
            content=f"Package: tar\nPackage URL: pkg:cargo/tar\nCVE: {cve}\nFixed in 1.2.3",
        )
        return DiscoveryWorkflow(
            QualifiedModel(), sbom, client.list_issues(), target_repo=REPO
        ).run([source], "", "")

    first = discover("CVE-2026-12345")
    assert first["records"][0]["decision"]["action"] == "create_issue"
    batch = review.build_review_batch(_context("cargo-create"), first)
    [number] = _approve(client, batch, {review.DISCOVERY_KIND_CREATE})
    result = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["outcome"] == "applied"
    [advisory] = client.fetch_open_update_issues()
    assert advisory.title == "update: tar"
    assert advisory.body.startswith("Name: tar\nCVEs:")
    assert "Note: Canonical package identity: `pkg:cargo/tar`." in advisory.body
    parsed = review.parse_issue_body(advisory.body)
    assert parsed.name == "tar" and parsed.identity == "pkg:cargo/tar"
    assert not find_existing_issue_matches({"package_name": "tar"}, [advisory])
    assert not review._identity_matches(parsed, "tar", parsed.cves)
    collision = review._execute_discovery_update(
        "native-tar",
        {
            "issue": advisory.number,
            "expected_package": "tar",
            "field_additions": {"cves": ["CVE-2026-99999"]},
        },
        client,
        GitHubActionRunner(client, _default_flags()),
    )
    assert collision["outcome"] == "skipped"
    assert client.get_issue(advisory.number).body == advisory.body
    assert discover("CVE-2026-12345")["records"][0]["decision"]["action"] == "ignore"

    following = discover("CVE-2026-22222")
    assert following["records"][0]["decision"]["action"] == "update_existing_issue"
    batch = review.build_review_batch(_context("cargo-update"), following)
    [number] = _approve(client, batch, {review.DISCOVERY_KIND_UPDATE})
    result = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["groups"][0]["outcome"] == "applied"
    body = client.get_issue(advisory.number).body
    assert "CVE-2026-12345" in body and "CVE-2026-22222" in body
    assert body.count("Canonical package identity") == 1
    assert len(client.fetch_open_update_issues()) == 1


@pytest.mark.parametrize(
    "original",
    [
        "",
        "Human rollout plan: https://example.org/plan",
        "Human rollout plan\nCVEs: CVE-2026-0001",
        "Name: widget\nSummary: Keep this human summary.\n\nrefmap.gentoo: TBD",
    ],
)
def test_title_only_update_adds_approved_fields_without_losing_prose(original):
    client = FakeGitHubIssueClient()
    client.seed_issue(65, "update: widget", original, [])
    source = SourceEntry(
        source="gentoo",
        source_url="https://bugs.gentoo.org/1",
        entry_id="1",
        title="widget: security advisory",
        content="Package: widget\nCVE: CVE-2026-9001\nFixed in 1.2.3",
    )
    document = DiscoveryWorkflow(
        HeuristicModelClient(),
        SBOMIndex([SBOMPackage("widget", "1.2.2", "SPDXRef-widget")]),
        [client.get_issue(65)],
        target_repo=REPO,
    ).run([source], "", "")
    [record] = document["records"]
    assert record["decision"]["action"] == "update_existing_issue"
    preview = record["proposed_update"]["updated_body"]
    batch = review.build_review_batch(_context(), document)
    [number] = _approve(client, batch, {review.DISCOVERY_KIND_UPDATE})
    result = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["groups"][0]["outcome"] == "applied"
    updated = client.get_issue(65).body
    assert updated == preview
    assert not removal_guard_violations(original, updated)
    assert all(
        line in updated
        for line in original.splitlines()
        if line and not line.endswith(": TBD")
    )
    assert review.parse_issue_body(updated).valid
    assert "\n\nrefmap.gentoo:" in updated
    assert "CVE-2026-9001" in updated
    assert "Action Needed: update to >= 1.2.3" in updated
    action = _action_ids_by_kind(batch.parts[0].manifest)[review.DISCOVERY_KIND_UPDATE][
        0
    ]
    retried = review._execute_discovery_update(
        action["action_id"],
        action["payload"],
        client,
        GitHubActionRunner(client, _default_flags()),
    )
    assert retried["outcome"] == "no_op"
    assert client.get_issue(65).body == updated


def test_namespace_suffix_does_not_authorize_unrelated_issue_match():
    client = FakeGitHubIssueClient()
    client.seed_issue(75, "update: openssl", "Name: openssl\nCVEs: CVE-2026-9001", [])
    assert not find_existing_issue_matches(
        {"package_name": "github.com/attacker/openssl"}, [client.get_issue(75)]
    )
    assert find_existing_issue_matches(
        {"package_name": "dev-libs/openssl"}, [client.get_issue(75)]
    )


def test_source_backed_purl_takes_precedence_over_ambiguous_display_name():
    client = FakeGitHubIssueClient()
    client.seed_issue(75, "update: widget", "Name: widget\nCVEs: CVE-2026-9001", [])
    extraction = {
        **_discovery_record()["llm_extraction"],
        "package_purl": "pkg:cargo/widget",
    }
    assert not find_existing_issue_matches(extraction, [client.get_issue(75)])
    record = _discovery_record(
        llm_extraction=extraction,
        decision={"action": "update_existing_issue", "confidence": "high"},
        proposed_update={"issue": 75},
        existing_issue_matches=[{"issue": 75, "package": "widget", "state": "open"}],
    )
    batch = review.build_review_batch(_context(), _discovery_document([record]))
    assert review.DISCOVERY_KIND_UPDATE not in _action_ids_by_kind(
        batch.parts[0].manifest
    )


def test_create_response_lost_after_success_is_idempotent_on_retry():
    advisory = FakeGitHubIssueClient()
    reviews = FakeGitHubIssueClient()
    batch = review.build_review_batch(
        _context(), _discovery_document([_discovery_record()])
    )
    number = _approve(reviews, batch)[0]
    create = advisory.create_issue

    def response_lost(*args):
        create(*args)
        raise RuntimeError("response lost")

    advisory.create_issue = response_lost
    result = review.apply_review_issue(
        reviews,
        advisory,
        GitHubActionRunner(advisory, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["outcome"] == "partial_failure"
    advisory.create_issue = create
    result = review.apply_review_issue(
        reviews,
        advisory,
        GitHubActionRunner(advisory, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["outcome"] == "applied" and result["groups"][0]["outcome"] == "no_op"
    assert len(advisory._issues) == len(reviews._comments[number]) == 1


def test_cleanup_new_active_cve_since_review_blocks_closure():
    client = FakeGitHubIssueClient()
    record = _cleanup_record(recommended_action="close_issue")
    client.seed_issue(
        record["issue"],
        "update: libgcrypt",
        "Name: libgcrypt\nCVEs: CVE-2026-1200, CVE-2026-9999\n"
        "CVSSs: n/a\nAction Needed: update to >= 1.12.2\nSummary: s\n\nrefmap.gentoo: TBD",
        ["advisory", "security"],
    )
    batch = review.build_review_batch(_context(), None, _cleanup_document([record]))
    number = _approve(client, batch)[0]
    result = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["groups"][0]["outcome"] == "skipped"
    assert client.get_issue(record["issue"]).state == "open"
    assert not client._comments[record["issue"]]


@pytest.mark.parametrize(
    "decision", ["create_issue", "update_existing_issue", "needs_manual_review"]
)
def test_failed_source_grounding_does_not_offer_mutating_manual_alternatives(decision):
    record = _discovery_record(
        decision={"action": decision, "confidence": "low"},
        proposed_update={"issue": 75},
        existing_issue_matches=[{"issue": 75, "package": "widget", "state": "open"}],
        llm_extraction={
            **_discovery_record()["llm_extraction"],
            "evidence_validation": {
                "status": "needs_manual_review",
                "errors": ["Unsupported CVE and fixed version claims"],
            },
        },
    )
    batch = review.build_review_batch(_context(), _discovery_document([record]))
    assert {
        candidate.kind for group in batch.groups for candidate in group.candidates
    } <= review.NON_MUTATING_KINDS
    assert "source-grounding validation failed" in batch.parts[0].body
    assert record["llm_extraction"]["cves"] == ["CVE-2026-9001"]


def test_feedback_snapshots_are_stored_once_and_hash_references_are_validated():
    batch = review.build_review_batch(
        _context(enable_feedback=True), _discovery_document([_discovery_record()])
    )
    part = batch.parts[0]
    block = review._MANIFEST_BLOCK_RE.search(part.body)
    stored = json.loads(base64.b64decode("".join(block.group("body").split())))
    assert len(stored["feedback_snapshots"]) == 1
    feedback_actions = [
        action
        for group in stored["groups"]
        for action in group["actions"]
        if action["kind"] == FEEDBACK_KIND
    ]
    assert len(feedback_actions) == 6
    assert all(
        "evidence_snapshot_ref" in action["payload"] for action in feedback_actions
    )
    assert all(
        "evidence_snapshot" not in action["payload"] for action in feedback_actions
    )
    assert review.extract_manifest(part.body) == part.manifest

    def encode(data):
        return (
            "<!-- security-triage:review-manifest:v1\n"
            + base64.b64encode(review.canonical_json(data).encode()).decode()
            + "\n-->"
        )

    # Existing expanded v1 manifests remain valid without the storage table.
    assert review.extract_manifest(encode(part.manifest)) == part.manifest
    snapshot = next(iter(stored["feedback_snapshots"].values()))
    snapshot["package"] = "wrong-package"
    with pytest.raises(review.ManifestCorruptionError, match="snapshot"):
        review.extract_manifest(encode(stored))


def test_summary_upsert_does_not_overwrite_a_spoofed_bot_identity():
    client = FakeGitHubIssueClient()
    client.seed_issue(1, "review", "", [review.REVIEW_LABEL])
    forged = client.post_comment(
        1, "Untrusted summary\n<!-- security-triage:action-id:review-summary-1 -->"
    )
    forged["user"]["id"] = 123
    review._publish_execution_summary(client, 1, "Trusted summary")
    assert len(client._comments[1]) == 2
    assert forged["body"].startswith("Untrusted summary")
    review._publish_execution_summary(client, 1, "Trusted updated summary")
    assert len(client._comments[1]) == 2
    assert client._comments[1][1]["body"].startswith("Trusted updated summary")


def test_feedback_index_label_failure_is_retryable_without_applied_label():
    client = FakeGitHubIssueClient()
    batch = review.build_review_batch(
        _context(enable_feedback=True), _discovery_document([_discovery_record()])
    )
    number = _select_feedback(client, batch, {"wrong_package"})
    add_labels = client.add_labels

    def fail_feedback_index(issue_number, labels):
        if review.REVIEW_FEEDBACK_LABEL in labels:
            assert client._comments[issue_number], (
                "Summary must persist before indexing"
            )
            raise RuntimeError("index label unavailable")
        return add_labels(issue_number, labels)

    client.add_labels = fail_feedback_index
    result = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["outcome"] == "partial_failure"
    assert review.REVIEW_APPLIED_LABEL not in client.get_issue(number).labels
    assert review.REVIEW_FEEDBACK_LABEL not in client.get_issue(number).labels
    assert "feedback index label" in client._comments[number][-1]["body"]
    client.add_labels = add_labels
    result = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["outcome"] == "applied"
    assert review.REVIEW_FEEDBACK_LABEL in client.get_issue(number).labels
    assert len(client._comments[number]) == 2


def test_retry_without_feedback_checks_preserves_and_indexes_prior_confirmation():
    client = FakeGitHubIssueClient()
    batch = review.build_review_batch(
        _context(enable_feedback=True), _discovery_document([_discovery_record()])
    )
    number = _select_feedback(client, batch, {"wrong_package"})
    add_labels = client.add_labels

    def fail_index(*args):
        raise RuntimeError("label unavailable")

    client.add_labels = fail_index
    first = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert first["outcome"] == "partial_failure"
    client.set_body(number, client.get_issue(number).body.replace("[x]", "[ ]"))
    client.add_labels = add_labels
    retried = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert retried["outcome"] == "applied"
    assert review.REVIEW_FEEDBACK_LABEL in client.get_issue(number).labels
    assert len(client._comments[number]) == 2
    assert (
        load_review_feedback(client, advisory_repository=REPO)[0]["decision"]
        == "wrong_package"
    )


@pytest.mark.parametrize("keep_previous", [False, True])
def test_changed_feedback_selection_on_partial_retry_preserves_both_receipts(
    keep_previous,
):
    records = [
        _discovery_record(record_id="first"),
        _discovery_record(
            record_id="second",
            source_url="https://bugs.gentoo.org/2",
            raw_advisory_id="2",
        ),
    ]
    batch = review.build_review_batch(
        _context(enable_feedback=True), _discovery_document(records)
    )
    client = FakeGitHubIssueClient()
    number = review.create_review_batch(client, batch)[0].issue_number
    actions = _action_ids_by_kind(batch.parts[0].manifest)[FEEDBACK_KIND]
    first = next(
        action
        for action in actions
        if action["payload"]["decision"] == "wrong_package"
        and action["payload"]["evidence_snapshot"]["source_url"].endswith("/1")
    )
    second = next(
        action
        for action in actions
        if action["payload"]["decision"] == "deferred"
        and action["payload"]["evidence_snapshot"]["source_url"].endswith("/2")
    )
    client.set_body(number, _check_action(batch.parts[0].body, first["action_id"]))
    client.close_as(number, "completed")
    add_labels = client.add_labels

    def fail_index(*args):
        raise RuntimeError("label unavailable")

    client.add_labels = fail_index
    result = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["outcome"] == "partial_failure"
    original_receipt = client._comments[number][0]["body"]
    body = _check_action(batch.parts[0].body, second["action_id"])
    if keep_previous:
        body = _check_action(body, first["action_id"])
    client.set_body(number, body)
    client.add_labels = add_labels
    result = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["outcome"] == "applied"
    assert client._comments[number][0]["body"] == original_receipt
    assert len(client._comments[number]) == 3
    assert {
        item["decision"]
        for item in load_review_feedback(client, advisory_repository=REPO)
    } == {"wrong_package", "deferred"}


def test_unrelated_retry_selection_cannot_refresh_feedback_past_revocation():
    client = FakeGitHubIssueClient()
    record = _discovery_record(record_id="first")
    other = _discovery_record(
        record_id="other", source_url="https://bugs.gentoo.org/2", raw_advisory_id="2"
    )
    batch = review.build_review_batch(
        _context(enable_feedback=True), _discovery_document([record, other])
    )
    [created] = review.create_review_batch(client, batch)
    first_action = next(
        action
        for action in _action_ids_by_kind(batch.parts[0].manifest)[FEEDBACK_KIND]
        if action["payload"]["decision"] == "wrong_package"
        and action["payload"]["evidence_snapshot"]["source_url"].endswith("/1")
    )
    other_action = _action_ids_by_kind(batch.parts[0].manifest)[
        review.DISCOVERY_KIND_CREATE
    ][1]
    first_body = _check_action(batch.parts[0].body, first_action["action_id"])
    client.set_body(
        created.issue_number, _check_action(first_body, other_action["action_id"])
    )
    client.close_as(created.issue_number, "completed")
    advisory_client = FakeGitHubIssueClient()

    def fail_create(*args):
        raise OSError("temporary issue creation failure")

    advisory_client.create_issue = fail_create
    result = review.apply_review_issue(
        client,
        advisory_client,
        GitHubActionRunner(advisory_client, _default_flags()),
        created.issue_number,
        _apply_ctx(),
    )
    assert result["outcome"] == "partial_failure"
    original = load_review_feedback(client, advisory_repository=REPO)[0]
    revocation = review.build_review_batch(
        _context("revocation", enable_feedback=True), _discovery_document([record])
    )
    number = _select_feedback(client, revocation, {"revoke"})
    review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    client.set_body(created.issue_number, first_body)
    result = review.apply_review_issue(
        client,
        advisory_client,
        GitHubActionRunner(advisory_client, _default_flags()),
        created.issue_number,
        _apply_ctx(),
    )
    assert result["outcome"] == "applied"
    feedback = load_review_feedback(client, advisory_repository=REPO)
    assert [item for item in feedback if item["decision"] == "wrong_package"] == [
        original
    ]
    annotate_review_feedback(record, feedback, advisory_repository=REPO)
    assert record["review_suppression"]["decision"] == "revoke"
    assert record["review_suppression"]["suppressed"] is False


def test_failed_receipt_write_does_not_index_or_mark_feedback_applied():
    batch = review.build_review_batch(
        _context(enable_feedback=True), _discovery_document([_discovery_record()])
    )
    client = FakeGitHubIssueClient()
    number = _select_feedback(client, batch, {"wrong_package"})
    post_comment = client.post_comment

    def fail_receipt(issue_number, body):
        if body.startswith("## Security-triage reviewer feedback receipt"):
            raise RuntimeError("receipt write unavailable")
        return post_comment(issue_number, body)

    client.post_comment = fail_receipt
    result = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["outcome"] == "partial_failure"
    assert review.REVIEW_APPLIED_LABEL not in client.get_issue(number).labels
    assert review.REVIEW_FEEDBACK_LABEL not in client.get_issue(number).labels
    assert (
        "Could not persist the trusted feedback receipt"
        in client._comments[number][0]["body"]
    )


@pytest.mark.parametrize("proposed", [True, False])
def test_create_labels_ignore_unsupported_model_secondary_scope(proposed):
    record = _discovery_record()
    record["llm_extraction"]["scope_assessment"] = "sdk-only and sysext"
    if proposed:
        record["proposed_issue"]["labels"] += ["advisory/only-sdk", "advisory/sysext"]
    else:
        record["proposed_issue"] = None
    payload = review._create_payload(record)
    assert "advisory/only-sdk" not in payload["labels"]
    assert "advisory/sysext" not in payload["labels"]


@pytest.mark.parametrize("with_sysext", [False, True])
@pytest.mark.parametrize("proposed", [False, True])
def test_review_apply_preserves_production_precedence_over_sdk_label(
    with_sysext, proposed
):
    inventory = SBOMIndex([SBOMPackage("widget", "1.2.2", "SPDXRef-widget")])
    scopes = [("sdk_only", inventory)]
    if with_sysext:
        scopes.append(("sysext", inventory))
    source = SourceEntry(
        source="gentoo",
        source_url="https://bugs.gentoo.org/1",
        entry_id="1",
        title="widget: security advisory",
        content="Package: widget\nCVE: CVE-2026-9001\nFixed in 1.2.3",
    )
    document = DiscoveryWorkflow(
        HeuristicModelClient(), inventory, [], target_repo=REPO, scope_sboms=scopes
    ).run([source], "", "")
    [record] = document["records"]
    assert record["flatcar_relevance"]["scope"] == "production"
    assert "advisory/only-sdk" not in record["proposed_issue"]["labels"]
    if not proposed:
        record["proposed_issue"] = None
    batch = review.build_review_batch(_context(review_detail="full"), document)
    [action] = _action_ids_by_kind(batch.parts[0].manifest)[
        review.DISCOVERY_KIND_CREATE
    ]
    assert "advisory/only-sdk" not in action["payload"]["labels"]
    assert ("advisory/sysext" in action["payload"]["labels"]) is with_sysext
    client = FakeGitHubIssueClient()
    [number] = _approve(client, batch, {review.DISCOVERY_KIND_CREATE})
    result = review.apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, _default_flags()),
        number,
        _apply_ctx(),
    )
    assert result["outcome"] == "applied"
    [advisory] = client.fetch_open_update_issues()
    assert "advisory/only-sdk" not in advisory.labels
    assert ("advisory/sysext" in advisory.labels) is with_sysext


def test_create_secondary_scope_requires_validated_same_identity_source_evidence():
    record = _discovery_record()
    record["flatcar_relevance"]["scope"] = "sdk_only"
    record["flatcar_relevance"]["scope_evidence"] = [
        {
            "package": "other",
            "scope": "sysext",
            "validated": True,
            "source": "inventory",
        },
        {"package": "widget", "scope": "sysext", "validated": True},
    ]
    assert "advisory/sysext" not in review._create_payload(record)["labels"]
    record["flatcar_relevance"]["scope_evidence"].append(
        {
            "package": "widget",
            "scope": "sysext",
            "validated": True,
            "source": "sysext-sbom",
        }
    )
    labels = review._create_payload(record)["labels"]
    assert {"advisory/only-sdk", "advisory/sysext"}.issubset(labels)
