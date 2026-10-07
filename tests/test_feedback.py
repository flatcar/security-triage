import base64
import copy
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from security_triage import issues as issues_module
from security_triage.actions import ActionFlags, GitHubActionRunner
from security_triage.discovery import DiscoveryWorkflow
from security_triage.feedback import (
    FEEDBACK_KIND,
    FEEDBACK_LABEL,
    annotate_review_feedback,
    build_feedback_payload,
    feedback_key,
    load_feedback_fixture,
    load_review_feedback,
    parse_feedback_summary,
    render_feedback_summary,
    validate_feedback_payload,
)
from security_triage.issues import GitHubIssueClient
from security_triage.models import HeuristicModelClient
from security_triage.records import Issue, SBOMPackage, SourceEntry
from security_triage.review import (
    ApplyContext,
    ReviewContext,
    apply_review_issue,
    build_review_batch,
    compute_digest,
    embed_manifest,
    render_checkbox_line,
)
from security_triage.sbom import SBOMIndex

REPO = "flatcar/security-triage"
BOT = {"login": "github-actions[bot]", "type": "Bot"}


def finding():
    return {
        "record_id": "gentoo:123",
        "source": "gentoo",
        "source_url": "https://bugs.gentoo.org/123",
        "raw_advisory_id": "123",
        "source_content": "Package: c-ares\nCVE: CVE-2026-12345\nFixed in 1.34.6",
        "raw_source_excerpt": "Unmodified raw evidence.",
        "llm_extraction": {
            "package_name": "c-ares",
            "cves": ["CVE-2026-12345"],
            "fixed_versions": ["1.34.6"],
            "affected_versions": ["<1.34.6"],
            "action_needed": "update to >= 1.34.6",
            "scope_assessment": "production",
        },
        "upstream_metadata": {"alias": ["CVE-2026-12345"]},
        "flatcar_relevance": {"scope": "production"},
        "sbom_package_matches": [{"name": "c-ares", "versionInfo": "1.34.5"}],
        "existing_issue_matches": [],
        "decision": {"action": "create_issue", "confidence": "high"},
        "evidence": ["SBOM: c-ares 1.34.5"],
    }


def approved(
    record=None, decision="deferred", *, comment_id=11, checked=True, issue_number=10
):
    payload = build_feedback_payload(
        record or finding(), decision, advisory_repository=REPO
    )
    action_id = f"feedback-{decision}"
    manifest = {
        "schema_version": "1.0",
        "batch_id": "test-batch",
        "part_id": "test-part",
        "part_index": 1,
        "part_count": 1,
        "advisory_repo": REPO,
        "review_repo": REPO,
        "groups": [
            {"group_id": "finding-group", "source": "discovery", "actions": []},
            {
                "group_id": "feedback-group",
                "source": "feedback",
                "feedback_for_group_id": "finding-group",
                "actions": [
                    {
                        "action_id": action_id,
                        "kind": FEEDBACK_KIND,
                        "payload": payload,
                    }
                ],
            },
        ],
    }
    manifest["digest"] = compute_digest(manifest)
    checkbox = render_checkbox_line(action_id, decision)
    if checked:
        checkbox = checkbox.replace("[ ]", "[x]")
    issue = Issue(
        number=issue_number,
        title="Security review",
        body=checkbox + "\n" + embed_manifest(manifest),
        labels=["security-triage/review"],
        html_url=f"https://github.com/{REPO}/issues/{issue_number}",
        state="closed",
        state_reason="completed",
        raw={"user": BOT.copy()},
    )
    result = {
        "action_id": action_id,
        "status": "feedback_recorded",
        "feedback": payload,
    }
    body = render_feedback_summary(
        manifest,
        [action_id] if checked else [],
        [result],
        review_issue_number=issue.number,
    )
    comment = {
        "id": comment_id,
        "user": BOT.copy(),
        "body": body,
        "html_url": f"{issue.html_url}#issuecomment-{comment_id}",
        "created_at": "2026-10-07T12:00:00Z",
    }
    return issue, comment


def confirmed(record=None, decision="deferred", **kwargs):
    issue, comment = approved(record, decision, **kwargs)
    return parse_feedback_summary(
        issue, comment, advisory_repository=REPO, review_repository=REPO
    )


@pytest.mark.parametrize(
    "decision,suppressed",
    [
        ("wrong_package", True),
        ("not_shipped", True),
        ("already_addressed", True),
        ("deferred", True),
        ("track_uncertain", False),
        ("revoke", False),
    ],
)
def test_confirmed_feedback_is_evidence_scoped_and_preserves_report(
    decision, suppressed
):
    record = finding()
    original = copy.deepcopy(record)
    feedback = confirmed(record, decision)
    assert len(feedback) == 1
    annotate_review_feedback(record, feedback, advisory_repository=REPO)
    assert record["review_suppression"]["suppressed"] is suppressed
    assert record["review_suppression"]["comment_url"].endswith("#issuecomment-11")
    assert record["decision"] == original["decision"]
    assert record["evidence"] == original["evidence"]
    assert record["raw_source_excerpt"] == original["raw_source_excerpt"]
    assert record["evidence_snapshot_id"].startswith("security-triage:evidence:v1:")


@pytest.mark.parametrize(
    "change", ["version", "cve", "scope", "range", "fixed", "source", "state"]
)
def test_meaningful_evidence_change_resurfaces(change):
    record = finding()
    old_key = feedback_key(record)
    feedback = confirmed(record)
    if change == "version":
        record["sbom_package_matches"][0]["versionInfo"] = "1.34.7"
    elif change == "cve":
        record["llm_extraction"]["cves"].append("CVE-2026-54321")
    elif change == "scope":
        record["flatcar_relevance"]["scope"] = "sysext"
    elif change == "range":
        record["llm_extraction"]["affected_versions"] = ["<1.34.7"]
    elif change == "fixed":
        record["llm_extraction"]["fixed_versions"] = ["1.34.7"]
    elif change == "source":
        record["source_content"] += "\nThe fix was incomplete."
    else:
        record["existing_issue_matches"] = [{"issue": 30, "state": "closed"}]
    assert feedback_key(record) != old_key
    annotate_review_feedback(record, feedback, advisory_repository=REPO)
    assert "review_suppression" not in record


def test_timestamps_cosmetics_and_housekeeping_do_not_change_key():
    record = finding()
    key = feedback_key(record)
    record["source_entry_updated_at"] = "2026-10-08T12:00:00Z"
    record["upstream_metadata"]["last_change_time"] = "2026-10-08T12:00:00Z"
    record["source_content"] = "  " + record["source_content"].replace("\n", "\n  ")
    record["upstream_comments"] = [
        {"text": "CC: person@example.org", "creation_time": "now"}
    ]
    assert feedback_key(record) == key


def test_scope_fixture_refresh_preserves_key_but_package_version_change_resurfaces():
    record = finding()
    record["scope_evidence"] = [
        {
            "package": "c-ares",
            "scope": "sysext",
            "source": "file:///workspace/sysext-sbom.json",
            "validated": True,
            "discovery_only": True,
            "evidence": {
                "name": "c-ares",
                "versionInfo": "1.34.5",
                "purls": [],
                "snapshot_sha256": "old-snapshot",
                "documentNamespace": "old-document",
            },
        }
    ]
    key = feedback_key(record)
    proof = record["scope_evidence"][0]["evidence"]
    proof["snapshot_sha256"] = "refreshed-snapshot"
    proof["documentNamespace"] = "refreshed-document"
    proof["generated_at"] = "2026-10-08T00:00:00Z"
    assert feedback_key(record) == key
    proof["versionInfo"] = "1.34.6"
    assert feedback_key(record) != key


def test_latest_confirmed_decision_revokes_or_resumes_tracking():
    record = finding()
    negative = confirmed(record, "not_shipped", comment_id=11)
    revoke = confirmed(record, "revoke", comment_id=12)
    annotate_review_feedback(record, revoke + negative, advisory_repository=REPO)
    assert record["review_suppression"]["suppressed"] is False
    assert record["review_suppression"]["decision"] == "revoke"


@pytest.mark.parametrize(
    "forgery",
    [
        "human-comment",
        "human-issue",
        "other-bot",
        "wrong-bot-id",
        "not-completed",
        "unchecked",
        "wrong-repo",
        "wrong-url",
        "duplicate-marker",
        "altered-manifest",
    ],
)
def test_forged_or_unapproved_feedback_never_suppresses(forgery):
    issue, comment = approved(checked=forgery != "unchecked")
    advisory_repo = REPO
    if forgery == "human-comment":
        comment["user"] = {"login": "maintainer", "type": "User"}
    elif forgery == "human-issue":
        issue.raw["user"] = {"login": "maintainer", "type": "User"}
    elif forgery == "other-bot":
        comment["user"] = {"login": "untrusted[bot]", "type": "Bot"}
    elif forgery == "wrong-bot-id":
        comment["user"] = {**BOT, "id": 12345}
    elif forgery == "not-completed":
        summary = json.loads(base64.b64decode(comment["body"].splitlines()[1]))
        summary["applied_state_reason"] = "not_planned"
        comment["body"] = (
            "<!-- security-triage:review-feedback:v1\n"
            + base64.b64encode(json.dumps(summary).encode()).decode()
            + "\n-->"
        )
    elif forgery == "wrong-repo":
        advisory_repo = "flatcar/Flatcar"
    elif forgery == "wrong-url":
        comment["html_url"] = "https://github.com/evil/repo/issues/10#issuecomment-11"
    elif forgery == "duplicate-marker":
        comment["body"] += "\n" + comment["body"]
    elif forgery == "altered-manifest":
        summary = json.loads(base64.b64decode(comment["body"].splitlines()[1]))
        summary["manifest_digest"] = "0" * 64
        comment["body"] = (
            "<!-- security-triage:review-feedback:v1\n"
            + base64.b64encode(json.dumps(summary).encode()).decode()
            + "\n-->"
        )
    assert not parse_feedback_summary(
        issue, comment, advisory_repository=advisory_repo, review_repository=REPO
    )


def test_naked_payload_or_forged_confirmed_flag_is_not_trusted():
    record = finding()
    payload = build_feedback_payload(record, "wrong_package", advisory_repository=REPO)
    payload["confirmed"] = True
    annotate_review_feedback(record, [payload], advisory_repository=REPO)
    assert "review_suppression" not in record


def test_payload_rejects_broad_or_cross_repository_decisions():
    payload = build_feedback_payload(
        finding(), "wrong_package", advisory_repository=REPO
    )
    with pytest.raises(ValueError, match="repository"):
        validate_feedback_payload(payload, advisory_repository="flatcar/Flatcar")
    payload["evidence_snapshot"]["cves"] = ["CVE-2026-*"]
    with pytest.raises(ValueError, match="snapshot"):
        validate_feedback_payload(payload)


def test_load_review_feedback_uses_api_authorship_and_correlation():
    issue, comment = approved()

    class Client:
        repo = REPO

        def list_issues_by_label(self, label, state):
            assert label == FEEDBACK_LABEL
            assert state == "all"
            return [issue]

        def list_comments(self, number):
            assert number == issue.number
            forged = {**comment, "user": {"login": "attacker", "type": "User"}}
            return [forged, comment]

    assert len(load_review_feedback(Client())) == 1


@pytest.mark.parametrize("limit", ["reviews", "per-issue", "total", "failure"])
def test_incomplete_feedback_scan_discards_older_decisions(limit):
    first, comment = approved()
    second = copy.deepcopy(first)
    second.number = 12
    second.html_url = f"https://github.com/{REPO}/issues/12"

    class Client:
        repo = REPO

        def list_issues_by_label(self, label, state):
            return [first, second]

        def list_comments(self, issue_number):
            if issue_number == second.number:
                if limit == "failure":
                    raise OSError("network unavailable")
                return [comment, comment]
            return [comment]

    limits = {
        "reviews": {"max_review_issues": 1},
        "per-issue": {"max_comments_per_issue": 1},
        "total": {"max_total_comments": 2},
        "failure": {},
    }
    feedback = load_review_feedback(Client(), **limits[limit])
    assert feedback == []
    assert feedback.coverage["complete"] is False
    assert feedback.coverage["warnings"]
    document = DiscoveryWorkflow(
        HeuristicModelClient(), SBOMIndex([]), [], feedback=feedback
    ).run([], "", "")
    assert document["feedback_coverage"] == feedback.coverage


def test_feedback_loader_uses_bounded_page_helpers():
    issue, comment = approved()

    class Client:
        repo = REPO

        def __init__(self):
            self.calls = []

        def list_issues_page(self, *, state, label, page, per_page):
            self.calls.append(("issues", page, per_page))
            assert state == "all"
            assert label == FEEDBACK_LABEL
            return [issue]

        def list_comments_page(self, number, *, page, per_page):
            self.calls.append(("comments", page, per_page))
            assert number == issue.number
            return [comment] * 100

        def list_comments(self, *args):
            pytest.fail("Unbounded comment listing must not be used")

    client = Client()
    feedback = load_review_feedback(client, max_comments_per_issue=150)
    assert feedback == []
    assert feedback.coverage["comments_scanned"] == 150
    assert feedback.coverage["complete"] is False
    assert client.calls == [
        ("issues", 1, 100),
        ("comments", 1, 100),
        ("comments", 2, 100),
    ]


@pytest.mark.parametrize("limit", [100, 200])
def test_feedback_pagination_counts_pr_rows_and_finds_later_revocation(
    monkeypatch, limit
):
    negative, negative_comment = approved()
    revoked, revoked_comment = approved(
        decision="revoke", comment_id=12, issue_number=12
    )
    pages = []

    def api_issue(issue):
        return {
            **{
                key: getattr(issue, key)
                for key in (
                    "number",
                    "title",
                    "body",
                    "labels",
                    "html_url",
                    "state",
                    "state_reason",
                )
            },
            "user": BOT.copy(),
        }

    def fetch(url, **kwargs):
        parsed = urlsplit(url)
        if parsed.path.endswith("/issues/10/comments"):
            return [negative_comment]
        if parsed.path.endswith("/issues/12/comments"):
            return [revoked_comment]
        page = int(parse_qs(parsed.query)["page"][0])
        pages.append(page)
        if page == 1:
            return [
                api_issue(negative),
                *[
                    {"number": number, "title": "No confirmed feedback"}
                    for number in range(100, 198)
                ],
                {"number": 300, "title": "A pull request", "pull_request": {}},
            ]
        assert page == 2
        return [api_issue(revoked)]

    monkeypatch.setattr(issues_module, "fetch_json", fetch)
    feedback = load_review_feedback(GitHubIssueClient(REPO), max_review_issues=limit)
    record = finding()
    annotate_review_feedback(record, feedback, advisory_repository=REPO)
    if limit == 100:
        assert pages == [1]
        assert feedback == []
        assert feedback.coverage["complete"] is False
        assert feedback.coverage["review_rows_scanned"] == 100
        assert feedback.coverage["review_issues_scanned"] == 99
        assert "review_suppression" not in record
    else:
        assert pages == [1, 2]
        assert len(feedback) == 2
        assert feedback.coverage["complete"] is True
        assert feedback.coverage["review_rows_scanned"] == 101
        assert feedback.coverage["review_issues_scanned"] == 100
        assert record["review_suppression"]["decision"] == "revoke"
        assert record["review_suppression"]["suppressed"] is False


def test_feedback_pagination_is_bounded_even_for_pr_only_pages(monkeypatch):
    pages = []

    def fetch(url, **kwargs):
        page = int(parse_qs(urlsplit(url).query)["page"][0])
        pages.append(page)
        assert page <= 2
        return [
            {"number": page * 100 + number, "pull_request": {}} for number in range(100)
        ]

    monkeypatch.setattr(issues_module, "fetch_json", fetch)
    feedback = load_review_feedback(GitHubIssueClient(REPO), max_review_issues=200)
    assert pages == [1, 2]
    assert feedback == []
    assert feedback.coverage["complete"] is False
    assert feedback.coverage["review_rows_scanned"] == 200
    assert feedback.coverage["review_issues_scanned"] == 0


def test_feedback_index_avoids_hundreds_of_unconfirmed_review_issues():
    issue, comment = approved()
    issue.labels.append(FEEDBACK_LABEL)
    historical_reviews = [
        Issue(
            number=number,
            title="Historical review without structured feedback",
            body="No confirmed feedback.",
            labels=["security-triage/review"],
            html_url=f"https://github.com/{REPO}/issues/{number}",
        )
        for number in range(100, 481)
    ]

    class Client:
        repo = REPO

        def list_issues_page(self, *, state, label, page, per_page):
            assert state == "all"
            assert label == FEEDBACK_LABEL
            assert page == 1
            return [
                item for item in [*historical_reviews, issue] if label in item.labels
            ]

        def list_comments_page(self, number, *, page, per_page):
            assert number == issue.number
            assert page == 1
            return [comment]

    feedback = load_review_feedback(Client())
    assert len(feedback) == 1
    assert feedback.coverage["complete"] is True
    assert feedback.coverage["review_label"] == FEEDBACK_LABEL
    assert feedback.coverage["review_issues_scanned"] == 1


def test_other_bot_identity_is_not_used_even_for_comment_discovery():
    issue, _ = approved()
    issue.raw["user"] = {"login": "arbitrary[bot]", "type": "Bot"}

    class Client:
        repo = REPO

        def list_issues_by_label(self, label, state):
            return [issue]

        def list_comments(self, number):
            pytest.fail("Do not retrieve feedback from a different bot's issue")

    feedback = load_review_feedback(Client())
    assert feedback == []
    assert feedback.coverage["complete"] is True


def test_reopened_review_preserves_approved_historical_feedback():
    issue, comment = approved()
    issue.state = "open"
    issue.state_reason = None
    issue.body = "Reopened for follow-up; original selections were edited."

    class Client:
        repo = REPO

        def list_issues_by_label(self, label, state):
            assert state == "all"
            return [issue]

        def list_comments(self, number):
            return [comment]

    feedback = load_review_feedback(Client())
    assert len(feedback) == 1
    assert feedback.coverage["complete"] is True
    assert feedback[0]["decision"] == "deferred"


def test_feedback_fixture_rejects_naked_decisions(monkeypatch):
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda *args, **kwargs: json.dumps([{"decision": "not_shipped"}]),
    )
    with pytest.raises(ValueError, match="envelope"):
        load_feedback_fixture("feedback.json", advisory_repository=REPO)


@pytest.mark.parametrize("approve_mutation", [False, True])
def test_discovery_review_apply_feedback_round_trip(approve_mutation):
    entry = SourceEntry(
        "gentoo",
        "https://bugs.gentoo.org/123",
        "123",
        "c-ares: memory corruption",
        "Package: c-ares\nCVE: CVE-2026-12345\nCVSS: 7.5\nFixed in 1.34.6",
    )
    sbom = SBOMIndex([SBOMPackage("c-ares", "1.34.5", "SPDXRef-cares")])
    model = HeuristicModelClient()
    document = DiscoveryWorkflow(model, sbom, [], target_repo=REPO).run([entry], "", "")
    context = ReviewContext(
        advisory_repo=REPO,
        review_repo=REPO,
        run_id="feedback-round-trip",
        generated_at="2026-10-07T12:00:00Z",
        enable_feedback=True,
    )
    batch = build_review_batch(context, document)
    feedback_group = next(group for group in batch.groups if group.source == "feedback")
    candidate = next(
        action
        for action in feedback_group.candidates
        if action.payload["decision"] == "wrong_package"
    )
    part = next(
        part for part in batch.parts if feedback_group.group_id in part.group_ids
    )
    issue = Issue(
        10,
        part.title,
        part.body.replace(
            render_checkbox_line(candidate.action_id, candidate.label),
            render_checkbox_line(candidate.action_id, candidate.label).replace(
                "[ ]", "[x]"
            ),
        ),
        ["security-triage/review"],
        f"https://github.com/{REPO}/issues/10",
        "closed",
        "completed",
        {"user": BOT.copy()},
    )
    if approve_mutation:
        mutation = next(
            action
            for group in batch.groups
            for action in group.candidates
            if action.kind == "discovery_create_issue"
        )
        issue.body = issue.body.replace(
            render_checkbox_line(mutation.action_id, mutation.label),
            render_checkbox_line(mutation.action_id, mutation.label).replace(
                "[ ]", "[x]"
            ),
        )

    class Client:
        repo = REPO

        def __init__(self):
            self.comments = []

        def get_issue(self, number):
            assert number == issue.number
            return issue

        def list_comments(self, number):
            assert number == issue.number
            return self.comments

        def post_comment(self, number, body):
            assert number == issue.number
            comment_id = 11 + len(self.comments)
            comment = {
                "id": comment_id,
                "html_url": issue.html_url + f"#issuecomment-{comment_id}",
                "body": body,
                "user": BOT.copy(),
                "created_at": "2026-10-07T12:00:00Z",
            }
            self.comments.append(comment)
            return comment

        def ensure_label_exists(self, *args, **kwargs):
            pass

        def add_labels(self, number, labels):
            assert number == issue.number
            issue.labels.extend(labels)

        def list_issues_by_label(self, label, state):
            return [issue]

    client = Client()
    result = apply_review_issue(
        client,
        client,
        GitHubActionRunner(client, ActionFlags()),
        issue.number,
        ApplyContext(REPO, REPO),
    )
    assert result["outcome"] == "applied"
    if approve_mutation:
        assert sum(group["outcome"] == "conflict" for group in result["groups"]) == 2
        assert load_review_feedback(client) == []
        return
    assert any(group.get("status") == "feedback_recorded" for group in result["groups"])
    feedback = load_review_feedback(client)
    assert len(feedback) == 1
    repeat = DiscoveryWorkflow(
        model, sbom, [], target_repo=REPO, feedback=feedback
    ).run([entry], "", "")
    record = repeat["records"][0]
    assert record["decision"] == document["records"][0]["decision"]
    assert record["review_suppression"]["suppressed"] is True
    full_review = build_review_batch(context, repeat)
    assert any(
        action.payload.get("decision") == "revoke"
        for group in full_review.groups
        for action in group.candidates
    )
    assert all(
        action.kind == FEEDBACK_KIND
        for group in full_review.groups
        for action in group.candidates
    )
