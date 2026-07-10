from security_triage.actions import ActionFlags, GitHubActionRunner


class FakeIssueClient:
    def __init__(self) -> None:
        self.body_updates: list[tuple[int, str]] = []
        self.comments: list[tuple[int, str]] = []
        self.created_issues: list[tuple[str, str, list[str]]] = []
        self.closed_issues: list[int] = []

    def create_issue(
        self, title: str, body: str, labels: list[str]
    ) -> dict[str, object]:
        self.created_issues.append((title, body, labels))
        return {"number": 999, "html_url": "https://github.com/x/y/issues/999"}

    def update_issue_body(self, issue_number: int, body: str) -> dict[str, object]:
        self.body_updates.append((issue_number, body))
        return {"number": issue_number, "body": body}

    def post_comment(self, issue_number: int, body: str) -> dict[str, object]:
        self.comments.append((issue_number, body))
        return {"number": issue_number, "body": body}

    def close_issue(self, issue_number: int) -> dict[str, object]:
        self.closed_issues.append(issue_number)
        return {"number": issue_number, "state": "closed"}


def test_apply_discovery_refuses_existing_issue_body_update_that_removes_cves():
    existing_body = (
        "Name: expat\n"
        "CVEs: CVE-2026-32776, CVE-2026-32777\n"
        "CVSSs: 7.5\n"
        "Action Needed: update to >= 2.7.5\n"
        "Summary: Existing human-curated context.\n"
        "\n"
        "refmap.gentoo: https://bugs.gentoo.org/971298"
    )
    unsafe_body = (
        "Name: expat\n"
        "CVEs: CVE-2026-41080\n"
        "CVSSs: 7.5\n"
        "Action Needed: update to >= 2.8.0\n"
        "Summary: New single-thread context.\n"
        "\n"
        "refmap.gentoo: https://bugs.gentoo.org/973144"
    )
    document = {
        "records": [
            {
                "record_id": "expat-973144",
                "decision": {"action": "update_existing_issue"},
                "proposed_update": {
                    "issue": 3000,
                    "updated_body": unsafe_body,
                    "comment_body": "Review new Bugzilla context.",
                    "matched_existing_issue": {"body": existing_body},
                },
            }
        ]
    }
    client = FakeIssueClient()

    results = GitHubActionRunner(
        client, ActionFlags(update_existing_issues=True)
    ).apply_discovery(document)

    assert client.body_updates == []
    assert client.comments == [(3000, "Review new Bugzilla context.")]
    assert results[0]["skipped"] is True
    assert "would remove existing content" in results[0]["reason"]


def test_create_issue_guarded_blocked_when_flag_disabled():
    client = FakeIssueClient()
    runner = GitHubActionRunner(client, ActionFlags())

    result = runner.create_issue_guarded(
        "disc-1", "title", "body", ["advisory", "security"]
    )

    assert result["outcome"] == "blocked"
    assert client.created_issues == []


def test_create_issue_guarded_blocked_when_action_id_not_allowlisted():
    client = FakeIssueClient()
    runner = GitHubActionRunner(
        client, ActionFlags(create_issues=True), allowed_action_ids={"disc-other"}
    )

    result = runner.create_issue_guarded(
        "disc-1", "title", "body", ["advisory", "security"]
    )

    assert result["outcome"] == "blocked"
    assert "allowlist" in result["reason"]
    assert client.created_issues == []


def test_create_issue_guarded_applies_when_allowed():
    client = FakeIssueClient()
    runner = GitHubActionRunner(
        client, ActionFlags(create_issues=True), allowed_action_ids={"disc-1"}
    )

    result = runner.create_issue_guarded(
        "disc-1", "title", "body", ["advisory", "security"]
    )

    assert result["outcome"] == "applied"
    assert client.created_issues == [("title", "body", ["advisory", "security"])]


def test_update_issue_body_guarded_blocks_removal_and_allows_additive_change():
    client = FakeIssueClient()
    runner = GitHubActionRunner(
        client, ActionFlags(update_existing_issues=True), allowed_action_ids={"disc-2"}
    )
    current = (
        "Name: expat\nCVEs: CVE-2026-1000, CVE-2026-2000\nCVSSs: n/a\n"
        "Action Needed: TBD\nSummary: s\n\nrefmap.gentoo: TBD"
    )
    unsafe = (
        "Name: expat\nCVEs: CVE-2026-1000\nCVSSs: n/a\nAction Needed: TBD\n"
        "Summary: s\n\nrefmap.gentoo: TBD"
    )
    safe = (
        "Name: expat\nCVEs: CVE-2026-1000, CVE-2026-2000, CVE-2026-3000\n"
        "CVSSs: n/a\nAction Needed: TBD\nSummary: s\n\nrefmap.gentoo: TBD"
    )

    blocked = runner.update_issue_body_guarded("disc-2", 10, current, unsafe)
    assert blocked["outcome"] == "blocked"
    assert client.body_updates == []

    applied = runner.update_issue_body_guarded("disc-2", 10, current, safe)
    assert applied["outcome"] == "applied"
    assert client.body_updates == [(10, safe)]


def test_update_issue_body_guarded_is_a_no_op_when_body_already_matches():
    client = FakeIssueClient()
    runner = GitHubActionRunner(client, ActionFlags(update_existing_issues=True))
    body = (
        "Name: x\nCVEs: CVE-2026-1000\nCVSSs: n/a\nAction Needed: TBD\n"
        "Summary: s\n\nrefmap.gentoo: TBD"
    )

    result = runner.update_issue_body_guarded("disc-3", 10, body, body)

    assert result["outcome"] == "no_op"
    assert client.body_updates == []


def test_post_comment_guarded_is_idempotent_when_already_posted():
    client = FakeIssueClient()
    runner = GitHubActionRunner(client, ActionFlags(post_cleanup_comments=True))

    result = runner.post_comment_guarded(
        "clean-1",
        20,
        "hello",
        required_permission="post_cleanup_comments",
        already_posted=True,
    )

    assert result["outcome"] == "no_op"
    assert client.comments == []


def test_post_comment_guarded_posts_when_allowed_and_not_already_posted():
    client = FakeIssueClient()
    runner = GitHubActionRunner(client, ActionFlags(post_cleanup_comments=True))

    result = runner.post_comment_guarded(
        "clean-1",
        20,
        "hello",
        required_permission="post_cleanup_comments",
        already_posted=False,
    )

    assert result["outcome"] == "applied"
    assert client.comments == [(20, "hello")]


def test_post_comment_guarded_does_not_cross_authorize_comment_kinds():
    cleanup_only = GitHubActionRunner(
        FakeIssueClient(), ActionFlags(post_cleanup_comments=True)
    )
    update_only = GitHubActionRunner(
        FakeIssueClient(), ActionFlags(update_existing_issues=True)
    )

    update_result = cleanup_only.post_comment_guarded(
        "disc-update",
        20,
        "discovery update",
        required_permission="update_existing_issues",
    )
    cleanup_result = update_only.post_comment_guarded(
        "cleanup-comment",
        20,
        "cleanup comment",
        required_permission="post_cleanup_comments",
    )

    assert update_result["outcome"] == "blocked"
    assert cleanup_result["outcome"] == "blocked"
    assert cleanup_only.client.comments == []
    assert update_only.client.comments == []


def test_close_issue_guarded_is_a_successful_no_op_when_already_closed():
    client = FakeIssueClient()
    runner = GitHubActionRunner(client, ActionFlags(close_issues=True))

    result = runner.close_issue_guarded("clean-2", 20, already_closed=True)

    assert result["outcome"] == "no_op"
    assert client.closed_issues == []


def test_close_issue_guarded_closes_when_allowed():
    client = FakeIssueClient()
    runner = GitHubActionRunner(client, ActionFlags(close_issues=True))

    result = runner.close_issue_guarded("clean-2", 20, already_closed=False)

    assert result["outcome"] == "applied"
    assert client.closed_issues == [20]


def test_action_allowed_defaults_to_true_without_an_explicit_allowlist():
    runner = GitHubActionRunner(FakeIssueClient(), ActionFlags())
    assert runner.action_allowed("anything") is True
