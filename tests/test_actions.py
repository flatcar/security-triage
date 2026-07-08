from security_triage.actions import ActionFlags, GitHubActionRunner


class FakeIssueClient:
    def __init__(self) -> None:
        self.body_updates: list[tuple[int, str]] = []
        self.comments: list[tuple[int, str]] = []

    def update_issue_body(self, issue_number: int, body: str) -> dict[str, object]:
        self.body_updates.append((issue_number, body))
        return {"number": issue_number, "body": body}

    def post_comment(self, issue_number: int, body: str) -> dict[str, object]:
        self.comments.append((issue_number, body))
        return {"number": issue_number, "body": body}


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

    results = GitHubActionRunner(client, ActionFlags(update_existing_issues=True)).apply_discovery(document)

    assert client.body_updates == []
    assert client.comments == [(3000, "Review new Bugzilla context.")]
    assert results[0]["skipped"] is True
    assert "would remove existing content" in results[0]["reason"]