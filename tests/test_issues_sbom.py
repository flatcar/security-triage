from pathlib import Path

import pytest

from security_triage import issues as issues_module
from security_triage.http_utils import HTTPError
from security_triage.issues import (
    GitHubIssueClient,
    find_existing_issue_matches,
    load_issue_fixture,
    parse_issue_body,
)
from security_triage.rules import RepositoryValidationError, advisory_issue_query
from security_triage.sbom import (
    compare_simple_versions,
    evaluate_fixed_version_requirements,
    extract_fixed_version_requirement,
    extract_fixed_version_requirements,
    fixed_version_requirements_are_alternatives,
    load_sbom_fixture,
)


def test_list_all_issues_uses_consistent_endpoint_without_label_filter(monkeypatch):
    urls = []

    def fetch(url, **kwargs):
        urls.append(url)
        return [
            {"number": 430, "title": "update: expat", "labels": []},
            {"number": 431, "title": "a pull request", "pull_request": {}},
        ]

    monkeypatch.setattr(issues_module, "fetch_json", fetch)
    client = GitHubIssueClient("flatcar/security-triage")
    assert [issue.number for issue in client.list_issues()] == [430]
    assert "/repos/flatcar/security-triage/issues?" in urls[0]
    assert "labels=" not in urls[0] and "/search/" not in urls[0]


def test_list_all_issues_fails_closed_on_malformed_response(monkeypatch):
    monkeypatch.setattr(issues_module, "fetch_json", lambda *args, **kwargs: {})
    with pytest.raises(HTTPError):
        GitHubIssueClient("flatcar/security-triage").list_issues()


@pytest.mark.parametrize(
    "summary",
    [
        "A vulnerability in the Rust crate tar.",
        "Upstream: https://rustsec.org/advisories/RUSTSEC-2026-0001.html",
        "Package URL: pkg:cargo/tar",
        "Note: Canonical package identity: `pkg:cargo/other`.",
        "Note: Canonical package identity: `pkg:cargo/tar@1.0`.",
        "Note: Canonical package identity: `pkg:cargo/tar`."
        " Note: Canonical package identity: `pkg:cargo/tar`.",
    ],
)
def test_ambiguous_or_conflicting_summary_identity_never_matches_native_tar(summary):
    body = (
        "Name: tar\nCVEs: CVE-2026-12345\nCVSSs: n/a\n"
        f"Action Needed: TBD\nSummary: {summary}\n\nrefmap.gentoo: TBD"
    )
    parsed = parse_issue_body(body)
    assert parsed.identity == ""
    assert not parsed.valid
    advisory = issues_module.issue_from_api(
        {"number": 1, "title": "update: tar", "body": body, "labels": []}
    )
    assert not find_existing_issue_matches({"package_name": "tar"}, [advisory])
    assert not find_existing_issue_matches(
        {"package_purl": "pkg:cargo/tar"}, [advisory]
    )


def test_legacy_native_names_remain_compatible_but_do_not_authorize_cargo_updates():
    advisory = issues_module.issue_from_api(
        {"number": 1, "title": "update: tar", "body": "Name: tar", "labels": []}
    )
    assert find_existing_issue_matches({"package_name": "tar"}, [advisory])
    assert not find_existing_issue_matches(
        {"package_purl": "pkg:cargo/tar"}, [advisory]
    )


def test_fetch_open_update_issues_includes_ordinary_updates_not_review_issues(
    monkeypatch,
):
    monkeypatch.setattr(
        issues_module,
        "fetch_json",
        lambda *args, **kwargs: [
            {"number": 430, "title": "update: expat", "labels": []},
            {"number": 431, "title": "review", "labels": ["security-triage/review"]},
            {
                "number": 432,
                "title": "security advisory",
                "labels": ["advisory", "security"],
            },
            {"number": 433, "title": "unrelated", "body": "Name: expat", "labels": []},
        ],
    )
    assert [
        issue.number for issue in GitHubIssueClient().fetch_open_update_issues()
    ] == [430, 432]


def test_update_comment_uses_repository_comment_endpoint(monkeypatch):
    client = GitHubIssueClient("flatcar/security-triage")
    requests = []

    def request(method, path, payload):
        requests.append((method, path, payload))
        return {"id": 146}

    monkeypatch.setattr(client, "_request_json", request)
    assert client.update_comment(146, "execution snapshot") == {"id": 146}
    assert requests == [
        (
            "PATCH",
            "/repos/flatcar/security-triage/issues/comments/146",
            {"body": "execution snapshot"},
        )
    ]


def test_bounded_issue_page_retains_raw_count_after_filtering_pull_requests(
    monkeypatch,
):
    urls = []

    def fetch(url, **kwargs):
        urls.append(url)
        return [{"number": 1}, {"number": 2, "pull_request": {}}]

    monkeypatch.setattr(issues_module, "fetch_json", fetch)
    page = GitHubIssueClient().list_issues_page(page=2, per_page=2)
    assert [issue.number for issue in page] == [1]
    assert page.raw_count == 2
    assert len(urls) == 1 and "page=2&per_page=2" in urls[0]


def test_bounded_comment_page_does_not_request_following_pages(monkeypatch):
    urls = []

    def fetch(url, **kwargs):
        urls.append(url)
        return [{"id": 1}, {"id": 2}]

    monkeypatch.setattr(issues_module, "fetch_json", fetch)
    assert len(GitHubIssueClient().list_comments_page(146, page=3, per_page=2)) == 2
    assert len(urls) == 1 and "/issues/146/comments?page=3&per_page=2" in urls[0]


@pytest.mark.parametrize("page,per_page", [(0, 100), (1, 101), (True, 100), (1, 0)])
def test_bounded_page_parameters_are_validated(page, per_page):
    client = GitHubIssueClient()
    with pytest.raises(ValueError):
        client.list_issues_page(page=page, per_page=per_page)
    with pytest.raises(ValueError):
        client.list_comments_page(146, page=page, per_page=per_page)


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_issue_body_expected_format():
    issues = load_issue_fixture(str(FIXTURES / "github_issues.json"))
    parsed = parse_issue_body(issues[0].body)
    assert parsed.valid
    assert parsed.name == "rust-openssl"
    assert parsed.cves == ["CVE-2026-10001"]
    assert parsed.action_needed == "update to >= 0.10.78"


def test_parse_issue_body_accepts_bold_manual_field_labels():
    parsed = parse_issue_body(
        "**Name**: expat\n"
        "**CVEs**: CVE-2026-32776, CVE-2026-32777\n"
        "**CVSSs**: 7.5\n"
        "**Action Needed**: update to >= 2.7.5\n"
        "**Summary**:\n"
        "  * Existing human-written context.\n"
        "\n"
        "**refmap.gentoo**: CVE-2026-3277[6-8]: https://bugs.gentoo.org/971298"
    )

    assert parsed.valid
    assert parsed.name == "expat"
    assert parsed.cves == ["CVE-2026-32776", "CVE-2026-32777"]
    assert parsed.summary == "* Existing human-written context."
    assert parsed.gentoo_ref == "CVE-2026-3277[6-8]: https://bugs.gentoo.org/971298"


def test_parse_issue_body_accepts_live_markdown_fields_and_active_text():
    body = """**Name**: libxml2
**CVEs**: ~[CVE-2026-0989](https://www.cve.org/CVERecord?id=CVE-2026-0989)~, [CVE-2026-6732](https://www.cve.org/CVERecord?id=CVE-2026-6732)
**CVSSs**: ~3.7~, 6.5
**Action Needed**: ~CVE-2026-0989: update to >= 2.15.2~, CVE-2026-6732: TBD

**Summary**: active summary

**refmap.gentoo**: TBD
"""
    parsed = parse_issue_body(body)

    assert parsed.valid
    assert parsed.name == "libxml2"
    assert parsed.cves == ["CVE-2026-6732"]
    assert parsed.cvss_scores == ["6.5"]
    assert parsed.action_needed == "CVE-2026-6732: TBD"


def test_existing_issue_matching_by_package_and_cve():
    issues = load_issue_fixture(str(FIXTURES / "github_issues.json"))
    matches = find_existing_issue_matches(
        {"package_name": "rust-openssl", "cves": ["CVE-2026-30002"]}, issues
    )
    assert matches
    assert matches[0]["issue"] == 2109
    assert "package_name" in matches[0]["match_reasons"]


def test_sbom_exact_name_and_purl_matching():
    sbom = load_sbom_fixture(str(FIXTURES / "sbom.json"))
    matches = sbom.match_package("dev-libs/openssl")
    assert len(matches) == 1
    assert matches[0]["name"] == "openssl"
    assert matches[0]["match_type"] == "exact_name"


def test_fixed_version_and_simple_compare():
    assert extract_fixed_version_requirement("update to >= 1.12.2") == "1.12.2"
    assert extract_fixed_version_requirement("Upgrade to >=1.8.1.3") == "1.8.1.3"
    assert compare_simple_versions("1.12.3", "1.12.2").result == "at_or_above"
    assert compare_simple_versions("1.12.1", "1.12.2").result == "below"
    assert compare_simple_versions("1.12.3-r1", "1.12.2").result == "at_or_above"
    assert compare_simple_versions("2.42-r7", "2.42-r6").result == "at_or_above"
    assert compare_simple_versions("260.1-r1", "260").result == "at_or_above"


def test_fixed_version_ignores_struck_through_requirements_with_active_tbd():
    action_needed = "~CVE-2026-0989: update to >= 2.15.2~, CVE-2026-6732: TBD"

    assert extract_fixed_version_requirement(action_needed) is None


def test_fixed_version_uses_single_active_requirement_after_struck_through():
    action_needed = (
        "~CVE-2026-0989: update to >= 2.15.2~, CVE-2026-6732: update to >= 2.15.3"
    )

    assert extract_fixed_version_requirement(action_needed) == "2.15.3"


def test_fixed_version_selects_highest_active_requirement():
    action_needed = (
        "CVE-2026-1111: update to >= 1.2.3, CVE-2026-2222: update to >= 1.3.0"
    )

    assert extract_fixed_version_requirements(action_needed) == ["1.2.3", "1.3.0"]
    assert extract_fixed_version_requirement(action_needed) == "1.3.0"


def test_or_style_alternatives_are_detected():
    action_needed = "update to >= 260 or 259.5"

    assert fixed_version_requirements_are_alternatives(action_needed)
    assert not fixed_version_requirements_are_alternatives(
        "CVE-2026-1111: update to >= 1.2.3, CVE-2026-2222: update to >= 1.3.0"
    )


def test_or_style_alternatives_remediated_when_lower_branch_satisfied():
    requirements = ["260", "259.5"]

    comparison = evaluate_fixed_version_requirements(
        "259.6", requirements, alternatives=True
    )
    assert comparison.result == "at_or_above"

    # Under AND-semantics the same installed version would be below the highest.
    assert (
        evaluate_fixed_version_requirements(
            "259.6", requirements, alternatives=False
        ).result
        == "below"
    )


def test_or_style_alternatives_not_remediated_when_below_all():
    requirements = ["260", "259.5"]

    assert (
        evaluate_fixed_version_requirements(
            "259.4", requirements, alternatives=True
        ).result
        == "below"
    )


def test_or_style_alternatives_ambiguous_when_not_conclusive():
    requirements = ["260", "259.5"]

    assert (
        evaluate_fixed_version_requirements(
            "259.6-rc1", requirements, alternatives=True
        ).result
        == "ambiguous"
    )


def test_github_issue_client_validates_repo_on_construction():
    with pytest.raises(RepositoryValidationError):
        GitHubIssueClient(repo="not-a-valid-repo")


def test_fetch_open_advisory_issues_defaults_to_the_configured_repo(monkeypatch):
    captured_urls = []

    def fake_fetch_json(url, token=None, accept="application/json"):
        captured_urls.append(url)
        return {"items": []}

    monkeypatch.setattr(issues_module, "fetch_json", fake_fetch_json)
    client = GitHubIssueClient(repo="flatcar/security-triage")

    client.fetch_open_advisory_issues()

    assert len(captured_urls) == 1
    assert (
        "flatcar%2Fsecurity-triage" in captured_urls[0]
        or "flatcar/security-triage" in captured_urls[0]
    )
    assert "flatcar%2FFlatcar" not in captured_urls[0]


def test_get_issue_returns_state_reason(monkeypatch):
    def fake_fetch_json(url, token=None, accept="application/json"):
        assert url.endswith("/repos/flatcar/security-triage/issues/42")
        return {
            "number": 42,
            "title": "t",
            "body": "b",
            "labels": [],
            "html_url": "u",
            "state": "closed",
            "state_reason": "completed",
        }

    monkeypatch.setattr(issues_module, "fetch_json", fake_fetch_json)
    client = GitHubIssueClient(repo="flatcar/security-triage")

    issue = client.get_issue(42)

    assert issue.number == 42
    assert issue.state == "closed"
    assert issue.state_reason == "completed"


def test_list_issues_by_label_paginates_and_skips_pull_requests(monkeypatch):
    pages = [
        [
            {
                "number": i,
                "title": "t",
                "body": "",
                "labels": [],
                "html_url": "u",
                "state": "open",
            }
            for i in range(100)
        ],
        [
            {
                "number": 200,
                "title": "t",
                "body": "",
                "labels": [],
                "html_url": "u",
                "state": "open",
            },
            {
                "number": 201,
                "title": "pr",
                "body": "",
                "labels": [],
                "html_url": "u",
                "state": "open",
                "pull_request": {},
            },
        ],
    ]

    def fake_fetch_json(url, token=None, accept="application/json"):
        assert "labels=security-triage%2Freview" in url
        assert "state=all" in url
        page_number = int(url.split("page=")[-1])
        return pages[page_number - 1]

    monkeypatch.setattr(issues_module, "fetch_json", fake_fetch_json)
    client = GitHubIssueClient(repo="flatcar/security-triage")

    result = client.list_issues_by_label("security-triage/review")

    assert len(result) == 101
    assert all(issue.number != 201 for issue in result)


def test_list_comments_paginates(monkeypatch):
    pages = [
        [{"id": i, "body": f"comment {i}"} for i in range(100)],
        [{"id": 200, "body": "last"}],
    ]

    def fake_fetch_json(url, token=None, accept="application/json"):
        page_number = int(url.split("page=")[-1])
        return pages[page_number - 1]

    monkeypatch.setattr(issues_module, "fetch_json", fake_fetch_json)
    client = GitHubIssueClient(repo="flatcar/security-triage")

    comments = client.list_comments(7)

    assert len(comments) == 101
    assert comments[-1]["body"] == "last"


def test_ensure_label_exists_skips_creation_when_label_already_exists(monkeypatch):
    def fake_fetch_json(url, token=None, accept="application/json"):
        return {"name": "security-triage/review"}

    def boom_request_json(self, method, path, payload):
        raise AssertionError("must not attempt to create a label that already exists")

    monkeypatch.setattr(issues_module, "fetch_json", fake_fetch_json)
    monkeypatch.setattr(GitHubIssueClient, "_request_json", boom_request_json)
    client = GitHubIssueClient(repo="flatcar/security-triage")

    client.ensure_label_exists("security-triage/review")


def test_ensure_label_exists_creates_missing_label(monkeypatch):
    created = {}

    def fake_fetch_json(url, token=None, accept="application/json"):
        raise HTTPError("GitHub API HTTP 404 for /repos/x/labels/y: not found")

    def fake_request_json(self, method, path, payload):
        created["method"] = method
        created["path"] = path
        created["payload"] = payload
        return {"name": payload["name"]}

    monkeypatch.setattr(issues_module, "fetch_json", fake_fetch_json)
    monkeypatch.setattr(GitHubIssueClient, "_request_json", fake_request_json)
    client = GitHubIssueClient(repo="flatcar/security-triage")

    client.ensure_label_exists(
        "security-triage/review", color="5319e7", description="d"
    )

    assert created["method"] == "POST"
    assert created["path"] == "/repos/flatcar/security-triage/labels"
    assert created["payload"] == {
        "name": "security-triage/review",
        "color": "5319e7",
        "description": "d",
    }


def test_ensure_label_exists_tolerates_concurrent_creation_race(monkeypatch):
    def fake_fetch_json(url, token=None, accept="application/json"):
        raise HTTPError("GitHub API HTTP 404 for /repos/x/labels/y: not found")

    def fake_request_json(self, method, path, payload):
        raise HTTPError("GitHub API HTTP 422 for /repos/x/labels: already_exists")

    monkeypatch.setattr(issues_module, "fetch_json", fake_fetch_json)
    monkeypatch.setattr(GitHubIssueClient, "_request_json", fake_request_json)
    client = GitHubIssueClient(repo="flatcar/security-triage")

    client.ensure_label_exists("security-triage/review")


def test_ensure_label_exists_reraises_unexpected_errors(monkeypatch):
    def fake_fetch_json(url, token=None, accept="application/json"):
        raise HTTPError("HTTP 500 for /repos/x/labels/y: server error")

    monkeypatch.setattr(issues_module, "fetch_json", fake_fetch_json)
    client = GitHubIssueClient(repo="flatcar/security-triage")

    with pytest.raises(HTTPError, match="500"):
        client.ensure_label_exists("security-triage/review")


def test_add_labels_posts_expected_payload(monkeypatch):
    captured = {}

    def fake_request_json(self, method, path, payload):
        captured["method"] = method
        captured["path"] = path
        captured["payload"] = payload
        return {}

    monkeypatch.setattr(GitHubIssueClient, "_request_json", fake_request_json)
    client = GitHubIssueClient(repo="flatcar/security-triage")

    client.add_labels(5, ["security-triage/review-applied"])

    assert captured == {
        "method": "POST",
        "path": "/repos/flatcar/security-triage/issues/5/labels",
        "payload": {"labels": ["security-triage/review-applied"]},
    }


def test_advisory_issue_query_matches_client_default(monkeypatch):
    captured_urls = []

    def fake_fetch_json(url, token=None, accept="application/json"):
        captured_urls.append(url)
        return {"items": []}

    monkeypatch.setattr(issues_module, "fetch_json", fake_fetch_json)
    client = GitHubIssueClient(repo="flatcar/security-triage")
    client.fetch_open_advisory_issues()

    import urllib.parse

    query = urllib.parse.parse_qs(urllib.parse.urlsplit(captured_urls[0]).query)["q"][0]
    assert query == advisory_issue_query("flatcar/security-triage")
