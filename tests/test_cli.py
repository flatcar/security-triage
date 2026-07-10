import json
from pathlib import Path
from typing import Any

import pytest

from security_triage import cli
from security_triage.cli import build_parser, main
from security_triage.issues import issue_from_api

FIXTURES = Path(__file__).parent / "fixtures"


def test_discovery_default_window_days_is_seven():
    args = build_parser().parse_args(["discovery"])
    assert args.window_days == 7


def test_discovery_accepts_source_cache_flags():
    args = build_parser().parse_args(
        [
            "discovery",
            "--oss-security-cache-dir",
            "reports/.cache/source-downloads",
            "--go-vulndb-cache-dir",
            "reports/.cache/source-downloads",
            "--rustsec-cache-dir",
            "reports/.cache/source-downloads",
        ]
    )
    assert args.oss_security_cache_dir == "reports/.cache/source-downloads"
    assert args.go_vulndb_cache_dir == "reports/.cache/source-downloads"
    assert args.rustsec_cache_dir == "reports/.cache/source-downloads"


def test_cli_accepts_foundry_model_args():
    args = build_parser().parse_args(
        [
            "discovery",
            "--model",
            "foundry",
            "--foundry-endpoint",
            "https://example-foundry.cognitiveservices.azure.com",
            "--foundry-deployment",
            "gpt-5.4",
            "--foundry-extraction-deployment",
            "gpt-5.4-mini",
            "--foundry-api-version",
            "2024-06-01",
        ]
    )
    assert args.model == "foundry"
    assert (
        args.foundry_endpoint == "https://example-foundry.cognitiveservices.azure.com"
    )
    assert args.foundry_deployment == "gpt-5.4"
    assert args.foundry_extraction_deployment == "gpt-5.4-mini"
    assert args.foundry_api_version == "2024-06-01"


def test_cli_discovery_writes_json_and_markdown(tmp_path, capsys):
    output = tmp_path / "discovery.json"
    markdown = tmp_path / "discovery.md"
    result = main(
        [
            "discovery",
            "--source-fixture",
            str(FIXTURES / "discovery_entries.json"),
            "--issues-fixture",
            str(FIXTURES / "github_issues.json"),
            "--sbom-fixture",
            str(FIXTURES / "sbom.json"),
            "--output",
            str(output),
            "--markdown-output",
            str(markdown),
        ]
    )
    assert result == 0
    document = json.loads(output.read_text())
    assert document["workflow"] == "new_vulnerability_discovery"
    assert markdown.read_text().startswith("# Flatcar Vulnerability Discovery Dry Run")
    captured = capsys.readouterr()
    assert "Starting Flatcar vulnerability discovery" in captured.err


def test_cli_cleanup_writes_json_and_markdown(tmp_path):
    output = tmp_path / "cleanup.json"
    markdown = tmp_path / "cleanup.md"
    result = main(
        [
            "cleanup",
            "--issues-fixture",
            str(FIXTURES / "github_issues.json"),
            "--sbom-fixture",
            str(FIXTURES / "sbom.json"),
            "--output",
            str(output),
            "--markdown-output",
            str(markdown),
        ]
    )
    assert result == 0
    document = json.loads(output.read_text())
    assert document["workflow"] == "advisory_cleanup_recommendation"
    assert markdown.read_text().startswith("# Flatcar Advisory Cleanup Dry Run")


def test_cli_quiet_suppresses_progress_logs(tmp_path, capsys):
    output = tmp_path / "discovery.json"
    result = main(
        [
            "discovery",
            "--quiet",
            "--source-fixture",
            str(FIXTURES / "discovery_entries.json"),
            "--issues-fixture",
            str(FIXTURES / "github_issues.json"),
            "--sbom-fixture",
            str(FIXTURES / "sbom.json"),
            "--output",
            str(output),
        ]
    )
    assert result == 0
    captured = capsys.readouterr()
    assert "Starting Flatcar vulnerability discovery" not in captured.err


def test_discovery_accepts_advisory_repo_flag_and_defaults_to_flatcar_flatcar():
    with_flag = build_parser().parse_args(
        ["discovery", "--advisory-repo", "flatcar/security-triage"]
    )
    without_flag = build_parser().parse_args(["discovery"])
    assert with_flag.advisory_repo == "flatcar/security-triage"
    assert (
        without_flag.advisory_repo is None
    )  # resolved to TARGET_REPO at run time, not at parse time


def test_cli_discovery_writes_parameterized_target_repo(tmp_path):
    output = tmp_path / "discovery.json"
    result = main(
        [
            "discovery",
            "--quiet",
            "--source-fixture",
            str(FIXTURES / "discovery_entries.json"),
            "--issues-fixture",
            str(FIXTURES / "github_issues.json"),
            "--sbom-fixture",
            str(FIXTURES / "sbom.json"),
            "--advisory-repo",
            "flatcar/security-triage",
            "--output",
            str(output),
        ]
    )
    assert result == 0
    document = json.loads(output.read_text())
    assert document["target_repo"] == "flatcar/security-triage"


def test_cli_cleanup_writes_parameterized_target_repo_and_query(tmp_path):
    output = tmp_path / "cleanup.json"
    result = main(
        [
            "cleanup",
            "--quiet",
            "--issues-fixture",
            str(FIXTURES / "github_issues.json"),
            "--sbom-fixture",
            str(FIXTURES / "sbom.json"),
            "--advisory-repo",
            "flatcar/security-triage",
            "--output",
            str(output),
        ]
    )
    assert result == 0
    document = json.loads(output.read_text())
    assert document["target_repo"] == "flatcar/security-triage"
    assert document["issue_query"].startswith("repo:flatcar/security-triage")
    assert "flatcar/Flatcar" not in document["issue_query"]


def test_review_render_and_create_and_apply_are_registered_subcommands():
    args = build_parser().parse_args(
        ["review", "render", "--advisory-repo", "a/b", "--review-repo", "a/b"]
    )
    assert args.review_command == "render"
    args = build_parser().parse_args(
        ["review", "create", "--advisory-repo", "a/b", "--review-repo", "a/b"]
    )
    assert args.review_command == "create"
    args = build_parser().parse_args(
        [
            "review",
            "apply",
            "--issue-number",
            "5",
            "--advisory-repo",
            "a/b",
            "--review-repo",
            "a/b",
        ]
    )
    assert args.review_command == "apply"
    assert args.issue_number == 5


def test_review_render_requires_explicit_repos_with_no_flatcar_flatcar_default(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("SECURITY_TRIAGE_ADVISORY_REPO", raising=False)
    monkeypatch.delenv("SECURITY_TRIAGE_REVIEW_REPO", raising=False)
    result = main(
        ["review", "render", "--quiet", "--output-dir", str(tmp_path / "out")]
    )
    assert result == 1


def test_cli_review_render_dry_run_writes_exact_body_and_no_mutation(tmp_path):
    discovery_output = tmp_path / "discovery.json"
    main(
        [
            "discovery",
            "--quiet",
            "--source-fixture",
            str(FIXTURES / "discovery_entries.json"),
            "--issues-fixture",
            str(FIXTURES / "github_issues.json"),
            "--sbom-fixture",
            str(FIXTURES / "sbom.json"),
            "--advisory-repo",
            "flatcar/security-triage",
            "--output",
            str(discovery_output),
        ]
    )
    output_dir = tmp_path / "review-dry-run"

    result = main(
        [
            "review",
            "render",
            "--quiet",
            "--discovery-json",
            str(discovery_output),
            "--advisory-repo",
            "flatcar/security-triage",
            "--review-repo",
            "flatcar/security-triage",
            "--run-id",
            "cli-smoke-1",
            "--output-dir",
            str(output_dir),
        ]
    )

    assert result == 0
    part_path = output_dir / "cli-smoke-1-part-1.md"
    assert part_path.exists()
    assert (output_dir / "dry-run-summary.md").exists()
    text = part_path.read_text(encoding="utf-8")
    assert (
        "security-triage dry-run review output: no GitHub mutation was performed"
        in text
    )
    assert "flatcar/security-triage" in text


class _FakeReviewClient:
    """Minimal stateful fake covering exactly the GitHubIssueClient methods
    the CLI wires up."""

    def __init__(self, repo: str, token: str | None = None) -> None:
        self.repo = repo
        self.token = token
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

    def fetch_open_advisory_issues(self, query=None):
        return [
            issue_from_api(item)
            for item in self._issues.values()
            if item["state"] == "open"
        ]

    def get_issue(self, issue_number: int):
        return issue_from_api(self._issues[issue_number])

    def list_issues_by_label(self, label: str, state: str = "all"):
        return [
            issue_from_api(item)
            for item in self._issues.values()
            if label in {entry["name"] for entry in item["labels"]}
            and (state == "all" or item["state"] == state)
        ]

    def list_comments(self, issue_number: int):
        return list(self._comments.get(issue_number, []))

    def ensure_label_exists(
        self, name: str, color: str = "", description: str = ""
    ) -> None:
        return None

    def add_labels(self, issue_number: int, labels: list[str]):
        item = self._issues[issue_number]
        existing = {entry["name"] for entry in item["labels"]}
        for label in labels:
            if label not in existing:
                item["labels"].append({"name": label})
        return {"number": issue_number}

    def create_issue(self, title: str, body: str, labels: list[str]):
        number = self._next_number
        self._next_number += 1
        self.seed_issue(number, title, body, labels, state="open")
        return {"number": number, "html_url": self._issues[number]["html_url"]}

    def update_issue_body(self, issue_number: int, body: str):
        self._issues[issue_number]["body"] = body
        return {"number": issue_number}

    def post_comment(self, issue_number: int, body: str):
        comment = {
            "id": len(self._comments.setdefault(issue_number, [])) + 1,
            "body": body,
        }
        self._comments[issue_number].append(comment)
        return comment

    def close_issue(self, issue_number: int):
        self._issues[issue_number]["state"] = "closed"
        return {"number": issue_number}


@pytest.fixture
def fake_review_client(monkeypatch):
    clients: dict[str, _FakeReviewClient] = {}

    def factory(repo: str, token: str | None = None):
        client = clients.setdefault(repo, _FakeReviewClient(repo, token))
        return client

    monkeypatch.setattr(cli, "GitHubIssueClient", factory)
    return clients


def test_cli_review_create_then_apply_end_to_end(tmp_path, fake_review_client):
    discovery_output = tmp_path / "discovery.json"
    main(
        [
            "discovery",
            "--quiet",
            "--source-fixture",
            str(FIXTURES / "discovery_entries.json"),
            "--issues-fixture",
            str(FIXTURES / "github_issues.json"),
            "--sbom-fixture",
            str(FIXTURES / "sbom.json"),
            "--advisory-repo",
            "flatcar/security-triage",
            "--output",
            str(discovery_output),
        ]
    )
    create_output = tmp_path / "review-create.json"
    result = main(
        [
            "review",
            "create",
            "--quiet",
            "--discovery-json",
            str(discovery_output),
            "--advisory-repo",
            "flatcar/security-triage",
            "--review-repo",
            "flatcar/security-triage",
            "--run-id",
            "cli-e2e-1",
            "--output",
            str(create_output),
        ]
    )
    assert result == 0
    created = json.loads(create_output.read_text())
    assert created["created"] is True
    issue_number = created["parts"][0]["issue_number"]

    # Not-planned close must apply zero mutations.
    client = fake_review_client["flatcar/security-triage"]
    client._issues[issue_number]["state"] = "closed"
    client._issues[issue_number]["state_reason"] = "not_planned"
    apply_output = tmp_path / "review-apply-not-planned.json"
    result = main(
        [
            "review",
            "apply",
            "--quiet",
            "--issue-number",
            str(issue_number),
            "--advisory-repo",
            "flatcar/security-triage",
            "--review-repo",
            "flatcar/security-triage",
            "--enable-all-review-actions",
            "--output",
            str(apply_output),
        ]
    )
    assert result == 0
    apply_result = json.loads(apply_output.read_text())
    assert apply_result["outcome"] == "skipped"

    # Re-run created a fresh idempotent check; rerunning create must not
    # duplicate the issue.
    result = main(
        [
            "review",
            "create",
            "--quiet",
            "--discovery-json",
            str(discovery_output),
            "--advisory-repo",
            "flatcar/security-triage",
            "--review-repo",
            "flatcar/security-triage",
            "--run-id",
            "cli-e2e-1",
            "--output",
            str(create_output),
        ]
    )
    assert result == 0
    rerun_created = json.loads(create_output.read_text())
    assert rerun_created["parts"][0]["created"] is False
    assert rerun_created["parts"][0]["issue_number"] == issue_number


def test_cli_review_apply_without_mutation_flags_still_reports_skip(
    tmp_path, fake_review_client
):
    client = cli.GitHubIssueClient("flatcar/security-triage")
    from security_triage.review import (
        ReviewContext,
        build_review_batch,
        create_review_batch,
    )

    context = ReviewContext(
        advisory_repo="flatcar/security-triage",
        review_repo="flatcar/security-triage",
        run_id="cli-noflags-1",
        generated_at="2026-07-10T06:00:00+00:00",
    )
    document = {
        "schema_version": "1.0",
        "workflow": "new_vulnerability_discovery",
        "generated_at": "2026-07-10T00:00:00Z",
        "target_repo": "flatcar/security-triage",
        "processing_window": {"start": "a", "end": "b", "timezone": "UTC"},
        "sources": [],
        "model": {},
        "errors": [],
        "records": [
            {
                "record_id": "gentoo:cli-1",
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
                "decision": {
                    "action": "create_issue",
                    "confidence": "high",
                    "reason": "clear",
                },
                "proposed_issue": {
                    "title": "update: widget",
                    "body": (
                        "Name: widget\nCVEs: CVE-2026-9001\nCVSSs: 7.5\n"
                        "Action Needed: update to >= 1.2\nSummary: widget issue\n\n"
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
        ],
    }
    batch = build_review_batch(context, document, None)
    results = create_review_batch(client, batch)
    issue_number = results[0].issue_number
    body = client._issues[issue_number]["body"]
    action_id = batch.parts[0].manifest["groups"][0]["actions"][0]["action_id"]
    marker = f"<!-- security-triage:action-id:{action_id} -->"
    body = "\n".join(
        line.replace("[ ]", "[x]") if marker in line else line
        for line in body.splitlines()
    )
    client._issues[issue_number]["body"] = body
    client._issues[issue_number]["state"] = "closed"
    client._issues[issue_number]["state_reason"] = "completed"

    apply_output = tmp_path / "review-apply.json"
    result = main(
        [
            "review",
            "apply",
            "--quiet",
            "--issue-number",
            str(issue_number),
            "--advisory-repo",
            "flatcar/security-triage",
            "--review-repo",
            "flatcar/security-triage",
            "--output",
            str(apply_output),
        ]
    )
    # No mutation flags were passed, so the create is blocked -- but the
    # overall apply run still completes (exit 0) because a disabled flag is a
    # deliberate skip, not an operational failure.
    assert result == 0
    apply_result = json.loads(apply_output.read_text())
    assert apply_result["groups"][0]["outcome"] == "skipped"
    assert len(client._issues) == 1
