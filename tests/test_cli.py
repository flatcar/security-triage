import json
from pathlib import Path
from typing import Any

import pytest

from security_triage import cli
from security_triage.cli import build_parser, main
from security_triage.issues import issue_from_api

FIXTURES = Path(__file__).parent / "fixtures"


# --- Parser: direct-mutation flags must not exist on discovery or cleanup -----


def test_discovery_parser_rejects_apply_actions():
    """discovery must never accept --apply-actions; direct writes are banned."""
    with pytest.raises(SystemExit):
        build_parser().parse_args(["discovery", "--apply-actions"])


def test_discovery_parser_rejects_enable_create_issues():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["discovery", "--enable-create-issues"])


def test_discovery_parser_rejects_enable_update_issues():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["discovery", "--enable-update-issues"])


def test_cleanup_parser_rejects_apply_actions():
    """cleanup must never accept --apply-actions; direct writes are banned."""
    with pytest.raises(SystemExit):
        build_parser().parse_args(["cleanup", "--apply-actions"])


def test_cleanup_parser_rejects_enable_post_cleanup_comments():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["cleanup", "--enable-post-cleanup-comments"])


def test_cleanup_parser_rejects_enable_close_issues():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["cleanup", "--enable-close-issues"])


def test_discovery_default_window_days_is_seven():
    args = build_parser().parse_args(["discovery"])
    assert args.window_days == 7


def test_review_presentation_controls_do_not_disable_discovery():
    args = cli.build_parser().parse_args(
        [
            "review",
            "render",
            "--go-review",
            "defer",
            "--rust-review",
            "include",
            "--enable-feedback",
        ]
    )
    assert args.review_detail == "compact"
    assert args.go_review == "defer"
    assert args.rust_review == "include"
    assert args.enable_feedback is True
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["discovery", "--go-review", "defer"])


def test_feedback_reads_are_opt_in_and_offline_replay_is_exclusive():
    parser = cli.build_parser()
    args = parser.parse_args(["discovery"])
    assert args.feedback_review_repo is None
    assert args.feedback_fixture is None
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "discovery",
                "--feedback-review-repo",
                "flatcar/security-triage",
                "--feedback-fixture",
                "feedback.json",
            ]
        )


def test_discovery_scope_snapshots_have_provenance_and_are_not_cleanup_inputs():
    parser = cli.build_parser()
    args = parser.parse_args(
        [
            "discovery",
            "--sdk-sbom-fixture",
            str(FIXTURES / "sbom.json"),
            "--sysext-sbom-fixture",
            str(FIXTURES / "sbom.json"),
        ]
    )
    evidence = [
        item
        for scope, index in cli._load_discovery_scope_sboms(args)
        for item in index.discovery_scope_evidence("openssl", scope)
    ]
    assert {entry["scope"] for entry in evidence} == {"sdk_only", "sysext"}
    assert all(entry["validated"] is True for entry in evidence)
    assert all(entry["snapshot_source"].startswith("file:") for entry in evidence)
    assert all(len(entry["snapshot_sha256"]) == 64 for entry in evidence)
    assert all(entry["discovery_only"] is True for entry in evidence)
    with pytest.raises(SystemExit):
        parser.parse_args(["cleanup", "--sdk-sbom-fixture", "sdk.json"])


def test_discovery_scope_snapshot_rejects_missing_spdx_metadata(tmp_path):
    path = tmp_path / "not-spdx.json"
    path.write_text('{"packages": [{"name": "bubblewrap", "versionInfo": "1.0"}]}')
    args = cli.build_parser().parse_args(["discovery", "--sdk-sbom-fixture", str(path)])
    with pytest.raises(ValueError, match="SPDX version"):
        cli._load_discovery_scope_sboms(args)


def test_ambiguous_scope_snapshot_does_not_supply_trusted_proof(tmp_path):
    path = tmp_path / "sdk.json"
    path.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {"name": "bubblewrap", "versionInfo": "1.0"},
                    {"name": "bubblewrap", "versionInfo": "2.0"},
                ],
            }
        )
    )
    args = cli.build_parser().parse_args(["discovery", "--sdk-sbom-fixture", str(path)])
    [(scope, index)] = cli._load_discovery_scope_sboms(args)
    assert index.discovery_scope_evidence("bubblewrap", scope) == []


def test_cli_fixed_production_does_not_hide_affected_sdk(tmp_path):
    sdk_path = tmp_path / "sdk.json"
    sdk_path.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "name": "openssl",
                        "versionInfo": "3.2.3",
                        "SPDXID": "SPDXRef-sdk-openssl",
                    }
                ],
            }
        )
    )
    output = tmp_path / "discovery.json"
    assert (
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
                "--sdk-sbom-fixture",
                str(sdk_path),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    record = next(
        record
        for record in json.loads(output.read_text())["records"]
        if record["llm_extraction"]["package_name"] == "openssl"
    )
    assert record["scope_evidence"][0]["versionInfo"] == "3.2.3"
    assert record["decision"]["action"] in {"needs_manual_review", "create_issue"}


@pytest.mark.parametrize(
    "flag,scope",
    [("--sdk-sbom-fixture", "sdk_only"), ("--sysext-sbom-fixture", "sysext")],
)
@pytest.mark.parametrize(
    "purls,matched",
    [
        (["pkg:cargo/tar", "pkg:gentoo/app-arch/tar"], True),
        (["pkg:gentoo/app-arch/tar", "pkg:gentoo/dev-libs/tar"], False),
        (["pkg:cargo/tar"], False),
    ],
)
def test_cli_scope_snapshots_match_each_finding_identity(
    tmp_path, flag, scope, purls, matched
):
    source = tmp_path / "source.json"
    source.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "source": "gentoo",
                        "source_url": "https://bugs.gentoo.org/12345",
                        "entry_id": "12345",
                        "title": "tar: security advisory",
                        "content": "Package: tar\nCVE: CVE-2026-12345\nFixed in 1.2.3",
                    }
                ]
            }
        )
    )
    production = tmp_path / "production.json"
    production.write_text('{"spdxVersion": "SPDX-2.3", "packages": []}')
    issues = tmp_path / "issues.json"
    issues.write_text("[]")
    snapshot = tmp_path / "scope.json"
    snapshot.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "name": "tar",
                        "versionInfo": "1.2.2",
                        "SPDXID": f"SPDXRef-tar-{number}",
                        "externalRefs": [
                            {"referenceType": "purl", "referenceLocator": purl}
                        ],
                    }
                    for number, purl in enumerate(purls)
                ],
            }
        )
    )
    output = tmp_path / "discovery.json"
    assert (
        main(
            [
                "discovery",
                "--quiet",
                "--source-fixture",
                str(source),
                "--issues-fixture",
                str(issues),
                "--sbom-fixture",
                str(production),
                flag,
                str(snapshot),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    record = json.loads(output.read_text())["records"][0]
    assert record["sbom_package_matches"] == []
    if matched:
        [proof] = record["scope_evidence"]
        assert proof["package"] == "tar"
        assert proof["scope"] == scope
        assert proof["purls"] == ["pkg:gentoo/app-arch/tar"]
        assert proof["snapshot_source"] == snapshot.resolve().as_uri()
        assert len(proof["snapshot_sha256"]) == 64
        assert proof["discovery_only"] is True
        assert record["decision"]["action"] == "create_issue"
    else:
        assert record["scope_evidence"] == []
        assert record["decision"]["action"] == "needs_manual_review"


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
    # Isolate from any real `.env` file in the repository root: `main()` calls
    # `load_dotenv()` with the default relative `.env` path, which must not
    # repopulate the two variables this test just deleted.
    monkeypatch.chdir(tmp_path)
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
            "user": {"login": "github-actions[bot]", "type": "Bot"},
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

    def list_issues(self, state: str = "open", label: str | None = None):
        return [
            issue_from_api(item)
            for item in self._issues.values()
            if (state == "all" or item["state"] == state)
            and (label is None or label in {entry["name"] for entry in item["labels"]})
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
        comment_id = len(self._comments.setdefault(issue_number, [])) + 1
        comment = {
            "id": comment_id,
            "body": body,
            "user": {"login": "github-actions[bot]", "type": "Bot"},
            "html_url": f"https://github.com/{self.repo}/issues/{issue_number}#issuecomment-{comment_id}",
            "created_at": "2026-10-07T12:00:00Z",
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


def test_cli_feedback_round_trip_is_separate_from_advisory_mutations(
    tmp_path, fake_review_client
):
    from security_triage.feedback import FEEDBACK_KIND
    from security_triage.review import extract_manifest

    repo = "flatcar/security-triage"
    discovery_path = tmp_path / "discovery.json"
    discovery_args = [
        "discovery",
        "--quiet",
        "--source-fixture",
        str(FIXTURES / "discovery_entries.json"),
        "--issues-fixture",
        str(FIXTURES / "github_issues.json"),
        "--sbom-fixture",
        str(FIXTURES / "sbom.json"),
        "--advisory-repo",
        repo,
        "--output",
        str(discovery_path),
    ]
    assert main(discovery_args) == 0
    create_path = tmp_path / "created.json"
    assert (
        main(
            [
                "review",
                "create",
                "--quiet",
                "--discovery-json",
                str(discovery_path),
                "--advisory-repo",
                repo,
                "--review-repo",
                repo,
                "--run-id",
                "feedback-roundtrip",
                "--review-detail",
                "full",
                "--enable-feedback",
                "--output",
                str(create_path),
            ]
        )
        == 0
    )
    number = json.loads(create_path.read_text())["parts"][0]["issue_number"]
    client = fake_review_client[repo]
    review = client._issues[number]
    manifest = extract_manifest(review["body"])
    action = next(
        action
        for group in manifest["groups"]
        for action in group["actions"]
        if action["kind"] == FEEDBACK_KIND
        and action["payload"]["decision"] == "wrong_package"
    )
    marker = f"<!-- security-triage:action-id:{action['action_id']} -->"
    review["body"] = "\n".join(
        line.replace("[ ]", "[x]") if marker in line else line
        for line in review["body"].splitlines()
    )
    review["state"] = "closed"
    review["state_reason"] = "completed"
    before = len(client._issues)
    assert (
        main(
            [
                "review",
                "apply",
                "--quiet",
                "--issue-number",
                str(number),
                "--advisory-repo",
                repo,
                "--review-repo",
                repo,
                "--output",
                str(tmp_path / "applied.json"),
            ]
        )
        == 0
    )
    assert len(client._issues) == before
    assert main(discovery_args + ["--feedback-review-repo", repo]) == 0
    result = json.loads(discovery_path.read_text())
    assert result["summary"]["confirmed_feedback_suppressions"] == 1
    assert all(record.get("decision") for record in result["records"])


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
