"""Structural and policy checks for the GitHub Actions workflow YAML files.

These tests parse the workflow YAML (not the Python `DiscoveryWorkflow`/
`CleanupWorkflow` pipeline objects covered by ``tests/test_workflows.py``) and
assert the safety properties the review/apply design plan requires: exact
triggers, least-privilege permissions, concurrency configuration, OIDC only in
the daily analysis workflow, no pull-request path ever receiving OIDC or
issue-write access, the apply workflow being label-filtered and passing the
issue number to the Python gate, and every battle-test repository reference
resolving to this repository rather than a hard-coded `flatcar/Flatcar`.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOWS_DIR = Path(__file__).parent.parent / ".github" / "workflows"
DAILY_WORKFLOW_PATH = WORKFLOWS_DIR / "security-triage.yml"
APPLY_WORKFLOW_PATH = WORKFLOWS_DIR / "security-triage-apply.yml"


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _triggers(document: dict[str, Any]) -> dict[str, Any]:
    # PyYAML's default (YAML 1.1) resolver parses the unquoted `on:` mapping
    # key as the boolean True, which is how every workflow in this repository
    # (and GitHub's own examples) writes the key.
    triggers = document.get("on", document.get(True))  # type: ignore[call-overload]
    assert triggers is not None, "workflow must declare an 'on:' trigger section"
    return triggers


def _all_run_steps(document: dict[str, Any]) -> list[str]:
    commands: list[str] = []
    for job in document.get("jobs", {}).values():
        for step in job.get("steps", []):
            if "run" in step:
                commands.append(step["run"])
    return commands


def _all_workflow_paths() -> list[Path]:
    return sorted(WORKFLOWS_DIR.glob("*.yml"))


# --- Daily analysis workflow ---------------------------------------------------


def test_daily_workflow_triggers_are_exactly_cron_and_dispatch():
    document = _load(DAILY_WORKFLOW_PATH)
    triggers = _triggers(document)

    assert "pull_request" not in triggers
    assert "workflow_dispatch" in triggers
    assert "schedule" in triggers
    crons = [entry["cron"] for entry in triggers["schedule"]]
    assert crons == ["0 6 * * 1-5"]


def test_daily_workflow_permissions_are_least_privilege():
    document = _load(DAILY_WORKFLOW_PATH)
    permissions = document["permissions"]

    assert permissions == {"contents": "read", "issues": "write", "id-token": "write"}
    assert "models" not in permissions, (
        "no GitHub Models fallback is wired into this workflow; omit the permission"
    )


def test_daily_workflow_has_a_non_cancelling_concurrency_group():
    document = _load(DAILY_WORKFLOW_PATH)
    concurrency = document["concurrency"]

    assert concurrency["cancel-in-progress"] is False
    assert concurrency["group"]


def test_daily_workflow_uses_azure_oidc_login():
    document = _load(DAILY_WORKFLOW_PATH)
    uses_values = [
        step.get("uses", "")
        for job in document["jobs"].values()
        for step in job["steps"]
    ]

    assert any(value.startswith("azure/login@") for value in uses_values)
    assert document["permissions"]["id-token"] == "write"


def test_daily_workflow_analysis_steps_never_pass_mutation_flags():
    document = _load(DAILY_WORKFLOW_PATH)
    commands = _all_run_steps(document)
    analysis_commands = [
        command
        for command in commands
        if "security-triage discovery" in command
        or "security-triage cleanup" in command
    ]

    assert analysis_commands, "expected discovery and cleanup steps"
    for command in analysis_commands:
        assert "--apply-actions" not in command
        assert "--enable-create-issues" not in command
        assert "--enable-update-issues" not in command
        assert "--enable-post-cleanup-comments" not in command
        assert "--enable-close-issues" not in command


def test_daily_workflow_uses_foundry_model_for_analysis():
    document = _load(DAILY_WORKFLOW_PATH)
    commands = _all_run_steps(document)
    analysis_commands = [
        command
        for command in commands
        if "security-triage discovery" in command
        or "security-triage cleanup" in command
    ]

    for command in analysis_commands:
        assert "--model foundry" in command


def test_daily_workflow_creates_review_issues_but_never_calls_review_apply():
    document = _load(DAILY_WORKFLOW_PATH)
    commands = "\n".join(_all_run_steps(document))

    assert "security-triage review create" in commands
    assert "review apply" not in commands


def test_daily_workflow_repository_configuration_is_parameterized_to_current_repo():
    document = _load(DAILY_WORKFLOW_PATH)
    env = document.get("env", {})

    assert env["SECURITY_TRIAGE_ADVISORY_REPO"] == "${{ github.repository }}"
    assert env["SECURITY_TRIAGE_REVIEW_REPO"] == "${{ github.repository }}"

    raw_text = DAILY_WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "flatcar/Flatcar" not in raw_text


def test_daily_workflow_foundry_bearer_token_is_masked_and_scoped():
    raw_text = DAILY_WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "::add-mask::" in raw_text
    assert "FOUNDRY_BEARER_TOKEN" in raw_text

    url_candidates = re.findall(r"https?://[^\s\"'<>]+", raw_text)
    hosts = {
        (urlparse(candidate).hostname or "").lower() for candidate in url_candidates
    }
    assert any(
        host == "cognitiveservices.azure.com"
        or host.endswith(".cognitiveservices.azure.com")
        for host in hosts
    )


# --- Apply workflow -------------------------------------------------------------


def test_apply_workflow_triggers_only_on_issue_closed_and_manual_dispatch():
    document = _load(APPLY_WORKFLOW_PATH)
    triggers = _triggers(document)

    assert "pull_request" not in triggers
    assert "schedule" not in triggers
    assert triggers["issues"]["types"] == ["closed"]
    assert "workflow_dispatch" in triggers
    assert triggers["workflow_dispatch"]["inputs"]["issue_number"]["required"] is True


def test_apply_workflow_permissions_are_least_privilege_with_no_oidc():
    document = _load(APPLY_WORKFLOW_PATH)
    permissions = document["permissions"]

    assert permissions == {"contents": "read", "issues": "write"}
    assert "id-token" not in permissions


def test_apply_workflow_concurrency_is_scoped_to_the_issue_and_never_cancels():
    document = _load(APPLY_WORKFLOW_PATH)
    concurrency = document["concurrency"]

    assert concurrency["cancel-in-progress"] is False
    assert (
        "issue.number" in concurrency["group"] or "issue_number" in concurrency["group"]
    )


def test_apply_workflow_job_is_filtered_by_the_review_label():
    document = _load(APPLY_WORKFLOW_PATH)
    job = document["jobs"]["apply"]

    assert "security-triage/review" in job["if"]


def test_apply_workflow_passes_the_issue_number_to_the_python_gate():
    document = _load(APPLY_WORKFLOW_PATH)
    commands = _all_run_steps(document)
    apply_commands = [
        command for command in commands if "security-triage review apply" in command
    ]

    assert len(apply_commands) == 1
    assert "--issue-number" in apply_commands[0]
    assert "github.event.issue.number" in apply_commands[0]
    assert "github.event.inputs.issue_number" in apply_commands[0]


def test_apply_workflow_never_touches_azure_foundry_or_reruns_analysis():
    document = _load(APPLY_WORKFLOW_PATH)
    raw_text = APPLY_WORKFLOW_PATH.read_text(encoding="utf-8")
    lowered = raw_text.lower()

    # Blanket-check the actual configuration surface (permissions, env vars,
    # `uses:` steps, and `run:` commands) rather than the whole raw text, so a
    # documentation link such as `docs/github-actions-foundry-oidc.md` in an
    # explanatory comment cannot be confused with real Foundry/Azure usage.
    assert "id-token" not in document.get("permissions", {})
    assert "azure/login" not in lowered
    assert "cognitiveservices.azure.com" not in lowered
    for job in document["jobs"].values():
        for step in job["steps"]:
            assert not step.get("uses", "").lower().startswith("azure/")
            step_env = step.get("env", {})
            assert not any(key.startswith("FOUNDRY_") for key in step_env)
            command = step.get("run", "")
            assert "security-triage discovery" not in command
            assert "security-triage cleanup" not in command
            assert "--model foundry" not in command
    assert "flatcar/Flatcar" not in raw_text


def test_apply_workflow_repository_configuration_uses_current_repository():
    document = _load(APPLY_WORKFLOW_PATH)
    commands = "\n".join(_all_run_steps(document))

    assert '--advisory-repo "${{ github.repository }}"' in commands
    assert '--review-repo "${{ github.repository }}"' in commands


# --- Cross-workflow policy: no PR path ever receives OIDC or issue-write -------


def test_no_workflow_grants_pr_trigger_oidc_or_issue_write():
    for path in _all_workflow_paths():
        document = _load(path)
        if not isinstance(document, dict):
            # e.g. an intentionally disabled, fully-commented-out
            # placeholder workflow
            continue
        triggers = _triggers(document)
        if "pull_request" not in triggers:
            continue
        permissions = document.get("permissions", {})
        assert permissions.get("id-token") != "write", (
            f"{path.name} must not grant id-token: write to a pull_request trigger"
        )
        assert permissions.get("issues") != "write", (
            f"{path.name} must not grant issues: write to a pull_request trigger"
        )


def test_no_workflow_yaml_in_this_repository_references_flatcar_flatcar():
    for path in _all_workflow_paths():
        raw_text = path.read_text(encoding="utf-8")
        assert "flatcar/Flatcar" not in raw_text, (
            f"{path.name} must not reference flatcar/Flatcar; battle "
            "testing is scoped to this repository"
        )


def test_both_review_workflows_are_valid_yaml_documents():
    for path in (DAILY_WORKFLOW_PATH, APPLY_WORKFLOW_PATH):
        document = _load(path)
        assert document["jobs"], f"{path.name} must declare at least one job"
