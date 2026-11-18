import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

from security_triage import agent_poc

pytest.importorskip("yaml")
CASE_FILE = Path(__file__).parent.parent / "poc/cve-investigation.yaml"


@pytest.fixture
def evidence_inputs(monkeypatch, tmp_path):
    scripts = tmp_path / "scripts"
    manifest = scripts / agent_poc.MANIFEST_PATH
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        f"FLATCAR_VERSION={agent_poc.NIGHTLY_VERSION}\n", encoding="utf-8"
    )
    (scripts / agent_poc.GENTOO_PATH / "dev-libs/openssl").mkdir(parents=True)
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "name": "nightly inventory",
        "packages": [
            {"name": "dev-libs/openssl", "versionInfo": "3.6.5"},
            {
                "name": "other-component",
                "versionInfo": "1.0",
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:cargo/other-component@1.0",
                    }
                ],
            },
        ],
        "files": [{"fileName": "not part of the package projection"}],
    }
    advisory = {"id": agent_poc.RUSTSEC_ID, "aliases": [agent_poc.CVE]}
    fetch = Mock(
        side_effect=lambda url, **kwargs: {
            agent_poc.SBOM_URL: sbom,
            agent_poc.OSV_URL: advisory,
        }[url]
    )
    revision = Mock(
        return_value=subprocess.CompletedProcess(
            [], 0, stdout=agent_poc.SCRIPTS_COMMIT + "\n"
        )
    )
    monkeypatch.setattr(agent_poc, "fetch_json", fetch)
    monkeypatch.setattr(agent_poc.subprocess, "run", revision)
    return scripts, tmp_path / "workspace", sbom, advisory, fetch, revision


def test_prepare_records_exact_source_and_preserves_complete_package_inventory(
    evidence_inputs,
):
    scripts, workspace, _, _, fetch, revision = evidence_inputs
    prompt = agent_poc.prepare_evidence(scripts, workspace, CASE_FILE)

    assert [call.args[0] for call in fetch.call_args_list] == [agent_poc.SBOM_URL]
    revision.assert_not_called()
    inventory = json.loads((workspace / "sbom-packages.json").read_text())
    assert len(inventory["packages"]) == 2
    assert inventory["packages"][1]["purls"] == ["pkg:cargo/other-component@1.0"]
    assert "files" not in inventory
    provenance = json.loads((workspace / "provenance.json").read_text())
    assert provenance["expected_scripts_commit"] == agent_poc.SCRIPTS_COMMIT
    assert provenance["nightly_version"] == agent_poc.NIGHTLY_VERSION
    assert str(scripts) in prompt
    assert "finding supplied by a discovery producer" in prompt
    assert "github.com/flatcar/security-triage/issues/" not in prompt
    assert "MUST perform this evidence collection using bash" in prompt
    assert "Clone https://github.com/flatcar/scripts.git" in prompt
    assert agent_poc.ADVISORY_URL in prompt and agent_poc.OSV_URL in prompt
    case = json.loads((workspace / "case.json").read_text())
    assert case["vulnerability"]["id"] == agent_poc.CVE
    assert case["packages"] == [{"name": "dev-libs/openssl", "version": "3.6.5"}]


def _downloaded_advisory(workspace, advisory):
    workspace.mkdir(exist_ok=True)
    (workspace / "advisory.json").write_text(json.dumps(advisory))
    (workspace / "advisory.html").write_text(f"<h1>{agent_poc.RUSTSEC_ID}</h1>")


@pytest.mark.parametrize(
    "mismatch", ["revision", "version", "submodule", "submodule_revision"]
)
def test_agent_collected_source_is_verified(evidence_inputs, mismatch):
    scripts, workspace, _, advisory, fetch, revision = evidence_inputs
    _downloaded_advisory(workspace, advisory)
    if mismatch == "revision":
        revision.return_value.stdout = "a" * 40
    elif mismatch == "version":
        (scripts / agent_poc.MANIFEST_PATH).write_text(
            "FLATCAR_VERSION=4886.0.0+nightly-20261117-2100\n"
        )
    elif mismatch == "submodule":
        (scripts / agent_poc.GENTOO_PATH / "dev-libs/openssl").rmdir()
    else:
        revision.side_effect = [
            subprocess.CompletedProcess([], 0, stdout=agent_poc.SCRIPTS_COMMIT),
            subprocess.CompletedProcess([], 0, stdout="b" * 40),
            subprocess.CompletedProcess([], 0, stdout="c" * 40),
        ]

    with pytest.raises(ValueError):
        agent_poc.verify_collected_evidence(scripts, workspace)
    fetch.assert_not_called()


def test_agent_collected_source_and_advisory_are_accepted(evidence_inputs):
    scripts, workspace, _, advisory, _, _ = evidence_inputs
    _downloaded_advisory(workspace, advisory)
    agent_poc.verify_collected_evidence(scripts, workspace)


@pytest.mark.parametrize("invalid", ["aliases", "html"])
def test_agent_downloaded_advisory_must_match_the_requested_cve(
    evidence_inputs, invalid
):
    scripts, workspace, _, advisory, _, _ = evidence_inputs
    if invalid == "aliases":
        advisory["aliases"] = ["CVE-2026-OTHER"]
    _downloaded_advisory(workspace, advisory)
    if invalid == "html":
        (workspace / "advisory.html").write_text("unrelated page")
    with pytest.raises(ValueError, match="RustSec"):
        agent_poc.verify_collected_evidence(scripts, workspace)


@pytest.mark.parametrize("invalid", ["version", "packages", "description"])
def test_invalid_mock_finding_is_rejected_before_source_or_network_access(
    evidence_inputs, tmp_path, invalid
):
    scripts, workspace, _, _, fetch, revision = evidence_inputs
    case = json.loads(json.dumps(agent_poc.load_structured_file(CASE_FILE)))
    if invalid == "version":
        case["flatcar"]["version"] = "another-nightly"
    elif invalid == "packages":
        case["packages"] = []
    else:
        case["vulnerability"]["description"] = ""
    case_file = tmp_path / "case.json"
    case_file.write_text(json.dumps(case))
    with pytest.raises(ValueError):
        agent_poc.prepare_evidence(scripts, workspace, case_file)
    fetch.assert_not_called()
    revision.assert_not_called()


@pytest.mark.parametrize("invalid", ["inventory", "package"])
def test_missing_evidence_fails_without_fallback(evidence_inputs, invalid):
    scripts, workspace, sbom, _, fetch, _ = evidence_inputs
    if invalid == "inventory":
        sbom.pop("packages")
    elif invalid == "package":
        sbom["packages"] = [{"name": "unrelated", "versionInfo": "1.0"}]

    with pytest.raises(ValueError):
        agent_poc.prepare_evidence(scripts, workspace, CASE_FILE)
    assert {call.args[0] for call in fetch.call_args_list} <= {
        agent_poc.SBOM_URL,
        agent_poc.OSV_URL,
    }
    assert not workspace.exists()


def _report():
    return (
        f"# openssl: {agent_poc.CVE}\n\n"
        f"- Source URL: {agent_poc.ADVISORY_URL}\n"
        f"- CVEs / upstream IDs: {agent_poc.CVE}, {agent_poc.RUSTSEC_ID}\n"
        "- CVSS: n/a\n"
        f"- Flatcar: {agent_poc.NIGHTLY_VERSION}, amd64, unreleased nightly\n"
        "- SBOM matches: dev-libs/openssl 3.6.5\n"
        "- Assessment: **under_investigation** (scope: unknown, confidence: low)\n"
        "- Recommendation: Verify Rust dependency linkage.\n"
        "- Summary: The system library version does not establish Rust crate linkage.\n\n"
        "**Evidence**\n"
        f"- [Primary advisory]({agent_poc.ADVISORY_URL}) identifies the affected crate.\n\n"
        "**Uncertainties:** Vendored dependency linkage is unverified.\n"
    )


@pytest.fixture
def inference(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_API_TEST", "dummy-anthropic-key")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-be-forwarded")
    monkeypatch.setenv("FOUNDRY_BEARER_TOKEN", "also-not-forwarded")
    monkeypatch.setattr(agent_poc, "prepare_evidence", lambda *args: "test task")
    monkeypatch.setattr(agent_poc, "verify_collected_evidence", Mock())
    run = Mock(return_value=_report())
    monkeypatch.setattr(agent_poc, "_stream_pi", run)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return tmp_path / "scripts", workspace, tmp_path / "output/report.md", run


def test_batch_inference_captures_report_without_forwarding_other_credentials(
    inference,
):
    scripts, workspace, output, run = inference
    agent_poc.run_investigation(scripts, workspace, output, "/installed/pi")

    assert output.is_file() and not output.is_symlink()
    assert output.read_text() == _report()
    command = run.call_args.args[0]
    options = run.call_args.kwargs
    assert command[0] == "/installed/pi"
    assert "--print" in command and "--no-session" in command
    assert command[command.index("--mode") + 1] == "json"
    assert command[command.index("--tools") + 1] == "read,bash"
    assert options["cwd"] == workspace
    environment = options["env"]
    assert environment["ANTHROPIC_API_KEY"] == "dummy-anthropic-key"
    assert environment["HOME"] == str(workspace / ".pi-home")
    assert not {"CLAUDE_API_TEST", "GITHUB_TOKEN", "FOUNDRY_BEARER_TOKEN"} & (
        environment.keys()
    )
    assert "dummy-anthropic-key" not in " ".join(command)


@pytest.mark.parametrize(
    "report",
    [
        "",
        "an incomplete answer",
        _report().replace("- Recommendation:", "- Other:"),
        _report() + "dummy-anthropic-key",
        _report() + "x" * 1048576,
    ],
)
def test_invalid_or_secret_containing_report_is_not_written(inference, report):
    scripts, workspace, output, run = inference
    run.return_value = report
    with pytest.raises(ValueError):
        agent_poc.run_investigation(scripts, workspace, output)
    assert not output.exists()


@pytest.mark.parametrize(
    "failure",
    [
        subprocess.CalledProcessError(1, ["pi"]),
        subprocess.TimeoutExpired(["pi"], 600),
    ],
)
def test_inference_failure_never_creates_a_success_shaped_report(inference, failure):
    scripts, workspace, output, run = inference
    run.side_effect = failure
    with pytest.raises(type(failure)):
        agent_poc.run_investigation(scripts, workspace, output)
    assert not output.exists()


def test_missing_key_fails_before_fetch_or_inference(inference, monkeypatch):
    scripts, workspace, output, run = inference
    monkeypatch.delenv("CLAUDE_API_TEST")
    prepare = Mock(side_effect=AssertionError("Must not prepare without a key"))
    monkeypatch.setattr(agent_poc, "prepare_evidence", prepare)
    with pytest.raises(ValueError, match="CLAUDE_API_TEST"):
        agent_poc.run_investigation(scripts, workspace, output)
    run.assert_not_called()
    prepare.assert_not_called()


def test_existing_report_is_not_reused_or_overwritten(inference):
    scripts, workspace, output, run = inference
    output.parent.mkdir()
    output.write_text("previous report")
    with pytest.raises(ValueError, match="Refusing to overwrite"):
        agent_poc.run_investigation(scripts, workspace, output)
    assert output.read_text() == "previous report"
    run.assert_not_called()


def test_report_is_rejected_if_required_collection_was_not_completed(
    inference, monkeypatch
):
    scripts, workspace, output, _ = inference
    monkeypatch.setattr(
        agent_poc,
        "verify_collected_evidence",
        Mock(side_effect=ValueError("The agent did not collect evidence")),
    )
    with pytest.raises(ValueError, match="did not collect evidence"):
        agent_poc.run_investigation(scripts, workspace, output)
    assert not output.exists()


@pytest.mark.parametrize("extra_words", [0, 1])
def test_report_word_limit_rejects_bloat_without_truncating(inference, extra_words):
    scripts, workspace, output, run = inference
    report = _report()
    padding = agent_poc.MAX_REPORT_WORDS - len(report.split()) + extra_words
    report += " ".join(["detail"] * padding)
    run.return_value = report
    if extra_words:
        with pytest.raises(ValueError, match="maintainer summary limit"):
            agent_poc.run_investigation(scripts, workspace, output)
        assert not output.exists()
    else:
        agent_poc.run_investigation(scripts, workspace, output)
        assert output.read_text() == report + "\n"


def _pi_events():
    def content(text):
        return {"content": [{"type": "text", "text": text}]}

    return [
        {"type": "agent_start"},
        {"type": "turn_start"},
        {
            "type": "message_end",
            "message": {
                "role": "assistant",
                "stopReason": "toolUse",
                **content("I will collect evidence."),
            },
        },
        {
            "type": "tool_execution_start",
            "toolName": "bash",
            "toolCallId": "call_1",
            "args": {"command": "echo dummy-anthropic-key"},
        },
        {
            "type": "tool_execution_update",
            "toolName": "bash",
            "toolCallId": "call_1",
            "partialResult": content("Cloning source...\n"),
        },
        {
            "type": "tool_execution_update",
            "toolName": "bash",
            "toolCallId": "call_1",
            "partialResult": content("Cloning source...\nReceived source.\n"),
        },
        {
            "type": "tool_execution_end",
            "toolName": "bash",
            "toolCallId": "call_1",
            "isError": False,
            "result": content("Cloning source...\nReceived source.\n"),
        },
        {
            "type": "message_end",
            "message": {
                "role": "assistant",
                "stopReason": "stop",
                "content": [
                    {"type": "thinking", "thinking": "not for progress logs"},
                    {"type": "text", "text": _report()},
                ],
            },
        },
        {"type": "agent_settled", "aborted": False},
    ]


@pytest.fixture
def pi_process(monkeypatch):
    process = MagicMock()
    process.stdout = iter(json.dumps(event) + "\n" for event in _pi_events())
    process.wait.return_value = 0
    process.poll.return_value = 0
    popen = MagicMock()
    popen.return_value.__enter__.return_value = process
    monkeypatch.setattr(agent_poc.subprocess, "Popen", popen)
    return process, popen


def test_stream_logs_tool_progress_and_returns_only_the_final_answer(
    pi_process, tmp_path, capsys
):
    _, popen = pi_process
    report = agent_poc._stream_pi(
        ["pi"], cwd=tmp_path, env={"ANTHROPIC_API_KEY": "dummy-anthropic-key"}
    )
    assert report == _report()
    logs = capsys.readouterr().out
    assert "I will collect evidence." in logs
    assert "echo [REDACTED]" in logs
    assert "dummy-anthropic-key" not in logs
    assert logs.count("Cloning source...") == 1
    assert logs.count("Received source.") == 1
    assert "bash finished" in logs
    assert "not for progress logs" not in logs
    assert popen.call_args.kwargs["stdin"] == subprocess.DEVNULL
    assert popen.call_args.kwargs["stdout"] == subprocess.PIPE


def test_progress_is_printed_before_the_rest_of_the_stream_is_consumed(
    pi_process, tmp_path, capsys
):
    process, _ = pi_process

    def lines():
        events = _pi_events()
        for event in events[:4]:
            yield json.dumps(event) + "\n"
        assert "[Pi] bash " in capsys.readouterr().out
        yield json.dumps(events[4]) + "\n"
        assert "[Pi] Cloning source..." in capsys.readouterr().out
        for event in events[5:]:
            yield json.dumps(event) + "\n"

    process.stdout = lines()
    agent_poc._stream_pi(
        ["pi"], cwd=tmp_path, env={"ANTHROPIC_API_KEY": "dummy-anthropic-key"}
    )


def test_key_split_across_tool_updates_is_not_logged(pi_process, tmp_path, capsys):
    process, _ = pi_process
    events = _pi_events()
    events[4]["partialResult"]["content"][0]["text"] = "output: dummy-anth"
    events[5]["partialResult"]["content"][0]["text"] = "output: dummy-anthropic-key\n"
    events[6]["result"]["content"][0]["text"] = "output: dummy-anthropic-key\n"
    process.stdout = iter(json.dumps(event) + "\n" for event in events)
    agent_poc._stream_pi(
        ["pi"], cwd=tmp_path, env={"ANTHROPIC_API_KEY": "dummy-anthropic-key"}
    )
    logs = capsys.readouterr().out
    assert "dummy-anth" not in logs
    assert "ropic-key" not in logs


def test_actions_command_processing_is_suspended_during_tool_logs(
    pi_process, tmp_path, monkeypatch, capsys
):
    process, _ = pi_process
    events = _pi_events()
    events[6]["result"]["content"][0]["text"] = "::error::untrusted tool output"
    process.stdout = iter(json.dumps(event) + "\n" for event in events)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    agent_poc._stream_pi(
        ["pi"], cwd=tmp_path, env={"ANTHROPIC_API_KEY": "dummy-anthropic-key"}
    )
    lines = capsys.readouterr().out.splitlines()
    token = lines[0].removeprefix("::stop-commands::")
    assert token and lines[0] == f"::stop-commands::{token}"
    assert "[Pi] ::error::untrusted tool output" in lines[1:-1]
    assert lines[-1] == f"::{token}::"


@pytest.mark.parametrize("failure", ["error", "length", "aborted", "unsettled"])
def test_incomplete_stream_cannot_reuse_an_earlier_report(
    pi_process, tmp_path, failure
):
    process, _ = pi_process
    events = _pi_events()
    if failure == "unsettled":
        events.pop()
    elif failure == "aborted":
        events[-1]["aborted"] = True
    else:
        events[-2]["message"]["stopReason"] = failure
    process.stdout = iter(json.dumps(event) + "\n" for event in events)
    with pytest.raises(ValueError, match="complete response"):
        agent_poc._stream_pi(
            ["pi"], cwd=tmp_path, env={"ANTHROPIC_API_KEY": "dummy-anthropic-key"}
        )


def test_nonzero_exit_rejects_an_otherwise_complete_report(pi_process, tmp_path):
    process, _ = pi_process
    process.wait.return_value = 7
    with pytest.raises(subprocess.CalledProcessError) as error:
        agent_poc._stream_pi(
            ["pi"], cwd=tmp_path, env={"ANTHROPIC_API_KEY": "dummy-anthropic-key"}
        )
    assert error.value.returncode == 7


def test_invalid_stream_kills_pi_and_restores_actions_commands(
    pi_process, tmp_path, monkeypatch, capsys
):
    process, _ = pi_process
    process.stdout = iter(["invalid JSON\n"])
    process.poll.return_value = None
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    with pytest.raises(json.JSONDecodeError):
        agent_poc._stream_pi(
            ["pi"], cwd=tmp_path, env={"ANTHROPIC_API_KEY": "dummy-anthropic-key"}
        )
    process.kill.assert_called_once()
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("::stop-commands::")
    token = lines[0].removeprefix("::stop-commands::")
    assert lines[-1] == f"::{token}::"


def test_silent_process_still_obeys_the_wall_clock_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_poc, "TIMEOUT_SECONDS", 0.05)
    with pytest.raises(subprocess.TimeoutExpired):
        agent_poc._stream_pi(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=tmp_path,
            env={"ANTHROPIC_API_KEY": "dummy-anthropic-key"},
        )
