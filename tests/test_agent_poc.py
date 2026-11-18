import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

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
        f"# {agent_poc.CVE}\n\n"
        "## Assessment\nunder_investigation\n"
        "## Evidence\nSource references\n"
        "## Uncertainties\nMissing linkage evidence\n"
        "## Suggested maintainer follow-up\nReview evidence\n"
    )


@pytest.fixture
def inference(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_API_TEST", "dummy-anthropic-key")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-be-forwarded")
    monkeypatch.setenv("FOUNDRY_BEARER_TOKEN", "also-not-forwarded")
    monkeypatch.setattr(agent_poc, "prepare_evidence", lambda *args: "test task")
    monkeypatch.setattr(agent_poc, "verify_collected_evidence", Mock())
    run = Mock(return_value=subprocess.CompletedProcess([], 0, stdout=_report()))
    monkeypatch.setattr(agent_poc.subprocess, "run", run)
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
    assert command[command.index("--tools") + 1] == "read,bash"
    assert options["stdin"] == subprocess.DEVNULL
    assert options["cwd"] == workspace
    assert options["timeout"] == 600
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
        _report() + "dummy-anthropic-key",
        _report() + "x" * 1048576,
    ],
)
def test_invalid_or_secret_containing_report_is_not_written(inference, report):
    scripts, workspace, output, run = inference
    run.return_value.stdout = report
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
