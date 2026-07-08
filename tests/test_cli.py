import json
from pathlib import Path

from security_triage.cli import build_parser, main

FIXTURES = Path(__file__).parent / "fixtures"


def test_discovery_default_window_days_is_seven():
    args = build_parser().parse_args(["discovery"])
    assert args.window_days == 7


def test_discovery_accepts_source_cache_flags():
    args = build_parser().parse_args([
        "discovery",
        "--oss-security-cache-dir",
        "reports/.cache/source-downloads",
        "--go-vulndb-cache-dir",
        "reports/.cache/source-downloads",
        "--rustsec-cache-dir",
        "reports/.cache/source-downloads",
    ])
    assert args.oss_security_cache_dir == "reports/.cache/source-downloads"
    assert args.go_vulndb_cache_dir == "reports/.cache/source-downloads"
    assert args.rustsec_cache_dir == "reports/.cache/source-downloads"


def test_cli_accepts_foundry_model_args():
    args = build_parser().parse_args([
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
    ])
    assert args.model == "foundry"
    assert args.foundry_endpoint == "https://example-foundry.cognitiveservices.azure.com"
    assert args.foundry_deployment == "gpt-5.4"
    assert args.foundry_extraction_deployment == "gpt-5.4-mini"
    assert args.foundry_api_version == "2024-06-01"


def test_cli_discovery_writes_json_and_markdown(tmp_path, capsys):
    output = tmp_path / "discovery.json"
    markdown = tmp_path / "discovery.md"
    result = main([
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
    ])
    assert result == 0
    document = json.loads(output.read_text())
    assert document["workflow"] == "new_vulnerability_discovery"
    assert markdown.read_text().startswith("# Flatcar Vulnerability Discovery Dry Run")
    captured = capsys.readouterr()
    assert "Starting Flatcar vulnerability discovery" in captured.err


def test_cli_cleanup_writes_json_and_markdown(tmp_path):
    output = tmp_path / "cleanup.json"
    markdown = tmp_path / "cleanup.md"
    result = main([
        "cleanup",
        "--issues-fixture",
        str(FIXTURES / "github_issues.json"),
        "--sbom-fixture",
        str(FIXTURES / "sbom.json"),
        "--output",
        str(output),
        "--markdown-output",
        str(markdown),
    ])
    assert result == 0
    document = json.loads(output.read_text())
    assert document["workflow"] == "advisory_cleanup_recommendation"
    assert markdown.read_text().startswith("# Flatcar Advisory Cleanup Dry Run")


def test_cli_quiet_suppresses_progress_logs(tmp_path, capsys):
    output = tmp_path / "discovery.json"
    result = main([
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
    ])
    assert result == 0
    captured = capsys.readouterr()
    assert "Starting Flatcar vulnerability discovery" not in captured.err
