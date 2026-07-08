#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from security_triage.cli import main


def wrapper() -> int:
    parser = argparse.ArgumentParser(description="Run fixture-backed cleanup dry run")
    parser.add_argument("--issues-fixture", default=str(ROOT / "tests/fixtures/github_issues.json"))
    parser.add_argument("--sbom-fixture", default=str(ROOT / "tests/fixtures/sbom.json"))
    parser.add_argument("--model-fixture")
    parser.add_argument("--debug-log")
    parser.add_argument("--output", default=str(ROOT / "reports/cleanup-dry-run.md"), help="Markdown output path")
    parser.add_argument("--json-output", help="Machine-readable JSON output path")
    args = parser.parse_args()

    markdown_output = Path(args.output)
    json_output = Path(args.json_output) if args.json_output else markdown_output.with_suffix(".json")
    cli_args = [
        "cleanup",
        "--issues-fixture",
        args.issues_fixture,
        "--sbom-fixture",
        args.sbom_fixture,
        "--output",
        str(json_output),
        "--markdown-output",
        str(markdown_output),
    ]
    if args.model_fixture:
        cli_args.extend(["--model-fixture", args.model_fixture])
    if args.debug_log:
        cli_args.extend(["--debug-log", args.debug_log])
    return main(cli_args)


if __name__ == "__main__":
    raise SystemExit(wrapper())
