#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_FOUNDRY_DEPLOYMENT = "gpt-5.4"
DEFAULT_FOUNDRY_EXTRACTION_DEPLOYMENT = "gpt-5.4-mini"
DEFAULT_FOUNDRY_API_VERSION = "2024-06-01"
COGNITIVE_SERVICES_RESOURCE = "https://cognitiveservices.azure.com/"

_ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Populate local .env values for Foundry-backed Flatcar security tracking runs.")
    parser.add_argument("--env-file", default=".env", help="Path to update (default: .env)")
    parser.add_argument("--foundry-endpoint", help="Foundry/Azure OpenAI endpoint base URL; when omitted, the existing .env value is left unchanged")
    parser.add_argument("--foundry-deployment", default=DEFAULT_FOUNDRY_DEPLOYMENT, help="Reasoning deployment name")
    parser.add_argument("--foundry-extraction-deployment", default=DEFAULT_FOUNDRY_EXTRACTION_DEPLOYMENT, help="Extraction deployment name")
    parser.add_argument("--foundry-api-version", default=DEFAULT_FOUNDRY_API_VERSION, help="Chat completions API version: dated value for legacy endpoints, v1/preview for OpenAI v1 endpoints")
    parser.add_argument("--subscription", help="Optional Azure subscription name or ID for az account get-access-token")
    parser.add_argument("--tenant", help="Optional Microsoft Entra tenant for az account get-access-token")
    parser.add_argument("--skip-foundry-token", action="store_true", help="Do not refresh FOUNDRY_BEARER_TOKEN from Azure CLI")
    parser.add_argument("--skip-github-token", action="store_true", help="Do not refresh GITHUB_TOKEN from GitHub CLI")
    args = parser.parse_args(argv)

    values = {
        "FOUNDRY_DEPLOYMENT": args.foundry_deployment,
        "FOUNDRY_EXTRACTION_DEPLOYMENT": args.foundry_extraction_deployment,
        "FOUNDRY_API_VERSION": args.foundry_api_version,
    }
    if args.foundry_endpoint:
        values["FOUNDRY_ENDPOINT"] = args.foundry_endpoint.rstrip("/")
    if not args.skip_foundry_token:
        values["FOUNDRY_BEARER_TOKEN"] = _azure_access_token(args.subscription, args.tenant)
    if not args.skip_github_token:
        values["GITHUB_TOKEN"] = _github_token()

    env_path = Path(args.env_file)
    updated = _write_env_values(env_path, values)
    print(f"Updated {env_path} with: {', '.join(updated)}")
    return 0


def _azure_access_token(subscription: str | None, tenant: str | None) -> str:
    command = [
        "az",
        "account",
        "get-access-token",
        "--resource",
        COGNITIVE_SERVICES_RESOURCE,
        "--query",
        "accessToken",
        "-o",
        "tsv",
    ]
    if subscription:
        command.extend(["--subscription", subscription])
    if tenant:
        command.extend(["--tenant", tenant])
    return _run_secret_command(command, "Azure CLI token lookup failed. Run az login and az account set first.")


def _github_token() -> str:
    return _run_secret_command(["gh", "auth", "token"], "GitHub CLI token lookup failed. Run gh auth login first.")


def _run_secret_command(command: list[str], error_prefix: str) -> str:
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise SystemExit(f"{error_prefix} Missing executable: {command[0]}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
        raise SystemExit(f"{error_prefix} {detail}")
    value = result.stdout.strip()
    if not value:
        raise SystemExit(f"{error_prefix} Command returned an empty token")
    return value


def _write_env_values(path: Path, values: dict[str, str]) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    remaining = dict(values)
    updated_lines: list[str] = []
    for line in lines:
        match = _ENV_LINE_RE.match(line)
        if match and match.group(1) in remaining:
            key = match.group(1)
            updated_lines.append(f"{key}={_dotenv_value(remaining.pop(key))}")
        else:
            updated_lines.append(line)
    if remaining and updated_lines and updated_lines[-1].strip():
        updated_lines.append("")
    for key, value in remaining.items():
        updated_lines.append(f"{key}={_dotenv_value(value)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")
    return list(values)


def _dotenv_value(value: str) -> str:
    if re.match(r"^[A-Za-z0-9_./:@+=,-]+$", value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))