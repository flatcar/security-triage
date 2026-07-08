# Flatcar Security Triage Automation

This repository contains a Flatcar-specific advisory assistant for two workflows:

- new vulnerability discovery from upstream security sources
- cleanup recommendations for open Flatcar advisory issues using the current Stable production SBOM

It is intentionally conservative. The default mode is read-only, produces machine-readable JSON/YAML, and sends uncertain cases to `needs_manual_review`.

## Install

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

YAML input/output is optional:

```bash
.venv/bin/python -m pip install -e '.[dev,yaml]'
```

## Authentication

Live GitHub issue reads can use     anonymous GitHub API access, but authenticated runs are more reliable:

```bash
export GITHUB_TOKEN=...
```

### Microsoft Foundry Local Model Runs

Local Foundry runs use Azure OpenAI chat completions with environment-provided credentials. The CLI does not shell out to Azure CLI at runtime; it reads `.env` or already-exported variables.

```bash
GITHUB_TOKEN=ghp_replace_with_your_token
FOUNDRY_BEARER_TOKEN=ey_replace_with_cognitive_services_access_token
FOUNDRY_ENDPOINT=https://<your-resource>.cognitiveservices.azure.com
FOUNDRY_DEPLOYMENT=gpt-5.4
FOUNDRY_EXTRACTION_DEPLOYMENT=gpt-5.4-mini
FOUNDRY_API_VERSION=2024-06-01
```

`FOUNDRY_DEPLOYMENT` is used for relevance decisions, issue normalization, and cleanup review. `FOUNDRY_EXTRACTION_DEPLOYMENT` is used for first-pass advisory extraction.

Two Foundry endpoint families are supported:

- Legacy resource endpoints such as `https://<resource>.cognitiveservices.azure.com` or `https://<resource>.services.ai.azure.com` call `/openai/deployments/<deployment>/chat/completions?api-version=<version>`. Use a dated Azure OpenAI API version supported by that resource.
- Foundry project or OpenAI v1 endpoints such as `https://<resource>.services.ai.azure.com/api/projects/<project>` or a base URL ending in `/openai/v1` call `/openai/v1/chat/completions`, send the deployment name as the request `model`, and do not send a dated `api-version`. Set `FOUNDRY_API_VERSION=v1` for this mode, or leave the project endpoint to auto-select v1. Unsupported dated values such as `2026-03-17` are normalized to `v1` for project/v1 endpoints.

If you are already logged in locally with Azure CLI and GitHub CLI, refresh `.env` without printing tokens:

```bash
.venv/bin/python scripts/local/populate_foundry_env.py
```

The Azure access token is short-lived. Re-run the helper when `FOUNDRY_BEARER_TOKEN` expires, or replace it manually in `.env`.

### GitHub Models Fallback

GitHub Models runs require `GITHUB_TOKEN`. Defaults:

```bash
GITHUB_MODELS_MODEL=openai/gpt-5
GITHUB_MODELS_ENDPOINT=https://models.github.ai/inference/chat/completions
GITHUB_MODELS_API_VERSION=2022-11-28
```

`GITHUB_MODELS_REASONING_EFFORT` is optional and is only sent when set, for models that support that parameter.

If GitHub Models returns `404`, check that `.env` or your shell is not still setting an old model value such as `GITHUB_MODELS_MODEL=openai/gpt-5.5`. Use `openai/gpt-5` unless you have verified another model ID in GitHub Models.

For GitHub Actions using GitHub Models, grant at least:

```yaml
permissions:
  contents: read
  issues: read
  models: read
```

## Fixture Dry Runs

Discovery dry run:

```bash
.venv/bin/python scripts/local/run_discovery_dry_run.py \
  --source-fixture tests/fixtures/discovery_entries.json \
  --issues-fixture tests/fixtures/github_issues.json \
  --debug-log reports/discovery-debug.jsonl \
  --output reports/discovery-dry-run.md
```

Cleanup dry run:

```bash
.venv/bin/python scripts/local/run_cleanup_dry_run.py \
  --issues-fixture tests/fixtures/github_issues.json \
  --debug-log reports/cleanup-debug.jsonl \
  --output reports/cleanup-dry-run.md
```

The wrappers write Markdown to `--output` and JSON beside it. Use the CLI directly when you want to choose the machine-readable output path.

## CLI

Discovery with fixtures:

```bash
security-triage discovery \
  --source-fixture tests/fixtures/discovery_entries.json \
  --issues-fixture tests/fixtures/github_issues.json \
  --sbom-fixture tests/fixtures/sbom.json \
  --output reports/discovery.json \
  --markdown-output reports/discovery.md \
  --debug-log reports/discovery-debug.jsonl
```

Cleanup with fixtures:

```bash
security-triage cleanup \
  --issues-fixture tests/fixtures/github_issues.json \
  --sbom-fixture tests/fixtures/sbom.json \
  --output reports/cleanup.json \
  --markdown-output reports/cleanup.md \
  --debug-log reports/cleanup-debug.jsonl
```

Live read-only discovery with Microsoft Foundry:

```bash
security-triage discovery \
  --model foundry \
  --window-days 1 \
  --oss-security-cache-dir reports/.cache/source-downloads \
  --go-vulndb-cache-dir reports/.cache/source-downloads \
  --rustsec-cache-dir reports/.cache/source-downloads \
  --prompt-cache-dir reports/.cache/prompt-cache \
  --output reports/discovery.json \
  --markdown-output reports/discovery.md \
  --debug-log reports/discovery-debug.jsonl
```

Live read-only cleanup with Microsoft Foundry:

```bash
security-triage cleanup \
  --model foundry \
  --prompt-cache-dir reports/.cache/prompt-cache \
  --output reports/cleanup.json \
  --markdown-output reports/cleanup.md \
  --debug-log reports/cleanup-debug.jsonl
```

Live read-only discovery with GitHub Models fallback:

```bash
security-triage discovery \
  --model github \
  --oss-security-cache-dir reports/.cache/source-downloads \
  --go-vulndb-cache-dir reports/.cache/source-downloads \
  --rustsec-cache-dir reports/.cache/source-downloads \
  --output reports/discovery.json \
  --markdown-output reports/discovery.md \
  --debug-log reports/discovery-debug.jsonl
```

Live read-only cleanup with GitHub Models fallback:

```bash
security-triage cleanup \
  --model github \
  --output reports/cleanup.json \
  --markdown-output reports/cleanup.md \
  --debug-log reports/cleanup-debug.jsonl
```

Discovery defaults to a seven-day processing window. Live sources are source-specific where structure is available:

- Gentoo uses Bugzilla REST bugs plus comments.
- oss-security uses Openwall archive day pages and thread navigation.
- Go uses the canonical Go vulnerability database at `https://vuln.go.dev/index/vulns.json` plus per-ID OSV JSON.
- Rust uses the RustSec advisory database via GitHub REST commit/file metadata and raw advisory Markdown.

For source freshness, discovery prefers the entry's published or creation time over later metadata updates for generic sources, while thread/advisory sources use their updated or modified time so new comments and modified advisories are not missed. Live source entries without a timestamp are skipped by default; include them only for intentional backfills.

## Safety Flags

No GitHub writes happen unless `--apply-actions` and the specific mutation flag are set.

Discovery flags:

- `--enable-create-issues`
- `--enable-update-issues`

Cleanup flags:

- `--enable-post-cleanup-comments`
- `--enable-close-issues`

Issue closure is disabled by default. Cleanup recommendations are `comment_only` unless closure is explicitly enabled.

## Outputs

Discovery JSON root fields include:

- `workflow: new_vulnerability_discovery`
- `processing_window`
- `sources`
- `model`
- `records`
- `errors`

Cleanup JSON root fields include:

- `workflow: advisory_cleanup_recommendation`
- `sbom_url`
- `issue_query`
- `records`
- `errors`

Every workflow validates its output contract before writing the document.

## Tests

```bash
.venv/bin/python -m pytest
```

The tests cover issue parsing, SBOM parsing, package matching, version comparison, severity/scope labels, discovery guardrails, cleanup guardrails, CLI output, GitHub Models and Foundry request shapes, source fetchers, and fixture dry-run behavior.
