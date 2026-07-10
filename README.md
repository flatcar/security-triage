# Flatcar Security Triage Automation

This repository contains a Flatcar-specific advisory assistant for two workflows:

- new vulnerability discovery from upstream security sources
- cleanup recommendations for open Flatcar advisory issues using the current Stable production SBOM

It is intentionally conservative. The default mode is read-only, produces machine-readable JSON/YAML, and sends uncertain cases to `needs_manual_review`.

## Requirements

- Python 3.12, 3.13, or 3.14
- [uv](https://docs.astral.sh/uv/) for dependency and environment management
- GNU Make (optional, but the `Makefile` is the recommended entry point)

Install `uv` once, for example:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Install

Set up a development environment (creates `.venv/`, installs the package plus the `dev` dependency group with ruff, mypy, pytest, pytest-cov, and pytest-mock):

```bash
make dev-install
```

Or, using `uv` directly:

```bash
uv sync --group dev
```

Production-mode install without development tooling:

```bash
make install
# or: uv sync
```

YAML input/output is exposed as the `yaml` optional dependency:

```bash
uv sync --group dev --extra yaml
```

Run `make help` to see the full list of targets (`test`, `lint`, `format`, `type-check`, `check`, `fix`, `build`, `clean`, `ci`, `all`).

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
uv run scripts/local/populate_foundry_env.py
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
uv run scripts/local/run_discovery_dry_run.py \
  --source-fixture tests/fixtures/discovery_entries.json \
  --issues-fixture tests/fixtures/github_issues.json \
  --debug-log reports/discovery-debug.jsonl \
  --output reports/discovery-dry-run.md
```

Cleanup dry run:

```bash
uv run scripts/local/run_cleanup_dry_run.py \
  --issues-fixture tests/fixtures/github_issues.json \
  --debug-log reports/cleanup-debug.jsonl \
  --output reports/cleanup-dry-run.md
```

The wrappers write Markdown to `--output` and JSON beside it. Use the CLI directly when you want to choose the machine-readable output path.

## CLI

The `security-triage` entry point is installed by `uv sync`. Invoke it via `uv run security-triage ...` or activate the environment first (`source .venv/bin/activate`).

Discovery with fixtures:

```bash
uv run security-triage discovery \
  --source-fixture tests/fixtures/discovery_entries.json \
  --issues-fixture tests/fixtures/github_issues.json \
  --sbom-fixture tests/fixtures/sbom.json \
  --output reports/discovery.json \
  --markdown-output reports/discovery.md \
  --debug-log reports/discovery-debug.jsonl
```

Cleanup with fixtures:

```bash
uv run security-triage cleanup \
  --issues-fixture tests/fixtures/github_issues.json \
  --sbom-fixture tests/fixtures/sbom.json \
  --output reports/cleanup.json \
  --markdown-output reports/cleanup.md \
  --debug-log reports/cleanup-debug.jsonl
```

Live read-only discovery with Microsoft Foundry:

```bash
uv run security-triage discovery \
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
uv run security-triage cleanup \
  --model foundry \
  --prompt-cache-dir reports/.cache/prompt-cache \
  --output reports/cleanup.json \
  --markdown-output reports/cleanup.md \
  --debug-log reports/cleanup-debug.jsonl
```

Live read-only discovery with GitHub Models fallback:

```bash
uv run security-triage discovery \
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
uv run security-triage cleanup \
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

## Repository Configuration

`discovery` and `cleanup` accept `--advisory-repo` (env `SECURITY_TRIAGE_ADVISORY_REPO`) to choose which repository's advisory issues are read/mutated. Both default to `flatcar/Flatcar` when unset, preserving existing standalone behavior. The `review` commands below require explicit `--advisory-repo`/`--review-repo` (or their environment variables) with no implicit default, so a review batch always states exactly which repositories it describes.

```bash
security-triage discovery --advisory-repo flatcar/security-triage ...
security-triage cleanup --advisory-repo flatcar/security-triage ...
```

## Safety Flags

No GitHub writes happen unless `--apply-actions` and the specific mutation flag are set.

Discovery flags:

- `--enable-create-issues`
- `--enable-update-issues`

Cleanup flags:

- `--enable-post-cleanup-comments`
- `--enable-close-issues`

Issue closure is disabled by default. Cleanup recommendations are `comment_only` unless closure is explicitly enabled.

## Human-Gated Review and Apply Workflow

Direct `--apply-actions` mutation (above) is one supported mode. The recommended mode for scheduled/CI runs is the two-stage, human-gated review workflow: discovery/cleanup produce reports, a review issue presents evidence and task-list checkboxes, and nothing touches an advisory issue until a maintainer closes that review issue with reason **Completed**.

### 1. Render a review locally (dry run, no GitHub calls)

`security-triage review render` builds the exact review issue title/body(ies) from discovery/cleanup JSON documents and writes them to local Markdown files. It never constructs a GitHub client, never reads `GITHUB_TOKEN`, and never makes a network call.

```bash
security-triage discovery --source-fixture tests/fixtures/discovery_entries.json \
  --issues-fixture tests/fixtures/github_issues.json --sbom-fixture tests/fixtures/sbom.json \
  --advisory-repo flatcar/security-triage --output reports/discovery.json

security-triage cleanup --issues-fixture tests/fixtures/github_issues.json \
  --sbom-fixture tests/fixtures/sbom.json --advisory-repo flatcar/security-triage \
  --output reports/cleanup.json

security-triage review render \
  --discovery-json reports/discovery.json \
  --cleanup-json reports/cleanup.json \
  --advisory-repo flatcar/security-triage \
  --review-repo flatcar/security-triage \
  --run-id local-preview-1 \
  --output-dir reports/review-dry-run
```

This writes one Markdown file per review part (for example
`reports/review-dry-run/local-preview-1-part-1.md`) plus a
`dry-run-summary.md` index. Each part file's content after the
`<!-- security-triage:dry-run-body-start -->` marker is byte-for-byte the
same body `review create` would submit to GitHub for that part, so this is a
safe way to inspect exactly what a scheduled run would produce before ever
creating anything.

### 2. Create the review issue(s)

`security-triage review create` builds the same batch and idempotently creates (or reuses, for a rerun of the same `--run-id`) one review issue per part, labeled `security-triage/review`:

```bash
security-triage review create \
  --discovery-json reports/discovery.json \
  --cleanup-json reports/cleanup.json \
  --advisory-repo flatcar/security-triage \
  --review-repo flatcar/security-triage \
  --run-id "$GITHUB_RUN_ID" \
  --output reports/review-create.json
```

Each review issue contains, per decision group: package/component, CVEs, CVSS, SBOM/existing-issue evidence, the recommendation and rationale, the exact proposed issue title/body or comment, and one or more checkboxes carrying a hidden machine-readable action ID. A single unchecked box means no action. A decision group with more than one checked box fails closed (conflict, skipped, reported). The full manifest needed to apply the batch is embedded, base64-encoded, in a hidden HTML comment; a SHA-256 digest inside it detects accidental corruption.

### 3. Apply on close

`security-triage review apply` re-fetches the review issue fresh (never trusts a webhook payload) and applies only checked, conflict-free, schema-valid actions when the issue's close reason is exactly `completed`:

```bash
security-triage review apply \
  --issue-number 123 \
  --advisory-repo flatcar/security-triage \
  --review-repo flatcar/security-triage \
  --enable-all-review-actions \
  --output reports/review-apply.json
```

Closing as **Not planned** (or any reason other than `completed`) makes zero GitHub writes. Apply performs only the fresh read needed to verify the close reason, then exits. Before every mutation, apply re-fetches the target issue, re-checks for a duplicate (for creates) or for open state and matching package/CVE identity (for updates/cleanup), and rebases additive body changes onto the *current* body using the same guarded field helpers as the direct-apply path, so existing content is never removed. Comments carry a hidden action-ID marker so reruns never repost. Once every selected group reaches a terminal result, the issue is labeled `security-triage/review-applied`; reopening and closing it again (or rerunning apply) is then a no-op.

`--enable-all-review-actions` is shorthand for `--enable-create-issues --enable-update-issues --enable-post-cleanup-comments --enable-close-issues`, reusing the same flags and removal guard as the direct `--apply-actions` path.

### GitHub Actions

- `.github/workflows/security-triage.yml` runs discovery/cleanup daily (`06:00 UTC`) with Microsoft Foundry via GitHub OIDC, then calls `review create`. See `docs/github-actions-foundry-oidc.md` for the one-time Azure setup (Portal and CLI paths, troubleshooting, and why no client secret is needed).
- `.github/workflows/security-triage-apply.yml` triggers only on `issues: closed` (plus a manual `workflow_dispatch` resume input) and calls `review apply`. It never calls Foundry, Azure, or reruns analysis.
- Both workflows pin `SECURITY_TRIAGE_ADVISORY_REPO`/`SECURITY_TRIAGE_REVIEW_REPO` (or the equivalent `--advisory-repo`/`--review-repo` arguments) to `${{ github.repository }}` for battle testing in this repository.

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

Review batches are not a stored document format in the same sense: `review render`/`review create` write per-part Markdown (the issue title/body) and a small JSON summary of created/existing issue URLs (`--output`, default `reports/review-create.json`); the authoritative, replayable state is the manifest embedded in each review issue itself, not a local file.

## Development

Common tasks run through the `Makefile`:

```bash
make test         # run pytest with coverage (term, HTML, XML, branch)
make test-quick   # run pytest without coverage
make lint         # ruff check src/ tests/
make format       # ruff format src/ tests/
make format-check # ruff format --check src/ tests/
make type-check   # mypy src/ tests/
make fix          # ruff format + ruff check --fix
make check        # format-check + lint + type-check + test
make ci           # alias for check, matches the CI pipeline
make build        # uv build (wheel + sdist into dist/)
make clean        # remove build/test artifacts
```

Equivalent `uv` invocations if you prefer to skip Make:

```bash
uv run pytest
uv run ruff check src/ tests/
uv run ruff format src/ tests/
uv run mypy src/ tests/
uv build
```

Coverage output lands in `htmlcov/` (HTML), `coverage.xml`, and the terminal report. Coverage is configured in `pyproject.toml`; the CLI-oriented `pytest.ini` mirrors the same options for direct `pytest` invocations.

The tests cover issue parsing, SBOM parsing, package matching, version comparison, severity/scope labels, discovery guardrails, cleanup guardrails, CLI output, GitHub Models and Foundry request shapes, source fetchers, fixture dry-run behavior, the review manifest/rendering/splitting/checkbox logic, apply-on-close gating and idempotency (using a stateful fake GitHub client), and GitHub Actions workflow policy (triggers, permissions, concurrency, and repository parameterization).

## Continuous Integration and Releases

GitHub Actions workflows live in `.github/workflows/`:

- `lint.yml`: ruff check, ruff format check, and mypy on push and pull request.
- `tests.yml`: pytest across Python 3.12, 3.13, and 3.14 on Ubuntu, macOS, and Windows.
- `install.yml`: builds the wheel and installs it into an isolated `uv venv` on all three OSes and Python versions, then verifies the `security-triage` entry point.
- `security-triage.yml`: the guarded discovery and cleanup pipeline itself.
- `release.yml`: semantic-release driven versioning, changelog, and GitHub Releases from `main`. Configuration lives in `release.config.js`.
- `publish.yml`: PyPI publishing template (disabled by default; uncomment when ready to publish).
