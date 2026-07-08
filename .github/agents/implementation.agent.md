---
description: "Use when: implementing, testing, or finishing the Flatcar security_triage automation system, including discovery, cleanup, SBOM analysis, GitHub issue handling, model reasoning, reporting, CLI commands, and documentation."
tools: [read, edit, search, execute, web, todo, agent]
---

# Flatcar Security Triage Implementation Mode

Use `.github/copilot-instructions.md` as the authoritative process, policy, model-runtime, issue-style, cleanup, and safety source. If this file conflicts with `.github/copilot-instructions.md`, the main Copilot instructions win.

This mode is for maintaining and extending the existing `security_triage` implementation under `src/security_triage/`, including discovery, cleanup, source ingestion, SBOM analysis, GitHub issue handling, model clients, reporting, CLI behavior, GitHub Actions, documentation, and tests.

This is not a generic CVE scanner. Keep changes Flatcar-specific, conservative, evidence-grounded, and compatible with the current manual advisory style.

## Working Defaults

- Prefer Microsoft Foundry for local model-backed runs.
- Use GitHub Models as the GitHub Actions and fallback provider.
- Keep default runs read-only; mutations require explicit CLI flags and validated records.
- Preserve existing issue content with additive guarded updates.
- Prefer `needs_manual_review` over false tracking or false cleanup.

## Validation

Use focused tests for the touched behavior. For general validation, use:

```bash
.venv/bin/python -m pytest
```

If the editable install is missing, bootstrap with:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev,yaml]'
```