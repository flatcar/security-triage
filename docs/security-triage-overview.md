# Flatcar `security-triage`: How It Works

A Flatcar-specific advisory assistant with two read-only analysis workflows
(`discovery`, `cleanup`) plus one mutation-capable workflow (`review`) that is
always human-gated. It never writes to GitHub except through `review apply`,
and only after a maintainer explicitly closes a review issue as Completed.

## 1. Big Picture

```mermaid
flowchart LR
    subgraph Analysis["Read-only analysis (weekdays, automated)"]
        A["security-triage discovery"]
        B["security-triage cleanup"]
    end

    subgraph Review["Human-gated mutation"]
        C["review create"]
        D["Maintainer reviews\nissue on GitHub"]
        E["review apply"]
    end

    A -->|"discovery.json"| C
    B -->|"cleanup.json"| C
    C -->|"opens review issue\nwith checkboxes"| D
    D -->|"closes as Completed"| E
    E -->|"creates/updates/comments\non advisory issues"| F["flatcar/Flatcar\nadvisory issues"]

    classDef ro fill:#dff0ff,stroke:#3366cc,color:#000
    classDef gate fill:#fff3cd,stroke:#cc9900,color:#000
    classDef out fill:#d9f2d9,stroke:#339933,color:#000
    class A,B ro
    class C,D,E gate
    class F out
```

Key rule: `discovery` and `cleanup` **never** accept a mutation flag. Only
`review apply` can touch GitHub issues, and only for actions a maintainer
explicitly checked.

## 2. Discovery: Finding New Vulnerabilities

Purpose: scan upstream sources, decide if a finding is Flatcar-relevant, and
propose either a new advisory issue or an update to an existing one.

```mermaid
flowchart TD
    S1["Default upstream sources:\nGentoo Bugzilla, oss-security,\nGo vulndb, RustSec\n(+ optional RedHat with\n--include-optional-sources)"] --> P["Parse into SourceEntry list\n(7-day window default)"]
    P --> X["LLM: extract_advisory\n(package, CVEs, CVSS, refs)"]
    X --> SBOM["Match package against\ncurrent SBOM index"]
    X --> ISS["Match against existing\nflatcar/Flatcar issues"]
    SBOM --> COV{"Already fully covered\nby an existing issue and\nno upstream change?"}
    ISS --> COV
    COV -->|yes| SKIP["Record: already_tracked\n(skip LLM relevance call)"]
    COV -->|no| REL["LLM: decide_relevance\n(Flatcar relevance + action)"]
    REL --> G["apply_discovery_guardrails()"]

    G --> K{"Kernel package?"}
    K -->|yes| KOUT["status: kernel_regular_update_flow\n(never tracked as advisory)"]
    K -->|no| DUP{"decision=create_issue\nbut issue match exists?"}
    DUP -->|yes| FORCEUPD["forced to\nupdate_existing_issue"]
    DUP -->|no| VALID{"Missing package name /\nCVE+summary / evidence /\ninvalid action?"}
    VALID -->|yes| MANUAL["status: needs_manual_review"]
    VALID -->|no| FINAL["decision: create_issue |\nupdate_existing_issue | ignore"]

    FORCEUPD --> FINAL
    FINAL --> DOC["records[] appended to\ndiscovery.json"]
    KOUT --> DOC
    MANUAL --> DOC
    SKIP --> DOC

    classDef llm fill:#e6d9ff,stroke:#6633cc,color:#000
    classDef guard fill:#fff3cd,stroke:#cc9900,color:#000
    classDef out fill:#d9f2d9,stroke:#339933,color:#000
    class X,REL llm
    class G,K,DUP,VALID guard
    class DOC out
```

**Guardrails matter more than the LLM.** `apply_discovery_guardrails()` in
`rules.py` overrides the model whenever:

- the package is a kernel package → forced to `kernel_regular_update_flow`
  (Kernel CVEs follow the regular stable kernel release flow, never an
  advisory issue)

- a `create_issue` decision collides with an existing issue match → forced to
  `update_existing_issue` (no duplicates)

- required evidence is missing (no package name, no CVE/summary, no SBOM or
  relevance evidence) → forced to `needs_manual_review`

## 3. Cleanup: Verifying Open Advisories Are Fixed

Purpose: for every open `advisory`+`security` issue in `flatcar/Flatcar`,
check whether the current production SBOM proves it's already fixed.

**Important: there is no multi-version/channel awareness.** Flatcar ships
four channels (Alpha, Beta, Stable, LTS) that genuinely run different
versions. This tool fetches exactly one hardcoded source, the **Alpha**
channel's `current` SBOM
(`https://alpha.release.flatcar-linux.net/.../flatcar_production_image_sbom.json`),
and nothing else. There's no `--channel`/`--stream` flag, and no logic that
cross-checks Beta/Stable/LTS. Since Alpha receives fixes first, a package can
show as "remediated" here while Stable/Beta/LTS users are still on the
vulnerable version for weeks. Earlier versions of this repo's README/CLI help
text incorrectly said "Stable production SBOM", which has been corrected to
"Alpha channel" to match actual behavior.

```mermaid
flowchart TD
    Q["GitHub search:\nrepo:flatcar/Flatcar is:open\nlabel:advisory label:security"] --> PI["Parse issue body\n(Name/CVEs/CVSSs/Action Needed)"]
    PI --> FV["Extract fixed-version\nrequirement(s) from\nAction Needed"]
    FV --> SB["Look up package in\nFlatcar production SBOM\n(SPDX JSON)"]
    SB --> CMP{"Compare SBOM versionInfo\nvs required fixed version"}

    CMP -->|"found, version >= fixed,\nall CVEs covered"| REM["remediated_in_current_\nproduction_sbom"]
    CMP -->|"found, version < fixed"| NOTREM["not_remediated_in_\ncurrent_production_sbom"]
    CMP -->|"TBD action / not found /\nambiguous / SDK-only /\nsysext-only / epoch or rc\nversions / partial CVE cover"| MAN["needs_manual_review"]

    REM --> ACT["recommended_action:\ncomment_only (default)\nnever auto-close"]
    NOTREM --> KEEP["recommended_action:\nkeep_open"]
    MAN --> KEEP2["recommended_action:\nmanual_review"]

    classDef sbom fill:#dff0ff,stroke:#3366cc,color:#000
    classDef result fill:#d9f2d9,stroke:#339933,color:#000
    classDef caution fill:#fff3cd,stroke:#cc9900,color:#000
    class Q,PI,FV,SB sbom
    class REM result
    class NOTREM,MAN caution
```

Conservative-by-default rules baked into the logic:

- `advisory/only-sdk` and `advisory/sysext` issues are **never** marked
  remediated from the production SBOM alone (SDK/sysext content isn't
  necessarily represented there) → always `needs_manual_review`.

- Multi-CVE issues need **every** CVE covered by the same fixed version, or
  they fall to `needs_manual_review`.

- Struck-through (`~text~`) CVE/action fragments in manually-edited issues are
  ignored before extraction.

## 4. Review: The Only Path to Mutating GitHub Issues

```mermaid
sequenceDiagram
    participant D as discovery.json / cleanup.json
    participant C as review create
    participant GH as GitHub Issue (label: security-triage/review)
    participant M as Maintainer
    participant A as review apply

    D->>C: decision records
    C->>C: build DecisionGroup per record<br/>render checkboxes + evidence
    C->>C: embed base64 JSON manifest<br/>(SHA-256 digest) in HTML comment
    C->>GH: create review issue(s)<br/>(idempotent per --run-id)
    M->>GH: check boxes, close issue
    Note over M,GH: close reason must be exactly "Completed"
    A->>GH: re-fetch issue fresh (never trust webhook)
    A->>A: parse checked boxes,<br/>validate manifest digest,<br/>reject >1 checked box per group (conflict)
    alt close reason == completed
        A->>GH: apply only checked, conflict-free,<br/>schema-valid actions
        A->>GH: label security-triage/review-applied
    else any other close reason (e.g. Not planned)
        A->>A: zero GitHub writes
    end
```

Safety properties:

- **Fresh re-fetch, not webhook trust**: `review apply` re-reads the issue
  and re-validates everything before mutating anything.

- **Fail closed on conflict**: more than one checked box in a decision group
  → skipped, reported, no action taken.

- **Additive-only body edits**: existing `Action Needed`, `Summary`, CVEs,
  and human text are preserved; guarded field helpers rebase changes onto the
  *current* body.

- **Idempotent**: comments carry a hidden action-ID marker so reruns never
  repost; once every group is terminal, the issue gets
  `security-triage/review-applied` and further closes are no-ops.

- **Granular flags**: `--enable-create-issues`, `--enable-update-issues`,
  `--enable-post-cleanup-comments`, `--enable-close-issues` gate mutation
  categories individually (`--enable-all-review-actions` is shorthand for all
  four). These flags exist only on `review apply`.

## 5. Automation in GitHub Actions

```mermaid
flowchart LR
    T1["cron: 06:00 UTC Mon-Fri\nor workflow_dispatch"] --> W1["security-triage.yml"]
    W1 --> S1["discovery (Foundry via OIDC)"]
    W1 --> S2["cleanup (Foundry via OIDC)"]
    S1 --> RC["review create"]
    S2 --> RC
    RC --> ISSUE["review issue opened"]

    T2["issues: closed event\nor manual workflow_dispatch"] --> W2["security-triage-apply.yml"]
    ISSUE -.->|"maintainer closes"| T2
    W2 --> AP["review apply"]

    classDef trig fill:#fff3cd,stroke:#cc9900,color:#000
    classDef wf fill:#dff0ff,stroke:#3366cc,color:#000
    class T1,T2 trig
    class W1,W2 wf
```

- `security-triage.yml`: holds `issues: write`, but the only step that uses
  it is `review create` (opening/reusing the review issue); discovery and
  cleanup themselves never call it. Uses GitHub OIDC (`azure/login`) to mint
  a short-lived Foundry bearer token; no client secret is stored.

- `security-triage-apply.yml`: triggers only on `issues: closed`; performs no
  model inference and no cloud calls; purely a deterministic GitHub API
  operation gated by the Python `review apply` logic.

- Both workflows currently pin `SECURITY_TRIAGE_ADVISORY_REPO` and
  `SECURITY_TRIAGE_REVIEW_REPO` to `flatcar/security-triage` itself for battle
  testing, before ever pointing at the real `flatcar/Flatcar` repo.

## 6. LLM Usage: Bounded, Advisory-Only

```mermaid
flowchart LR
    E1["extract_advisory\n(gpt-5.4-mini)"] --> E2["decide_relevance\n(gpt-5.4)"]
    E2 --> E3["cleanup review\n(gpt-5.4, cleanup workflow)"]

    subgraph Providers
        F["Microsoft Foundry\n(--model foundry, preferred)"]
        G["GitHub Models\n(--model github, fallback)"]
    end
    Providers --> E1

    E1 -.->|"output is untrusted\nJSON, always validated"| GUARD["rules.py guardrails\n(deterministic, non-negotiable)"]
    E2 -.-> GUARD
    E3 -.-> GUARD
    GUARD --> FINAL["Final decision"]

    classDef llm fill:#e6d9ff,stroke:#6633cc,color:#000
    classDef guard fill:#fff3cd,stroke:#cc9900,color:#000
    class E1,E2,E3,F,G llm
    class GUARD guard
```

The LLM only extracts/summarizes/proposes; it never directly creates,
updates, or closes anything. All upstream text (Bugzilla comments, advisory
bodies) is treated as untrusted data, never as instructions: mentions are
neutralized and non-Gentoo `refmap.gentoo` URLs are rejected.

## 7. Quick Command Reference

```bash
# Analysis (read-only)
security-triage discovery --model foundry --output reports/discovery.json
security-triage cleanup   --model foundry --output reports/cleanup.json

# Human-gated mutation
security-triage review render --discovery-json ... --cleanup-json ... --output-dir reports/preview
security-triage review create --discovery-json ... --cleanup-json ... --run-id "$RUN_ID"
security-triage review apply  --issue-number 123 --enable-all-review-actions
```

## TL;DR

1. **Discovery/cleanup produce evidence, never touch GitHub.**
2. **Deterministic guardrails in `rules.py` override the LLM** for kernel
   packages, duplicates, missing evidence, and SDK/sysext ambiguity.
3. **`review create/apply` is the single, auditable gate** for every GitHub
   mutation, requiring an explicit maintainer "Completed" close and only
   acting on checked, conflict-free, freshly-revalidated actions.
