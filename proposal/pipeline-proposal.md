# Proposal: ETL-Based Security Pipeline with LLM-Assisted CVE Triage

> **Status: Work in progress**
>
> I will be away for approximately one month and expect to return on **September 21, 2026**. I did not have much time to fully develop or validate this proposal, so please treat it as an initial discussion document rather than a finalized design. Feedback, corrections, and alternative approaches are very welcome.

## Summary

This proposal explores treating the Flatcar security pipeline as an ETL-style pipeline:

**Extract → Transform → Triage → Load and Report**

The goal is to separate mechanical vulnerability processing from human security judgment while preserving the existing custom logic in `vex-automation` and the LLM-assisted workflow in `security-triage`.

The proposed system would:

1. Gather vulnerability information from multiple sources.
2. Normalize and match advisories against Flatcar packages and releases.
3. Create or update GitHub issues for findings that require review.
4. Use an LLM to prepare an initial triage proposal.
5. Allow a security triage maintainer to review and approve or override the proposal.
6. Store the resulting decision in a durable format.
7. Generate VEX documents from the findings and reviewed decisions.
8. Run checks to identify when previous `not_affected` decisions may no longer be valid.

This is not intended to replace the existing tools immediately. It is a possible direction for bringing them together into a more traceable and maintainable workflow.

## Problem

Flatcar vulnerability scanners may report CVEs against packages that are not actually exploitable in a Flatcar image.

For example, a package may contain vulnerable functionality upstream, but Flatcar may build the package with a USE flag that disables that functionality. Other reasons for a package being unaffected might include:

- The vulnerable component is not included in the image.
- The vulnerable code is not compiled into the package.
- The vulnerable code path cannot be reached in the Flatcar configuration.
- A mitigation already exists.
- The package version or product configuration is outside the affected scope.

These findings still need to be investigated and represented accurately in VEX. The important output is not only whether a CVE exists, but also why Flatcar is or is not affected.

A related concern is that a previous `not_affected` decision may become invalid if the underlying configuration changes.

For example:

1. Package `abc` version `1.2` contains code related to a CVE.
2. Flatcar builds it with `-someflag`.
3. The flag disables the vulnerable functionality.
4. The CVE is marked `not_affected`.
5. Later, the build configuration changes and the flag is removed.
6. Package `abc` remains at version `1.2`.
7. The vulnerable functionality is now included.
8. The previous triage decision is no longer valid.

One question for maintainers is whether this type of invalidation is already detected somewhere in the existing tooling.

## Proposed Pipeline Model

The pipeline could be organized into four broad stages:

### Extract

Collect raw data from sources such as:

- Gentoo GLSA data
- OSV
- Go vulnerability databases
- RustSec
- Gentoo Bugzilla
- `oss-security`
- Flatcar SBOMs
- Flatcar release metadata
- Flatcar build configuration

Where practical, raw upstream data should be retained before parsing. This would make it possible to fix a parser and rerun the transformation without retrieving all upstream data again.

A possible structure would be:

- `raw/glsa/<date>/`
- `raw/osv/<date>/`
- `raw/rustsec/<date>/`
- `raw/bugzilla/<date>/`

The Extract stage should primarily fetch and preserve data. Source-specific parsing and normalization should happen in the Transform stage.

### Transform

The Transform stage would convert source-specific records into normalized advisories and findings.

Possible outputs include:

- `advisories.ndjson`
- `findings.ndjson`

`advisories.ndjson` would contain normalized, release-independent advisory data, including:

- CVE identifier
- Source
- Package or product
- Affected version range
- Fixed version
- Advisory description
- Source timestamps
- References
- Severity information
- EPSS or KEV information, if available

`findings.ndjson` would contain the result of matching advisories against Flatcar packages and releases.

A finding might represent:

**CVE × package × Flatcar release**

Possible fields include:

- CVE identifier
- Package identifier
- Package version
- Flatcar channel
- Flatcar release
- SBOM reference
- Matching advisory
- Affected version result
- Initial status
- Evidence used by the matcher
- Build configuration information, if available
- Whether a previous decision exists
- Whether the previous decision may need revalidation

The default status for an unreviewed finding would likely be:

`under_investigation`

A raw version match should not automatically become `affected`. A match means that the finding requires investigation, not that the vulnerability is definitely exploitable in Flatcar.

### Triage

The Triage stage would combine automated analysis with human review.

The proposed workflow would be:

1. Generate findings.
2. Have the LLM analyze each finding.
3. Produce a proposed status, justification, confidence rating, and explanation.
4. Create or update GitHub issues.
5. Have a security triage maintainer review the proposal.
6. Allow the maintainer to approve or override the proposal.
7. Store the final decision.
8. Pass the decisions to VEX generation.

### Load and Report

The final stage would:

- Store the reviewed decisions.
- Generate VEX documents.
- Update GitHub issues.
- Produce reports or dashboards.
- Run validation checks.
- Re-queue decisions whose assumptions may no longer hold.

## LLM-Assisted Triage

The LLM would review each finding and prepare a proposal for the security triage maintainer.

The proposal could include:

- Suggested status
- Suggested VEX justification
- Confidence rating
- Explanation
- Evidence from the advisory
- Relevant package information
- Relevant Flatcar build configuration
- Similar previous decisions
- Whether manual review is required
- Suggested priority

The LLM should not be allowed to freely invent VEX values. Statuses and justifications should be limited to known values and validated before they are used.

The free-text explanation would be useful to the human reviewer, but structured fields should be the values consumed by automation.

Possible statuses include:

- `under_investigation`
- `not_affected`
- `affected`
- `fixed`

Possible `not_affected` justifications include:

- `component_not_present`
- `vulnerable_code_not_present`
- `vulnerable_code_not_in_execute_path`
- `vulnerable_code_cannot_be_controlled_by_adversary`
- `inline_mitigations_already_exist`

The exact set should be checked against the VEX format used by the project.

## GitHub Issues as the Review Interface

One possible approach is to create one issue per CVE. This would provide a durable, linkable record for each CVE and allow the discussion, evidence, and decision to remain associated with that CVE.

However, a single CVE may affect multiple packages, channels, or releases. The issue would therefore need to contain multiple finding entries rather than assuming that one CVE always corresponds to one package or one release.

Another possibility is to create grouped review issues for efficient triage. Findings could be grouped by:

- Similar proposed rationale
- The same USE flag
- The same Flatcar release
- The same package
- The same type of manual review
- Similar confidence levels

A possible hybrid model would be:

- Use grouped review issues for efficient triage.
- Maintain one canonical CVE issue or record for long-term history.
- Store the authoritative decision outside the issue body.
- Use GitHub issues as the review interface rather than the only database.

A review issue might contain entries such as:

- CVE: `CVE-2026-1234`
- Package: `app-misc/abc`
- Release: `stable-4593.2.4`
- Proposed status: `not_affected`
- Proposed justification: `vulnerable_code_not_present`
- Confidence: high
- Reason: built with `-someflag`
- Evidence: links to advisory and build configuration

The exact interaction mechanism remains open. Options include:

- Checkboxes in the issue body
- Commands in comments
- GitHub labels
- GitHub Projects custom fields
- A separate review interface that writes back to GitHub

Any automation that interprets a click, checkbox, label, or custom field should echo the parsed result before applying it. This would make incorrect parsing visible to the reviewer.

## Storing Decisions

The system needs to store more than just:

- CVE: `CVE-2026-1234`
- Status: `not_affected`

It should also store why the decision was made and what the decision depends on.

A possible decision record could contain:

- CVE identifier
- Package identifier
- Status
- VEX justification
- Human-readable rationale
- Confidence rating
- Reviewer
- Timestamp
- Source issue
- Supporting evidence
- Relevant package version
- Relevant USE flags
- Relevant build configuration
- Scope of the decision
- Conditions under which the decision remains valid

Possible storage locations include version-controlled files or GitHub issue data.

### Version-Controlled Decision Files

Decision files could be stored in a repository as NDJSON or JSON, for example:

- `decisions.ndjson`
- `decisions/CVE-2026-1234.json`

Advantages include:

- Review through pull requests.
- Easy backup.
- Independence from a specific platform.
- Clear history.
- Direct use by VEX generation.
- Compatibility with future tooling.

### GitHub Issue Data

GitHub issues have useful properties:

- Easy for maintainers to browse.
- Comments provide discussion history.
- Labels and custom fields provide a user interface.
- Each CVE can have a stable URL.

However:

- Issue data can be difficult to consume reliably.
- Labels and comments are not a complete decision model.
- Decisions become closely tied to GitHub.
- Multiple releases can be difficult to represent cleanly.

A possible approach is to treat version-controlled decision files as the authoritative source while using GitHub issues as the human review interface.

The filename and terminology are still open. Possible names include:

- `adjudications.ndjson`
- `decisions.ndjson`
- `verdicts.ndjson`
- `triage-decisions.ndjson`

`decisions.ndjson` may be clearer to maintainers than `adjudications.ndjson`.

## Multiple Flatcar Versions and Releases

A decision may apply to one release, several releases, or every release where the relevant conditions remain true.

For example:

- CVE-2026-1234 affects `abc` versions below `2.4`.
- Flatcar builds `abc` version `1.2` with `-someflag`.
- The vulnerable functionality is disabled.

The decision could apply to every Flatcar release that satisfies those same conditions.

At VEX generation time, the pipeline would evaluate the decision against each release:

1. Check whether package `abc` is present.
2. Check the package version.
3. Check the relevant build configuration.
4. Check whether the decision's premise still holds.
5. Apply the decision if it remains valid.
6. Otherwise return the finding to `under_investigation`.

This avoids requiring a maintainer to manually repeat the same decision for every release.

Possible decision scopes include:

| Scope | Example | Possible invalidation |
|---|---|---|
| Single release | Stable `4593.2.4` | A new release is produced |
| Package version | `abc < 2.4.0` | Package version changes |
| USE flag state | `-someflag` | The flag changes |
| Package presence | Package absent from image | Package appears |
| Build configuration | Specific profile or configuration | Configuration changes |
| General rule | Applies to all matching builds | Rule or package behavior changes |

It is still an open question whether the current build system exposes enough information to evaluate all of these conditions automatically.

A conservative implementation could initially attach decisions to specific release and package records. Broader conditions could be added later once the required build metadata is available.

## Revalidation and Configuration Changes

A key question is whether previous `not_affected` decisions are automatically rechecked when the build changes.

Potential checks include:

### SBOM Comparison

Compare the SBOM from the current release with the SBOM from the release where a decision was made.

This can detect:

- A package appearing in the image.
- A package disappearing.
- A package version changing.
- A dependency being added.
- A component being removed.

For example, a decision based on `component_not_present` could be checked by asking whether the component is still absent from the new SBOM.

### Build Configuration Comparison

Compare relevant build configuration between releases.

This might include:

- USE flags
- Package configuration
- Build profiles
- Sysext configuration
- Runtime configuration
- Kernel or image feature configuration

If a decision says that `-someflag` disables the vulnerable feature, the pipeline could detect whether the relevant resolved USE flag changed.

This requires both:

1. The decision to record its premise in a structured form.
2. The build system to expose the corresponding facts.

Whether the current system already provides this information is an open question.

### Re-running the Matcher

The mechanical matcher should run for every release. Previous decisions should not automatically suppress new findings without checking whether their premises still hold.

Possible outcomes include:

- Previous decision still valid.
- Previous decision may be invalid.
- Previous decision cannot be verified.
- New finding with no previous decision.

A changed or unverifiable decision could be returned to the review queue with a message such as:

> Previous decision requires review because the package build configuration changed.

### Policy Checks

Policy-as-code tools such as OPA or Conftest could potentially express rules such as:

- A `component_not_present` decision is valid only when the component is absent.
- A decision based on `-someflag` requires that `-someflag` still be enabled or disabled as expected.
- Every decision must have an author and timestamp.
- Every `not_affected` decision must have a valid justification.
- A decision must reference the evidence used to make it.

It is not yet clear whether an existing policy tool can model the Flatcar-specific configuration facts directly. A custom validator may be simpler.

## VEX Generation

VEX generation would consume:

- `findings.ndjson`
- Decision records
- Current SBOM
- Current build configuration
- Relevant advisory data

The generator would then:

1. Include unreviewed findings as `under_investigation`.
2. Apply reviewed decisions whose conditions still hold.
3. Re-queue or downgrade decisions whose premises changed.
4. Validate statuses and justifications.
5. Generate the VEX document.
6. Include issue references and supporting rationale where appropriate.
7. Produce a report of findings that were invalidated or require review.

The important safety property is that a stale decision should not silently remain active.

If a previous `not_affected` decision cannot be confirmed, the conservative fallback should be:

`under_investigation`

This is preferable to publishing an unsupported `not_affected` claim.

Possible output files could include:

- `vex/stable-4593.2.4.json`
- `vex/beta-4593.2.4.json`
- `findings/stable-4593.2.4.ndjson`
- `review/invalidated-decisions.ndjson`
- `review/new-findings.ndjson`
- `reports/triage-summary.html`

## Validation Layers

The pipeline could include several types of checks.

### Structural Checks

- Valid CVE identifiers.
- Valid package identifiers.
- Valid VEX statuses.
- Valid VEX justifications.
- Required author and timestamp.
- Required source issue or evidence.
- No duplicate decision keys.

### Mechanical Contradiction Checks

These should block VEX generation or fail the pipeline:

- `component_not_present` while the component is present.
- A decision references a package that is not part of the finding.
- A version condition is impossible.
- An invalid VEX justification is supplied.
- A `not_affected` statement has no justification.

### Premise-Change Checks

These should generally re-queue the finding rather than silently publish the old decision:

- Package version changed.
- Package appeared in or disappeared from an image.
- USE flags changed.
- Build profile changed.
- Relevant configuration changed.
- Advisory scope changed.
- The decision is older than an agreed review period.

### Reporting

The system should report:

- New findings.
- Findings still under investigation.
- Decisions applied.
- Decisions invalidated.
- Decisions that could not be verified.
- Findings where the LLM proposal was overridden.
- Findings associated with KEV or high EPSS values, if those signals are added.

## Possible Role for Trustify

Trustify may provide a useful user interface, search layer, and storage system for SBOMs, advisories, and VEX documents.

However, the custom Flatcar matching and triage logic would likely remain outside Trustify.

A possible integration would be:

`vex-automation` → `security-triage` → version-controlled decisions → VEX and SBOMs → Trustify

Trustify could then provide:

- Search
- Cross-release browsing
- VEX and SBOM history
- Access control
- A general vulnerability view

Before making Trustify the central triage application, we would need to determine whether it supports:

- Pending LLM proposals.
- Human approval and override.
- Custom Flatcar-specific findings.
- USE flag and build configuration evidence.
- Multiple Flatcar releases.
- Revalidation of previous decisions.
- External decision imports.
- OpenVEX round-tripping without losing justifications.

A likely initial integration strategy would be to keep the custom automation outside Trustify and use Trustify as a presentation and query layer.

## Open Questions

1. Does the current pipeline already detect invalidated `not_affected` decisions?
2. Are USE flags and relevant build configuration stored in a machine-readable form for each release?
3. What is currently the source of truth for triage decisions?
4. Should there be one issue per CVE, one issue per finding, or grouped review issues?
5. Should GitHub issues be authoritative, or should decisions be stored in version-controlled files?
6. How should decisions apply across multiple Flatcar releases?
7. Which decision premises can be revalidated automatically?
8. Which changes should invalidate a decision immediately?
9. How should the LLM confidence rating affect the review workflow?
10. Can high-confidence decisions be carried forward automatically?
11. Should a configuration change create a new issue, reopen an existing issue, or add a comment to an existing CVE issue?
12. Does Trustify support the pending-review workflow required here?
13. Should Trustify be used as the main interface, as a reporting layer, or not at all?
14. Should the initial implementation use a static dashboard and GitHub issues before introducing another platform?
15. Which data should be included in public VEX documents, and which should remain internal?

## Suggested Questions for Maintainers

> Do we currently track the assumptions behind a `not_affected` decision, such as USE flags, package presence, package version, or build configuration?
>
> If a package remains at the same version but its build configuration changes, does the security pipeline detect that a previous triage decision may no longer be valid?
>
> Are previous VEX decisions re-evaluated against every new SBOM and release, or are they treated as reusable suppressions once recorded?
>
> What is currently considered the source of truth for a CVE decision?
>
> Would a workflow that creates GitHub issues, uses LLM-generated triage suggestions, allows a maintainer to approve or override them, and then generates VEX documents be compatible with the existing process?
>
> Which parts of this workflow are already implemented, and which parts would require new automation?

## Closing Note

This proposal is intentionally incomplete. Its purpose is to make the possible workflow visible and provide concrete questions for discussion.

The most important areas to clarify are:

1. How decisions are currently stored.
2. Whether previous decisions are revalidated.
3. Whether build configuration is available as machine-readable evidence.
4. Which interface would make human triage efficient.
5. Whether an existing platform such as Trustify can provide that interface without replacing the custom Flatcar automation.

I will be away for approximately one month and expect to be back on **September 21, 2026**. Please treat this document as a work in progress because I did not have much time to fully develop it before leaving. Feedback and corrections are welcome.
