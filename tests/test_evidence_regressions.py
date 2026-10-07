import copy
import hashlib
import json

import pytest

from security_triage.cleanup import CleanupWorkflow
from security_triage.discovery import DiscoveryWorkflow
from security_triage.models import HeuristicModelClient
from security_triage.reasoning import build_discovery_evidence_bundle
from security_triage.records import Issue, SBOMPackage, SourceEntry
from security_triage.rules import (
    apply_discovery_guardrails,
    coerce_extraction,
    package_identities_match,
    package_identity,
    render_issue_body,
    source_fixed_version_evidence,
    validate_extraction_evidence,
)
from security_triage.sbom import (
    SBOMIndex,
    evaluate_simple_affected_range,
    fixed_version_coverage,
)


def entry(package, extra="Fixed in 1.2.3"):
    return SourceEntry(
        source="gentoo",
        source_url="https://bugs.gentoo.org/12345",
        entry_id="12345",
        title=f"{package}: security advisory",
        content=f"Package: {package}\nCVE: CVE-2026-12345\n{extra}",
    )


def index(package, version="1.2.3", purls=None, metadata=None):
    return SBOMIndex(
        [SBOMPackage(package, version, "SPDXRef-package", purls=purls or [])],
        metadata=metadata,
    )


def decide(source, sbom):
    model = HeuristicModelClient()
    extraction = validate_extraction_evidence(model.extract_advisory(source), source)
    identity = extraction["package_identity"]
    matches = sbom.match_package(identity)
    scope = sbom.scope_evidence(identity)
    bundle = build_discovery_evidence_bundle(
        source.entry_id,
        source,
        extraction,
        matches,
        [],
        scope_evidence=scope,
        sbom_metadata=sbom.metadata,
    )
    result = model.decide_relevance(bundle)
    relevance, decision, reasons = apply_discovery_guardrails(
        extraction,
        result["flatcar_relevance"],
        result["decision"],
        matches,
        [],
        source.title,
        scope_evidence=scope,
    )
    return extraction, relevance, decision, reasons


def issue(
    package="expat",
    action="update to >= 2.7.5",
    cves=None,
    labels=None,
    summary="Upstream security fixes.",
):
    return Issue(
        number=10,
        title=f"update: {package}",
        body=render_issue_body(
            package,
            cves or ["CVE-2026-11111", "CVE-2026-22222"],
            [],
            action,
            summary,
            "TBD",
        ),
        labels=labels or ["advisory", "security"],
        html_url="https://github.com/flatcar/security-triage/issues/10",
    )


class OverconfidentModel(HeuristicModelClient):
    def review_cleanup(self, evidence_bundle):
        return {
            "decision": "remediated_in_current_production_sbom",
            "confidence": "high",
            "reasons": ["Trust me, every CVE is fixed."],
        }


@pytest.mark.parametrize(
    "left,right",
    [
        ("tar", "pkg:cargo/tar@0.4.44"),
        ("go", "pkg:golang/go@1.0"),
        ("github.com/pion/dtls/v3", "pkg:golang/go.etcd.io/etcd/client/v3@3.6.0"),
        ("v3", "pkg:golang/github.com/pion/dtls/v3@3.0.1"),
        ("policycoreutils", "pkg:github/Castro-Fidel/PortProtonQt@1.0"),
        ("etcdctl", "etcd"),
        ("org-a/component", "org-b/component"),
        ("pkg:cargo/python", "python"),
        ("pkg:gentoo/dev-libs/component", "pkg:gentoo/net-libs/component"),
    ],
)
def test_identity_preserves_ecosystem_and_namespace(left, right):
    assert not package_identities_match(left, right)


@pytest.mark.parametrize(
    "left,right",
    [
        ("openssl", "dev-libs/openssl"),
        ("CPython", "python"),
        ("python", "pkg:gentoo/dev-lang/python@3.13.2"),
        ("github.com/pion/dtls/v3", "pkg:golang/github.com/pion/dtls/v3@v3.0.1"),
        ("pkg:cargo/tar@0.4.44?arch=amd64", "pkg:cargo/tar@0.4.43"),
    ],
)
def test_explicit_aliases_and_full_identities_match(left, right):
    assert package_identities_match(left, right)


def test_generic_module_namespace_is_not_stripped():
    assert (
        package_identity("some.example/team/component") == "some.example/team/component"
    )


@pytest.mark.parametrize(
    "name,purl,query",
    [
        ("tar", "pkg:gentoo/app-arch/tar@1.35", "pkg:cargo/tar"),
        ("tar", "pkg:cargo/tar@0.4.44", "tar"),
        ("go", "pkg:golang/go@1.0", "go"),
        (
            "go.etcd.io/etcd/client/v3",
            "pkg:golang/go.etcd.io/etcd/client/v3@3.6",
            "github.com/pion/dtls/v3",
        ),
        ("PortProtonQt", "pkg:github/Castro-Fidel/PortProtonQt@1.0", "policycoreutils"),
    ],
)
def test_sbom_never_promotes_colliding_names_to_exact(name, purl, query):
    assert not any(
        match["match_type"] in {"exact_name", "exact_purl"}
        for match in index(name, purls=[purl]).match_package(query)
    )


def test_rust_tar_advisory_does_not_use_gnu_tar_presence():
    source = entry("tar", "Rust tar crate vulnerability.\nFixed in 0.4.44")
    extraction, relevance, decision, _ = decide(
        source, index("tar", "1.35", ["pkg:gentoo/app-arch/tar@1.35"])
    )
    assert extraction["package_identity"] == "pkg:cargo/tar"
    assert relevance["scope"] == "unknown"
    assert decision["action"] == "needs_manual_review"


def test_go_module_named_go_is_not_the_native_go_toolchain():
    source = entry("go", "Go module named go has a vulnerability.\nFixed in 1.2.3")
    extraction, relevance, decision, _ = decide(
        source,
        index("go", "1.25", ["pkg:gentoo/dev-lang/go@1.25"]),
    )
    assert extraction["package_identity"] == "pkg:golang/go"
    assert relevance["scope"] == "unknown"
    assert decision["action"] == "needs_manual_review"


def test_model_cannot_pair_different_source_package_names_and_purls():
    source = entry("openssl", "Related package: pkg:cargo/tar@0.4.44\nFixed in 1.2.3")
    extraction = validate_extraction_evidence(
        {
            "package_name": "openssl",
            "cves": ["CVE-2026-12345"],
            "package_purl": "pkg:cargo/tar@0.4.44",
        },
        source,
    )
    assert extraction["evidence_validation"]["status"] == "needs_manual_review"


def test_source_derived_ecosystem_identity_can_be_revalidated():
    source = entry("tar", "Rust tar crate vulnerability.\nFixed in 0.4.44")
    first = validate_extraction_evidence(
        HeuristicModelClient().extract_advisory(source), source
    )
    second = validate_extraction_evidence(first, source)
    assert second["package_identity"] == "pkg:cargo/tar"
    assert second["evidence_validation"]["status"] == "validated"


@pytest.mark.parametrize("package", ["bubblewrap", "zfs", "podman"])
def test_absence_does_not_guess_sdk_sysext_or_not_shipped(package):
    _, relevance, decision, _ = decide(entry(package), SBOMIndex([]))
    assert relevance["scope"] == "unknown"
    assert decision["action"] == "needs_manual_review"


@pytest.mark.parametrize(
    "package,scope",
    [
        ("bubblewrap", "sdk_only"),
        ("zfs", "sysext"),
        ("podman", "sysext"),
        ("build-tool", "build_only"),
    ],
)
def test_scope_can_be_provided_by_validated_caller_evidence(package, scope):
    metadata = {
        "scope_evidence": [
            {
                "package": package,
                "scope": scope,
                "source": "maintainer-validated-fixture",
                "validated": True,
            }
        ]
    }
    _, relevance, decision, _ = decide(entry(package), SBOMIndex([], metadata))
    assert relevance["scope"] == scope
    assert decision["action"] == "create_issue"


def test_source_scope_assertions_do_not_prove_shipping():
    _, relevance, decision, _ = decide(
        entry("bubblewrap", "Flatcar ships this SDK-only package.\nFixed in 1.2.3"),
        SBOMIndex([]),
    )
    assert relevance["scope"] == "unknown"
    assert decision["action"] == "needs_manual_review"


def test_weak_identity_cannot_be_upgraded_by_model_scope_assertion():
    source = entry("etcdctl")
    extraction = validate_extraction_evidence(
        HeuristicModelClient().extract_advisory(source), source
    )
    matches = index("etcd").match_package("etcdctl")
    relevance, decision, _ = apply_discovery_guardrails(
        extraction,
        {"status": "relevant", "scope": "production", "evidence": ["I say so"]},
        {"action": "create_issue", "confidence": "high"},
        matches,
        [],
        source.title,
    )
    assert relevance["scope"] == "unknown"
    assert decision["action"] == "needs_manual_review"


def test_opentelemetry_bsd_only_bug_is_not_linux_affectedness():
    package = "go.opentelemetry.io/otel"
    source = entry(package, "This defect only affects FreeBSD.\nFixed in 1.2.3")
    _, relevance, decision, _ = decide(source, index(package))
    assert relevance["status"] == "not_relevant"
    assert relevance["scope"] == "unknown"
    assert decision["action"] == "ignore"


def test_c_ares_before_known_fix_remains_actionable():
    extraction, relevance, decision, _ = decide(
        entry("c-ares", "Affected versions: < 1.34.7\nFixed in 1.34.7"),
        index("c-ares", "1.34.6"),
    )
    assert relevance["scope"] == "production"
    assert decision["action"] == "create_issue"
    assert extraction["action_needed"] == "update to >= 1.34.7"
    report = CleanupWorkflow(
        HeuristicModelClient(),
        index("c-ares", "1.34.6"),
        [issue("c-ares", "update to >= 1.34.7")],
    ).run()
    assert report["records"][0]["status"] == "not_remediated_in_current_production_sbom"


@pytest.mark.parametrize(
    "placeholder", ["TBD", "update target", "<update target>", "update target or TBD"]
)
def test_known_source_fix_replaces_placeholder_not_template(placeholder):
    source = entry("c-ares", "Fixed in 1.34.7")
    extraction = validate_extraction_evidence(
        {
            "package_name": "c-ares",
            "cves": ["CVE-2026-12345"],
            "fixed_versions": ["1.34.7"],
            "action_needed": placeholder,
            "confidence": "high",
        },
        source,
    )
    assert extraction["action_needed"] == "update to >= 1.34.7"
    assert extraction["evidence_validation"]["status"] == "validated"


def test_branch_requirements_are_preserved_and_never_pick_first():
    source = entry("systemd", "Fixed in 260 or 259.5")
    extraction = validate_extraction_evidence(
        {
            "package_name": "systemd",
            "fixed_versions": ["260", "259.5"],
            "action_needed": "update to >= 260",
        },
        source,
    )
    assert extraction["action_needed"] == "update to >= 260 or >= 259.5"
    assert (
        coerce_extraction(
            {
                "package_name": "systemd",
                "fixed_versions": ["260", "259.5"],
            }
        )["action_needed"]
        == "TBD"
    )


def test_affected_version_cannot_be_recast_as_a_fix_by_model():
    source = entry("expat", "Affected versions: >= 2.7.0\nNo fix is available.")
    extraction = validate_extraction_evidence(
        {
            "package_name": "expat",
            "fixed_versions": ["2.7.0"],
            "action_needed": "update to >= 2.7.0",
            "confidence": "high",
            "evidence_validation": {"status": "validated"},
        },
        source,
    )
    assert extraction["evidence_validation"]["status"] == "needs_manual_review"
    assert extraction["action_needed"] == "TBD"


@pytest.mark.parametrize(
    "evidence",
    [
        {
            "fixed_versions": [
                {"source_url": "https://evil.example/", "quote": "Fixed in 1.2.3"}
            ]
        },
        {
            "fixed_versions": [
                {"source_url": "https://bugs.gentoo.org/12345", "quote": "Fixed in 9.9"}
            ]
        },
        {"package_name": [{"source_url": ["not", "a", "url"], "quote": "expat"}]},
    ],
)
def test_malicious_model_evidence_is_revalidated(evidence):
    source = entry("expat")
    extraction = validate_extraction_evidence(
        {
            "package_name": "expat",
            "fixed_versions": ["1.2.3"],
            "field_evidence": evidence,
            "confidence": "high",
            "evidence_validation": {"status": "validated", "errors": []},
        },
        source,
    )
    assert extraction["evidence_validation"]["status"] == "needs_manual_review"
    assert extraction["confidence"] == "low"


def test_source_citations_are_retained_without_granting_scope_confidence():
    source = entry("expat")
    extraction = validate_extraction_evidence(
        {
            "package_name": "expat",
            "cves": ["CVE-2026-12345"],
            "fixed_versions": ["1.2.3"],
            "field_evidence": {
                "fixed_versions": [
                    {
                        "source_url": source.source_url,
                        "quote": "Fixed in 1.2.3",
                    }
                ]
            },
            "scope_assessment": "production",
            "confidence": "high",
        },
        source,
    )
    assert extraction["evidence_validation"]["status"] == "validated"
    assert extraction["confidence_dimensions"]["scope"] == "low"
    assert (
        extraction["field_evidence"]["fixed_versions"][0]["quote"] == "Fixed in 1.2.3"
    )


@pytest.mark.parametrize(
    "action",
    [
        "CVE-2026-11111: update to >= 2.7.5",
        "CVE-2026-11111: update to >= 2.7.5; CVE-2026-22222: TBD",
        "update to >= 2.7.5 and apply another patch",
        "update to >= 2.7.5 or wait for an unreleased fix",
        "update to >= 2.7.5; CVE-2026-22222 remains open",
        "CVE-2026-11111: update to >= 2.7.5 or CVE-2026-22222: update to >= 3.0",
    ],
)
def test_partial_expat_requirements_never_close_even_with_model_approval(action):
    report = CleanupWorkflow(
        OverconfidentModel(),
        index("expat", "9.9"),
        [issue(action=action)],
    ).run()
    record = report["records"][0]
    assert record["status"] == "needs_manual_review"
    assert not record["cve_coverage"]["complete"]
    assert record["comment_body"] == ""


def test_incus_summary_partial_coverage_blocks_shared_version_requirement():
    record = CleanupWorkflow(
        OverconfidentModel(),
        index("incus", "6.20"),
        [
            issue(
                "incus",
                "update to >= 6.19",
                summary="Only fixes CVE-2026-11111; CVE-2026-22222 is unresolved.",
            )
        ],
    ).run()["records"][0]
    assert record["status"] == "needs_manual_review"


@pytest.mark.parametrize(
    "action",
    [
        "update to >= 260 or 259.5",
        "update to >= 260 or >= 259.5",
    ],
)
def test_simple_or_branch_requirements_remain_supported(action):
    record = CleanupWorkflow(
        HeuristicModelClient(),
        index("systemd", "259.6"),
        [issue("systemd", action)],
    ).run()["records"][0]
    assert record["status"] == "remediated_in_current_production_sbom"
    assert record["cve_coverage"]["complete"]


def test_all_cve_explicit_and_requirements_use_highest():
    action = "CVE-2026-11111: update to >= 2.7.5; CVE-2026-22222: update to >= 2.8.0"
    record = CleanupWorkflow(
        HeuristicModelClient(),
        index("expat", "2.7.5"),
        [issue(action=action)],
    ).run()["records"][0]
    assert record["status"] == "not_remediated_in_current_production_sbom"
    assert record["cve_coverage"]["covered_cves"] == [
        "CVE-2026-11111",
        "CVE-2026-22222",
    ]


def test_invalid_normalization_cannot_invent_fixed_requirement_or_drop_cves():
    class InventedNormalization(OverconfidentModel):
        def normalize_issue(self, advisory):
            return {
                "name": "expat",
                "cves": ["CVE-2026-11111"],
                "action_needed": "update to >= 1.0",
                "valid": True,
                "missing_fields": [],
            }

    advisory = issue(action="TBD")
    advisory.body = advisory.body.replace("CVSSs: n/a\n", "")
    record = CleanupWorkflow(
        InventedNormalization(),
        index("expat", "9.9"),
        [advisory],
    ).run()["records"][0]
    assert record["status"] == "needs_manual_review"
    assert record["fixed_version_requirement"] is None
    assert record["cves_from_issue"] == ["CVE-2026-11111", "CVE-2026-22222"]


def test_true_ambiguous_match_cannot_be_overridden_by_model():
    sbom = SBOMIndex(
        [
            SBOMPackage("expat", "2.7.5", "SPDXRef-one"),
            SBOMPackage("expat", "2.8.0", "SPDXRef-two"),
        ]
    )
    record = CleanupWorkflow(OverconfidentModel(), sbom, [issue()]).run()["records"][0]
    assert record["status"] == "needs_manual_review"


@pytest.mark.parametrize(
    "package,scope,label",
    [
        ("bubblewrap", "sdk_only", "advisory/only-sdk"),
        ("podman", "sysext", "advisory/sysext"),
        ("zfs", "sysext", "advisory/sysext"),
    ],
)
def test_cleanup_requires_explicit_scope_associated_with_exact_sbom_entry(
    package, scope, label
):
    advisory = issue(
        package, "update to >= 1.2.3", labels=["advisory", "security", label]
    )
    sbom = index(package)
    assert (
        CleanupWorkflow(OverconfidentModel(), sbom, [advisory]).run()["records"][0][
            "status"
        ]
        == "needs_manual_review"
    )
    sbom.metadata["scope_evidence"] = [
        {
            "package": package,
            "scope": scope,
            "source": "validated production SPDX scope",
            "validated": True,
        }
    ]
    assert (
        CleanupWorkflow(OverconfidentModel(), sbom, [advisory]).run()["records"][0][
            "status"
        ]
        == "needs_manual_review"
    )
    sbom.metadata["scope_evidence"][0]["spdx_id"] = "SPDXRef-package"
    assert (
        CleanupWorkflow(OverconfidentModel(), sbom, [advisory]).run()["records"][0][
            "status"
        ]
        == "remediated_in_current_production_sbom"
    )


def test_cleanup_document_has_spdx_metadata_and_stable_snapshot_digest():
    payload = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-document",
        "creationInfo": {"created": "2026-10-01T00:00:00Z"},
        "packages": [
            {"name": "expat", "versionInfo": "2.7.5", "SPDXID": "SPDXRef-package"}
        ],
    }
    sbom = SBOMIndex.from_spdx(payload)
    advisory = issue()
    document = CleanupWorkflow(HeuristicModelClient(), sbom, [advisory]).run()
    expected = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert document["sbom_snapshot_sha256"] == expected
    assert document["sbom_metadata"]["spdxVersion"] == "SPDX-2.3"
    assert (
        document["records"][0]["issue_body_sha256"]
        == hashlib.sha256(advisory.body.encode()).hexdigest()
    )
    changed = copy.deepcopy(payload)
    changed["packages"][0]["versionInfo"] = "2.7.6"
    assert SBOMIndex.from_spdx(changed).metadata["snapshot_sha256"] != expected


def test_source_fix_parser_does_not_accept_affected_only_ranges():
    assert source_fixed_version_evidence("Affected: >= 1.0") == []
    assert source_fixed_version_evidence("Fixed in 260 or 259.5")[0]["versions"] == [
        "260",
        "259.5",
    ]
    assert not fixed_version_coverage(
        "update to >= 2.0 then investigate", ["CVE-2026-12345"]
    )["complete"]


def test_negated_fix_is_not_a_fixed_version():
    assert source_fixed_version_evidence("This is not fixed in 1.2.3") == []


def test_linux_inclusion_is_not_misread_as_bsd_exclusion():
    source = entry(
        "go.opentelemetry.io/otel",
        "This defect does not only affect FreeBSD; Linux is affected too.\nFixed in 1.2.3",
    )
    extraction = validate_extraction_evidence(
        HeuristicModelClient().extract_advisory(source), source
    )
    assert extraction["platform_applicability"] == "unknown"


@pytest.mark.parametrize(
    "constraint",
    [
        "This defect only affects FreeBSD. Linux is also affected.",
        "Linux is not affected on amd64 but is vulnerable on arm64.",
    ],
)
def test_scoped_or_conflicting_platform_claims_cannot_exclude_all_linux(constraint):
    source = entry("component", f"{constraint}\nFixed in 1.2.3")
    extraction = validate_extraction_evidence(
        HeuristicModelClient().extract_advisory(source), source
    )
    assert extraction["platform_applicability"] == "unknown"


def test_reused_spdx_id_does_not_hide_conflicting_package_versions():
    sbom = SBOMIndex(
        [
            SBOMPackage("expat", "2.7.4", "SPDXRef-duplicate"),
            SBOMPackage("expat", "2.7.5", "SPDXRef-duplicate"),
        ]
    )
    assert len(sbom.match_package("expat")) == 2
    record = CleanupWorkflow(OverconfidentModel(), sbom, [issue()]).run()["records"][0]
    assert record["status"] == "needs_manual_review"


def test_main_repository_snapshot_is_not_cleanup_release_proof():
    sbom = index(
        "expat",
        "9.9",
        metadata={
            "source_url": "https://github.com/flatcar/coreos-overlay/tree/main",
        },
    )
    record = CleanupWorkflow(OverconfidentModel(), sbom, [issue()]).run()["records"][0]
    assert record["status"] == "needs_manual_review"


def test_model_cannot_silently_drop_source_cves():
    source = entry("expat", "CVE-2026-23456\nFixed in 2.7.5")
    extraction = validate_extraction_evidence(
        {
            "package_name": "expat",
            "cves": ["CVE-2026-12345"],
            "fixed_versions": ["2.7.5"],
            "confidence": "high",
        },
        source,
    )
    assert extraction["evidence_validation"]["status"] == "needs_manual_review"
    assert any(
        "omitted" in reason for reason in extraction["evidence_validation"]["errors"]
    )


def test_shared_action_cannot_hide_a_higher_per_cve_summary_requirement():
    record = CleanupWorkflow(
        OverconfidentModel(),
        index("expat", "2.7.5"),
        [
            issue(
                summary="CVE-2026-11111 fixed in 2.7.5. CVE-2026-22222 affects versions before 2.8.0."
            )
        ],
    ).run()["records"][0]
    assert record["status"] == "needs_manual_review"
    assert not record["cve_coverage"]["complete"]


def test_package_presence_does_not_override_explicit_affected_version_range():
    _, relevance, decision, _ = decide(
        entry("c-ares", "Affected versions: < 1.34.7\nFixed in 1.34.7"),
        index("c-ares", "1.34.7"),
    )
    assert relevance["affectedness_assessment"]["status"] == "not_affected"
    assert decision["action"] == "ignore"


@pytest.mark.parametrize(
    "version,affected_range,result",
    [
        ("1.2.3", "< 1.2.3", "not_affected"),
        ("1.2.3", "<= 1.2.3", "affected"),
        ("1.2.3", "> 1.2.3", "not_affected"),
        ("1.2.3", ">= 1.2.3", "affected"),
        ("1.2.3-r1", "> 1.2.3", "affected"),
        ("1.2.3-rc1", "< 1.2.3", "ambiguous"),
        ("1.2.3", ">= 1.0, < 2.0", "ambiguous"),
    ],
)
def test_simple_affected_version_comparisons(version, affected_range, result):
    assert evaluate_simple_affected_range(version, affected_range).result == result


@pytest.mark.parametrize(
    "summary",
    [
        "This also fixes CVE-2026-99999.",
        "Upstream reference https://invented.example/advisory",
        "Fixed in 9.9.",
    ],
)
def test_summary_cannot_smuggle_unsupported_structured_claims(summary):
    source = entry("expat")
    extraction = validate_extraction_evidence(
        {
            "package_name": "expat",
            "cves": ["CVE-2026-12345"],
            "summary": summary,
            "fixed_versions": ["1.2.3"],
            "confidence": "high",
        },
        source,
    )
    assert extraction["evidence_validation"]["status"] == "needs_manual_review"


@pytest.mark.parametrize(
    "package,scope",
    [
        ("bubblewrap", "sdk_only"),
        ("zfs", "sysext"),
        ("podman", "sysext"),
    ],
)
def test_authoritative_scope_snapshots_produce_executable_discovery_evidence(
    package, scope
):
    scope_sbom = index(package)
    evidence = scope_sbom.discovery_scope_evidence(package, scope)
    assert evidence[0]["snapshot_sha256"] == scope_sbom.metadata["snapshot_sha256"]
    assert evidence[0]["match_type"] == "exact_name"
    assert evidence[0]["discovery_only"] is True
    production_sbom = SBOMIndex([], {"scope_evidence": evidence})
    _, relevance, decision, _ = decide(entry(package), production_sbom)
    assert relevance["scope"] == scope
    assert decision["action"] == "create_issue"


def test_scope_snapshot_never_promotes_weak_or_ambiguous_matches():
    assert index("etcd").discovery_scope_evidence("etcdctl", "sdk_only") == []
    ambiguous = SBOMIndex(
        [
            SBOMPackage("podman", "5.1", "SPDXRef-one"),
            SBOMPackage("podman", "5.2", "SPDXRef-two"),
        ]
    )
    assert ambiguous.discovery_scope_evidence("podman", "sysext") == []
    assert (
        index("tar", purls=["pkg:gentoo/app-arch/tar@1.35"]).discovery_scope_evidence(
            "pkg:cargo/tar",
            "sdk_only",
        )
        == []
    )


def test_sdk_snapshot_presence_does_not_make_production_package_sdk_only():
    production = index("bubblewrap")
    production.metadata["scope_evidence"] = index(
        "bubblewrap"
    ).discovery_scope_evidence(
        "bubblewrap",
        "sdk_only",
    )
    _, relevance, decision, _ = decide(entry("bubblewrap"), production)
    assert relevance["scope"] == "production"
    assert decision["action"] == "create_issue"


def test_discovery_scope_snapshot_can_never_prove_cleanup_scope():
    scope_sbom = index("podman", "5.4.2")
    production = index("podman", "5.4.2")
    production.metadata["scope_evidence"] = scope_sbom.discovery_scope_evidence(
        "podman",
        "sysext",
    )
    advisory = issue(
        "podman",
        "update to >= 5.4.2",
        labels=["advisory", "security", "advisory/sysext"],
    )
    record = CleanupWorkflow(OverconfidentModel(), production, [advisory]).run()[
        "records"
    ][0]
    assert record["status"] == "needs_manual_review"


def test_scope_snapshot_cannot_be_misdeclared_as_production_proof():
    with pytest.raises(ValueError, match="Discovery scope snapshots"):
        index("podman").discovery_scope_evidence("podman", "production")


@pytest.mark.parametrize(
    "package,scope,label",
    [
        ("bubblewrap", "sdk_only", "advisory/only-sdk"),
        ("podman", "sysext", "advisory/sysext"),
    ],
)
def test_scope_snapshot_evidence_runs_end_to_end_through_discovery(
    package, scope, label
):
    workflow = DiscoveryWorkflow(
        HeuristicModelClient(),
        SBOMIndex([]),
        [],
        scope_evidence=index(package).discovery_scope_evidence(package, scope),
    )
    record = workflow.run(
        [entry(package)],
        "2026-10-01T00:00:00Z",
        "2026-10-07T00:00:00Z",
    )["records"][0]
    assert record["decision"]["action"] == "create_issue"
    assert record["flatcar_relevance"]["scope"] == scope
    assert label in record["proposed_issue"]["labels"]


def test_conflicting_exclusive_scope_cannot_override_production_evidence():
    production = index(
        "bubblewrap",
        metadata={
            "scope_evidence": [
                {
                    "package": "bubblewrap",
                    "scope": "sdk_only",
                    "source": "exclusive-caller-claim",
                    "validated": True,
                }
            ]
        },
    )
    _, relevance, decision, reasons = decide(entry("bubblewrap"), production)
    assert relevance["scope"] == "production"
    assert relevance["confirmed_scopes"] == ["production"]
    assert decision["action"] == "needs_manual_review"
    assert any("conflicts" in reason for reason in reasons)


@pytest.mark.parametrize("production_present", [False, True])
def test_dual_sdk_sysext_snapshots_preserve_all_confirmed_scopes(production_present):
    package = "python"
    scopes = [
        *index(package).discovery_scope_evidence(package, "sdk_only"),
        *index(package).discovery_scope_evidence(package, "sysext"),
    ]
    production = index(package) if production_present else SBOMIndex([])
    production.metadata["scope_evidence"] = scopes
    _, relevance, decision, _ = decide(entry(package), production)
    assert relevance["confirmed_scopes"] == (
        ["production", "sysext"] if production_present else ["sdk_only", "sysext"]
    )
    assert relevance["scope"] == ("production" if production_present else "sdk_only")
    assert decision["action"] == "create_issue"


@pytest.mark.parametrize("production_present", [False, True])
def test_sdk_sysext_labels_follow_snapshot_production_precedence(production_present):
    production = index("python") if production_present else SBOMIndex([])
    workflow = DiscoveryWorkflow(
        HeuristicModelClient(),
        production,
        [],
        scope_evidence=[
            *index("python").discovery_scope_evidence("python", "sdk_only"),
            *index("python").discovery_scope_evidence("python", "sysext"),
        ],
    )
    record = workflow.run(
        [entry("python")],
        "2026-10-01T00:00:00Z",
        "2026-10-07T00:00:00Z",
    )["records"][0]
    assert record["decision"]["action"] == "create_issue"
    labels = record["proposed_issue"]["labels"]
    assert "advisory/sysext" in labels
    assert ("advisory/only-sdk" in labels) is not production_present


def test_repeated_sysext_snapshots_are_searched_independently():
    workflow = DiscoveryWorkflow(
        HeuristicModelClient(),
        SBOMIndex([]),
        [],
        scope_evidence=[
            *index("podman").discovery_scope_evidence("podman", "sysext"),
            *index("zfs").discovery_scope_evidence("zfs", "sysext"),
        ],
    )
    record = workflow.run(
        [entry("zfs")],
        "2026-10-01T00:00:00Z",
        "2026-10-07T00:00:00Z",
    )["records"][0]
    assert record["decision"]["action"] == "create_issue"
    assert record["flatcar_relevance"]["scope"] == "sysext"
    assert len(record["scope_evidence"]) == 1
    assert record["scope_evidence"][0]["sbom_package"] == "zfs"


@pytest.mark.parametrize(
    "purl,ecosystem",
    [
        ("pkg:golang/github.com/siyuan-note/siyuan/kernel", "Go"),
        ("pkg:cargo/kernel", "cargo"),
    ],
)
def test_foreign_kernel_display_name_does_not_override_validated_identity(
    purl, ecosystem
):
    source = entry("kernel", f"Package URL: {purl}\nFixed in 1.2.3")
    extraction = validate_extraction_evidence(
        {
            "package_name": "kernel",
            "package_purl": purl,
            "ecosystem": ecosystem,
            "cves": ["CVE-2026-12345"],
            "fixed_versions": ["1.2.3"],
            "confidence": "high",
        },
        source,
    )
    assert extraction["evidence_validation"]["status"] == "validated"
    matches = index("kernel", purls=[purl]).match_package(
        extraction["package_identity"]
    )
    bundle = build_discovery_evidence_bundle(
        "kernel-test", source, extraction, matches, []
    )
    pair = HeuristicModelClient().decide_relevance(bundle)
    relevance, decision, _ = apply_discovery_guardrails(
        extraction,
        pair["flatcar_relevance"],
        pair["decision"],
        matches,
        [],
        source.title,
    )
    assert relevance["status"] != "kernel_regular_update_flow"
    assert decision["action"] == "create_issue"
    _, unsupported, reasons = apply_discovery_guardrails(
        extraction,
        {"status": "kernel_regular_update_flow", "scope": "unknown"},
        {"action": "kernel_regular_update_flow", "confidence": "high"},
        matches,
        [],
        source.title,
    )
    assert unsupported["action"] == "needs_manual_review"
    assert any("kernel routing is unsupported" in reason for reason in reasons)


def test_actual_linux_kernel_still_routes_but_util_linux_does_not():
    _, _, kernel_decision, _ = decide(entry("linux-kernel"), SBOMIndex([]))
    assert kernel_decision["action"] == "kernel_regular_update_flow"
    source = entry(
        "util-linux", "Linux kernel interaction in a userspace tool.\nFixed in 1.2.3"
    )
    source.title = "util-linux: Linux kernel interaction"
    _, _, userspace_decision, _ = decide(source, index("util-linux"))
    assert userspace_decision["action"] == "create_issue"


def test_unaffected_range_cannot_be_extracted_as_affected_and_hide_vulnerable_package():
    source = entry("expat", "Unaffected versions: >= 2.7.5\nFixed in 2.7.5")
    extraction, _, decision, _ = decide(source, index("expat", "2.7.4"))
    assert extraction["affected_versions"] == []
    assert decision["action"] != "ignore"


def test_model_affected_range_requires_positive_affected_context_not_token_presence():
    source = entry("expat", "Unaffected versions: >= 2.7.5\nFixed in 2.7.5")
    extraction = validate_extraction_evidence(
        {
            "package_name": "expat",
            "cves": ["CVE-2026-12345"],
            "affected_versions": [">= 2.7.5"],
            "fixed_versions": ["2.7.5"],
            "confidence": "high",
        },
        source,
    )
    assert extraction["evidence_validation"]["status"] == "needs_manual_review"
    _, decision, _ = apply_discovery_guardrails(
        extraction,
        {"status": "not_relevant", "scope": "production"},
        {"action": "ignore", "confidence": "high"},
        index("expat", "2.7.4").match_package("expat"),
        [],
        source.title,
    )
    assert decision["action"] == "needs_manual_review"


def test_linux_exclusion_must_cover_every_source_cve():
    source = entry(
        "expat",
        "CVE-2026-12345 only affects FreeBSD. "
        "CVE-2026-23456 affects every supported platform.\nFixed in 2.7.5",
    )
    extraction, _, decision, _ = decide(source, index("expat", "2.7.4"))
    assert set(extraction["cves"]) == {"CVE-2026-12345", "CVE-2026-23456"}
    assert extraction["platform_applicability"] != "not_affected_linux"
    assert decision["action"] == "needs_manual_review"
    _, model_ignore, _ = apply_discovery_guardrails(
        extraction,
        {"status": "not_relevant", "scope": "production"},
        {"action": "ignore", "confidence": "high"},
        index("expat", "2.7.4").match_package("expat"),
        [],
        source.title,
    )
    assert model_ignore["action"] == "needs_manual_review"


@pytest.mark.parametrize("sdk_version", ["2.7.4", None, "2.7.5-rc1"])
def test_unaffected_production_cannot_hide_affected_or_unknown_sdk(sdk_version):
    production = index("expat", "2.7.5")
    production.metadata["scope_evidence"] = index(
        "expat",
        sdk_version,
    ).discovery_scope_evidence("expat", "sdk_only")
    _, relevance, decision, reasons = decide(
        entry("expat", "Affected versions: < 2.7.5\nFixed in 2.7.5"),
        production,
    )
    assert decision["action"] == "needs_manual_review"
    assert relevance["affectedness_assessment"]["status"] == "needs_manual_review"
    assert any("sdk_only" in reason for reason in reasons)


@pytest.mark.parametrize(
    "prefix", ["Unaffected", "Not affected", "Previously affected"]
)
def test_nonpositive_affected_labels_never_supply_affected_ranges(prefix):
    source = entry("expat", f"{prefix} versions: >= 2.7.5\nFixed in 2.7.5")
    extraction, _, decision, _ = decide(source, index("expat", "2.7.4"))
    assert extraction["affected_versions"] == []
    assert decision["action"] != "ignore"


def test_platform_exclusion_does_not_cross_cve_boundaries_in_one_sentence():
    source = entry(
        "expat",
        "CVE-2026-12345 only affects FreeBSD, whereas CVE-2026-23456 "
        "has an upstream memory safety defect.\nFixed in 2.7.5",
    )
    extraction, _, decision, _ = decide(source, index("expat", "2.7.4"))
    assert extraction["platform_applicability"] == "needs_manual_review"
    assert extraction["platform_evidence"]["unproven_advisory_ids"] == [
        "CVE-2026-23456"
    ]
    assert decision["action"] == "needs_manual_review"


def test_explicit_linux_exclusion_for_each_cve_can_ignore_the_advisory():
    source = entry(
        "expat",
        "CVE-2026-12345 only affects FreeBSD. "
        "CVE-2026-23456 only affects OpenBSD.\nFixed in 2.7.5",
    )
    extraction, _, decision, _ = decide(source, index("expat", "2.7.4"))
    assert extraction["platform_evidence"]["unproven_advisory_ids"] == []
    assert decision["action"] == "ignore"


def test_all_evidenced_scopes_must_be_outside_range_before_ignore():
    production = index("expat", "2.7.5")
    production.metadata["scope_evidence"] = [
        *index("expat", "2.7.6").discovery_scope_evidence("expat", "sdk_only"),
        *index("expat", "2.7.5").discovery_scope_evidence("expat", "sysext"),
    ]
    _, relevance, decision, _ = decide(
        entry("expat", "Affected versions: < 2.7.5\nFixed in 2.7.5"),
        production,
    )
    assert decision["action"] == "ignore"
    assert {
        item["scope"]
        for item in relevance["affectedness_assessment"]["scope_assessments"]
    } == {
        "sdk_only",
        "sysext",
    }
    assert all(
        item["status"] == "not_affected"
        for item in relevance["affectedness_assessment"]["scope_assessments"]
    )
