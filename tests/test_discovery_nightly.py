import json
import runpy
import sys
from pathlib import Path
from typing import Any

import pytest

from security_triage import sbom as sbom_module
from security_triage.cli import build_parser, main
from security_triage.discovery import DiscoveryWorkflow
from security_triage.http_utils import HTTPError
from security_triage.models import HeuristicModelClient
from security_triage.records import Issue, SourceEntry
from security_triage.reporting import render_discovery_markdown
from security_triage.rules import FLATCAR_PRODUCTION_SBOM_URL
from security_triage.sbom import (
    FLATCAR_MAIN_VERSION_URL,
    FLATCAR_NIGHTLY_IMAGE_BASE_URL,
    SBOMIndex,
    fetch_flatcar_discovery_sbom,
    resolve_main_nightly_version,
)

FIXTURES = Path(__file__).parent / "fixtures"
VERSION = "4845.0.0+nightly-20261006-2100"
NIGHTLY_URL = (
    f"{FLATCAR_NIGHTLY_IMAGE_BASE_URL}/{VERSION}/flatcar_production_image_sbom.json"
)
MANIFEST = (
    f"FLATCAR_VERSION={VERSION}\n"
    "FLATCAR_VERSION_ID=4845.0.0\n"
    'FLATCAR_BUILD_ID="nightly-20261006-2100"\n'
    f"FLATCAR_SDK_VERSION={VERSION}\n"
)


def _payload(version: str | None = "3.2.4") -> dict[str, Any]:
    return {
        "spdxVersion": "SPDX-2.3",
        "packages": [{"name": "openssl", "versionInfo": version}],
    }


def _sbom(version: str | None = "3.2.4", source: str = "nightly") -> SBOMIndex:
    index = SBOMIndex.from_spdx(_payload(version))
    index.metadata["provenance"] = {
        "source": source,
        "version": VERSION if source == "nightly" else None,
        "manifest_url": FLATCAR_MAIN_VERSION_URL if source == "nightly" else None,
        "sbom_url": NIGHTLY_URL if source == "nightly" else FLATCAR_PRODUCTION_SBOM_URL,
    }
    return index


def _entry() -> SourceEntry:
    return SourceEntry(
        source="gentoo",
        source_url="https://bugs.gentoo.org/123456",
        entry_id="123456",
        title="openssl: security vulnerability",
        content="Package: openssl\nCVE: CVE-2026-12345\nAffected versions: < 3.2.4\nFixed in 3.2.4",
    )


def _run(entry=None, index=None, model=None, issues=None):
    return DiscoveryWorkflow(
        model or HeuristicModelClient(), index or _sbom(), issues or []
    ).run([entry or _entry()], "2026-10-01T00:00:00Z", "2026-10-07T00:00:00Z")


def test_resolve_main_manifest_preserves_image_plus_version():
    assert resolve_main_nightly_version(MANIFEST) == VERSION


@pytest.mark.parametrize(
    "manifest",
    [
        "",
        f"FLATCAR_VERSION_ID={VERSION}",
        f"FLATCAR_VERSION={VERSION}\nFLATCAR_VERSION={VERSION}",
        f"FLATCAR_VERSION={VERSION}\nexport FLATCAR_VERSION=1.2.3",
        f'FLATCAR_VERSION="{VERSION}"',
        f"FLATCAR_VERSION={VERSION}-INTERMEDIATE",
        "FLATCAR_VERSION=4845.0.0",
        "FLATCAR_VERSION=4845.0.0-nightly-20261006-2100",
        "FLATCAR_VERSION=../../some/path",
        "FLATCAR_VERSION=https://untrusted.test/sbom",
        "FLATCAR_VERSION=$(untrusted-command)",
        f"FLATCAR_VERSION={VERSION};untrusted-command",
        f"FLATCAR_VERSION={VERSION}/../../other",
    ],
)
def test_reject_unsafe_or_nonfinal_manifest(manifest):
    with pytest.raises(ValueError):
        resolve_main_nightly_version(manifest)


def test_fetch_nightly_pins_once_and_records_provenance(monkeypatch):
    calls = []

    def text(url, **kwargs):
        calls.append(url)
        return MANIFEST

    def payload(url, **kwargs):
        calls.append(url)
        # SPDX missing optional fields remains valid.
        return {"spdxVersion": "SPDX-2.3", "packages": [{"name": "openssl"}, {}]}

    monkeypatch.setattr(sbom_module, "fetch_text", text)
    monkeypatch.setattr(sbom_module, "fetch_json", payload)
    index = fetch_flatcar_discovery_sbom()
    assert calls == [FLATCAR_MAIN_VERSION_URL, NIGHTLY_URL]
    assert index.packages[0].version_info is None
    assert index.metadata["provenance"] == {
        "source": "nightly",
        "version": VERSION,
        "manifest_url": FLATCAR_MAIN_VERSION_URL,
        "sbom_url": NIGHTLY_URL,
        "architecture": "amd64",
    }


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"spdxVersion": "SPDX-2.3"},
        {"spdxVersion": "SPDX-2.3", "packages": None},
        {"spdxVersion": "SPDX-2.3", "packages": []},
        {"spdxVersion": "SPDX-2.3", "packages": {}},
        {"spdxVersion": "SPDX-2.3", "packages": ["invalid"]},
        {"spdxVersion": "SPDX-2.3", "packages": [{}]},
        {"spdxVersion": "SPDX-2.3", "packages": [{"name": 42}]},
        {
            "spdxVersion": "SPDX-2.3",
            "packages": [{"name": "openssl", "externalRefs": ["bad"]}],
        },
    ],
)
def test_nightly_rejects_missing_or_malformed_inventory(monkeypatch, payload):
    calls = []
    monkeypatch.setattr(sbom_module, "fetch_text", lambda *a, **k: MANIFEST)

    def fetch(url, **kwargs):
        calls.append(url)
        return payload

    monkeypatch.setattr(sbom_module, "fetch_json", fetch)
    with pytest.raises(ValueError, match="No fallback was used"):
        fetch_flatcar_discovery_sbom()
    assert calls == [NIGHTLY_URL]


@pytest.mark.parametrize(
    "failure",
    [HTTPError("HTTP 404"), HTTPError("DNS unavailable"), ValueError("invalid JSON")],
)
def test_nightly_unavailable_fails_without_alpha_fallback(monkeypatch, failure):
    calls = []
    monkeypatch.setattr(sbom_module, "fetch_text", lambda *a, **k: MANIFEST)

    def fetch(url, **kwargs):
        calls.append(url)
        raise failure

    monkeypatch.setattr(sbom_module, "fetch_json", fetch)
    with pytest.raises(
        ValueError, match="Discovery nightly SBOM unavailable or invalid"
    ) as error:
        fetch_flatcar_discovery_sbom()
    assert VERSION in str(error.value)
    assert calls == [NIGHTLY_URL]


@pytest.mark.parametrize("failure", [HTTPError("unavailable"), None])
def test_manifest_failure_never_fetches_artifact(monkeypatch, failure):
    def fetch(*args, **kwargs):
        if failure:
            raise failure
        return "FLATCAR_VERSION=INTERMEDIATE"

    monkeypatch.setattr(sbom_module, "fetch_text", fetch)
    monkeypatch.setattr(
        sbom_module, "fetch_json", lambda *a, **k: pytest.fail("artifact fetch")
    )
    with pytest.raises(ValueError, match="Cannot resolve main nightly manifest"):
        fetch_flatcar_discovery_sbom()


@pytest.mark.parametrize("source", ["nightly", "alpha", "fixture"])
def test_cli_discovery_source_selection_and_offline_fixture_precedence(
    monkeypatch, tmp_path, capsys, source
):
    calls = []

    def text(url, **kwargs):
        calls.append(url)
        assert source == "nightly"
        return MANIFEST

    def payload(url, **kwargs):
        calls.append(url)
        assert source != "fixture"
        return _payload()

    monkeypatch.setattr(sbom_module, "fetch_text", text)
    monkeypatch.setattr(sbom_module, "fetch_json", payload)
    output, markdown = tmp_path / "discovery.json", tmp_path / "discovery.md"
    args = [
        "discovery",
        "--source-fixture",
        str(FIXTURES / "discovery_entries.json"),
        "--issues-fixture",
        str(FIXTURES / "github_issues.json"),
        "--output",
        str(output),
        "--markdown-output",
        str(markdown),
    ]
    if source == "alpha":
        args.extend(["--sbom-source", "alpha"])
    elif source == "fixture":
        args.extend(
            ["--sbom-source", "alpha", "--sbom-fixture", str(FIXTURES / "sbom.json")]
        )
    assert main(args) == 0
    document = json.loads(output.read_text())
    provenance = document["sbom_metadata"]["provenance"]
    assert provenance["source"] == source
    assert all(
        record["sbom_provenance"] == provenance for record in document["records"]
    )
    assert f"SBOM source: {source}" in markdown.read_text()
    assert f"Discovery SBOM source: {source}" in capsys.readouterr().err
    if source == "fixture":
        assert calls == []
        assert provenance["fixture_path"] == str((FIXTURES / "sbom.json").resolve())
        assert "nightly" not in provenance
    elif source == "nightly":
        assert calls == [FLATCAR_MAIN_VERSION_URL, NIGHTLY_URL]
        assert provenance["version"] == VERSION
        assert "does not prove all CI passed" in markdown.read_text()
    else:
        assert calls == [FLATCAR_PRODUCTION_SBOM_URL]
        assert provenance["sbom_url"] == FLATCAR_PRODUCTION_SBOM_URL


def test_cli_cleanup_still_fetches_alpha_and_has_no_source_flag(monkeypatch, tmp_path):
    calls = []

    def fetch(url, **kwargs):
        calls.append(url)
        return _payload()

    monkeypatch.setattr(sbom_module, "fetch_json", fetch)
    monkeypatch.setattr(
        sbom_module, "fetch_text", lambda *a, **k: pytest.fail("manifest fetch")
    )
    output = tmp_path / "cleanup.json"
    assert (
        main(
            [
                "cleanup",
                "--issues-fixture",
                str(FIXTURES / "github_issues.json"),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert calls == [FLATCAR_PRODUCTION_SBOM_URL]
    assert json.loads(output.read_text())["sbom_url"] == FLATCAR_PRODUCTION_SBOM_URL
    with pytest.raises(SystemExit):
        build_parser().parse_args(["cleanup", "--sbom-source", "nightly"])


def test_cli_missing_nightly_does_not_write_discovery_report(monkeypatch, tmp_path):
    monkeypatch.setattr(sbom_module, "fetch_text", lambda *a, **k: MANIFEST)

    def fail(*args, **kwargs):
        raise HTTPError("HTTP 404")

    monkeypatch.setattr(sbom_module, "fetch_json", fail)
    output = tmp_path / "discovery.json"
    assert (
        main(
            [
                "discovery",
                "--issues-fixture",
                str(FIXTURES / "github_issues.json"),
                "--source-fixture",
                str(FIXTURES / "discovery_entries.json"),
                "--output",
                str(output),
            ]
        )
        == 1
    )
    assert not output.exists()


def test_existing_discovery_dry_run_wrapper_stays_offline(monkeypatch, tmp_path):
    def no_network(*args, **kwargs):
        pytest.fail("Fixture-backed dry-run wrapper attempted network I/O")

    monkeypatch.setattr("security_triage.http_utils.open_request", no_network)
    output = tmp_path / "discovery.md"
    wrapper_path = FIXTURES.parents[1] / "scripts/local/run_discovery_dry_run.py"
    monkeypatch.setattr(sys, "argv", [str(wrapper_path), "--output", str(output)])
    # The existing wrapper adjusts sys.path; keep that local to this test.
    monkeypatch.setattr(sys, "path", list(sys.path))
    wrapper = runpy.run_path(str(wrapper_path))
    assert wrapper["wrapper"]() == 0
    document = json.loads(output.with_suffix(".json").read_text())
    assert document["sbom_metadata"]["provenance"]["source"] == "fixture"
    assert all(
        record["sbom_provenance"]["source"] == "fixture"
        for record in document["records"]
    )


def test_old_alpha_proposes_but_fixed_nightly_ignores_with_heuristic():
    old = _run(index=_sbom("3.2.3", "alpha"))["records"][0]
    assert old["decision"]["action"] == "create_issue"
    assert old["proposed_issue"]["title"] == "update: openssl"
    assert set(old["proposed_issue"]["labels"]) == {"advisory", "security"}
    document = _run()
    record = document["records"][0]
    assert record["decision"]["action"] == "ignore"
    assert record["proposed_issue"] is None
    assert record["fixed_version_evidence"]["fixed_version"] == "3.2.4"
    assert f"Already fixed in main nightly {VERSION}" in record["decision"]["reason"]
    assert "not released remediation" in record["decision"]["reason"]
    assert NIGHTLY_URL in render_discovery_markdown(document)


@pytest.mark.parametrize("package_field", [True, False])
@pytest.mark.parametrize("fix", ["Fixed in 3.2.4", "Action Needed: update to >= 3.2.4"])
def test_source_grounded_simple_fix_forms(package_field, fix):
    entry = _entry()
    entry.content = entry.content.replace("Fixed in 3.2.4", fix)
    if not package_field:
        entry.content = entry.content.replace("Package: openssl\n", "")
    record = _run(entry=entry, index=_sbom("3.2.4-r1"))["records"][0]
    assert record["decision"]["action"] == "ignore"
    assert record["fixed_version_evidence"]["source_statement"] == fix


@pytest.mark.parametrize(
    "change",
    [
        "missing_version",
        "prerelease",
        "ambiguous_match",
        "weak_match",
        "purl_only",
        "no_fix",
        "tbd",
        "backport",
        "sdk",
        "sysext",
        "build",
        "multi_cve",
        "hidden_cve",
        "multi_package",
        "branch",
        "qualified_fix",
        "comments",
        "different_package",
        "affected_range",
    ],
)
def test_uncertain_fixed_versions_do_not_suppress_tracking(change):
    entry, index = _entry(), _sbom()
    if change == "missing_version":
        index = _sbom(None)
    elif change == "prerelease":
        index = _sbom("3.2.4-rc1")
    elif change == "ambiguous_match":
        index.packages.extend(_sbom("3.2.3").packages)
    elif change == "weak_match":
        index.packages[0].name = "openssl-library"
    elif change == "purl_only":
        index.packages[0].name = "different-name"
        index.packages[0].purls = ["pkg:gentoo/dev-libs/openssl@3.2.4"]
    elif change == "no_fix":
        entry.content = entry.content.replace("Fixed in 3.2.4", "")
    elif change == "tbd":
        entry.content += "\nAction Needed: TBD"
    elif change == "backport":
        entry.description = "A backport must be verified separately."
    elif change == "sdk":
        entry.content += "\nSDK-only package."
    elif change == "sysext":
        entry.content += "\nSystem extension package."
    elif change == "build":
        entry.content += "\nBuild-only package."
    elif change == "multi_cve":
        entry.content += "\nCVE-2026-54321 is also affected."
    elif change == "hidden_cve":
        entry.raw = {"additional_cve": "CVE-2026-54321"}
    elif change == "multi_package":
        entry.content += "\nPackage: libgcrypt"
    elif change == "branch":
        entry.content = entry.content.replace(
            "Fixed in 3.2.4", "Fixed in 3.2.4 or 3.1.8"
        )
    elif change == "qualified_fix":
        entry.content = entry.content.replace("Fixed in 3.2.4", "Not fixed in 3.2.4")
    elif change == "comments":
        entry.comments = [{"text": "The scope is being discussed."}]
    elif change == "different_package":
        entry.content = entry.content.replace(
            "Fixed in 3.2.4", "libgcrypt fixed in 3.2.4"
        )
    elif change == "affected_range":
        entry.content = entry.content.replace("< 3.2.4", "< 4.0")
    record = _run(entry=entry, index=index)["records"][0]
    assert record["decision"]["action"] in {"create_issue", "needs_manual_review"}
    assert record["fixed_version_evidence"] is None


def test_live_like_multi_cve_gentoo_model_uses_nightly_without_shortcut():
    cves = ["CVE-2026-12345", "CVE-2026-54321"]
    description = (
        "Upstream reports two certificate validation issues, CVE-2026-12345 and "
        "CVE-2026-54321, affecting OpenSSL 3.2.x before 3.2.4. "
        "OpenSSL 3.2.4 addresses both issues in the production library."
    )
    comment = {
        "count": 1,
        "creator": "maintainer@gentoo.org",
        "creation_time": "2026-10-06T21:00:00Z",
        "text": "Confirmed upstream: upgrading dev-libs/openssl to 3.2.4 fixes both CVEs.",
    }
    entry = SourceEntry(
        source="gentoo",
        source_url="https://bugs.gentoo.org/123456",
        entry_id="123456",
        title="dev-libs/openssl: multiple certificate validation vulnerabilities",
        content=f"Gentoo vulnerability bug 123456\nDescription:\n{description}\nNew comments:\n{comment['text']}",
        description=description,
        comments=[comment],
        new_comments=[comment],
        metadata={"alias": cves, "severity": "major"},
    )
    seen_sources = []

    class SourceGroundedModel(HeuristicModelClient):
        def extract_advisory(self, entry):
            return {
                "package_name": "openssl",
                "cves": cves,
                "affected_versions": ["3.2.x before 3.2.4"],
                "fixed_versions": ["3.2.4"],
                "action_needed": "update to >= 3.2.4",
                "summary": description,
                "scope_assessment": "production",
                "confidence": "high",
            }

        def decide_relevance(self, bundle):
            assert bundle["fixed_version_evidence"] is None
            assert bundle["source_entry"]["description"] == description
            assert bundle["source_entry"]["comments"] == [comment]
            assert bundle["source_entry"]["new_comments"] == [comment]
            assert bundle["llm_extraction"]["cves"] == cves
            provenance = bundle["sbom_metadata"]["provenance"]
            seen_sources.append(provenance["source"])
            match = bundle["sbom_package_matches"][0]
            assert match["match_type"] == "exact_name"
            fixed = match["versionInfo"] == "3.2.4"
            if fixed:
                assert provenance["source"] == "nightly"
                assert provenance["version"] == VERSION
                assert provenance["sbom_url"] == NIGHTLY_URL
                reason = (
                    "Main nightly contains OpenSSL 3.2.4; the upstream description "
                    "and maintainer comment confirm both CVEs share this fix. "
                    "This does not establish released remediation."
                )
            else:
                assert provenance["source"] == "alpha"
                assert provenance["sbom_url"] == FLATCAR_PRODUCTION_SBOM_URL
                reason = (
                    "Alpha contains affected OpenSSL 3.2.3, below the shared 3.2.4 fix."
                )
            result = super().decide_relevance(bundle)
            result["flatcar_relevance"].update(
                status="not_relevant" if fixed else "relevant",
                scope="production",
                evidence=[description, comment["text"], reason],
            )
            result["decision"].update(
                action="ignore" if fixed else "create_issue",
                confidence="high",
                reason=reason,
            )
            return result

    model = SourceGroundedModel()
    alpha = _run(entry=entry, index=_sbom("3.2.3", "alpha"), model=model)["records"][0]
    nightly = _run(entry=entry, index=_sbom(), model=model)["records"][0]
    assert seen_sources == ["alpha", "nightly"]
    assert alpha["decision"]["action"] == "create_issue"
    assert alpha["proposed_issue"] is not None
    assert nightly["decision"]["action"] == "ignore"
    assert nightly["proposed_issue"] is None
    assert nightly["manual_review_reasons"] == []
    assert nightly["fixed_version_evidence"] is None
    assert "both CVEs share this fix" in nightly["decision"]["reason"]


@pytest.mark.parametrize(
    "reason",
    [
        "The affected optional feature is excluded by Flatcar's USE flags.",
        "The advisory's affected version range does not include this production package.",
    ],
)
def test_normal_model_exclusions_survive_exact_sbom_matches(reason):
    class ExclusionModel(HeuristicModelClient):
        def decide_relevance(self, bundle):
            assert bundle["sbom_package_matches"][0]["match_type"] == "exact_name"
            assert bundle["fixed_version_evidence"] is None
            result = super().decide_relevance(bundle)
            result["flatcar_relevance"]["status"] = "not_relevant"
            result["flatcar_relevance"]["evidence"] = [reason]
            result["decision"].update(action="ignore", reason=reason)
            return result

    entry = _entry()
    entry.content = entry.content.replace("Fixed in 3.2.4", "Action Needed: TBD")
    record = _run(entry=entry, model=ExclusionModel())["records"][0]
    assert record["decision"]["action"] == "ignore"
    assert record["decision"]["reason"] == reason
    assert record["manual_review_reasons"] == []
    assert record["proposed_issue"] is None


@pytest.mark.parametrize("change", ["low_confidence", "hidden_range", "title_package"])
def test_uncertain_source_cannot_be_overruled_by_extraction(change):
    class IncompleteModel(HeuristicModelClient):
        def extract_advisory(self, entry):
            extraction = super().extract_advisory(entry)
            if change == "low_confidence":
                extraction["confidence"] = "low"
            if change == "hidden_range":
                extraction["affected_versions"] = []
            return extraction

    entry = _entry()
    if change == "hidden_range":
        entry.content = entry.content.replace("< 3.2.4", "< 4.0")
    elif change == "title_package":
        entry.title = "libgcrypt: another package is affected"
    record = _run(entry=entry, model=IncompleteModel())["records"][0]
    assert record["decision"]["action"] in {"create_issue", "needs_manual_review"}
    assert record["fixed_version_evidence"] is None


@pytest.mark.parametrize("change", ["comment", "cve"])
def test_fixed_nightly_does_not_suppress_additive_existing_issue_update(change):
    body = (
        "Name: openssl\nCVEs: CVE-2026-12345\nCVSSs: n/a\n"
        "Action Needed: update to >= 3.2.4\nSummary: Keep human context.\n\n"
        "refmap.gentoo: https://bugs.gentoo.org/123456"
    )
    issue = Issue(
        42,
        "update: openssl",
        body,
        ["security", "advisory"],
        "https://github.com/flatcar/Flatcar/issues/42",
    )
    entry = _entry()
    if change == "comment":
        entry.new_comments = [
            {"count": 1, "text": "Additional upstream exploitability details."}
        ]
    else:
        entry.content += "\nCVE: CVE-2026-54321"
    record = _run(entry=entry, issues=[issue])["records"][0]
    assert record["decision"]["action"] == "update_existing_issue"
    assert record["fixed_version_evidence"] is None
    update = record["proposed_update"]
    assert update["matched_existing_issue"]["body"] == body
    if change == "comment":
        assert "Additional upstream exploitability details." in update["comment_body"]
        assert update["updated_body"] is None
    else:
        assert "Keep human context." in update["updated_body"]
        assert "CVE-2026-54321" in update["updated_body"]
        assert update["body_update_mode"] == "additive_guarded"
