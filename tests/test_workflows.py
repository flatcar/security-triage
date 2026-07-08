from pathlib import Path

from security_triage.cleanup import CleanupWorkflow
from security_triage.discovery import DiscoveryWorkflow
from security_triage.issue_updates import append_field_values
from security_triage.issues import load_issue_fixture
from security_triage.models import HeuristicModelClient
from security_triage.records import Issue, SBOMPackage, SourceEntry
from security_triage.reporting import render_discovery_markdown
from security_triage.sbom import SBOMIndex, load_sbom_fixture
from security_triage.sources import load_source_fixture

FIXTURES = Path(__file__).parent / "fixtures"


def test_append_field_values_adds_cve_that_is_not_exact_match():
    body = (
        "Name: rust-openssl\n"
        "CVEs: CVE-2026-10001\n"
        "CVSSs: 8.1\n"
        "Action Needed: update to >= 0.10.78\n"
        "Summary: Existing context.\n"
        "\n"
        "refmap.gentoo: https://bugs.gentoo.org/10001"
    )

    updated = append_field_values(body, "CVEs", ["CVE-2026-1000"])

    assert "CVEs: CVE-2026-10001, CVE-2026-1000" in updated


def test_discovery_workflow_fixture_decisions():
    entries = load_source_fixture(str(FIXTURES / "discovery_entries.json"))
    issues = load_issue_fixture(str(FIXTURES / "github_issues.json"))
    sbom = load_sbom_fixture(str(FIXTURES / "sbom.json"))
    document = DiscoveryWorkflow(HeuristicModelClient(), sbom, issues).run(entries, "2026-04-29T00:00:00Z", "2026-04-30T00:00:00Z")

    records_by_package = {record["llm_extraction"]["package_name"]: record for record in document["records"]}
    assert records_by_package["openssl"]["decision"]["action"] == "create_issue"
    assert records_by_package["openssl"]["proposed_issue"]["title"] == "update: openssl"
    assert "security" in records_by_package["openssl"]["proposed_issue"]["labels"]
    assert records_by_package["rust-openssl"]["decision"]["action"] == "update_existing_issue"
    assert records_by_package["linux-kernel"]["decision"]["action"] == "kernel_regular_update_flow"
    assert records_by_package["gnome-shell"]["decision"]["action"] == "ignore"
    assert records_by_package["left-pad-plus"]["decision"]["action"] == "ignore"


def test_discovery_does_not_route_userspace_advisory_to_kernel_flow_from_content_text():
    sbom = SBOMIndex([SBOMPackage(name="systemd", version_info="260", spdx_id="SPDXRef-Package-systemd", purls=[])])
    entry = SourceEntry(
        source="gentoo",
        source_url="https://bugs.gentoo.org/40001",
        entry_id="gentoo-40001",
        title="systemd: userspace service vulnerability",
        content="Package: systemd\nCVE: CVE-2026-40001\nCVSS: 7.5\nThe advisory discussion mentions Linux kernel interactions, but the affected package is systemd.\nFixed in 260",
        published_at="2026-04-29T00:10:00Z",
        updated_at="2026-04-29T00:10:00Z",
    )

    document = DiscoveryWorkflow(HeuristicModelClient(), sbom, []).run([entry], "2026-04-29T00:00:00Z", "2026-04-30T00:00:00Z")
    record = document["records"][0]

    assert record["decision"]["action"] == "create_issue"
    assert record["flatcar_relevance"]["status"] == "relevant"


def test_discovery_ignores_advisory_ids_already_present_in_open_issue():
    issues = load_issue_fixture(str(FIXTURES / "github_issues.json"))
    sbom = load_sbom_fixture(str(FIXTURES / "sbom.json"))
    entry = SourceEntry(
        source="gentoo",
        source_url="https://bugs.gentoo.org/already-covered",
        entry_id="already-covered",
        title="rust-openssl: already tracked CVE",
        content="Package: rust-openssl\nCVE: CVE-2026-10001\nCVSS: 8.1\nFixed in 0.10.78",
        published_at="2026-04-29T00:00:00Z",
        updated_at="2026-04-29T00:00:00Z",
    )

    document = DiscoveryWorkflow(HeuristicModelClient(), sbom, issues).run([entry], "2026-04-23T00:00:00Z", "2026-04-30T00:00:00Z")
    record = document["records"][0]

    assert record["decision"]["action"] == "ignore"
    assert record["decision"]["confidence"] == "high"
    assert record["proposed_update"] is None
    assert "Already tracked" in record["decision"]["reason"]


def test_discovery_updates_existing_issue_for_new_bugzilla_comment():
    issues = load_issue_fixture(str(FIXTURES / "github_issues.json"))
    sbom = load_sbom_fixture(str(FIXTURES / "sbom.json"))
    entry = SourceEntry(
        source="gentoo",
        source_url="https://bugs.gentoo.org/10001",
        entry_id="10001",
        title="rust-openssl: already tracked CVE with new upstream comment",
        content="Package: rust-openssl\nCVE: CVE-2026-10001\nCVSS: 8.1\nFixed in 0.10.78",
        published_at="2026-04-01T00:00:00Z",
        updated_at="2026-04-29T12:00:00Z",
        references=["https://bugs.gentoo.org/10001"],
        description="Original Bugzilla description.",
        comments=[
            {
                "count": 1,
                "creator": "security@gentoo.org",
                "creation_time": "2026-04-29T12:00:00Z",
                "text": "Upstream added exploitability details worth reflecting in the Flatcar issue.",
                "is_creator": True,
            }
        ],
        new_comments=[
            {
                "count": 1,
                "creator": "security@gentoo.org",
                "creation_time": "2026-04-29T12:00:00Z",
                "text": "Upstream added exploitability details worth reflecting in the Flatcar issue.",
                "is_creator": True,
            }
        ],
        metadata={"alias": ["CVE-2026-10001", "CVE-2026-10002"], "severity": "normal"},
    )

    document = DiscoveryWorkflow(HeuristicModelClient(), sbom, issues).run([entry], "2026-04-23T00:00:00Z", "2026-04-30T00:00:00Z")
    record = document["records"][0]

    assert record["decision"]["action"] == "update_existing_issue"
    assert record["proposed_update"]["issue"] == 2109
    assert record["proposed_update"]["update_reason"] == "Upstream Bugzilla data introduced advisory IDs not present in the existing issue."
    assert record["proposed_update"]["detected_changes"][0]["kind"] == "new_extracted_cves"
    assert record["proposed_update"]["detected_changes"][1]["kind"] == "new_bugzilla_aliases"
    assert record["proposed_update"]["detected_changes"][2]["kind"] == "bugzilla_severity"
    assert record["proposed_update"]["detected_changes"][3]["kind"] == "new_bugzilla_comment"
    assert "Bugzilla comment #1" in record["proposed_update"]["comment_body"]
    markdown = render_discovery_markdown(document)
    assert "### gentoo rust-openssl (2026-04-01T00:00:00Z)" in markdown
    assert f"### {record['record_id']}" not in markdown
    assert "- Created (updated): 2026-04-01T00:00:00Z (2026-04-29T12:00:00Z)" in markdown
    assert "Proposed additive issue body update" in markdown
    assert "Comment preview" in markdown
    assert "CVE-2026-10002" in record["proposed_update"]["updated_body"]
    assert record["upstream_activity"]["requires_issue_update"] is True


def test_discovery_existing_issue_update_preserves_cross_thread_cves_and_refs():
    issue_body = (
        "**Name**: expat\n"
        "**CVEs**: CVE-2026-32776, CVE-2026-32777, CVE-2026-32778\n"
        "**CVSSs**: 7.5\n"
        "**Action Needed**: update to >= 2.7.5\n"
        "**Summary**:\n"
        "  * CVE-2026-32776: libexpat before 2.7.5 allows a NULL pointer dereference.\n"
        "  * CVE-2026-32777: libexpat before 2.7.5 allows an infinite loop.\n"
        "  * CVE-2026-32778: libexpat before 2.7.5 allows a NULL pointer dereference after OOM.\n"
        "\n"
        "**refmap.gentoo**: CVE-2026-3277[6-8]: https://bugs.gentoo.org/971298"
    )
    issues = [
        Issue(
            number=3000,
            title="update: expat",
            body=issue_body,
            labels=["advisory", "security"],
            html_url="https://github.com/flatcar/Flatcar/issues/3000",
            state="open",
            raw={},
        )
    ]
    sbom = SBOMIndex([SBOMPackage(name="expat", version_info="2.7.4", spdx_id="SPDXRef-Package-expat", purls=[])])
    entry = SourceEntry(
        source="gentoo",
        source_url="https://bugs.gentoo.org/973144",
        entry_id="973144",
        title="expat: hash flooding in crafted XML documents",
        content="Package: expat\nCVE: CVE-2026-41080\nCVSS: 7.5\nFixed in 2.8.0",
        published_at="2026-06-29T00:00:00Z",
        updated_at="2026-06-30T00:00:00Z",
        metadata={"alias": ["CVE-2026-41080"], "url": "https://bugs.gentoo.org/973144"},
    )

    document = DiscoveryWorkflow(HeuristicModelClient(), sbom, issues).run([entry], "2026-06-29T00:00:00Z", "2026-06-30T00:00:00Z")
    record = document["records"][0]
    updated_body = record["proposed_update"]["updated_body"]
    markdown = render_discovery_markdown(document)

    assert record["decision"]["action"] == "update_existing_issue"
    assert updated_body is not None
    assert "CVE-2026-32776, CVE-2026-32777, CVE-2026-32778, CVE-2026-41080" in updated_body
    assert "https://bugs.gentoo.org/971298" in updated_body
    assert "https://bugs.gentoo.org/973144" in updated_body
    assert "CVE-2026-32776: libexpat before 2.7.5" in updated_body
    assert "Issue body diff" not in markdown
    assert "Proposed additive issue body update" in markdown


def test_discovery_treats_unrelated_ambiguous_sbom_matches_as_not_shipped():
    sbom = SBOMIndex(
        [
            SBOMPackage(
                name="golang.org/x/text",
                version_info="v0.21.0",
                spdx_id="SPDXRef-Package-go-module-golang.org-x-text-one",
                purls=["pkg:golang/golang.org/x/text@v0.21.0"],
            ),
            SBOMPackage(
                name="golang.org/x/text",
                version_info="v0.23.0",
                spdx_id="SPDXRef-Package-go-module-golang.org-x-text-two",
                purls=["pkg:golang/golang.org/x/text@v0.23.0"],
            ),
        ]
    )
    entry = SourceEntry(
        source="gentoo",
        source_url="https://bugs.gentoo.org/973376",
        entry_id="973376",
        title="dev-perl/Text-CSV_XS: use-after-free",
        content="Package: dev-perl/Text-CSV_XS\nCVE: CVE-2026-7111\nFixed in 1.62",
        published_at="2026-04-29T15:41:51Z",
        updated_at="2026-04-30T05:08:38Z",
    )

    document = DiscoveryWorkflow(HeuristicModelClient(), sbom, []).run([entry], "2026-04-29T00:00:00Z", "2026-04-30T23:59:59Z")
    record = document["records"][0]

    assert {match["match_type"] for match in record["sbom_package_matches"]} == {"ambiguous_substring"}
    assert record["flatcar_relevance"]["sbom_match_assessment"]["status"] == "unrelated_matches"
    assert record["flatcar_relevance"]["scope"] == "not_shipped"
    assert record["decision"]["action"] == "ignore"
    assert "strong not-shipped evidence" in record["decision"]["reason"]
    assert "SBOM match assessment: unrelated_matches" in render_discovery_markdown(document)


def test_cleanup_workflow_fixture_decisions():
    issues = load_issue_fixture(str(FIXTURES / "github_issues.json"))
    sbom = load_sbom_fixture(str(FIXTURES / "sbom.json"))
    document = CleanupWorkflow(HeuristicModelClient(), sbom, issues).run()
    records = {record["issue"]: record for record in document["records"]}

    assert records[2088]["status"] == "remediated_in_current_production_sbom"
    assert records[2088]["recommended_action"] == "comment_only"
    assert "Pipeline recommendation: close as fixed/remediated." in records[2088]["comment_body"]
    assert records[1970]["status"] == "not_remediated_in_current_production_sbom"
    assert records[1970]["recommended_action"] == "keep_open"
    assert records[2082]["status"] == "needs_manual_review"
    assert records[2083]["status"] == "needs_manual_review"
    assert records[2084]["status"] == "needs_manual_review"


def test_cleanup_live_markdown_fields_keep_below_version_open():
    issues = [
        Issue(
            number=2190,
            title="update: net-misc/socat",
            html_url="https://github.com/flatcar/Flatcar/issues/2190",
            labels=["security", "advisory"],
            body="""**Name**: net-misc/socat
**CVEs**: [CVE-2026-56123](https://www.cve.org/CVERecord?id=CVE-2026-56123)
**CVSSs**: 9.2
**Action Needed**: Upgrade to >=1.8.1.3

**Summary**: heap buffer overflow in the SOCKS5 reply parser

**refmap.gentoo**: https://bugs.gentoo.org/978227
""",
        )
    ]
    sbom = SBOMIndex([SBOMPackage(name="net-misc/socat", version_info="1.8.1.1", spdx_id="SPDXRef-socat")])

    document = CleanupWorkflow(HeuristicModelClient(), sbom, issues).run()
    record = document["records"][0]

    assert record["package_from_issue"] == "net-misc/socat"
    assert record["cves_from_issue"] == ["CVE-2026-56123"]
    assert record["fixed_version_requirement"] == "1.8.1.3"
    assert record["status"] == "not_remediated_in_current_production_sbom"
    assert record["recommended_action"] == "keep_open"


def test_cleanup_active_tbd_after_struck_through_stays_manual_review():
    issues = [
        Issue(
            number=2049,
            title="update: libxml2",
            html_url="https://github.com/flatcar/Flatcar/issues/2049",
            labels=["security", "advisory"],
            body="""**Name**: libxml2
**CVEs**: ~[CVE-2026-0989](https://www.cve.org/CVERecord?id=CVE-2026-0989)~, [CVE-2026-6732](https://www.cve.org/CVERecord?id=CVE-2026-6732)
**CVSSs**: ~3.7~, 6.5
**Action Needed**: ~CVE-2026-0989: update to >= 2.15.2~, CVE-2026-6732: TBD

**Summary**: active libxml2 issue

**refmap.gentoo**: TBD
""",
        )
    ]
    sbom = SBOMIndex([SBOMPackage(name="dev-libs/libxml2", version_info="2.15.3", spdx_id="SPDXRef-libxml2")])

    document = CleanupWorkflow(HeuristicModelClient(), sbom, issues).run()
    record = document["records"][0]

    assert record["cves_from_issue"] == ["CVE-2026-6732"]
    assert record["fixed_version_requirement"] is None
    assert record["status"] == "needs_manual_review"


def test_cleanup_multiple_active_fixed_versions_use_highest_requirement():
    issues = [
        Issue(
            number=2087,
            title="update: rsync",
            html_url="https://github.com/flatcar/Flatcar/issues/2087",
            labels=["security", "advisory"],
            body="""**Name**: rsync
**CVEs**: [CVE-2026-41035](https://www.cve.org/CVERecord?id=CVE-2026-41035), [CVE-2026-29518](https://www.cve.org/CVERecord?id=CVE-2026-29518)
**CVSSs**: 7.5, 8.1
**Action Needed**: CVE-2026-41035: update to >= 3.4.2, CVE-2026-29518: update to >= 3.4.3

**Summary**: multiple active fixed-version requirements

**refmap.gentoo**: TBD
""",
        )
    ]
    sbom = SBOMIndex([SBOMPackage(name="net-misc/rsync", version_info="3.4.3", spdx_id="SPDXRef-rsync")])

    document = CleanupWorkflow(HeuristicModelClient(), sbom, issues).run()
    record = document["records"][0]

    assert record["fixed_version_requirement"] == "3.4.3"
    assert record["fixed_version_requirements"] == ["3.4.2", "3.4.3"]
    assert record["status"] == "remediated_in_current_production_sbom"


def test_cleanup_gentoo_revision_suffix_can_satisfy_requirement():
    issues = [
        Issue(
            number=2054,
            title="update: systemd",
            html_url="https://github.com/flatcar/Flatcar/issues/2054",
            labels=["security", "advisory"],
            body="""**Name**: systemd
**CVEs**: [CVE-2026-40225](https://www.cve.org/CVERecord?id=CVE-2026-40225)
**CVSSs**: 6.8
**Action Needed**: CVE-2026-40225: update to >= 260 or 259.5 or 258.7

**Summary**: systemd issue fixed in newer major branch

**refmap.gentoo**: TBD
""",
        )
    ]
    sbom = SBOMIndex([SBOMPackage(name="sys-apps/systemd", version_info="260.1-r1", spdx_id="SPDXRef-systemd")])

    document = CleanupWorkflow(HeuristicModelClient(), sbom, issues).run()
    record = document["records"][0]

    assert record["fixed_version_requirement"] == "260"
    assert record["status"] == "remediated_in_current_production_sbom"


def test_cleanup_or_alternative_branch_remediates_below_highest_requirement():
    issues = [
        Issue(
            number=2055,
            title="update: systemd",
            html_url="https://github.com/flatcar/Flatcar/issues/2055",
            labels=["security", "advisory"],
            body="""**Name**: systemd
**CVEs**: [CVE-2026-40226](https://www.cve.org/CVERecord?id=CVE-2026-40226)
**CVSSs**: 6.8
**Action Needed**: CVE-2026-40226: update to >= 260 or 259.5

**Summary**: systemd issue fixed on the 260 branch and backported to 259.5

**refmap.gentoo**: TBD
""",
        )
    ]
    sbom = SBOMIndex([SBOMPackage(name="sys-apps/systemd", version_info="259.6", spdx_id="SPDXRef-systemd")])

    document = CleanupWorkflow(HeuristicModelClient(), sbom, issues).run()
    record = document["records"][0]

    assert record["fixed_version_requirements"] == ["260", "259.5"]
    assert record["status"] == "remediated_in_current_production_sbom"


def test_cleanup_can_use_model_to_keep_open_for_ambiguous_package_match():
    class NotRemediatedModel(HeuristicModelClient):
        def review_cleanup(self, evidence_bundle):
            return {
                "decision": "not_remediated_in_current_production_sbom",
                "confidence": "high",
                "reasons": ["The relevant package candidate is below the required version."],
            }

    issues = [
        Issue(
            number=2072,
            title="update: docker",
            html_url="https://github.com/flatcar/Flatcar/issues/2072",
            labels=["security", "advisory"],
            body="""**Name**: docker
**CVEs**: [CVE-2026-41000](https://www.cve.org/CVERecord?id=CVE-2026-41000)
**CVSSs**: 8.1
**Action Needed**: update to >= 29.3.1

**Summary**: docker issue

**refmap.gentoo**: TBD
""",
        )
    ]
    sbom = SBOMIndex(
        [
            SBOMPackage(name="acct-group/docker", version_info="0-r3", spdx_id="SPDXRef-docker-group"),
            SBOMPackage(name="app-containers/docker", version_info="28.2.2", spdx_id="SPDXRef-docker"),
        ]
    )

    document = CleanupWorkflow(NotRemediatedModel(), sbom, issues).run()
    record = document["records"][0]

    assert record["status"] == "not_remediated_in_current_production_sbom"
    assert record["recommended_action"] == "keep_open"


def test_cleanup_can_use_model_to_close_for_ambiguous_package_match_with_low_confidence():
    class RemediatedModel(HeuristicModelClient):
        def review_cleanup(self, evidence_bundle):
            return {
                "decision": "remediated_in_current_production_sbom",
                "confidence": "high",
                "reasons": ["The relevant package candidate satisfies the required version."],
            }

    issues = [
        Issue(
            number=3000,
            title="update: docker",
            html_url="https://github.com/flatcar/Flatcar/issues/3000",
            labels=["security", "advisory"],
            body="""**Name**: docker
**CVEs**: [CVE-2026-41000](https://www.cve.org/CVERecord?id=CVE-2026-41000)
**CVSSs**: 8.1
**Action Needed**: update to >= 29.3.1

**Summary**: docker issue

**refmap.gentoo**: TBD
""",
        )
    ]
    sbom = SBOMIndex(
        [
            SBOMPackage(name="acct-group/docker", version_info="0-r3", spdx_id="SPDXRef-docker-group"),
            SBOMPackage(name="app-containers/docker", version_info="29.3.1", spdx_id="SPDXRef-docker"),
        ]
    )

    document = CleanupWorkflow(RemediatedModel(), sbom, issues, allow_close=True).run()
    record = document["records"][0]

    assert record["status"] == "remediated_in_current_production_sbom"
    assert record["confidence"] == "low"
    assert record["recommended_action"] == "close_issue"
