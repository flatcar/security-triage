from pathlib import Path

from security_triage.issues import find_existing_issue_matches, load_issue_fixture, parse_issue_body
from security_triage.sbom import (
    compare_simple_versions,
    evaluate_fixed_version_requirements,
    extract_fixed_version_requirement,
    extract_fixed_version_requirements,
    fixed_version_requirements_are_alternatives,
    load_sbom_fixture,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_issue_body_expected_format():
    issues = load_issue_fixture(str(FIXTURES / "github_issues.json"))
    parsed = parse_issue_body(issues[0].body)
    assert parsed.valid
    assert parsed.name == "rust-openssl"
    assert parsed.cves == ["CVE-2026-10001"]
    assert parsed.action_needed == "update to >= 0.10.78"


def test_parse_issue_body_accepts_bold_manual_field_labels():
    parsed = parse_issue_body(
        "**Name**: expat\n"
        "**CVEs**: CVE-2026-32776, CVE-2026-32777\n"
        "**CVSSs**: 7.5\n"
        "**Action Needed**: update to >= 2.7.5\n"
        "**Summary**:\n"
        "  * Existing human-written context.\n"
        "\n"
        "**refmap.gentoo**: CVE-2026-3277[6-8]: https://bugs.gentoo.org/971298"
    )

    assert parsed.valid
    assert parsed.name == "expat"
    assert parsed.cves == ["CVE-2026-32776", "CVE-2026-32777"]
    assert parsed.summary == "* Existing human-written context."
    assert parsed.gentoo_ref == "CVE-2026-3277[6-8]: https://bugs.gentoo.org/971298"


def test_parse_issue_body_accepts_live_markdown_fields_and_active_text():
    body = """**Name**: libxml2
**CVEs**: ~[CVE-2026-0989](https://www.cve.org/CVERecord?id=CVE-2026-0989)~, [CVE-2026-6732](https://www.cve.org/CVERecord?id=CVE-2026-6732)
**CVSSs**: ~3.7~, 6.5
**Action Needed**: ~CVE-2026-0989: update to >= 2.15.2~, CVE-2026-6732: TBD

**Summary**: active summary

**refmap.gentoo**: TBD
"""
    parsed = parse_issue_body(body)

    assert parsed.valid
    assert parsed.name == "libxml2"
    assert parsed.cves == ["CVE-2026-6732"]
    assert parsed.cvss_scores == ["6.5"]
    assert parsed.action_needed == "CVE-2026-6732: TBD"


def test_existing_issue_matching_by_package_and_cve():
    issues = load_issue_fixture(str(FIXTURES / "github_issues.json"))
    matches = find_existing_issue_matches({"package_name": "rust-openssl", "cves": ["CVE-2026-30002"]}, issues)
    assert matches
    assert matches[0]["issue"] == 2109
    assert "package_name" in matches[0]["match_reasons"]


def test_sbom_exact_name_and_purl_matching():
    sbom = load_sbom_fixture(str(FIXTURES / "sbom.json"))
    matches = sbom.match_package("dev-libs/openssl")
    assert len(matches) == 1
    assert matches[0]["name"] == "openssl"
    assert matches[0]["match_type"] == "exact_name"


def test_fixed_version_and_simple_compare():
    assert extract_fixed_version_requirement("update to >= 1.12.2") == "1.12.2"
    assert extract_fixed_version_requirement("Upgrade to >=1.8.1.3") == "1.8.1.3"
    assert compare_simple_versions("1.12.3", "1.12.2").result == "at_or_above"
    assert compare_simple_versions("1.12.1", "1.12.2").result == "below"
    assert compare_simple_versions("1.12.3-r1", "1.12.2").result == "at_or_above"
    assert compare_simple_versions("2.42-r7", "2.42-r6").result == "at_or_above"
    assert compare_simple_versions("260.1-r1", "260").result == "at_or_above"


def test_fixed_version_ignores_struck_through_requirements_with_active_tbd():
    action_needed = "~CVE-2026-0989: update to >= 2.15.2~, CVE-2026-6732: TBD"

    assert extract_fixed_version_requirement(action_needed) is None


def test_fixed_version_uses_single_active_requirement_after_struck_through():
    action_needed = "~CVE-2026-0989: update to >= 2.15.2~, CVE-2026-6732: update to >= 2.15.3"

    assert extract_fixed_version_requirement(action_needed) == "2.15.3"


def test_fixed_version_selects_highest_active_requirement():
    action_needed = "CVE-2026-1111: update to >= 1.2.3, CVE-2026-2222: update to >= 1.3.0"

    assert extract_fixed_version_requirements(action_needed) == ["1.2.3", "1.3.0"]
    assert extract_fixed_version_requirement(action_needed) == "1.3.0"


def test_or_style_alternatives_are_detected():
    action_needed = "update to >= 260 or 259.5"

    assert fixed_version_requirements_are_alternatives(action_needed)
    assert not fixed_version_requirements_are_alternatives(
        "CVE-2026-1111: update to >= 1.2.3, CVE-2026-2222: update to >= 1.3.0"
    )


def test_or_style_alternatives_remediated_when_lower_branch_satisfied():
    requirements = ["260", "259.5"]

    comparison = evaluate_fixed_version_requirements("259.6", requirements, alternatives=True)
    assert comparison.result == "at_or_above"

    # Under AND-semantics the same installed version would be below the highest.
    assert evaluate_fixed_version_requirements("259.6", requirements, alternatives=False).result == "below"


def test_or_style_alternatives_not_remediated_when_below_all():
    requirements = ["260", "259.5"]

    assert evaluate_fixed_version_requirements("259.4", requirements, alternatives=True).result == "below"


def test_or_style_alternatives_ambiguous_when_not_conclusive():
    requirements = ["260", "259.5"]

    assert evaluate_fixed_version_requirements("259.6-rc1", requirements, alternatives=True).result == "ambiguous"
