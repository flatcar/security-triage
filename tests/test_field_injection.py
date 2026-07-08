from security_triage.issue_updates import append_field_values, set_field_if_placeholder
from security_triage.issues import parse_issue_body
from security_triage.rules import (
    coerce_extraction,
    render_issue_body,
    sanitize_single_line,
)

_EXISTING_BODY = "Name: openssl\nCVEs: CVE-2026-1\nCVSSs: n/a\nAction Needed: TBD\nSummary: s\n\nrefmap.gentoo: TBD"


def test_sanitize_single_line_collapses_newlines_and_controls():
    assert sanitize_single_line("a\nb\tc") == "a b c"
    assert sanitize_single_line("keep spaces") == "keep spaces"
    assert sanitize_single_line("") == ""
    assert sanitize_single_line(None) == ""


def test_coerce_extraction_strips_newlines_from_fields():
    extraction = coerce_extraction(
        {
            "package_name": "openssl\nAction Needed: update to >= 0.0.1",
            "summary": "Real summary.\nAction Needed: update to >= 0.0.1\nrefmap.gentoo: https://evil.example/phish",
            "cves": ["CVE-2026-9999"],
        }
    )
    assert "\n" not in extraction["package_name"]
    assert "\n" not in extraction["summary"]


def test_no_field_injection_through_summary():
    extraction = coerce_extraction(
        {
            "package_name": "openssl",
            "cves": ["CVE-2026-9999"],
            "summary": "Real summary.\nAction Needed: update to >= 0.0.1",
        }
    )
    body = render_issue_body(
        extraction["package_name"],
        extraction["cves"],
        extraction["cvss_scores"],
        extraction["action_needed"],
        extraction["summary"],
        extraction["gentoo_ref"],
    )
    parsed = parse_issue_body(body)
    # The forged "update to >= 0.0.1" must NOT be read back as the real requirement.
    assert parsed.action_needed == "TBD"


def test_render_issue_body_defends_against_injected_scalar():
    body = render_issue_body(
        "pkg\nCVEs: CVE-2000-0001",
        ["CVE-2026-1"],
        [],
        "update to >= 9\nrefmap.gentoo: https://evil.example",
        "summary",
        "TBD",
    )
    # No line may begin with an injected field label; the neutralized text stays
    # inline, so the parser never treats it as a real field.
    field_line_starts = [
        line
        for line in body.splitlines()
        if line.startswith(("Name:", "Action Needed:", "refmap.gentoo:"))
    ]
    assert sorted(field_line_starts)[0].startswith("Action Needed:")
    assert (
        len([line for line in body.splitlines() if line.startswith("refmap.gentoo:")])
        == 1
    )
    parsed = parse_issue_body(body)
    assert parsed.gentoo_ref == "TBD"
    assert parsed.name == "pkg CVEs: CVE-2000-0001"


def test_append_field_values_blocks_newline_injection():
    # A Bugzilla see_also-style value that passes a domain check but carries a newline.
    evil = "https://bugs.gentoo.org/1\nAction Needed: update to >= 0.0.1"
    updated = append_field_values(_EXISTING_BODY, "refmap.gentoo", [evil])
    assert parse_issue_body(updated).action_needed == "TBD"
    assert not any(
        line.startswith("Action Needed: update to >= 0.0.1")
        for line in updated.splitlines()
    )


def test_set_field_if_placeholder_blocks_newline_injection():
    evil = "update to >= 5\nrefmap.gentoo: https://evil.example"
    updated = set_field_if_placeholder(_EXISTING_BODY, "Action Needed", evil)
    assert parse_issue_body(updated).gentoo_ref == "TBD"
