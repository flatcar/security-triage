from security_triage.rules import (
    extract_cves,
    is_kernel_advisory,
    issue_labels,
    render_issue_body,
    severity_label,
)


def test_extract_cves_deduplicates_and_uppercases():
    assert extract_cves("cve-2026-1234 CVE-2026-1234 CVE-2026-99999") == [
        "CVE-2026-1234",
        "CVE-2026-99999",
    ]


def test_severity_label_mapping():
    assert severity_label(["9.8", "6.5"]) == "cvss/CRITICAL"
    assert severity_label(["8.1"]) == "cvss/HIGH"
    assert severity_label(["6.9"]) == "cvss/MEDIUM"
    assert severity_label([]) is None


def test_issue_labels_are_restricted_and_scoped():
    assert issue_labels(["8.1"], "sysext") == [
        "advisory",
        "security",
        "advisory/sysext",
        "cvss/HIGH",
    ]
    assert issue_labels(["9.1"], "sdk_only") == [
        "advisory",
        "security",
        "advisory/only-sdk",
        "cvss/CRITICAL",
    ]


def test_render_issue_body_exact_field_order():
    body = render_issue_body(
        "openssl",
        ["CVE-2026-1"],
        ["8.8"],
        "update to >= 3.2.4",
        "summary",
        "https://bugs.gentoo.org/1",
    )
    assert body.splitlines() == [
        "Name: openssl",
        "CVEs: CVE-2026-1",
        "CVSSs: 8.8",
        "Action Needed: update to >= 3.2.4",
        "Summary: summary",
        "",
        "refmap.gentoo: https://bugs.gentoo.org/1",
    ]


def test_kernel_advisory_detection():
    assert is_kernel_advisory("linux-kernel", "Linux kernel CVE")
    assert not is_kernel_advisory("openssl", "OpenSSL CVE")
