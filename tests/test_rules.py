import pytest

from security_triage.rules import (
    ADVISORY_ISSUE_QUERY,
    REVIEW_LABEL,
    RepositoryValidationError,
    advisory_issue_query,
    extract_cves,
    is_gentoo_reference,
    is_kernel_advisory,
    issue_labels,
    render_issue_body,
    review_issue_label_query,
    severity_label,
    validate_repo_name,
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


@pytest.mark.parametrize(
    "value",
    [
        "flatcar/security-triage",
        "flatcar/Flatcar",
        "a/b",
        "some-org/some.repo_name",
    ],
)
def test_validate_repo_name_accepts_well_formed_values(value):
    assert validate_repo_name(value) == value


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "flatcar",
        "flatcar/Flatcar/extra",
        "flatcar /Flatcar",
        "flatcar/Flat car",
        "-flatcar/x",
        "flatcar/",
        "/x",
        "flatcar/..",
        "flatcar/.",
        "flatcar/x?y=1",
        "flatcar/x#y",
        "flatcar/x\ny",
        "a" * 40 + "/x",
        "flatcar/" + "a" * 101,
    ],
)
def test_validate_repo_name_rejects_unsafe_or_malformed_values(value):
    with pytest.raises(RepositoryValidationError):
        validate_repo_name(value)


def test_advisory_issue_query_is_parameterized_and_excludes_review_label():
    query = advisory_issue_query("flatcar/security-triage")
    assert query == (
        "repo:flatcar/security-triage is:issue is:open label:advisory "
        'label:security -label:"security-triage/review"'
    )
    assert "flatcar/Flatcar" not in query


def test_advisory_issue_query_can_omit_review_label_exclusion():
    query = advisory_issue_query("flatcar/security-triage", exclude_review_label=False)
    assert REVIEW_LABEL not in query


def test_advisory_issue_query_constant_uses_target_repo():
    assert ADVISORY_ISSUE_QUERY == advisory_issue_query("flatcar/Flatcar")


def test_advisory_issue_query_rejects_invalid_repo():
    with pytest.raises(RepositoryValidationError):
        advisory_issue_query("not-a-valid-repo")


def test_review_issue_label_query_uses_review_label():
    query = review_issue_label_query("flatcar/security-triage")
    assert (
        query == 'repo:flatcar/security-triage is:issue label:"security-triage/review"'
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://bugs.gentoo.org/12345", True),
        ("https://security.gentoo.org/glsa/202601-01", True),
        ("https://glsa.gentoo.org/glsa-202601-01", True),
        (
            "https://evil.example/bugs.gentoo.org",
            False,
        ),
        # Non-Gentoo hosts must be rejected even if the URL contains a marker substring.
        ("https://example.com/not-gentoo", False),
        ("n/a", False),
        ("", False),
        (None, False),
    ],
)
def test_is_gentoo_reference(value, expected):
    assert is_gentoo_reference(value) is expected
