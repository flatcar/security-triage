from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote

from .records import SourceEntry

SCHEMA_VERSION = "1.0"
PROMPT_VERSION = "security-triage-2026-10-07-evidence"
TARGET_REPO = "flatcar/Flatcar"
FLATCAR_PRODUCTION_SBOM_URL = "https://alpha.release.flatcar-linux.net/amd64-usr/current/flatcar_production_image_sbom.json"
REVIEW_LABEL = "security-triage/review"
REVIEW_APPLIED_LABEL = "security-triage/review-applied"

REQUIRED_LABELS = {"advisory", "security"}
ALLOWED_LABELS = {
    "advisory",
    "security",
    "advisory/only-sdk",
    "advisory/sysext",
    "cvss/CRITICAL",
    "cvss/HIGH",
    "cvss/MEDIUM",
}
ALLOWED_CONFIDENCE = {"high", "medium", "low"}
DISCOVERY_ACTIONS = {
    "create_issue",
    "update_existing_issue",
    "ignore",
    "kernel_regular_update_flow",
    "needs_manual_review",
}
RELEVANCE_STATUSES = {
    "relevant",
    "not_relevant",
    "needs_manual_review",
    "kernel_regular_update_flow",
}
RELEVANCE_SCOPES = {
    "production",
    "sdk_only",
    "sysext",
    "build_only",
    "not_shipped",
    "unknown",
}
SBOM_MATCH_ASSESSMENT_STATUSES = {
    "confirmed_match",
    "plausible_match",
    "unrelated_matches",
    "no_matches",
    "needs_manual_review",
}
CLEANUP_STATUSES = {
    "remediated_in_current_production_sbom",
    "not_remediated_in_current_production_sbom",
    "needs_manual_review",
}
CLEANUP_RECOMMENDATIONS = {"comment_only", "close_issue", "keep_open", "manual_review"}

MAX_ACTION_NEEDED_LENGTH = 300
MAX_SUMMARY_LENGTH = 2000
MAX_PACKAGE_NAME_LENGTH = 200
MAX_GENTOO_REF_LENGTH = 400

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")
_MENTION_RE = re.compile(
    r"(^|[^\w`])@([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:/[A-Za-z0-9._-]+)?)"
)
_CVSS_RE = re.compile(r"(?<!\d)(10(?:\.0)?|[0-9](?:\.\d)?)(?!\d)")
_KERNEL_RE = re.compile(
    r"\b(?:linux[-\s]+kernel|gentoo[-\s]+kernel|"
    r"sys-kernel/(?:gentoo-kernel(?:-bin)?|gentoo-sources|vanilla-sources))\b",
    re.IGNORECASE,
)
_STRIKETHROUGH_RE = re.compile(r"(?:~~.*?~~|~[^~]*~)", re.DOTALL)
_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
_REPO_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_REPO_FORBIDDEN_CHARS = frozenset(" \t\r\n?#@\\\"'<>|*")
_GENTOO_CATEGORIES = frozenset(
    "app-admin app-arch app-containers app-crypt app-editors app-emulation app-misc "
    "app-shells dev-db dev-lang dev-libs dev-python dev-util net-analyzer net-dialup "
    "net-dns net-firewall net-libs net-misc sys-apps sys-auth sys-block sys-boot "
    "sys-cluster sys-devel sys-fs sys-kernel sys-libs sys-process virtual".split()
)


class SchemaValidationError(ValueError):
    pass


class RepositoryValidationError(SchemaValidationError):
    """Raised when a configured GitHub repository identifier is missing or unsafe.

    Target repositories always come from trusted CLI arguments, environment
    variables, or workflow configuration -- never from editable issue prose --
    but every value is still validated defensively before use in an API path
    or search query.
    """


def validate_repo_name(value: str | None) -> str:
    """Validate and normalize a GitHub ``owner/repo`` identifier.

    Rejects empty values, control characters, whitespace, and query/fragment
    style characters, and requires exactly one ``/``-delimited owner/repo pair
    using the character set GitHub allows in login and repository slugs.
    """
    text = (value or "").strip()
    if not text:
        raise RepositoryValidationError("Repository name must not be empty")
    if _CONTROL_CHARS_RE.search(text) or any(
        char in _REPO_FORBIDDEN_CHARS for char in text
    ):
        raise RepositoryValidationError(
            f"Repository name contains invalid characters: {value!r}"
        )
    parts = text.split("/")
    if len(parts) != 2:
        raise RepositoryValidationError(
            f"Repository name must be 'owner/repo': {value!r}"
        )
    owner, repo = parts
    if not owner or len(owner) > 39 or not _OWNER_RE.match(owner):
        raise RepositoryValidationError(f"Invalid repository owner: {owner!r}")
    if (
        not repo
        or len(repo) > 100
        or repo in {".", ".."}
        or not _REPO_NAME_RE.match(repo)
    ):
        raise RepositoryValidationError(f"Invalid repository name: {repo!r}")
    return f"{owner}/{repo}"


def advisory_issue_query(repo: str, *, exclude_review_label: bool = True) -> str:
    """Build the advisory-issue search query for ``repo``.

    Parameterized so battle testing in ``flatcar/security-triage`` and a later
    production rollout to ``flatcar/Flatcar`` only change configuration, never
    the query-building logic. The dedicated review label is excluded as
    defense in depth even though review issues never receive the ``advisory``
    or ``security`` labels.
    """
    validated = validate_repo_name(repo)
    query = f"repo:{validated} is:issue is:open label:advisory label:security"
    if exclude_review_label:
        query += f' -label:"{REVIEW_LABEL}"'
    return query


def review_issue_label_query(repo: str) -> str:
    """Build a diagnostic search query for review issues in any state.

    The review pipeline's own duplicate/idempotency checks use the Issues
    List API (label filter with ``state=all``) instead of this search query
    because GitHub's search index is only eventually consistent, and a rerun
    of the same Actions run needs an immediately consistent duplicate check.
    """
    validated = validate_repo_name(repo)
    return f'repo:{validated} is:issue label:"{REVIEW_LABEL}"'


def is_gentoo_reference(value: Any) -> bool:
    """Return True when ``value`` looks like a real Gentoo Bugzilla/GLSA reference.

    Used to keep ``refmap.gentoo`` restricted to genuine Gentoo URLs instead of
    an arbitrary upstream link that untrusted source text might suggest.
    """
    text = str(value or "").strip()
    if not text or text.upper() in {"TBD", "N/A", "NONE"}:
        return False

    if not (text.startswith("https://") or text.startswith("http://")):
        return False

    from urllib.parse import urlsplit

    parts = urlsplit(text)
    host = (parts.hostname or "").lower()
    path = parts.path or ""

    if host in {"bugs.gentoo.org", "glsa.gentoo.org"}:
        return True
    if host == "security.gentoo.org" and path.startswith("/glsa/"):
        return True
    return False


def sanitize_single_line(value: str | None) -> str:
    """Collapse control characters (newlines, tabs, etc.) to single spaces.

    Advisory fields are rendered into a line-oriented issue body such as
    ``Action Needed: <value>``. Without this, a value that contains a newline
    could inject additional ``Field: value`` lines that downstream issue parsing
    and cleanup automation would trust (for example a forged low fixed-version
    that makes a still-vulnerable package look remediated).
    """
    if not value:
        return ""
    return _CONTROL_CHARS_RE.sub(" ", value).strip()


def extract_cves(text: str | None) -> list[str]:
    if not text:
        return []
    seen: set[str] = set()
    cves: list[str] = []
    for match in _CVE_RE.findall(text):
        cve = match.upper()
        if cve not in seen:
            cves.append(cve)
            seen.add(cve)
    return cves


def neutralize_mentions(text: str | None) -> str:
    """Wrap @mentions in code spans so upstream-controlled text cannot ping GitHub users or teams."""
    if not text:
        return ""
    return _MENTION_RE.sub(lambda match: f"{match.group(1)}`@{match.group(2)}`", text)


def truncate_text(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3].rstrip() + "..."


def active_markdown_text(text: str | None) -> str:
    if not text:
        return ""
    active = _STRIKETHROUGH_RE.sub("", text)
    lines = [line.strip(" \t,;") for line in active.splitlines()]
    return "\n".join(line for line in lines if line).strip()


def normalize_name(value: str | None) -> str:
    if not value:
        return ""
    text = value.strip().lower()
    if ":" in text and text.startswith("pkg:"):
        text = text.rsplit("/", 1)[-1].split("@", 1)[0]
    if "/" in text:
        text = text.rsplit("/", 1)[-1]
    return re.sub(r"[^a-z0-9.+_-]+", "-", text).strip("-")


def package_identity(value: str | None) -> str:
    """Canonical identity, never an arbitrary namespace's final path component."""
    text = (value or "").strip()
    if not text:
        return ""
    if text.lower().startswith("pkg:"):
        locator = text[4:].split("#", 1)[0].split("?", 1)[0].split("@", 1)[0]
        ecosystem, separator, path = locator.partition("/")
        if not separator or not path:
            return ""
        ecosystem = ecosystem.lower()
        path = unquote(path)
        if ecosystem in {"gentoo", "pypi", "cargo"}:
            path = path.lower()
        text = f"pkg:{ecosystem}/{path}"
    elif "/" in text:
        category, _, _name = text.partition("/")
        if category.lower() in _GENTOO_CATEGORIES and text.count("/") == 1:
            text = f"pkg:gentoo/{text.lower()}"
        elif re.match(
            r"^(?:github\.com|go\.etcd\.io|golang\.org|go\.opentelemetry\.io)/", text
        ):
            text = f"pkg:golang/{text}"
    else:
        text = text.lower()
    if text in {"cpython", "python", "pkg:gentoo/dev-lang/python"}:
        return "python"
    return text


def package_identities_match(left: str | None, right: str | None) -> bool:
    left_id, right_id = package_identity(left), package_identity(right)
    if not left_id or not right_id:
        return False
    if left_id == right_id:
        return True
    # A native unqualified name may be the short name of a Gentoo atom, not of
    # Cargo, Go, npm, or an arbitrary repository path.
    for native, qualified in ((left_id, right_id), (right_id, left_id)):
        if (
            "/" not in native
            and ":" not in native
            and qualified.startswith("pkg:gentoo/")
        ):
            atom = qualified.removeprefix("pkg:gentoo/")
            category, _, name = atom.partition("/")
            if category in _GENTOO_CATEGORIES and "/" not in name and native == name:
                return True
    return False


def parse_cvss_scores(values: list[Any] | str | None) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        raw_values = re.split(r"[,\s]+", values)
    else:
        raw_values = [str(value) for value in values]
    scores: list[str] = []
    for raw in raw_values:
        text = raw.strip()
        if not text or text.lower() == "n/a":
            continue
        match = _CVSS_RE.search(text)
        if not match:
            continue
        score = match.group(1)
        if score not in scores:
            scores.append(score)
    return scores


def severity_label(cvss_scores: list[Any] | str | None) -> str | None:
    parsed = parse_cvss_scores(cvss_scores)
    if not parsed:
        return None
    highest = max(float(score) for score in parsed)
    if highest >= 9:
        return "cvss/CRITICAL"
    if highest > 7:
        return "cvss/HIGH"
    if highest >= 4:
        return "cvss/MEDIUM"
    return None


def scope_labels(scope: str | None, scope_assessment: str | None = None) -> list[str]:
    labels: list[str] = []
    text = f"{scope or ''} {scope_assessment or ''}".lower()
    if scope == "sdk_only" or "sdk-only" in text or "sdk only" in text:
        labels.append("advisory/only-sdk")
    if scope == "sysext" or "sysext" in text or "system extension" in text:
        labels.append("advisory/sysext")
    return labels


def issue_labels(
    cvss_scores: list[Any] | str | None,
    scope: str | None,
    scope_assessment: str | None = None,
) -> list[str]:
    labels = ["advisory", "security"]
    labels.extend(scope_labels(scope, scope_assessment))
    label = severity_label(cvss_scores)
    if label:
        labels.append(label)
    return sanitize_labels(labels)


def sanitize_labels(labels: list[str]) -> list[str]:
    ordered: list[str] = []
    for label in ["advisory", "security", *labels]:
        if label in ALLOWED_LABELS and label not in ordered:
            ordered.append(label)
    return ordered


def render_issue_body(
    package_name: str,
    cves: list[str],
    cvss_scores: list[str] | None,
    action_needed: str | None,
    summary: str | None,
    gentoo_ref: str | None,
) -> str:
    cve_text = ", ".join(sanitize_single_line(cve) for cve in cves) if cves else "TBD"
    cvss_text = (
        ", ".join(sanitize_single_line(score) for score in cvss_scores or [])
        if cvss_scores
        else "n/a"
    )
    return (
        f"Name: {sanitize_single_line(package_name)}\n"
        f"CVEs: {cve_text}\n"
        f"CVSSs: {cvss_text}\n"
        f"Action Needed: {sanitize_single_line(action_needed) or 'TBD'}\n"
        f"Summary: {sanitize_single_line(summary) or 'TBD'}\n\n"
        f"refmap.gentoo: {sanitize_single_line(gentoo_ref) or 'TBD'}"
    )


def is_kernel_advisory(package_name: str | None, title: str | None = None) -> bool:
    """Return true if the package name or title clearly indicates a Linux Kernel advisory.

    This intentionally avoids matching generic terms like "linux" to prevent false positives
    in case of packages like "util-linux". It also avoids matching generic terms like "kernel"
    in the text body, to prevent false positives in case of packages like "systemd" which
    unexpectedly contain text about Linux Kernel. The heuristic only looks for explicit
    kernel identifiers in the package name and title.
    """

    identity = package_identity(package_name)
    if identity.startswith("pkg:gentoo/sys-kernel/"):
        return identity.rsplit("/", 1)[-1] in {
            "gentoo-kernel",
            "gentoo-kernel-bin",
            "gentoo-sources",
            "vanilla-sources",
        }
    if identity.startswith("pkg:") or "/" in identity:
        return False
    if identity in {
        "kernel",
        "linux-kernel",
        "sys-kernel",
        "gentoo-kernel",
    }:
        return True
    # A known userspace identity takes precedence over incidental title prose.
    return identity in {"", "linux"} and bool(_KERNEL_RE.search(title or ""))


def coerce_confidence(value: Any, default: str = "low") -> str:
    text = str(value or default).lower()
    return text if text in ALLOWED_CONFIDENCE else default


def coerce_extraction(data: dict[str, Any] | None) -> dict[str, Any]:
    source = data or {}
    cves = [
        sanitize_single_line(str(cve).upper())
        for cve in source.get("cves", [])
        if str(cve).strip()
    ]
    if not cves:
        cves = extract_cves(
            " ".join(
                str(source.get(key, "")) for key in ("summary", "raw_text", "title")
            )
        )
    cvss_scores = parse_cvss_scores(source.get("cvss_scores", []))
    fixed_versions = [
        sanitize_single_line(str(item))
        for item in source.get("fixed_versions", [])
        if str(item).strip()
    ]
    action_needed = normalize_action_needed(
        source.get("action_needed"),
        fixed_versions,
        source.get("fixed_version_semantics"),
    )
    return {
        "package_name": sanitize_single_line(str(source.get("package_name") or ""))[
            :MAX_PACKAGE_NAME_LENGTH
        ],
        "cves": cves,
        "cvss_scores": cvss_scores,
        "affected_versions": [
            sanitize_single_line(str(item))
            for item in source.get("affected_versions", [])
            if str(item).strip()
        ],
        "fixed_versions": fixed_versions,
        "fixed_version_semantics": str(
            source.get("fixed_version_semantics") or "unknown"
        ),
        "package_purl": str(source.get("package_purl") or ""),
        "package_identity": package_identity(
            str(source.get("package_purl") or source.get("package_name") or "")
        ),
        "ecosystem": str(source.get("ecosystem") or "unknown"),
        "field_evidence": source.get("field_evidence")
        if isinstance(source.get("field_evidence"), dict)
        else {},
        "confidence_dimensions": {
            field: coerce_confidence(
                (source.get("confidence_dimensions") or {}).get(field)
            )
            for field in (
                "identity",
                "source_extraction",
                "scope",
                "affectedness",
                "remediation",
            )
        }
        if isinstance(source.get("confidence_dimensions", {}), dict)
        else {},
        **(
            {"evidence_validation": source["evidence_validation"]}
            if isinstance(source.get("evidence_validation"), dict)
            else {}
        ),
        "action_needed": truncate_text(
            neutralize_mentions(action_needed or "TBD"), MAX_ACTION_NEEDED_LENGTH
        ),
        "summary": truncate_text(
            neutralize_mentions(
                sanitize_single_line(str(source.get("summary") or "")) or "TBD"
            ),
            MAX_SUMMARY_LENGTH,
        ),
        "gentoo_ref": (
            sanitize_single_line(str(source.get("gentoo_ref") or "")) or "TBD"
        )[:MAX_GENTOO_REF_LENGTH],
        "scope_assessment": str(source.get("scope_assessment") or "unknown").strip(),
        "confidence": coerce_confidence(source.get("confidence")),
    }


def normalize_action_needed(
    action: Any, fixed_versions: list[str], semantics: Any = None
) -> str:
    text = sanitize_single_line(str(action or ""))
    template = bool(
        re.search(
            r"(?:update\s+target|<[^>]+>|\bstring\s+or\s+null\b)", text, re.IGNORECASE
        )
    )
    if text and text.upper() not in {"TBD", "N/A", "UNKNOWN"} and not template:
        return text
    from .sbom import compare_simple_versions, highest_fixed_version_requirement

    if not fixed_versions or any(
        compare_simple_versions(version, version).result == "ambiguous"
        for version in fixed_versions
    ):
        return "TBD"
    versions = list(dict.fromkeys(fixed_versions))
    if len(versions) == 1:
        return f"update to >= {versions[0]}"
    if semantics == "or":
        return "update to " + " or ".join(f">= {version}" for version in versions)
    if semantics == "and":
        highest = highest_fixed_version_requirement(versions)
        return f"update to >= {highest}" if highest else "TBD"
    return "TBD"


def source_fixed_version_evidence(text: str) -> list[dict[str, Any]]:
    version = r"v?[0-9][0-9A-Za-z._+:-]*"
    pattern = (
        r"(?:\bfixed\s+(?:in|versions?\s*:?)|\bfix(?:ed)?\s*:\s*|"
        r"\b(?:update|upgrade)\s+to|\bresolved\s+in)\s*(?:>=\s*)?"
        rf"({version}(?:\s*(?:,|;|\band\b|\bor\b)\s*(?:>=\s*)?{version})*)"
    )
    evidence = []
    for match in re.finditer(pattern, text, re.IGNORECASE):
        if re.search(
            r"\b(?:not|never)\s+$",
            text[max(0, match.start() - 16) : match.start()],
            re.IGNORECASE,
        ):
            continue
        versions = [
            value.removeprefix("v").rstrip(".,;)")
            for value in re.findall(version, match.group(1))
        ]
        evidence.append(
            {
                "versions": versions,
                "semantics": "or"
                if re.search(r"\bor\b", match.group(1), re.IGNORECASE)
                else "unknown",
                "quote": match.group(0),
            }
        )
    return evidence


def source_affected_version_evidence(text: str) -> list[dict[str, str]]:
    """Recognize positive affected-range fields, never unaffected/negated prose."""
    pattern = (
        r"^\s*(?:[-*]\s+)?(?:\*\*)?"
        r"(?:affected|vulnerable)(?:\s+versions?)?(?:\*\*)?\s*:\s*([^\n]+)"
    )
    return [
        {"range": match.group(1).strip(), "quote": match.group(0).strip()}
        for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
    ]


def validate_extraction_evidence(
    extraction: dict[str, Any], entry: SourceEntry
) -> dict[str, Any]:
    """Revalidate model claims at the workflow boundary, including fixture clients.

    Quotes prove source attribution, not truth or Flatcar shipping/scope. Missing
    legacy citations can be grounded by exact source tokens, but never by model
    prose or a model-supplied ``validated`` flag.
    """
    result = coerce_extraction(extraction)
    source_text = "\n".join(
        [
            entry.title,
            entry.content,
            entry.description or "",
            *[str(comment.get("text") or "") for comment in entry.comments],
            *[str(comment.get("text") or "") for comment in entry.new_comments],
            *[str(alias) for alias in entry.metadata.get("alias", [])],
        ]
    )
    sources = {entry.source_url, *entry.references}
    errors: list[str] = []
    evidence = result["field_evidence"]
    for field, citations in evidence.items():
        if not isinstance(citations, list) or not citations:
            errors.append(f"Invalid source citations for {field}.")
            continue
        for citation in citations:
            if (
                not isinstance(citation, dict)
                or not isinstance(citation.get("source_url"), str)
                or citation.get("source_url") not in sources
                or not isinstance(citation.get("quote"), str)
                or not citation["quote"].strip()
                or citation["quote"] not in source_text
            ):
                errors.append(f"Unverifiable source citation for {field}.")
                break

    def present(value: str) -> bool:
        return bool(
            value
            and re.search(
                rf"(?<![\w.+/-]){re.escape(value)}(?![\w.+/-])",
                source_text,
                re.IGNORECASE,
            )
        )

    name = result["package_name"]
    if not present(name):
        if not (
            package_identity(name) == "python"
            and re.search(
                r"\b(?:cpython|python|dev-lang/python)\b", source_text, re.IGNORECASE
            )
        ):
            errors.append("Package identity is not grounded in the source.")
    for cve in result["cves"]:
        if not present(cve):
            errors.append(f"Unsupported cves value: {cve}")
    affected_ranges = {
        " ".join(item["range"].split()).casefold()
        for item in source_affected_version_evidence(source_text)
    }
    for affected_range in result["affected_versions"]:
        if " ".join(affected_range.split()).casefold() not in affected_ranges:
            errors.append(
                f"Affected range has no positive affected-context source evidence: {affected_range}"
            )
    omitted_cves = sorted(set(extract_cves(source_text)) - set(result["cves"]))
    if omitted_cves:
        errors.append(
            f"Source CVE coverage is incomplete; omitted: {', '.join(omitted_cves)}"
        )
    if set(extract_cves(result["summary"])) - set(extract_cves(source_text)):
        errors.append("Summary introduces CVEs not present in the source.")
    for url in re.findall(r"https?://[^\s<>]+", result["summary"]):
        url = url.rstrip(".,;)")
        if url not in sources and url not in source_text:
            errors.append("Summary introduces a URL not present in the source.")
    cvss_context = " ".join(
        re.findall(r"\bCVSS(?:s|\s+score)?\s*:?\s*([^\n]+)", source_text, re.IGNORECASE)
    )
    supported_scores = parse_cvss_scores(cvss_context)
    if any(score not in supported_scores for score in result["cvss_scores"]):
        errors.append("CVSS scores are not grounded in source severity evidence.")
    gentoo_ref = result["gentoo_ref"]
    if gentoo_ref != "TBD" and (
        not is_gentoo_reference(gentoo_ref)
        or gentoo_ref not in sources
        and gentoo_ref not in source_text
    ):
        errors.append("Gentoo reference is not grounded in the source.")
        result["gentoo_ref"] = "TBD"
    fixes = source_fixed_version_evidence(source_text)
    supported_fixes = {version for item in fixes for version in item["versions"]}
    summary_fixes = {
        version
        for item in source_fixed_version_evidence(result["summary"])
        for version in item["versions"]
    }
    if summary_fixes - supported_fixes:
        errors.append("Summary introduces fixed versions not present in the source.")
    for version in result["fixed_versions"]:
        if version not in supported_fixes:
            errors.append(f"Unsupported fixed_versions value: {version}")
    for item in fixes:
        if (
            set(item["versions"]) == set(result["fixed_versions"])
            and item["semantics"] == "or"
        ):
            result["fixed_version_semantics"] = "or"
    if (
        result["action_needed"] == "TBD"
        and result["fixed_versions"]
        and all(version in supported_fixes for version in result["fixed_versions"])
    ):
        result["action_needed"] = normalize_action_needed(
            "TBD", result["fixed_versions"], result["fixed_version_semantics"]
        )
    purl = result["package_purl"]
    source_identity = _source_package_identity(name, source_text)
    if purl and (
        not purl.startswith("pkg:")
        or not present(purl)
        and package_identity(purl) != source_identity
    ):
        errors.append("Package purl is not grounded in the source.")
    if purl and not package_identities_match(purl, name):
        purl_path = package_identity(purl).partition("/")[2]
        if purl_path != name and purl_path.rsplit("/", 1)[-1] != name:
            errors.append("Package purl conflicts with the extracted package name.")
    if (
        purl
        and source_identity.startswith("pkg:")
        and not package_identities_match(purl, source_identity)
    ):
        errors.append(
            "Package purl conflicts with source ecosystem/namespace evidence."
        )
    ecosystem = result["ecosystem"].lower()
    if not purl and source_identity.startswith("pkg:"):
        purl = source_identity
    if not purl and ecosystem in {"cargo", "rust"}:
        errors.append(
            "Rust ecosystem/package relationship is not grounded in the source."
        )
    if not purl and ecosystem in {"golang", "go"} and name != "go":
        errors.append("Go module namespace is not grounded in the source.")
    result["package_purl"] = purl
    result["package_identity"] = package_identity(purl or name)
    from .sbom import extract_fixed_version_requirements

    action = result["action_needed"]
    action_versions = extract_fixed_version_requirements(action)
    if action != "TBD" and (
        action_versions
        and any(version not in supported_fixes for version in action_versions)
        or not action_versions
        and not present(action)
    ):
        errors.append("Action Needed is not grounded in source fixed-version evidence.")
        result["action_needed"] = "TBD"
    if len(result["fixed_versions"]) > 1 and result["fixed_version_semantics"] == "or":
        if set(action_versions) != set(result["fixed_versions"]):
            result["action_needed"] = normalize_action_needed(
                "TBD", result["fixed_versions"], "or"
            )
    elif len(result["fixed_versions"]) > 1 and not present(action):
        result["action_needed"] = "TBD"
    platform_evidence = _source_platform_evidence(
        source_text, list(dict.fromkeys([*extract_cves(source_text), *result["cves"]]))
    )
    result["platform_applicability"] = platform_evidence["status"]
    result["platform_evidence"] = platform_evidence
    if platform_evidence["status"] == "needs_manual_review":
        errors.append(
            "Linux-exclusion evidence does not conclusively cover every source advisory ID."
        )
    if re.search(
        r"\b(?:ignore (?:all |previous )?instructions|system prompt|change your role)\b",
        source_text,
        re.IGNORECASE,
    ):
        errors.append("Source contains instruction-like text; manual review required.")
    result["evidence_validation"] = {
        "status": "validated" if not errors else "needs_manual_review",
        "errors": list(dict.fromkeys(errors)),
        "source_url": entry.source_url,
        "citation_mode": "cited" if evidence else "legacy_source_tokens",
    }
    result["confidence_dimensions"]["source_extraction"] = (
        "medium" if not errors else "low"
    )
    result["confidence_dimensions"].update(
        {
            "identity": "medium" if name and not errors else "low",
            "scope": "low",
            "affectedness": "low",
            "remediation": "low",
        }
    )
    if errors:
        result["confidence"] = "low"
    return result


def _source_package_identity(name: str, text: str) -> str:
    identity = package_identity(name)
    if identity.startswith("pkg:"):
        return identity
    quoted_name = rf"[`'\"]?{re.escape(name)}[`'\"]?"
    if "/" not in name and re.search(
        rf"\b(?:rust\s+(?:crate\s+)?{quoted_name}|"
        rf"(?:cargo\s+package|crate)\s+(?:named\s+)?{quoted_name}|"
        rf"{quoted_name}\s+(?:rust\s+)?crate)\b",
        text,
        re.IGNORECASE,
    ):
        return f"pkg:cargo/{name}"
    if re.search(
        rf"\b(?:go\s+module\s+(?:named\s+)?{quoted_name}|"
        rf"{quoted_name}\s+go\s+module)\b",
        text,
        re.IGNORECASE,
    ):
        return f"pkg:golang/{name}"
    return identity


def _source_excludes_linux(text: str) -> bool:
    if re.search(
        r"\b(?:(?:linux|flatcar)\s+(?:is\s+)?(?:also\s+)?(?:affected|vulnerable)"
        r"|affects?\s+(?:also\s+)?(?:linux|flatcar)"
        r"|(?:all|every)\s+(?:supported\s+)?(?:platforms?|operating\s+systems?))\b",
        text,
        re.IGNORECASE,
    ):
        return False
    for sentence in re.split(r"[.!?\n]", text.lower()):
        if re.fullmatch(
            r"\s*(?:linux|flatcar)\s+is\s+not\s+affected(?:\s+by\s+this\s+(?:issue|defect|vulnerability))?\s*",
            sentence,
        ):
            return True
        if re.search(r"\b(?:not|never|linux|flatcar)\b", sentence):
            continue
        if re.search(
            r"\b(?:(?:only\s+affects?|affects?\s+only)\s+"
            r"(?:freebsd|openbsd|netbsd|windows|macos)|"
            r"(?:freebsd|openbsd|netbsd|windows|macos)[ -]only\s+"
            r"(?:vulnerability|defect|issue|bug))\b",
            sentence,
        ):
            return True
    return False


def _source_platform_evidence(text: str, advisory_ids: list[str]) -> dict[str, Any]:
    covered: set[str] = set()
    for clause in re.split(r"(?<=[.!?])\s+|\n+", text):
        ids = list(_CVE_RE.finditer(clause))
        for index, match in enumerate(ids):
            end = ids[index + 1].start() if index + 1 < len(ids) else len(clause)
            if _source_excludes_linux(clause[match.start() : end]):
                covered.add(match.group(0).upper())
    global_exclusion = _source_excludes_linux(text)
    required = set(advisory_ids)
    if global_exclusion and (len(required) <= 1 or required <= covered):
        status = "not_affected_linux"
        covered.update(required)
    elif global_exclusion or covered:
        status = "needs_manual_review"
    else:
        status = "unknown"
    return {
        "status": status,
        "covered_advisory_ids": sorted(required & covered),
        "unproven_advisory_ids": sorted(required - covered),
    }


def coerce_relevance(data: dict[str, Any] | None) -> dict[str, Any]:
    source = data or {}
    status = str(source.get("status") or "needs_manual_review")
    scope = str(source.get("scope") or "unknown")
    return {
        "status": status if status in RELEVANCE_STATUSES else "needs_manual_review",
        "scope": scope if scope in RELEVANCE_SCOPES else "unknown",
        "llm_decision": str(source.get("llm_decision") or source.get("decision") or ""),
        "reasons": _string_list(source.get("reasons")),
        "evidence": _string_list(source.get("evidence")),
        "sbom_match_assessment": coerce_sbom_match_assessment(
            source.get("sbom_match_assessment")
        ),
    }


def coerce_sbom_match_assessment(data: Any) -> dict[str, Any]:
    source = data if isinstance(data, dict) else {}
    status = str(source.get("status") or "needs_manual_review")
    return {
        "status": status
        if status in SBOM_MATCH_ASSESSMENT_STATUSES
        else "needs_manual_review",
        "reason": str(source.get("reason") or ""),
        "related_matches": _string_list(source.get("related_matches")),
        "unrelated_matches": _string_list(source.get("unrelated_matches")),
    }


def coerce_discovery_decision(data: dict[str, Any] | None) -> dict[str, Any]:
    source = data or {}
    action = str(source.get("action") or "needs_manual_review")
    return {
        "action": action if action in DISCOVERY_ACTIONS else "needs_manual_review",
        "confidence": coerce_confidence(source.get("confidence")),
        "reason": str(source.get("reason") or ""),
    }


def coerce_cleanup_review(data: dict[str, Any] | None) -> dict[str, Any]:
    source = data or {}
    decision = str(source.get("decision") or "needs_manual_review")
    return {
        "decision": decision if decision in CLEANUP_STATUSES else "needs_manual_review",
        "confidence": coerce_confidence(source.get("confidence")),
        "reasons": _string_list(source.get("reasons")),
    }


def apply_discovery_guardrails(
    extraction: dict[str, Any],
    relevance: dict[str, Any],
    decision: dict[str, Any],
    sbom_matches: list[dict[str, Any]],
    issue_matches: list[dict[str, Any]],
    source_title: str,
    scope_evidence: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    manual_reasons: list[str] = []
    package_name = extraction.get("package_name") or ""
    validated_scope_entries = [
        item
        for item in scope_evidence or []
        if isinstance(item, dict)
        and item.get("validated") is True
        and item.get("scope") in RELEVANCE_SCOPES - {"unknown"}
        and item.get("source")
        and package_identities_match(
            extraction.get("package_identity") or package_name, item.get("package")
        )
    ]
    sbom_match_assessment = relevance.get("sbom_match_assessment") or {}
    unrelated_weak_sbom_matches = (
        sbom_match_assessment.get("status") == "unrelated_matches"
        and _only_weak_sbom_matches(sbom_matches)
        and not issue_matches
        and not validated_scope_entries
    )

    canonical_identity = (
        extraction.get("package_identity")
        or extraction.get("package_purl")
        or package_name
    )
    if is_kernel_advisory(canonical_identity, source_title):
        relevance = {
            "status": "kernel_regular_update_flow",
            "scope": "production",
            "llm_decision": relevance.get("llm_decision")
            or "Kernel CVEs use the regular Flatcar kernel update flow.",
            "reasons": [
                *relevance.get("reasons", []),
                "Kernel advisory routed away from normal advisory issues.",
            ],
            "evidence": relevance.get("evidence", []),
        }
        return (
            relevance,
            {
                "action": "kernel_regular_update_flow",
                "confidence": "high",
                "reason": "Kernel CVEs are not tracked as normal Flatcar advisory issues.",
            },
            [],
        )

    if (
        decision.get("action") == "kernel_regular_update_flow"
        or relevance.get("status") == "kernel_regular_update_flow"
    ):
        manual_reasons.append(
            "Canonical package identity does not identify the Linux kernel; model kernel routing is unsupported."
        )
    validation = extraction.get("evidence_validation") or {}
    if validation.get("status") != "validated":
        manual_reasons.extend(
            validation.get("errors")
            or [
                "Source extraction evidence was not validated at the workflow boundary."
            ]
        )

    if (extraction.get("evidence_validation") or {}).get(
        "status"
    ) == "validated" and extraction.get(
        "platform_applicability"
    ) == "not_affected_linux":
        return (
            {
                **relevance,
                "status": "not_relevant",
                "scope": "unknown",
                "reasons": [
                    *relevance.get("reasons", []),
                    "Source explicitly limits affected platforms; Linux is not affected.",
                ],
            },
            {
                "action": "ignore",
                "confidence": "medium",
                "reason": "Explicit source platform constraint excludes Linux; package presence is not affectedness.",
            },
            [],
        )

    if unrelated_weak_sbom_matches:
        assessment_reason = (
            sbom_match_assessment.get("reason")
            or "LLM judged the weak SBOM substring matches unrelated to the advisory package."
        )
        relevance = {
            **relevance,
            "status": "needs_manual_review",
            "scope": "unknown",
            "llm_decision": relevance.get("llm_decision")
            or "Weak SBOM matches are unrelated; no Flatcar package evidence remains.",
            "reasons": [
                *relevance.get("reasons", []),
                "LLM judged weak SBOM substring matches unrelated to the advisory package.",
            ],
            "evidence": [*relevance.get("evidence", []), assessment_reason],
        }
        decision = {
            "action": "needs_manual_review",
            "confidence": "low",
            "reason": "Unrelated SBOM matches do not prove not_shipped; scope evidence is missing.",
        }

    exact_matches = [
        match
        for match in sbom_matches
        if match.get("match_type") in {"exact_name", "exact_purl"}
    ]
    trusted_scopes = {item["scope"] for item in validated_scope_entries}
    if trusted_scopes:
        scope = next(
            (
                value
                for value in (
                    "sdk_only",
                    "sysext",
                    "build_only",
                    "production",
                    "not_shipped",
                )
                if value in trusted_scopes
            ),
            "unknown",
        )
        if exact_matches:
            scope = "production"
            if any(
                not item.get("discovery_only")
                and item["scope"] in {"sdk_only", "build_only"}
                for item in validated_scope_entries
            ):
                manual_reasons.append(
                    "Exclusive SDK/build scope assertion conflicts with reliable production package evidence."
                )
        confirmed_scopes = set(trusted_scopes)
        if scope == "production":
            confirmed_scopes -= {"sdk_only", "build_only"}
            confirmed_scopes.add("production")
        relevance = {
            **relevance,
            "scope": scope,
            "scope_evidence": validated_scope_entries,
            "confirmed_scopes": sorted(confirmed_scopes),
        }
        if "not_shipped" in trusted_scopes and (
            exact_matches or len(trusted_scopes) > 1
        ):
            manual_reasons.append(
                "Validated not-shipped scope conflicts with package presence or other scopes."
            )
    elif exact_matches:
        relevance = {
            **relevance,
            "scope": "production",
            "confirmed_scopes": ["production"],
        }
    elif relevance.get("scope") in {
        "production",
        "sdk_only",
        "sysext",
        "build_only",
        "not_shipped",
    }:
        relevance = {**relevance, "scope": "unknown"}
        if decision.get("action") in {
            "create_issue",
            "update_existing_issue",
            "ignore",
        }:
            manual_reasons.append(
                "Claimed Flatcar scope has no validated package evidence."
            )

    affectedness = "unknown"
    ranges = extraction.get("affected_versions") or []
    if (
        (extraction.get("evidence_validation") or {}).get("status") == "validated"
        and relevance.get("scope") == "production"
        and len(exact_matches) == 1
        and ranges
    ):
        from .sbom import evaluate_simple_affected_range

        if len(ranges) == 1:
            affected = evaluate_simple_affected_range(
                exact_matches[0].get("versionInfo"), ranges[0]
            )
            affectedness = affected.result
            relevance = {
                **relevance,
                "affectedness_assessment": {
                    "status": affected.result,
                    "reason": affected.reason,
                },
            }
            if affected.result == "not_affected":
                scope_assessments = []
                for scope_entry in validated_scope_entries:
                    if scope_entry["scope"] == "production":
                        continue
                    scoped_comparison = evaluate_simple_affected_range(
                        scope_entry.get("versionInfo")
                        if scope_entry.get("discovery_only")
                        and scope_entry.get("match_type")
                        in {"exact_name", "exact_purl"}
                        else None,
                        ranges[0],
                    )
                    scope_assessments.append(
                        {
                            "scope": scope_entry["scope"],
                            "versionInfo": scope_entry.get("versionInfo"),
                            "status": scoped_comparison.result,
                            "reason": scoped_comparison.reason,
                            "snapshot_sha256": scope_entry.get("snapshot_sha256"),
                        }
                    )
                    if scoped_comparison.result != "not_affected":
                        manual_reasons.append(
                            f"Production is outside the affected range, but {scope_entry['scope']} "
                            f"scope is {scoped_comparison.result}; scoped review is required."
                        )
                relevance["affectedness_assessment"]["scope_assessments"] = (
                    scope_assessments
                )
                if any(item["status"] != "not_affected" for item in scope_assessments):
                    relevance["affectedness_assessment"]["status"] = (
                        "needs_manual_review"
                    )
            if affected.result == "not_affected" and not manual_reasons:
                return (
                    {**relevance, "status": "not_relevant"},
                    {
                        "action": "ignore",
                        "confidence": "medium",
                        "reason": affected.reason,
                    },
                    [],
                )
            if affected.result == "ambiguous":
                manual_reasons.append("Affected-version comparison is ambiguous.")
        else:
            manual_reasons.append(
                "Multiple affected ranges have unspecified branch semantics."
            )

    if decision.get("action") in {"create_issue", "update_existing_issue"}:
        if not exact_matches and not trusted_scopes and not issue_matches:
            manual_reasons.append(
                "No exact package identity or validated Flatcar scope evidence."
            )
        if relevance.get("scope") == "unknown" and not issue_matches:
            manual_reasons.append("Flatcar package scope is unknown.")
        decision = {
            **decision,
            "confidence": min_confidence(
                min_confidence(
                    decision.get("confidence"), extraction.get("confidence", "low")
                ),
                (extraction.get("confidence_dimensions") or {}).get(
                    "source_extraction", "low"
                ),
            ),
        }
    relevance = {
        **relevance,
        "confidence_dimensions": {
            "identity": "high"
            if exact_matches
            else "medium"
            if trusted_scopes or issue_matches
            else "low",
            "scope": "high"
            if trusted_scopes
            or exact_matches
            and relevance.get("scope") == "production"
            else "low",
            "source_extraction": (extraction.get("confidence_dimensions") or {}).get(
                "source_extraction", "low"
            ),
            "affectedness": "high" if affectedness == "affected" else "low",
        },
        "open_questions": [
            {
                "field": "scope",
                "question": "Where does Flatcar ship or use this exact package identity?",
                "evidence_needed": "Validated production, SDK, sysext, build-only, or not-shipped evidence.",
            }
        ]
        if relevance.get("scope") == "unknown"
        else [],
    }
    if relevance["confidence_dimensions"]["affectedness"] != "high":
        relevance["open_questions"].append(
            {
                "field": "affectedness",
                "question": "Do the shipped version, OS, architecture, and enabled USE/features satisfy the advisory's affected conditions?",
                "evidence_needed": "Source-backed affected ranges and validated Flatcar build/runtime configuration.",
            }
        )
    if not package_name:
        manual_reasons.append(
            "LLM extraction did not identify a package or component name."
        )
    if decision["action"] not in DISCOVERY_ACTIONS:
        manual_reasons.append(f"Invalid discovery action: {decision['action']}")
    if relevance["status"] == "needs_manual_review":
        manual_reasons.append("LLM relevance decision requested manual review.")
    if decision["action"] == "create_issue" and issue_matches:
        decision = {
            "action": "update_existing_issue",
            "confidence": min_confidence(decision.get("confidence"), "medium"),
            "reason": "Existing Flatcar issue match found; recommend updating it instead of creating a duplicate.",
        }
    if decision["action"] == "update_existing_issue" and not issue_matches:
        manual_reasons.append(
            "LLM recommended updating an existing issue but no existing issue match was found."
        )
    if (
        decision["action"] in {"create_issue", "update_existing_issue"}
        and relevance["status"] != "relevant"
    ):
        manual_reasons.append(
            "Issue mutation recommendation requires a relevant Flatcar status."
        )
    if decision["action"] == "create_issue" and not (
        extraction.get("cves") or extraction.get("summary") != "TBD"
    ):
        manual_reasons.append(
            "Create recommendation lacks CVE IDs or an upstream security issue summary."
        )
    if decision["action"] == "create_issue" and not (
        sbom_matches or relevance.get("evidence")
    ):
        manual_reasons.append(
            "Create recommendation lacks SBOM match or other explicit Flatcar relevance evidence."
        )

    if manual_reasons:
        relevance = {**relevance, "status": "needs_manual_review"}
        decision = {
            "action": "needs_manual_review",
            "confidence": "low",
            "reason": "; ".join(manual_reasons),
        }
    elif relevance["status"] == "not_relevant":
        decision = {
            "action": "ignore",
            "confidence": decision.get("confidence", "medium"),
            "reason": decision.get("reason")
            or "LLM decision found the advisory not relevant to Flatcar tracking rules.",
        }
    return relevance, decision, manual_reasons


def _only_weak_sbom_matches(sbom_matches: list[dict[str, Any]]) -> bool:
    if not sbom_matches:
        return True
    return all(
        match.get("match_type") in {"unique_substring", "ambiguous_substring"}
        for match in sbom_matches
    )


def min_confidence(left: str | None, right: str | None) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    left_text = coerce_confidence(left)
    right_text = coerce_confidence(right)
    return left_text if order[left_text] <= order[right_text] else right_text


def validate_discovery_document(document: dict[str, Any]) -> None:
    _require_root(
        document,
        [
            "schema_version",
            "workflow",
            "generated_at",
            "target_repo",
            "processing_window",
            "sources",
            "model",
            "records",
            "errors",
        ],
    )
    if document["workflow"] != "new_vulnerability_discovery":
        raise SchemaValidationError("Invalid discovery workflow name")
    for record in document.get("records", []):
        _require_root(
            record,
            [
                "record_id",
                "source",
                "source_url",
                "raw_advisory_id",
                "llm_extraction",
                "flatcar_relevance",
                "decision",
                "manual_review_reasons",
                "evidence",
            ],
        )
        action = record["decision"].get("action")
        if action not in DISCOVERY_ACTIONS:
            raise SchemaValidationError(f"Invalid discovery action {action}")
        status = record["flatcar_relevance"].get("status")
        if status not in RELEVANCE_STATUSES:
            raise SchemaValidationError(f"Invalid relevance status {status}")
        proposed_issue = record.get("proposed_issue")
        if proposed_issue:
            labels = set(proposed_issue.get("labels", []))
            if not REQUIRED_LABELS.issubset(labels):
                raise SchemaValidationError(
                    "Proposed issue is missing required advisory/security labels"
                )
            unknown = labels - ALLOWED_LABELS
            if unknown:
                raise SchemaValidationError(
                    f"Proposed issue contains unsupported labels: {sorted(unknown)}"
                )


def validate_cleanup_document(document: dict[str, Any]) -> None:
    _require_root(
        document,
        [
            "schema_version",
            "workflow",
            "generated_at",
            "target_repo",
            "sbom_url",
            "issue_query",
            "records",
            "errors",
        ],
    )
    if document["workflow"] != "advisory_cleanup_recommendation":
        raise SchemaValidationError("Invalid cleanup workflow name")
    for record in document.get("records", []):
        _require_root(
            record,
            [
                "issue",
                "issue_url",
                "title",
                "package_from_issue",
                "labels",
                "sbom_url",
                "cves_from_issue",
                "fixed_version_requirement",
                "sbom_package_matches",
                "llm_review",
                "status",
                "confidence",
                "evidence",
                "recommended_action",
                "comment_body",
            ],
        )
        if record["status"] not in CLEANUP_STATUSES:
            raise SchemaValidationError(f"Invalid cleanup status {record['status']}")
        if record["recommended_action"] not in CLEANUP_RECOMMENDATIONS:
            raise SchemaValidationError(
                f"Invalid cleanup recommendation {record['recommended_action']}"
            )


#: Default advisory issue query for ``TARGET_REPO``. Callers that target a
#: different repository should call ``advisory_issue_query(repo)`` directly.
ADVISORY_ISSUE_QUERY = advisory_issue_query(TARGET_REPO)


def cleanup_comment_body(
    package: str, cves: list[str], action_needed: str | None, match: dict[str, Any]
) -> str:
    cve_text = ", ".join(cves) if cves else "n/a"
    return (
        "This advisory appears to be remediated in the current Flatcar production SBOM.\n\n"
        "Evidence:\n"
        f"- SBOM: {FLATCAR_PRODUCTION_SBOM_URL}\n"
        f"- Issue package: {package}\n"
        f"- Issue CVEs: {cve_text}\n"
        f"- Required action from issue: {action_needed or 'TBD'}\n"
        f"- SBOM package match: {match.get('name') or 'unknown'}\n"
        f"- SBOM versionInfo: {match.get('versionInfo') or 'unknown'}\n\n"
        "Pipeline recommendation: close as fixed/remediated."
    )


def _require_root(document: dict[str, Any], fields: list[str]) -> None:
    missing = [field for field in fields if field not in document]
    if missing:
        raise SchemaValidationError(f"Missing required field(s): {', '.join(missing)}")


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str):
        return [value] if value.strip() else []
    return [str(value)]
