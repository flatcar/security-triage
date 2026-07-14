from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .http_utils import fetch_json
from .io_utils import load_structured_file
from .records import SBOMPackage
from .rules import FLATCAR_PRODUCTION_SBOM_URL, active_markdown_text, normalize_name

_REQUIREMENT_RE = re.compile(
    r"(?:>=|at\s+least|(?:update|upgrade)\s+to\s+>=?)\s*v?([0-9][0-9A-Za-z._+:-]*)",
    re.IGNORECASE,
)
_COMPARABLE_VERSION_RE = re.compile(
    r"^v?(?P<base>\d+(?:\.\d+){0,5})(?:-r(?P<revision>\d+))?$", re.IGNORECASE
)
_OR_ALTERNATIVE_RE = re.compile(r"\bor\b", re.IGNORECASE)
_OR_BARE_VERSION_RE = re.compile(r"\bor\s+v?([0-9][0-9A-Za-z._+:-]*)", re.IGNORECASE)


@dataclass(slots=True)
class VersionComparison:
    result: str
    reason: str


class SBOMIndex:
    def __init__(
        self, packages: list[SBOMPackage], metadata: dict[str, Any] | None = None
    ) -> None:
        self.packages = packages
        self.metadata = metadata or {}

    @classmethod
    def from_spdx(cls, payload: dict[str, Any]) -> SBOMIndex:
        packages: list[SBOMPackage] = []
        for item in payload.get("packages", []) or []:
            purls = [
                str(ref.get("referenceLocator"))
                for ref in item.get("externalRefs", []) or []
                if ref.get("referenceType") == "purl" and ref.get("referenceLocator")
            ]
            packages.append(
                SBOMPackage(
                    name=str(item.get("name") or ""),
                    version_info=str(item.get("versionInfo") or "") or None,
                    spdx_id=str(item.get("SPDXID") or "") or None,
                    supplier=str(item.get("supplier") or "") or None,
                    download_location=str(item.get("downloadLocation") or "") or None,
                    purls=purls,
                    raw=item,
                )
            )
        metadata = {
            "spdxVersion": payload.get("spdxVersion"),
            "SPDXID": payload.get("SPDXID"),
            "name": payload.get("name"),
            "documentNamespace": payload.get("documentNamespace"),
            "creationInfo": payload.get("creationInfo"),
            "package_count": len(packages),
        }
        return cls(packages, metadata)

    def match_package(self, package_name: str | None) -> list[dict[str, Any]]:
        normalized_query = normalize_name(package_name)
        if not normalized_query:
            return []

        exact_matches: list[tuple[SBOMPackage, str]] = []
        for package in self.packages:
            if normalize_name(package.name) == normalized_query:
                exact_matches.append((package, "exact_name"))
                continue
            purl_names = {
                normalize_name(package_name_from_purl(purl)) for purl in package.purls
            }
            if normalized_query in purl_names:
                exact_matches.append((package, "exact_purl"))

        if exact_matches:
            return _dedupe_matches(exact_matches)

        substring_matches: list[tuple[SBOMPackage, str]] = []
        for package in self.packages:
            normalized_name = normalize_name(package.name)
            if len(normalized_query) >= 4 and (
                normalized_query in normalized_name
                or normalized_name in normalized_query
            ):
                substring_matches.append((package, "unique_substring"))
                continue
            if any(
                len(normalized_query) >= 4
                and normalized_query in normalize_name(package_name_from_purl(purl))
                for purl in package.purls
            ):
                substring_matches.append((package, "unique_substring"))
        deduped = _dedupe_matches(substring_matches)
        if len(deduped) > 1:
            for match in deduped:
                match["match_type"] = "ambiguous_substring"
        return deduped


def load_sbom_fixture(path: str) -> SBOMIndex:
    payload = load_structured_file(path)
    if not isinstance(payload, dict):
        raise ValueError("SBOM fixture must be an SPDX JSON object")
    return SBOMIndex.from_spdx(payload)


def fetch_flatcar_production_sbom(url: str = FLATCAR_PRODUCTION_SBOM_URL) -> SBOMIndex:
    payload = fetch_json(url, accept="application/json")
    if not isinstance(payload, dict):
        raise ValueError("Flatcar production SBOM response was not a JSON object")
    return SBOMIndex.from_spdx(payload)


def package_name_from_purl(purl: str | None) -> str:
    if not purl:
        return ""
    locator = purl.split("?", 1)[0].split("#", 1)[0]
    before_version = locator.split("@", 1)[0]
    return before_version.rsplit("/", 1)[-1]


def extract_fixed_version_requirement(action_needed: str | None) -> str | None:
    return highest_fixed_version_requirement(
        extract_fixed_version_requirements(action_needed)
    )


def extract_fixed_version_requirements(action_needed: str | None) -> list[str]:
    active_action = active_markdown_text(action_needed)
    if not active_action:
        return []
    if re.search(r"\bTBD\b", active_action, re.IGNORECASE):
        return []
    versions: list[str] = []
    for match in _REQUIREMENT_RE.finditer(active_action):
        version = match.group(1).rstrip(".,;)")
        if version not in versions:
            versions.append(version)
    if versions:
        # Capture bare OR-alternatives such as "update to >= 260 or 259.5",
        # where later branch versions omit the leading operator.
        for match in _OR_BARE_VERSION_RE.finditer(active_action):
            version = match.group(1).rstrip(".,;)")
            if version not in versions:
                versions.append(version)
    return versions


def highest_fixed_version_requirement(requirements: list[str]) -> str | None:
    if not requirements:
        return None
    highest = requirements[0]
    for requirement in requirements[1:]:
        comparison = compare_simple_versions(requirement, highest)
        if comparison.result == "ambiguous":
            return None
        if comparison.result == "at_or_above":
            highest = requirement
    return highest


def fixed_version_requirements_are_alternatives(action_needed: str | None) -> bool:
    """Return True when Action Needed lists OR-style branch alternatives.

    Multiple requirements joined by "or" (e.g. "update to >= 260 or 259.5")
    describe fixed versions on different release branches, so satisfying any one
    of them remediates the issue. Otherwise requirements are treated as AND-style
    (all must be satisfied, i.e. the highest applies).
    """
    active_action = active_markdown_text(action_needed)
    if not active_action:
        return False
    return bool(_OR_ALTERNATIVE_RE.search(active_action))


def evaluate_fixed_version_requirements(
    installed_version: str | None,
    requirements: list[str],
    alternatives: bool = False,
) -> VersionComparison:
    """Compare an installed version against one or more fixed-version requirements.

    When ``alternatives`` is True the requirements are OR-style branch
    alternatives: the installed version is considered at or above the fix when it
    satisfies any single requirement. Otherwise the highest requirement applies.
    """
    if not requirements:
        return VersionComparison("ambiguous", "No fixed-version requirement to compare")
    if not alternatives:
        highest = highest_fixed_version_requirement(requirements)
        if highest is None:
            return VersionComparison(
                "ambiguous",
                f"Fixed-version requirements are not comparable: {', '.join(requirements)}",
            )
        return compare_simple_versions(installed_version, highest)
    comparisons = [
        compare_simple_versions(installed_version, requirement)
        for requirement in requirements
    ]
    satisfied = next(
        (
            comparison
            for comparison in comparisons
            if comparison.result == "at_or_above"
        ),
        None,
    )
    if satisfied is not None:
        return VersionComparison(
            "at_or_above",
            f"{satisfied.reason} (satisfies one of the alternative requirements: {', '.join(requirements)})",
        )
    if all(comparison.result == "below" for comparison in comparisons):
        return VersionComparison(
            "below",
            f"{installed_version} is below all alternative requirements: {', '.join(requirements)}",
        )
    return VersionComparison(
        "ambiguous",
        f"Alternative fixed-version requirements are not conclusively comparable: {', '.join(requirements)}",
    )


def compare_simple_versions(
    installed_version: str | None, required_version: str | None
) -> VersionComparison:
    if not installed_version or not required_version:
        return VersionComparison("ambiguous", "Missing installed or required version")
    installed = installed_version.strip()
    required = required_version.strip()
    installed_parsed = _parse_comparable_version(installed)
    if installed_parsed is None:
        return VersionComparison(
            "ambiguous",
            f"Installed version is not a simple dotted numeric or Gentoo revision version: {installed_version}",
        )
    required_parsed = _parse_comparable_version(required)
    if required_parsed is None:
        return VersionComparison(
            "ambiguous",
            f"Required version is not a simple dotted numeric or Gentoo revision version: {required_version}",
        )
    installed_parts, installed_revision = installed_parsed
    required_parts, required_revision = required_parsed
    max_length = max(len(installed_parts), len(required_parts))
    installed_padded = installed_parts + (0,) * (max_length - len(installed_parts))
    required_padded = required_parts + (0,) * (max_length - len(required_parts))
    if installed_padded > required_padded or (
        installed_padded == required_padded and installed_revision >= required_revision
    ):
        return VersionComparison(
            "at_or_above", f"{installed_version} is at or above {required_version}"
        )
    return VersionComparison(
        "below", f"{installed_version} is below {required_version}"
    )


def _parse_comparable_version(value: str) -> tuple[tuple[int, ...], int] | None:
    match = _COMPARABLE_VERSION_RE.match(value)
    if not match:
        return None
    parts = tuple(int(part) for part in match.group("base").split("."))
    revision = int(match.group("revision") or 0)
    return parts, revision


def _dedupe_matches(matches: list[tuple[SBOMPackage, str]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for package, match_type in matches:
        key = package.spdx_id or f"{package.name}:{package.version_info}"
        if key in seen:
            continue
        deduped.append(package.evidence_dict(match_type=match_type))
        seen.add(key)
    return deduped
