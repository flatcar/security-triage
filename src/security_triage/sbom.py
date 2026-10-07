from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .http_utils import fetch_json
from .io_utils import load_structured_file
from .records import SBOMPackage
from .rules import (
    FLATCAR_PRODUCTION_SBOM_URL,
    RELEVANCE_SCOPES,
    active_markdown_text,
    extract_cves,
    package_identities_match,
    package_identity,
    source_fixed_version_evidence,
)

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
        self.metadata = dict(metadata or {})
        self.metadata.setdefault("package_count", len(packages))
        self.metadata.setdefault(
            "snapshot_sha256",
            hashlib.sha256(
                json.dumps(
                    [package.evidence_dict() for package in packages],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
        )
        self.metadata.setdefault("snapshot_digest_kind", "canonical_package_evidence")

    @classmethod
    def from_spdx(cls, payload: dict[str, Any]) -> SBOMIndex:
        packages: list[SBOMPackage] = []
        for item in payload.get("packages", []) or []:
            if not isinstance(item, dict):
                continue
            purls = [
                str(ref.get("referenceLocator"))
                for ref in item.get("externalRefs", []) or []
                if isinstance(ref, dict)
                and ref.get("referenceType") == "purl"
                and ref.get("referenceLocator")
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
            "snapshot_sha256": hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "snapshot_digest_kind": "canonical_spdx_json",
        }
        return cls(packages, metadata)

    def match_package(self, package_name: str | None) -> list[dict[str, Any]]:
        normalized_query = package_identity(package_name)
        if not normalized_query:
            return []

        exact_matches: list[tuple[SBOMPackage, str]] = []
        for package in self.packages:
            foreign_purls = [
                purl for purl in package.purls if not purl.startswith("pkg:gentoo/")
            ]
            name_is_qualified = "/" in package.name or package.name.startswith("pkg:")
            if package_identities_match(package.name, package_name) and (
                not foreign_purls
                or name_is_qualified
                or any(
                    package_identities_match(package_name, purl)
                    for purl in package.purls
                )
            ):
                exact_matches.append((package, "exact_name"))
                continue
            if any(
                package_identities_match(package_name, purl) for purl in package.purls
            ):
                exact_matches.append((package, "exact_purl"))

        if exact_matches:
            return self._with_scope(_dedupe_matches(exact_matches), package_name)

        substring_matches: list[tuple[SBOMPackage, str]] = []
        for package in self.packages:
            normalized_name = package_identity(package.name)
            if (
                normalized_name
                and len(normalized_query) >= 4
                and (
                    normalized_query in normalized_name
                    or normalized_name in normalized_query
                )
            ):
                substring_matches.append((package, "unique_substring"))
                continue
            if any(
                len(normalized_query) >= 4
                and normalized_query in package_identity(purl)
                for purl in package.purls
            ):
                substring_matches.append((package, "unique_substring"))
        deduped = _dedupe_matches(substring_matches)
        if len(deduped) > 1:
            for match in deduped:
                match["match_type"] = "ambiguous_substring"
        return deduped

    def scope_evidence(self, package_name: str | None) -> list[dict[str, Any]]:
        """Read caller-validated scope evidence, never upstream model scope claims.

        Metadata entries use package, scope, source, validated=true, and optional
        spdx_id. Only an exact SPDX association can prove SDK/sysext cleanup.
        """
        entries = self.metadata.get("scope_evidence", [])
        if not isinstance(entries, list):
            return []
        return [
            dict(entry)
            for entry in entries
            if isinstance(entry, dict)
            and entry.get("validated") is True
            and isinstance(entry.get("package"), str)
            and package_identities_match(package_name, entry["package"])
            and entry.get("scope") in RELEVANCE_SCOPES - {"unknown"}
            and isinstance(entry.get("source"), str)
            and entry["source"].strip()
        ]

    def discovery_scope_evidence(
        self, package_name: str | None, scope: str
    ) -> list[dict[str, Any]]:
        """Use a caller-supplied scope snapshot for discovery, never cleanup.

        A unique exact identity match proves presence in the supplied SDK/sysext
        snapshot. Absence or weak/ambiguous matches prove nothing about scope.
        """
        if scope not in {"sdk_only", "sysext", "build_only"}:
            raise ValueError(
                "Discovery scope snapshots require sdk_only, sysext, or build_only scope"
            )
        matches = self.match_package(package_name)
        if len(matches) != 1 or matches[0].get("match_type") not in {
            "exact_name",
            "exact_purl",
        }:
            return []
        match = matches[0]
        return [
            {
                "package": package_identity(package_name),
                "scope": scope,
                "source": "discovery_scope_sbom",
                "validated": True,
                "discovery_only": True,
                "spdx_id": match.get("SPDXID"),
                "versionInfo": match.get("versionInfo"),
                "sbom_package": match.get("name"),
                "purls": match.get("purls", []),
                "match_type": match["match_type"],
                "snapshot_sha256": self.metadata["snapshot_sha256"],
                "snapshot_source": self.metadata.get("source_url"),
                "snapshot_metadata": {
                    key: self.metadata.get(key)
                    for key in (
                        "spdxVersion",
                        "SPDXID",
                        "name",
                        "documentNamespace",
                        "creationInfo",
                    )
                },
            }
        ]

    def _with_scope(
        self, matches: list[dict[str, Any]], package_name: str | None
    ) -> list[dict[str, Any]]:
        evidence = self.scope_evidence(package_name)
        for match in matches:
            match["scope_evidence"] = [
                item
                for item in evidence
                if not item.get("spdx_id") or item["spdx_id"] == match.get("SPDXID")
            ]
        return matches


def load_sbom_fixture(path: str) -> SBOMIndex:
    payload = load_structured_file(path)
    if not isinstance(payload, dict):
        raise ValueError("SBOM fixture must be an SPDX JSON object")
    return SBOMIndex.from_spdx(payload)


def fetch_flatcar_production_sbom(url: str = FLATCAR_PRODUCTION_SBOM_URL) -> SBOMIndex:
    payload = fetch_json(url, accept="application/json")
    if not isinstance(payload, dict):
        raise ValueError("Flatcar production SBOM response was not a JSON object")
    index = SBOMIndex.from_spdx(payload)
    index.metadata["source_url"] = url
    return index


def package_name_from_purl(purl: str | None) -> str:
    """Return a version-independent identity, retaining ecosystem and namespace."""
    return package_identity(purl)


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


def fixed_version_coverage(
    action_needed: str | None, cves: list[str], summary: str | None = None
) -> dict[str, Any]:
    """Prove that the complete active action covers every listed advisory ID."""
    action = active_markdown_text(action_needed)
    reasons: list[str] = []
    requirements = extract_fixed_version_requirements(action)
    explicit_cves = extract_cves(action)
    missing = [cve for cve in cves if cve not in explicit_cves] if explicit_cves else []
    if missing:
        reasons.append("Action Needed explicitly covers only some issue CVEs.")
    if not cves:
        reasons.append("No active advisory IDs are available to prove coverage.")
    if not requirements:
        reasons.append("Action Needed has no complete fixed-version requirement.")
    # Consume the entire expression, rather than accepting one numeric fragment
    # from otherwise unresolved prose.
    remaining = re.sub(r"\bCVE-\d{4}-\d{4,}\b", "", action, flags=re.IGNORECASE)
    remaining = _REQUIREMENT_RE.sub(" FIX ", remaining)
    remaining = _OR_BARE_VERSION_RE.sub(" or FIX ", remaining)
    remaining = re.sub(r"[*`():,;\s]+", " ", remaining).strip()
    if not re.fullmatch(r"FIX(?:\s+(?:(?:and|or)\s+)?FIX)*", remaining, re.IGNORECASE):
        reasons.append("Action Needed contains partial or unclear requirement text.")
    if re.search(r"\band\b", remaining, re.IGNORECASE) and re.search(
        r"\bor\b", remaining, re.IGNORECASE
    ):
        reasons.append(
            "Mixed AND/OR requirements need explicit per-CVE interpretation."
        )
    if explicit_cves:
        positions = list(re.finditer(r"\bCVE-\d{4}-\d{4,}\b", action, re.IGNORECASE))
        for index, match in enumerate(positions):
            end = (
                positions[index + 1].start()
                if index + 1 < len(positions)
                else len(action)
            )
            if not extract_fixed_version_requirements(action[match.end() : end]):
                reasons.append(
                    f"No fixed requirement associated with {match.group(0)}."
                )
        if len(explicit_cves) > 1 and fixed_version_requirements_are_alternatives(
            action
        ):
            reasons.append("OR requirements spanning distinct CVEs need manual review.")
    if re.search(
        r"\b(?:partial(?:ly)?|only\s+fix(?:es)?|not\s+fixed|unfixed|unresolved|pending|"
        r"remaining\s+CVEs?)\b",
        active_markdown_text(summary),
        re.IGNORECASE,
    ):
        reasons.append("Summary indicates incomplete or unresolved remediation.")
    summary_text = active_markdown_text(summary)
    summary_cves = list(
        re.finditer(r"\bCVE-\d{4}-\d{4,}\b", summary_text, re.IGNORECASE)
    )
    for index, match in enumerate(summary_cves):
        if match.group(0).upper() not in cves:
            continue
        end = (
            summary_cves[index + 1].start()
            if index + 1 < len(summary_cves)
            else len(summary_text)
        )
        clause = summary_text[match.end() : end]
        summary_requirements = source_fixed_version_evidence(clause)
        summary_requirements.extend(
            {"versions": [version.rstrip(".,;")], "semantics": "and", "quote": ""}
            for version in re.findall(r"\bbefore\s+v?([0-9][0-9A-Za-z._+:-]*)", clause)
        )
        action_versions = (
            requirements
            if fixed_version_requirements_are_alternatives(action)
            else [highest_fixed_version_requirement(requirements)]
        )
        for requirement in summary_requirements:
            alternatives = requirement["semantics"] == "or"
            if alternatives and re.search(
                r"\band\b", requirement["quote"], re.IGNORECASE
            ):
                reasons.append(
                    f"Summary mixes AND/OR requirements for {match.group(0)}."
                )
                continue
            # Every selectable action branch must cover this CVE's requirement,
            # but an explicitly alternative summary needs only one of its fixes.
            if any(
                evaluate_fixed_version_requirements(
                    action_version, requirement["versions"], alternatives=alternatives
                ).result
                != "at_or_above"
                for action_version in action_versions
            ):
                reasons.append(
                    f"Action Needed does not cover the summary requirement for {match.group(0)}."
                )
    return {
        "complete": not reasons,
        "covered_cves": list(cves) if not reasons else [],
        "missing_cves": missing,
        "requirements": requirements,
        "semantics": "or"
        if fixed_version_requirements_are_alternatives(action)
        else "and",
        "reasons": list(dict.fromkeys(reasons)),
    }


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


def evaluate_simple_affected_range(
    installed_version: str | None, affected_range: str
) -> VersionComparison:
    match = re.fullmatch(
        r"\s*(<=|>=|<|>|==|=)\s*(v?[0-9][0-9A-Za-z._+:-]*)\s*", affected_range
    )
    if not match:
        return VersionComparison(
            "ambiguous", "Affected range is not a single simple comparison."
        )
    operator, boundary = match.groups()
    forward = compare_simple_versions(installed_version, boundary)
    reverse = compare_simple_versions(boundary, installed_version)
    if "ambiguous" in {forward.result, reverse.result}:
        return VersionComparison(
            "ambiguous", "Affected range or installed version is not comparable."
        )
    equal = forward.result == reverse.result == "at_or_above"
    affected = {
        "<": forward.result == "below",
        "<=": forward.result == "below" or equal,
        ">": forward.result == "at_or_above" and not equal,
        ">=": forward.result == "at_or_above",
        "=": equal,
        "==": equal,
    }[operator]
    return VersionComparison(
        "affected" if affected else "not_affected",
        f"SBOM version {installed_version} {'satisfies' if affected else 'does not satisfy'} affected range {affected_range}.",
    )


def _parse_comparable_version(value: str) -> tuple[tuple[int, ...], int] | None:
    match = _COMPARABLE_VERSION_RE.match(value)
    if not match:
        return None
    parts = tuple(int(part) for part in match.group("base").split("."))
    revision = int(match.group("revision") or 0)
    return parts, revision


def _dedupe_matches(matches: list[tuple[SBOMPackage, str]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    deduped: list[dict[str, Any]] = []
    for package, match_type in matches:
        key = (
            package.spdx_id,
            package.name,
            package.version_info,
            tuple(package.purls),
        )
        if key in seen:
            continue
        deduped.append(package.evidence_dict(match_type=match_type))
        seen.add(key)
    return deduped
