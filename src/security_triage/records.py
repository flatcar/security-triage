from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class SourceEntry:
    source: str
    source_url: str
    entry_id: str
    title: str
    content: str
    published_at: str | None = None
    updated_at: str | None = None
    references: list[str] = field(default_factory=list)
    description: str | None = None
    comments: list[dict[str, Any]] = field(default_factory=list)
    new_comments: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def excerpt(self, limit: int = 1200) -> str:
        text = f"{self.title}\n\n{self.content}".strip()
        return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


@dataclass(slots=True)
class Issue:
    number: int
    title: str
    body: str
    labels: list[str]
    html_url: str
    state: str = "open"
    state_reason: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ParsedIssue:
    name: str | None
    cves: list[str]
    cvss_scores: list[str]
    action_needed: str | None
    summary: str | None
    gentoo_ref: str | None
    valid: bool
    missing_fields: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SBOMPackage:
    name: str
    version_info: str | None
    spdx_id: str | None
    supplier: str | None = None
    download_location: str | None = None
    purls: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def evidence_dict(self, match_type: str | None = None) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "versionInfo": self.version_info,
            "SPDXID": self.spdx_id,
            "purls": list(self.purls),
        }
        if match_type:
            data["match_type"] = match_type
        return data
