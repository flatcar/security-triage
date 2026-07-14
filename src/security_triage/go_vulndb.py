"""Fetcher for the canonical Go vulnerability database."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .console import NullProgressLogger, ProgressLogger
from .http_utils import fetch_json
from .records import SourceEntry
from .time_utils import in_window

GO_VULNDB_BASE_URL = "https://vuln.go.dev"

JsonFetcher = Callable[[str], Any]


def fetch_go_vulndb_entries(
    start: str | None,
    end: str | None,
    *,
    cache_dir: str | Path | None = None,
    base_url: str = GO_VULNDB_BASE_URL,
    fetcher: JsonFetcher | None = None,
    progress_logger: ProgressLogger | None = None,
) -> list[SourceEntry]:
    """Return one SourceEntry per Go advisory modified in [start, end]."""
    progress = progress_logger or NullProgressLogger()
    json_fetcher = fetcher or _default_fetcher
    base = base_url.rstrip("/")

    index_url = f"{base}/index/vulns.json"
    index_payload = json_fetcher(index_url)
    if not isinstance(index_payload, list):
        raise ValueError("Go vulnerability index must be a list")

    selected = [
        item
        for item in index_payload
        if isinstance(item, dict)
        and in_window(
            str(item.get("modified") or ""), start, end, include_undated=False
        )
    ]
    progress.info(
        f"go_vulndb: {len(selected)} advisories modified in processing window"
    )

    entries: list[SourceEntry] = []
    for item in selected:
        advisory_id = str(item.get("id") or "").strip()
        if not advisory_id:
            continue
        modified = str(item.get("modified") or "")
        record = _fetch_advisory_record(
            advisory_id, modified, base, cache_dir, json_fetcher
        )
        if not isinstance(record, dict):
            continue
        entries.append(
            _entry_from_osv(
                record,
                fallback_modified=modified,
                fallback_aliases=_string_list(item.get("aliases")),
            )
        )
    return entries


def _default_fetcher(url: str) -> Any:
    return fetch_json(url, accept="application/json")


def _fetch_advisory_record(
    advisory_id: str,
    modified: str,
    base_url: str,
    cache_dir: str | Path | None,
    json_fetcher: JsonFetcher,
) -> Any:
    encoded_id = quote(advisory_id, safe="")
    url = f"{base_url}/ID/{encoded_id}.json"
    if cache_dir is None:
        return json_fetcher(url)

    cache_path = _cache_path(Path(cache_dir), advisory_id, modified)
    if cache_path.is_file():
        try:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass

    payload = json_fetcher(url)
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )
    except OSError:
        pass
    return payload


def _cache_path(root: Path, advisory_id: str, modified: str) -> Path:
    key = _safe_filename(f"{advisory_id}-{modified or 'unknown'}.json")
    return root / "go_vulndb" / key


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "advisory.json"


def _entry_from_osv(
    record: dict[str, Any], *, fallback_modified: str, fallback_aliases: list[str]
) -> SourceEntry:
    advisory_id = str(record.get("id") or "").strip()
    aliases = _unique([*_string_list(record.get("aliases")), *fallback_aliases])
    packages = _affected_packages(record)
    fixed_versions = _fixed_versions(record)
    affected_ranges = _affected_ranges(record)
    import_paths = _import_paths(record)
    reference_urls = _reference_urls(record)
    database_specific = (
        record.get("database_specific")
        if isinstance(record.get("database_specific"), dict)
        else {}
    )
    if not isinstance(database_specific, dict):
        database_specific = {}
    report_url = str(
        database_specific.get("url") or f"https://pkg.go.dev/vuln/{advisory_id}"
    )
    summary = str(record.get("summary") or advisory_id)
    details = str(record.get("details") or "")

    references = _unique([report_url, *aliases, *packages, *reference_urls])
    metadata = {
        "aliases": aliases,
        "affected_packages": packages,
        "affected_ranges": affected_ranges,
        "fixed_versions": fixed_versions,
        "import_paths": import_paths,
        "references": reference_urls,
        "database_specific": database_specific,
        "severity": record.get("severity")
        if isinstance(record.get("severity"), list)
        else [],
        "credits": record.get("credits")
        if isinstance(record.get("credits"), list)
        else [],
    }

    return SourceEntry(
        source="go_vulndb",
        source_url=report_url,
        entry_id=advisory_id,
        title=summary,
        content=_render_go_content(
            advisory_id,
            summary,
            report_url,
            aliases,
            packages,
            affected_ranges,
            fixed_versions,
            import_paths,
            details,
        ),
        published_at=_string_or_none(record.get("published")),
        updated_at=_string_or_none(record.get("modified")) or fallback_modified or None,
        references=references,
        description=details,
        comments=[],
        new_comments=[],
        metadata=metadata,
        raw=record,
    )


def _render_go_content(
    advisory_id: str,
    summary: str,
    report_url: str,
    aliases: list[str],
    packages: list[str],
    affected_ranges: list[str],
    fixed_versions: list[str],
    import_paths: list[str],
    details: str,
) -> str:
    lines = [f"Go vulnerability {advisory_id}: {summary}", report_url]
    if packages:
        lines.append(f"Package: {packages[0]}")
        if len(packages) > 1:
            lines.append(f"Affected packages: {', '.join(packages)}")
    if aliases:
        lines.append(f"Aliases: {', '.join(aliases)}")
    if affected_ranges:
        lines.append(f"Affected versions: {'; '.join(affected_ranges)}")
    if fixed_versions:
        lines.append(f"Fixed versions: {', '.join(fixed_versions)}")
    if import_paths:
        lines.append(f"Affected import paths: {', '.join(import_paths)}")
    if details:
        lines.extend(["", "Details:", _truncate(details, 3000)])
    return "\n".join(lines)


def _affected_packages(record: dict[str, Any]) -> list[str]:
    packages: list[str] = []
    for affected in _dict_list(record.get("affected")):
        raw_package = affected.get("package")
        package = raw_package if isinstance(raw_package, dict) else {}
        name = str(package.get("name") or "").strip()
        if name:
            packages.append(name)
    return _unique(packages)


def _affected_ranges(record: dict[str, Any]) -> list[str]:
    ranges: list[str] = []
    for affected in _dict_list(record.get("affected")):
        raw_package = affected.get("package")
        package = raw_package if isinstance(raw_package, dict) else {}
        package_name = str(package.get("name") or "package").strip() or "package"
        for item in _dict_list(affected.get("ranges")):
            events = _dict_list(item.get("events"))
            parts = []
            for event in events:
                if event.get("introduced") is not None:
                    parts.append(f">= {event['introduced']}")
                if event.get("fixed") is not None:
                    parts.append(f"< {event['fixed']}")
                if event.get("last_affected") is not None:
                    parts.append(f"<= {event['last_affected']}")
            if parts:
                ranges.append(f"{package_name}: {'; '.join(parts)}")
    return _unique(ranges)


def _fixed_versions(record: dict[str, Any]) -> list[str]:
    versions: list[str] = []
    for affected in _dict_list(record.get("affected")):
        for item in _dict_list(affected.get("ranges")):
            for event in _dict_list(item.get("events")):
                fixed = event.get("fixed")
                if fixed is not None:
                    versions.append(str(fixed))
    return _unique(versions)


def _import_paths(record: dict[str, Any]) -> list[str]:
    imports: list[str] = []
    for affected in _dict_list(record.get("affected")):
        ecosystem_specific_raw = affected.get("ecosystem_specific")
        ecosystem_specific: dict[str, Any] = (
            ecosystem_specific_raw if isinstance(ecosystem_specific_raw, dict) else {}
        )
        for item in _dict_list(ecosystem_specific.get("imports")):
            path = str(item.get("path") or "").strip()
            if path:
                imports.append(path)
    return _unique(imports)


def _reference_urls(record: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for reference in _dict_list(record.get("references")):
        url = str(reference.get("url") or "").strip()
        if url:
            urls.append(url)
    return _unique(urls)


def _dict_list(value: Any) -> list[dict[str, Any]]:
    return (
        [item for item in value if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _string_or_none(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def _unique(values: list[str]) -> list[str]:
    unique_values: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in unique_values:
            unique_values.append(text)
    return unique_values


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3].rstrip() + "..."
