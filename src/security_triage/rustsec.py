"""Fetcher for the RustSec advisory database."""

from __future__ import annotations

import os
import re
import tomllib
from collections.abc import Callable
from datetime import date, datetime, time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from .console import NullProgressLogger, ProgressLogger
from .http_utils import fetch_json, fetch_text
from .records import SourceEntry
from .time_utils import in_window, parse_datetime

RUSTSEC_REPO_API_URL = "https://api.github.com/repos/RustSec/advisory-db"
RUSTSEC_RAW_BASE_URL = "https://raw.githubusercontent.com/RustSec/advisory-db"
RUSTSEC_ADVISORY_BASE_URL = "https://rustsec.org/advisories"

JsonFetcher = Callable[[str], Any]
TextFetcher = Callable[[str], str]

_FRONT_MATTER_RE = re.compile(
    r"\A\s*```toml\s*\n(.*?)\n```\s*(.*)\Z", re.DOTALL | re.IGNORECASE
)
_HEADING_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)


def fetch_rustsec_entries(
    start: str | None,
    end: str | None,
    *,
    cache_dir: str | Path | None = None,
    token: str | None = None,
    api_url: str = RUSTSEC_REPO_API_URL,
    raw_base_url: str = RUSTSEC_RAW_BASE_URL,
    json_fetcher: JsonFetcher | None = None,
    text_fetcher: TextFetcher | None = None,
    progress_logger: ProgressLogger | None = None,
    max_pages: int = 3,
) -> list[SourceEntry]:
    """Return one SourceEntry per RustSec advisory touched in [start, end]."""
    progress = progress_logger or NullProgressLogger()
    github_token = token if token is not None else os.getenv("GITHUB_TOKEN")
    json_loader = json_fetcher or _build_json_fetcher(github_token)
    text_loader = text_fetcher or _default_text_fetcher
    base = api_url.rstrip("/")

    changed_files = _recent_advisory_files(
        base, start, end, json_loader, max_pages=max_pages
    )
    progress.info(
        f"rustsec: {len(changed_files)} advisory file(s) changed in processing window"
    )

    entries: list[SourceEntry] = []
    for path, change in sorted(changed_files.items()):
        markdown = _fetch_raw_advisory(
            path, change, raw_base_url.rstrip("/"), cache_dir, text_loader
        )
        entry = _entry_from_markdown(
            path, markdown, commit_sha=change["sha"], commit_date=change.get("date")
        )
        entries.append(entry)
    return entries


def _build_json_fetcher(token: str | None) -> JsonFetcher:
    def load(url: str) -> Any:
        return fetch_json(url, token=token, accept="application/vnd.github+json")

    return load


def _default_text_fetcher(url: str) -> str:
    return fetch_text(url, accept="text/plain,*/*;q=0.8")


def _recent_advisory_files(
    api_url: str,
    start: str | None,
    end: str | None,
    json_fetcher: JsonFetcher,
    *,
    max_pages: int,
) -> dict[str, dict[str, str]]:
    since = _github_timestamp(start)
    until = _github_timestamp(end)
    changed: dict[str, dict[str, str]] = {}
    for path_prefix in ("crates", "rust"):
        for commit in _iter_commits(
            api_url, path_prefix, since, until, json_fetcher, max_pages=max_pages
        ):
            detail_url = str(commit.get("url") or "")
            if not detail_url:
                continue
            detail = json_fetcher(detail_url)
            if not isinstance(detail, dict):
                continue
            sha = str(detail.get("sha") or commit.get("sha") or "")
            commit_date = _commit_date(detail) or _commit_date(commit)
            for file_info in _dict_list(detail.get("files")):
                filename = str(file_info.get("filename") or "")
                if (
                    not _is_advisory_path(filename)
                    or file_info.get("status") == "removed"
                ):
                    continue
                if commit_date and not in_window(
                    commit_date, start, end, include_undated=False
                ):
                    continue
                previous = changed.get(filename)
                if previous and _is_newer_or_equal(previous.get("date"), commit_date):
                    continue
                changed[filename] = {
                    "sha": sha,
                    "date": commit_date or "",
                    "raw_url": str(file_info.get("raw_url") or ""),
                }
    return changed


def _iter_commits(
    api_url: str,
    path_prefix: str,
    since: str | None,
    until: str | None,
    json_fetcher: JsonFetcher,
    *,
    max_pages: int,
) -> list[dict[str, Any]]:
    commits: list[dict[str, Any]] = []
    for page in range(1, max_pages + 1):
        params: list[tuple[str, str]] = [
            ("path", path_prefix),
            ("per_page", "100"),
            ("page", str(page)),
        ]
        if since:
            params.append(("since", since))
        if until:
            params.append(("until", until))
        payload = json_fetcher(f"{api_url}/commits?{urlencode(params)}")
        if not isinstance(payload, list):
            break
        page_commits = [item for item in payload if isinstance(item, dict)]
        commits.extend(page_commits)
        if len(page_commits) < 100:
            break
    return commits


def _fetch_raw_advisory(
    path: str,
    change: dict[str, str],
    raw_base_url: str,
    cache_dir: str | Path | None,
    text_fetcher: TextFetcher,
) -> str:
    sha = change.get("sha") or "main"
    raw_url = (
        change.get("raw_url")
        or f"{raw_base_url}/{quote(sha, safe='')}/{quote(path, safe='/')}"
    )
    if cache_dir is None:
        return text_fetcher(raw_url)

    cache_path = _cache_path(Path(cache_dir), path, sha)
    if cache_path.is_file():
        try:
            return cache_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    text = text_fetcher(raw_url)
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(text, encoding="utf-8")
    except OSError:
        pass
    return text


def _cache_path(root: Path, path: str, sha: str) -> Path:
    safe_path = re.sub(r"[^A-Za-z0-9_.-]+", "_", path).strip("_") or "advisory.md"
    safe_sha = re.sub(r"[^A-Za-z0-9_.-]+", "_", sha).strip("_") or "unknown"
    return root / "rustsec" / safe_sha / safe_path


def _entry_from_markdown(
    path: str, markdown: str, *, commit_sha: str, commit_date: str | None
) -> SourceEntry:
    metadata, body = _parse_advisory_markdown(markdown)
    raw_advisory = metadata.get("advisory")
    advisory: dict[str, Any] = raw_advisory if isinstance(raw_advisory, dict) else {}
    raw_versions = metadata.get("versions")
    versions: dict[str, Any] = raw_versions if isinstance(raw_versions, dict) else {}
    raw_affected = metadata.get("affected")
    affected: dict[str, Any] = raw_affected if isinstance(raw_affected, dict) else {}

    advisory_id = str(advisory.get("id") or Path(path).stem)
    package = str(advisory.get("package") or "").strip()
    rustsec_url = f"{RUSTSEC_ADVISORY_BASE_URL}/{advisory_id}.html"
    aliases = _string_list(advisory.get("aliases"))
    related = _string_list(advisory.get("related"))
    reference_urls = _string_list(advisory.get("references"))
    advisory_url = _string_or_none(advisory.get("url"))
    patched_versions = _string_list(versions.get("patched"))
    unaffected_versions = _string_list(versions.get("unaffected"))
    title = _markdown_title(body) or f"{advisory_id}: {package or 'RustSec advisory'}"

    references = _unique(
        [rustsec_url, advisory_url or "", *reference_urls, *aliases, *related, package]
    )
    entry_metadata = {
        "id": advisory_id,
        "package": package,
        "date": advisory.get("date"),
        "url": advisory_url,
        "references": reference_urls,
        "aliases": aliases,
        "related": related,
        "categories": _string_list(advisory.get("categories")),
        "keywords": _string_list(advisory.get("keywords")),
        "informational": advisory.get("informational"),
        "cvss": advisory.get("cvss"),
        "withdrawn": advisory.get("withdrawn"),
        "license": advisory.get("license"),
        "versions": versions,
        "affected": affected,
        "path": path,
        "commit_sha": commit_sha,
        "commit_date": commit_date,
        "rustsec_url": rustsec_url,
    }

    return SourceEntry(
        source="rustsec",
        source_url=rustsec_url,
        entry_id=advisory_id,
        title=title,
        content=_render_rustsec_content(
            advisory_id,
            title,
            rustsec_url,
            package,
            aliases,
            related,
            patched_versions,
            unaffected_versions,
            body,
        ),
        published_at=_string_or_none(advisory.get("date")),
        updated_at=commit_date or _string_or_none(advisory.get("date")),
        references=references,
        description=body.strip(),
        comments=[],
        new_comments=[],
        metadata=entry_metadata,
        raw={"front_matter": metadata, "markdown": body, "path": path},
    )


def _parse_advisory_markdown(markdown: str) -> tuple[dict[str, Any], str]:
    match = _FRONT_MATTER_RE.match(markdown)
    if not match:
        raise ValueError("RustSec advisory did not start with fenced TOML front matter")
    metadata = tomllib.loads(match.group(1))
    if not isinstance(metadata, dict):
        raise ValueError("RustSec advisory TOML front matter must be a table")
    return _json_safe(metadata), match.group(2).strip()


def _render_rustsec_content(
    advisory_id: str,
    title: str,
    rustsec_url: str,
    package: str,
    aliases: list[str],
    related: list[str],
    patched_versions: list[str],
    unaffected_versions: list[str],
    body: str,
) -> str:
    lines = [f"RustSec advisory {advisory_id}: {title}", rustsec_url]
    if package:
        lines.append(f"Package: {package}")
    if aliases:
        lines.append(f"Aliases: {', '.join(aliases)}")
    if related:
        lines.append(f"Related: {', '.join(related)}")
    if unaffected_versions:
        lines.append(f"Unaffected versions: {', '.join(unaffected_versions)}")
    if patched_versions:
        lines.append(f"Fixed versions: {', '.join(patched_versions)}")
    if body:
        lines.extend(["", "Description:", _truncate(body, 3000)])
    return "\n".join(lines)


def _github_timestamp(value: str | None) -> str | None:
    parsed = parse_datetime(value)
    if parsed is None:
        return None
    return parsed.isoformat().replace("+00:00", "Z")


def _commit_date(commit_payload: dict[str, Any]) -> str | None:
    raw_commit = commit_payload.get("commit")
    commit: dict[str, Any] = raw_commit if isinstance(raw_commit, dict) else {}
    for actor_key in ("committer", "author"):
        raw_actor = commit.get(actor_key)
        actor: dict[str, Any] = raw_actor if isinstance(raw_actor, dict) else {}
        date_value = _string_or_none(actor.get("date"))
        if date_value:
            return date_value
    return None


def _is_advisory_path(path: str) -> bool:
    return (path.startswith("crates/") or path.startswith("rust/")) and path.endswith(
        ".md"
    )


def _is_newer_or_equal(existing: str | None, candidate: str | None) -> bool:
    existing_dt = parse_datetime(existing)
    candidate_dt = parse_datetime(candidate)
    if existing_dt is None:
        return False
    if candidate_dt is None:
        return True
    return existing_dt >= candidate_dt


def _markdown_title(body: str) -> str | None:
    match = _HEADING_RE.search(body)
    return match.group(1).strip() if match else None


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


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, (date, datetime, time)):
        return value.isoformat()
    return value


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3].rstrip() + "..."
