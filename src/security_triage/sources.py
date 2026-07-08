from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlencode, urljoin

from .console import NullProgressLogger, ProgressLogger
from .go_vulndb import GO_VULNDB_BASE_URL, fetch_go_vulndb_entries
from .http_utils import fetch_json, fetch_text
from .io_utils import load_structured_file
from .oss_security import OSS_SECURITY_BASE_URL, fetch_oss_security_entries
from .records import SourceEntry
from .rustsec import RUSTSEC_REPO_API_URL, fetch_rustsec_entries
from .time_utils import in_window, parse_datetime

GENTOO_BUGZILLA_BASE_URL = "https://bugs.gentoo.org"
GENTOO_SECURITY_URL = "https://bugs.gentoo.org/buglist.cgi?bug_status=__open__&component=Vulnerabilities&list_id=6015515&product=Gentoo%20Security"
GENTOO_BUGZILLA_REST_BUG_URL = f"{GENTOO_BUGZILLA_BASE_URL}/rest/bug"
GENTOO_BUGZILLA_FIELDS = (
    "id",
    "alias",
    "component",
    "creation_time",
    "creator_detail",
    "last_change_time",
    "product",
    "see_also",
    "severity",
    "status",
    "summary",
    "url",
    "weburl",
)
GENTOO_BUGZILLA_REST_URL = f"{GENTOO_BUGZILLA_REST_BUG_URL}?" + urlencode(
    {
        "bug_status": "__open__",
        "component": "Vulnerabilities",
        "product": "Gentoo Security",
        "include_fields": ",".join(GENTOO_BUGZILLA_FIELDS),
    }
)

REDHAT_VULNERABILITIES_URL = "https://bugzilla.redhat.com/buglist.cgi?component=vulnerability&product=Security%20Response&resolution=---"


@dataclass(frozen=True, slots=True)
class SourceSpec:
    name: str
    url: str
    optional: bool = False


DEFAULT_SOURCE_SPECS = [
    SourceSpec("gentoo", GENTOO_SECURITY_URL),
    SourceSpec("oss_security", OSS_SECURITY_BASE_URL),
    SourceSpec("go_vulndb", GO_VULNDB_BASE_URL),
    SourceSpec("rustsec", RUSTSEC_REPO_API_URL),
]
OPTIONAL_SOURCE_SPECS = [SourceSpec("redhat", REDHAT_VULNERABILITIES_URL, optional=True)]


class SourceFetchError(RuntimeError):
    pass


def load_source_fixture(path: str, start: str | None = None, end: str | None = None) -> list[SourceEntry]:
    payload = load_structured_file(path)
    items = payload.get("entries", payload) if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        raise ValueError("Source fixture must be a list or an object with an 'entries' list")
    entries = [source_entry_from_mapping(item) for item in items]
    return filter_entries_by_window(entries, start, end)


def source_entry_from_mapping(item: dict[str, Any]) -> SourceEntry:
    source = str(item.get("source") or "other")
    title = str(item.get("title") or item.get("summary") or "")
    content = str(item.get("content") or item.get("raw_source_excerpt") or item.get("body") or "")
    source_url = str(item.get("source_url") or item.get("url") or "")
    entry_id = str(item.get("entry_id") or item.get("id") or item.get("raw_advisory_id") or source_url or title)
    references = item.get("references") or item.get("upstream_references") or []
    return SourceEntry(
        source=source,
        source_url=source_url,
        entry_id=entry_id,
        title=title,
        content=content,
        published_at=item.get("published_at") or item.get("source_entry_published_at"),
        updated_at=item.get("updated_at") or item.get("source_entry_updated_at"),
        references=[str(reference) for reference in references],
        description=item.get("description") or item.get("upstream_description"),
        comments=_dict_list(item.get("comments") or item.get("upstream_comments")),
        new_comments=_dict_list(item.get("new_comments") or item.get("upstream_new_comments") or item.get("upstream_recent_comments")),
        metadata=dict(item.get("metadata") or item.get("upstream_metadata") or {}),
        raw=item,
    )


def fetch_live_sources(
    include_optional: bool = False,
    start: str | None = None,
    end: str | None = None,
    specs: list[SourceSpec] | None = None,
    include_undated: bool = False,
    progress_logger: ProgressLogger | None = None,
    oss_security_cache_dir: str | None = None,
    go_vulndb_cache_dir: str | None = None,
    rustsec_cache_dir: str | None = None,
) -> tuple[list[SourceEntry], list[dict[str, Any]]]:
    selected_specs = specs or [*DEFAULT_SOURCE_SPECS, *(OPTIONAL_SOURCE_SPECS if include_optional else [])]
    progress = progress_logger or NullProgressLogger()
    entries: list[SourceEntry] = []
    errors: list[dict[str, Any]] = []
    for spec in selected_specs:
        try:
            progress.info(f"Fetching source {spec.name}")
            if spec.name == "gentoo":
                fetched = fetch_gentoo_entries(start=start, end=end)
                filtered = filter_entries_by_window(fetched, start, end, include_undated=include_undated, prefer_published=False)
            elif spec.name == "oss_security":
                fetched = fetch_oss_security_entries(start, end, cache_dir=oss_security_cache_dir, progress_logger=progress)
                filtered = filter_entries_by_window(fetched, start, end, include_undated=include_undated, prefer_published=False)
            elif spec.name == "go_vulndb":
                fetched = fetch_go_vulndb_entries(start, end, cache_dir=go_vulndb_cache_dir, progress_logger=progress)
                filtered = filter_entries_by_window(fetched, start, end, include_undated=include_undated, prefer_published=False)
            elif spec.name == "rustsec":
                fetched = fetch_rustsec_entries(start, end, cache_dir=rustsec_cache_dir, progress_logger=progress)
                filtered = filter_entries_by_window(fetched, start, end, include_undated=include_undated, prefer_published=False)
            else:
                fetched = fetch_generic_source_entries(spec)
                filtered = filter_entries_by_window(fetched, start, end, include_undated=include_undated, prefer_published=True)
            progress.info(f"Source {spec.name}: fetched {len(fetched)} entr{'y' if len(fetched) == 1 else 'ies'}, kept {len(filtered)} in window")
            entries.extend(filtered)
        except Exception as exc:
            errors.append({"source": spec.name, "url": spec.url, "error": str(exc)})
            progress.info(f"Source {spec.name}: failed with {exc}")
    return entries, errors


def fetch_gentoo_entries(start: str | None = None, end: str | None = None) -> list[SourceEntry]:
    try:
        payload = fetch_json(_gentoo_bugzilla_search_url(start, end), accept="application/json")
        bugs = payload.get("bugs", []) if isinstance(payload, dict) else []
        comments_by_bug = fetch_gentoo_comments([str(bug.get("id")) for bug in bugs if bug.get("id")])
        entries: list[SourceEntry] = []
        for bug in bugs:
            bug_id = str(bug.get("id") or "")
            url = str(bug.get("weburl") or f"https://bugs.gentoo.org/{bug_id}")
            summary = str(bug.get("summary") or "")
            comments_payload = comments_by_bug.get(bug_id, [])
            description, comments = _split_bugzilla_comments(comments_payload, bug.get("creator_detail"))
            new_comments = _new_comments_in_window(comments, start, end)
            metadata = _gentoo_bug_metadata(bug)
            references = _gentoo_references(url, metadata)
            entries.append(
                SourceEntry(
                    source="gentoo",
                    source_url=url,
                    entry_id=bug_id,
                    title=summary,
                    content=_gentoo_content(bug_id, summary, url, metadata, description, new_comments),
                    published_at=bug.get("creation_time"),
                    updated_at=bug.get("last_change_time"),
                    references=references,
                    description=description,
                    comments=comments,
                    new_comments=new_comments,
                    metadata=metadata,
                    raw={**bug, "description": description, "comments": comments, "new_comments": new_comments},
                )
            )
        return entries
    except Exception:
        return fetch_generic_source_entries(SourceSpec("gentoo", GENTOO_SECURITY_URL))


def fetch_gentoo_comments(bug_ids: list[str], batch_size: int = 100) -> dict[str, list[dict[str, Any]]]:
    ids = [bug_id for bug_id in bug_ids if bug_id]
    comments: dict[str, list[dict[str, Any]]] = {}
    for batch in _batches(ids, batch_size):
        if not batch:
            continue
        try:
            comments.update(_comments_from_bugzilla_payload(fetch_json(_gentoo_bugzilla_comments_url(batch), accept="application/json")))
        except Exception:
            for bug_id in batch:
                try:
                    comments.update(_comments_from_bugzilla_payload(fetch_json(f"{GENTOO_BUGZILLA_BASE_URL}/rest/bug/{bug_id}/comment", accept="application/json")))
                except Exception:
                    comments.setdefault(bug_id, [])
    return comments


def _gentoo_bugzilla_search_url(start: str | None, end: str | None) -> str:
    params: list[tuple[str, str]] = [
        ("bug_status", "__open__"),
        ("component", "Vulnerabilities"),
        ("product", "Gentoo Security"),
        ("include_fields", ",".join(GENTOO_BUGZILLA_FIELDS)),
    ]
    if start:
        params.append(("chfieldfrom", _bugzilla_timestamp(start)))
    if end:
        params.append(("chfieldto", _bugzilla_timestamp(end)))
    return f"{GENTOO_BUGZILLA_REST_BUG_URL}?{urlencode(params)}"


def _gentoo_bugzilla_comments_url(bug_ids: list[str]) -> str:
    path_id = bug_ids[0] if bug_ids else "1"
    params = [("ids", bug_id) for bug_id in bug_ids]
    return f"{GENTOO_BUGZILLA_BASE_URL}/rest/bug/{path_id}/comment?{urlencode(params)}"


def _bugzilla_timestamp(value: str) -> str:
    parsed = parse_datetime(value)
    if parsed is None:
        return value
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _comments_from_bugzilla_payload(payload: Any) -> dict[str, list[dict[str, Any]]]:
    bugs = payload.get("bugs", {}) if isinstance(payload, dict) else {}
    comments: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(bugs, dict):
        return comments
    for bug_id, item in bugs.items():
        if isinstance(item, dict):
            raw_comments = item.get("comments", [])
        else:
            raw_comments = item
        comments[str(bug_id)] = _dict_list(raw_comments)
    return comments


def _split_bugzilla_comments(raw_comments: list[dict[str, Any]], creator_detail: Any) -> tuple[str, list[dict[str, Any]]]:
    description = ""
    comments: list[dict[str, Any]] = []
    creator_identities = _creator_identities(creator_detail)
    for raw_comment in raw_comments:
        comment = _normalize_bugzilla_comment(raw_comment, creator_identities)
        if comment.get("count") == 0:
            description = str(comment.get("text") or "")
        else:
            comments.append(comment)
    comments.sort(key=lambda item: int(item.get("count") or 0))
    return description, comments


def _normalize_bugzilla_comment(raw_comment: dict[str, Any], creator_identities: set[str]) -> dict[str, Any]:
    raw_creator_detail = raw_comment.get("creator_detail")
    creator_detail: dict[str, Any] = raw_creator_detail if isinstance(raw_creator_detail, dict) else {}
    creator_values = _creator_identities(creator_detail)
    creator = str(raw_comment.get("creator") or creator_detail.get("email") or creator_detail.get("name") or "")
    if creator:
        creator_values.add(creator.lower())
    return {
        "id": raw_comment.get("id"),
        "count": _int_or_none(raw_comment.get("count")),
        "creator": creator,
        "creator_detail": creator_detail,
        "creation_time": raw_comment.get("creation_time") or raw_comment.get("time"),
        "text": str(raw_comment.get("text") or ""),
        "is_private": bool(raw_comment.get("is_private")),
        "is_creator": bool(creator_values.intersection(creator_identities)),
    }


def _new_comments_in_window(comments: list[dict[str, Any]], start: str | None, end: str | None) -> list[dict[str, Any]]:
    return [
        comment
        for comment in comments
        if in_window(str(comment.get("creation_time") or ""), start, end, include_undated=False)
    ]


def _gentoo_bug_metadata(bug: dict[str, Any]) -> dict[str, Any]:
    return {
        "alias": _string_list(bug.get("alias")),
        "component": bug.get("component"),
        "creator_detail": bug.get("creator_detail") if isinstance(bug.get("creator_detail"), dict) else {},
        "product": bug.get("product"),
        "see_also": _string_list(bug.get("see_also")),
        "severity": bug.get("severity"),
        "status": bug.get("status"),
        "summary": bug.get("summary"),
        "url": bug.get("url"),
        "weburl": bug.get("weburl"),
    }


def _gentoo_references(source_url: str, metadata: dict[str, Any]) -> list[str]:
    references: list[str] = []
    for reference in [source_url, metadata.get("url"), *metadata.get("see_also", [])]:
        if reference and str(reference) not in references:
            references.append(str(reference))
    return references


def _gentoo_content(
    bug_id: str,
    summary: str,
    source_url: str,
    metadata: dict[str, Any],
    description: str,
    new_comments: list[dict[str, Any]],
) -> str:
    lines = [f"Gentoo vulnerability bug {bug_id}: {summary}", source_url]
    if metadata.get("alias"):
        lines.append(f"Aliases: {', '.join(metadata['alias'])}")
    if metadata.get("severity"):
        lines.append(f"Severity: {metadata['severity']}")
    if metadata.get("url"):
        lines.append(f"Severity source: {metadata['url']}")
    if metadata.get("see_also"):
        lines.append(f"See also: {', '.join(metadata['see_also'])}")
    if description:
        lines.extend(["", "Description:", description])
    if new_comments:
        lines.extend(["", "New comments in processing window:"])
        for comment in new_comments[:10]:
            creator = comment.get("creator") or "unknown"
            created = comment.get("creation_time") or "unknown time"
            text = _truncate(str(comment.get("text") or ""), 800)
            lines.append(f"- Comment #{comment.get('count')} by {creator} at {created}: {text}")
    return "\n".join(lines)


def _creator_identities(detail: Any) -> set[str]:
    if not isinstance(detail, dict):
        return {str(detail).lower()} if detail else set()
    identities: set[str] = set()
    for key in ("email", "name", "real_name", "login_name"):
        value = detail.get(key)
        if value:
            identities.add(str(value).lower())
    return identities


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _batches(items: list[str], size: int) -> list[list[str]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3].rstrip() + "..."


def fetch_generic_source_entries(spec: SourceSpec) -> list[SourceEntry]:
    text = fetch_text(spec.url, accept="text/html,application/rss+xml,application/atom+xml,application/xml;q=0.9,*/*;q=0.8")
    stripped = text.lstrip()
    if stripped.startswith("<?xml") or stripped.startswith("<rss") or stripped.startswith("<feed"):
        return parse_feed_entries(spec, text)
    return parse_html_entries(spec, text)


_DOCTYPE_RE = re.compile(r"<!DOCTYPE", re.IGNORECASE)


def _parse_xml_secure(text: str) -> ET.Element:
    """Parse XML while refusing any DTD/DOCTYPE.

    Python's ElementTree is expat-based and expands internal entities, so an
    untrusted feed can define nested entities and trigger exponential
    "billion laughs" memory/CPU blowup. Custom entities can only be declared
    inside a DTD, so rejecting DOCTYPE removes that class of attack (and any
    external-DTD reference) while leaving predefined and numeric character
    references working normally.
    """
    if _DOCTYPE_RE.search(text):
        raise ValueError("Refusing to parse XML containing a DOCTYPE/DTD declaration")
    return ET.fromstring(text)


def parse_feed_entries(spec: SourceSpec, text: str) -> list[SourceEntry]:
    root = _parse_xml_secure(text)
    entries: list[SourceEntry] = []
    for item in root.findall(".//item"):
        title = _xml_text(item, "title")
        link = _xml_text(item, "link") or spec.url
        description = _xml_text(item, "description")
        published = _xml_text(item, "pubDate")
        guid = _xml_text(item, "guid") or link or title
        entries.append(
            SourceEntry(
                source=spec.name,
                source_url=link,
                entry_id=guid,
                title=html.unescape(title),
                content=_strip_tags(description),
                published_at=published,
                updated_at=published,
                references=[link] if link else [],
                raw={"title": title, "link": link, "description": description, "pubDate": published, "guid": guid},
            )
        )
    atom_ns = {"atom": "http://www.w3.org/2005/Atom"}
    for item in root.findall(".//atom:entry", atom_ns):
        title = _xml_text(item, "atom:title", atom_ns)
        link_node = item.find("atom:link", atom_ns)
        link = link_node.attrib.get("href") if link_node is not None else spec.url
        content = _xml_text(item, "atom:content", atom_ns) or _xml_text(item, "atom:summary", atom_ns)
        published = _xml_text(item, "atom:published", atom_ns)
        updated = _xml_text(item, "atom:updated", atom_ns) or published
        entry_id = _xml_text(item, "atom:id", atom_ns) or link or title
        entries.append(
            SourceEntry(
                source=spec.name,
                source_url=link or spec.url,
                entry_id=entry_id,
                title=html.unescape(title),
                content=_strip_tags(content),
                published_at=published,
                updated_at=updated,
                references=[link] if link else [],
                raw={"title": title, "link": link, "content": content, "published": published, "updated": updated, "id": entry_id},
            )
        )
    return entries


def parse_html_entries(spec: SourceSpec, text: str) -> list[SourceEntry]:
    parser = LinkCollectingHTMLParser(spec.url)
    parser.feed(text)
    relevant_links = [link for link in parser.links if _looks_security_related(link[1]) or _looks_security_related(link[0])]
    entries: list[SourceEntry] = []
    for index, (href, label) in enumerate(relevant_links[:100]):
        url = urljoin(spec.url, href)
        entries.append(
            SourceEntry(
                source=spec.name,
                source_url=url,
                entry_id=url,
                title=html.unescape(label or url),
                content=html.unescape(label or url),
                published_at=None,
                updated_at=None,
                references=[url],
                raw={"href": href, "label": label, "index": index},
            )
        )
    if entries:
        return entries
    page_text = _strip_tags(text)
    return [
        SourceEntry(
            source=spec.name,
            source_url=spec.url,
            entry_id=spec.url,
            title=f"{spec.name} source page",
            content=page_text[:4000],
            published_at=None,
            updated_at=None,
            references=[spec.url],
            raw={"url": spec.url, "content_excerpt": page_text[:4000]},
        )
    ]


def filter_entries_by_window(
    entries: list[SourceEntry],
    start: str | None,
    end: str | None,
    include_undated: bool = True,
    prefer_published: bool = True,
) -> list[SourceEntry]:
    return [
        entry
        for entry in entries
        if in_window(_entry_window_timestamp(entry, prefer_published=prefer_published), start, end, include_undated=include_undated)
    ]


def _entry_window_timestamp(entry: SourceEntry, prefer_published: bool = True) -> str | None:
    if prefer_published:
        return entry.published_at or entry.updated_at
    return entry.updated_at or entry.published_at


class LinkCollectingHTMLParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        attrs_dict = dict(attrs)
        href = attrs_dict.get("href")
        if href:
            self._current_href = href
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_href:
            label = " ".join(part.strip() for part in self._current_text if part.strip())
            self.links.append((self._current_href, label))
            self._current_href = None
            self._current_text = []


def _xml_text(node: ET.Element, path: str, namespaces: dict[str, str] | None = None) -> str:
    child = node.find(path, namespaces or {})
    return "" if child is None or child.text is None else child.text.strip()


def _strip_tags(text: str) -> str:
    without_scripts = re.sub(r"<script\b[^>]*>.*?</script>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    without_styles = re.sub(r"<style\b[^>]*>.*?</style>", " ", without_scripts, flags=re.IGNORECASE | re.DOTALL)
    without_tags = re.sub(r"<[^>]+>", " ", without_styles)
    return re.sub(r"\s+", " ", html.unescape(without_tags)).strip()


def _looks_security_related(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in ["cve-", "security", "vulnerab", "glsa", "announce", "advisory"])
