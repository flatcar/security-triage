"""Threaded fetcher for the oss-security mailing list (openwall.com/lists)."""

from __future__ import annotations

import email
import html
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from .console import NullProgressLogger, ProgressLogger
from .http_utils import HTTPError, fetch_text
from .records import SourceEntry
from .rules import extract_cves
from .time_utils import in_window, parse_datetime

OSS_SECURITY_BASE_URL = "https://www.openwall.com/lists/oss-security/"

_MSG_INDEX_RE = re.compile(r'href="(\d+)"')
_PRE_RE = re.compile(
    r"<pre[^>]*white-space:\s*pre-wrap[^>]*>(.*?)</pre>",
    re.DOTALL | re.IGNORECASE,
)
_THREAD_NAV_RE = re.compile(
    r'<a\s+href="([^"]+)">\[(?:&lt;|<)?(thread-prev|thread-next)(?:&gt;|>)?\]</a>',
    re.IGNORECASE,
)

Fetcher = Callable[[str], str]


@dataclass(slots=True)
class _Message:
    url: str
    message_id: str
    subject: str
    sender: str
    date_iso: str | None
    body: str
    in_reply_to: str | None
    references: list[str]
    thread_prev_url: str | None
    thread_next_url: str | None


@dataclass(slots=True)
class _Thread:
    root: _Message
    replies: list[_Message] = field(default_factory=list)


def fetch_oss_security_entries(
    start: str | None,
    end: str | None,
    *,
    cache_dir: str | Path | None = None,
    max_messages: int = 500,
    base_url: str = OSS_SECURITY_BASE_URL,
    fetcher: Fetcher | None = None,
    progress_logger: ProgressLogger | None = None,
) -> list[SourceEntry]:
    """Return one SourceEntry per oss-security thread touched in [start, end]."""
    progress = progress_logger or NullProgressLogger()
    http = _build_fetcher(cache_dir, fetcher)

    days = list(_iter_days(start, end))
    if not days:
        return []

    in_window_urls: list[str] = []
    for day in days:
        day_url = f"{base_url.rstrip('/')}/{day:%Y/%m/%d}/"
        try:
            page = http(day_url)
        except HTTPError:
            continue
        indices = sorted({int(match) for match in _MSG_INDEX_RE.findall(page)})
        for index in indices:
            in_window_urls.append(f"{day_url}{index}")
        progress.info(f"oss-security {day.isoformat()}: {len(indices)} message(s)")

    if max_messages and len(in_window_urls) > max_messages:
        progress.info(
            f"oss-security: capping at {max_messages} of {len(in_window_urls)} message(s) for safety"
        )
        in_window_urls = in_window_urls[-max_messages:]

    cache: dict[str, _Message] = {}
    threads: dict[str, _Thread] = {}
    for url in in_window_urls:
        try:
            root = _resolve_root(url, http, cache)
        except _MessageFetchError as exc:
            progress.info(f"oss-security: skipping {url} ({exc})")
            continue
        if root.url in threads:
            continue
        try:
            thread = _walk_thread(root, http, cache)
        except _MessageFetchError as exc:
            progress.info(f"oss-security: thread walk failed for {root.url} ({exc})")
            continue
        threads[root.url] = thread

    entries: list[SourceEntry] = []
    for thread in threads.values():
        entry = _thread_to_entry(thread, start, end)
        if entry is not None:
            entries.append(entry)
    progress.info(f"oss-security: assembled {len(entries)} thread(s)")
    return entries


# --- internals ---------------------------------------------------------------


class _MessageFetchError(RuntimeError):
    pass


def _build_fetcher(cache_dir: str | Path | None, fetcher: Fetcher | None) -> Fetcher:
    if fetcher is not None:
        base = fetcher
    else:

        def base(url: str) -> str:
            return fetch_text(url, accept="text/html,*/*;q=0.8", timeout=30)

    if cache_dir is None:
        return base
    cache_root = Path(cache_dir)

    def cached(url: str) -> str:
        path = _cache_path(cache_root, url)
        if path.is_file():
            try:
                return path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        text = base(url)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        except OSError:
            pass
        return text

    return cached


# Cache file names are derived from URLs found in fetched (untrusted) HTML, so
# every path segment must stay strictly inside the cache root: no separators,
# no drive letters (Path("cache") / "C:/x" would REPLACE the root on Windows),
# and no "." / ".." components.
_CACHE_SEGMENT_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _cache_path(root: Path, url: str) -> Path:
    parsed = urlparse(url)
    segments = []
    for raw in parsed.path.split("/"):
        segment = _CACHE_SEGMENT_UNSAFE_RE.sub("_", raw).strip(".")
        if segment:
            segments.append(segment)
    if not segments:
        segments.append("index.html")
    elif "." not in segments[-1]:
        segments[-1] += ".html"
    return root.joinpath(*segments)


def _iter_days(start: str | None, end: str | None) -> list[date]:
    end_dt = parse_datetime(end) or datetime.now(UTC)
    start_dt = parse_datetime(start) or (end_dt - timedelta(days=7))
    if start_dt > end_dt:
        return []
    days: list[date] = []
    current = start_dt.date()
    final = end_dt.date()
    while current <= final:
        days.append(current)
        current = current + timedelta(days=1)
    return days


def _fetch_message(url: str, http: Fetcher, cache: dict[str, _Message]) -> _Message:
    if url in cache:
        return cache[url]
    try:
        page = http(url)
    except HTTPError as exc:
        raise _MessageFetchError(str(exc)) from exc
    message = _parse_message_page(url, page)
    cache[url] = message
    return message


def _resolve_root(url: str, http: Fetcher, cache: dict[str, _Message]) -> _Message:
    visited: set[str] = set()
    current = _fetch_message(url, http, cache)
    while current.thread_prev_url and current.url not in visited:
        visited.add(current.url)
        current = _fetch_message(current.thread_prev_url, http, cache)
    return current


def _walk_thread(root: _Message, http: Fetcher, cache: dict[str, _Message]) -> _Thread:
    replies: list[_Message] = []
    visited: set[str] = {root.url}
    current = root
    while current.thread_next_url:
        next_url = current.thread_next_url
        if next_url in visited:
            break
        visited.add(next_url)
        current = _fetch_message(next_url, http, cache)
        replies.append(current)
    return _Thread(root=root, replies=replies)


def _parse_message_page(url: str, page: str) -> _Message:
    pre_match = _PRE_RE.search(page)
    if not pre_match:
        raise _MessageFetchError(f"no message body found at {url}")
    raw_pre = html.unescape(_strip_inner_tags(pre_match.group(1))).lstrip("\n")

    headers_part, _, body_part = raw_pre.partition("\n\n")
    parsed = email.message_from_string(headers_part)
    message_id = (parsed.get("Message-ID") or "").strip().strip("<>") or url
    subject = _normalize_header(parsed.get("Subject") or "")
    sender = _normalize_header(parsed.get("From") or "")
    date_raw = parsed.get("Date")
    date_dt = parse_datetime(date_raw) if date_raw else None
    date_iso = date_dt.isoformat() if date_dt else None
    in_reply_to = (parsed.get("In-Reply-To") or "").strip().strip("<>") or None
    refs_field = parsed.get("References") or ""
    references = [ref.strip("<>") for ref in refs_field.split() if ref.strip()]

    thread_prev_url, thread_next_url = _extract_thread_nav(url, page)

    return _Message(
        url=url,
        message_id=message_id,
        subject=subject,
        sender=sender,
        date_iso=date_iso,
        body=body_part.strip("\n"),
        in_reply_to=in_reply_to,
        references=references,
        thread_prev_url=thread_prev_url,
        thread_next_url=thread_next_url,
    )


def _extract_thread_nav(url: str, page: str) -> tuple[str | None, str | None]:
    prev_url: str | None = None
    next_url: str | None = None
    for href, label in _THREAD_NAV_RE.findall(page):
        target = urljoin(url, href)
        if label.lower() == "thread-prev":
            prev_url = target
        elif label.lower() == "thread-next":
            next_url = target
    return prev_url, next_url


def _normalize_header(value: str) -> str:
    return " ".join(value.split())


class _TagStripper(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def handle_entityref(self, name: str) -> None:
        self.parts.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        self.parts.append(f"&#{name};")


def _strip_inner_tags(html_fragment: str) -> str:
    stripper = _TagStripper()
    stripper.feed(html_fragment)
    stripper.close()
    return "".join(stripper.parts)


def _thread_to_entry(
    thread: _Thread, start: str | None, end: str | None
) -> SourceEntry | None:
    root = thread.root
    all_messages = [root, *thread.replies]
    dates = [parse_datetime(msg.date_iso) for msg in all_messages]
    valid_dates = [dt for dt in dates if dt is not None]
    updated_iso = max(valid_dates).isoformat() if valid_dates else root.date_iso

    comments = [
        _message_to_comment(msg, index)
        for index, msg in enumerate(thread.replies, start=1)
    ]
    new_comments = [
        comment
        for comment in comments
        if in_window(
            str(comment.get("creation_time") or ""), start, end, include_undated=False
        )
    ]
    root_in_window = in_window(root.date_iso or "", start, end, include_undated=False)
    if not root_in_window and not new_comments:
        return None

    cve_ids = extract_cves(
        " ".join(msg.subject for msg in all_messages) + "\n" + root.body
    )
    references = [root.url, *cve_ids]

    return SourceEntry(
        source="oss_security",
        source_url=root.url,
        entry_id=root.message_id,
        title=root.subject or "(no subject)",
        content=_render_thread_content(root, new_comments),
        published_at=root.date_iso,
        updated_at=updated_iso,
        references=references,
        description=root.body,
        comments=comments,
        new_comments=new_comments,
        metadata={
            "message_id": root.message_id,
            "from": root.sender,
            "thread_size": len(all_messages),
            "cve_ids": cve_ids,
        },
        raw={
            "root": _message_to_dict(root),
            "messages": [_message_to_dict(msg) for msg in all_messages],
        },
    )


def _message_to_comment(msg: _Message, index: int) -> dict[str, Any]:
    return {
        "id": msg.message_id,
        "count": index,
        "creator": msg.sender,
        "creation_time": msg.date_iso,
        "text": msg.body,
        "url": msg.url,
        "subject": msg.subject,
    }


def _message_to_dict(msg: _Message) -> dict[str, Any]:
    return {
        "url": msg.url,
        "message_id": msg.message_id,
        "subject": msg.subject,
        "from": msg.sender,
        "date": msg.date_iso,
        "in_reply_to": msg.in_reply_to,
        "references": list(msg.references),
        "body": msg.body,
    }


def _render_thread_content(root: _Message, new_comments: list[dict[str, Any]]) -> str:
    lines = [
        f"oss-security thread: {root.subject}",
        root.url,
        f"From: {root.sender}",
        f"Date: {root.date_iso or 'unknown'}",
        "",
        "Root message:",
        _truncate(root.body, 2000),
    ]
    if new_comments:
        lines.extend(["", "New replies in processing window:"])
        for comment in new_comments[:10]:
            creator = comment.get("creator") or "unknown"
            created = comment.get("creation_time") or "unknown time"
            text = _truncate(str(comment.get("text") or ""), 600)
            lines.append(
                f"- Reply #{comment.get('count')} by {creator} at {created}: {text}"
            )
    return "\n".join(lines)


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3].rstrip() + "..."
