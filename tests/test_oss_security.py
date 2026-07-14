from __future__ import annotations

from security_triage.http_utils import HTTPError
from security_triage.oss_security import fetch_oss_security_entries

BASE = "https://www.openwall.com/lists/oss-security/"

DAY_INDEX_HTML = """
<html><body>
<a href="1">Subject A</a>
<a href="2">Re: Subject A</a>
<a href="3">Other</a>
</body></html>
"""

ROOT_PAGE = """
<html><body>
<pre style="white-space: pre-wrap">
Message-ID: &lt;root@example.com&gt;
Date: Mon, 4 May 2026 10:00:00 +0000
From: Alice &lt;alice@...ample.com&gt;
To: oss-security@...ts.openwall.com
Subject: CVE-2026-12345: example issue

Root body text mentioning CVE-2026-12345.
Second paragraph.
</pre>
<a href="../03/9">[&lt;prev]</a> <a href="2">[next&gt;]</a> <a href="2">[thread-next&gt;]</a> <a href=".">[day]</a>
</body></html>
"""

REPLY_PAGE = """
<html><body>
<pre style="white-space: pre-wrap">
Message-ID: &lt;reply@example.com&gt;
Date: Mon, 4 May 2026 12:00:00 +0000
From: Bob &lt;bob@...ample.com&gt;
To: oss-security@...ts.openwall.com
Subject: Re: CVE-2026-12345: example issue
In-Reply-To: &lt;root@example.com&gt;
References: &lt;root@example.com&gt;

Reply body discussing the fix.
</pre>
<a href="1">[&lt;prev]</a> <a href="3">[next&gt;]</a> <a href="1">[&lt;thread-prev]</a> <a href=".">[day]</a>
</body></html>
"""

OTHER_PAGE = """
<html><body>
<pre style="white-space: pre-wrap">
Message-ID: &lt;other@example.com&gt;
Date: Mon, 4 May 2026 13:00:00 +0000
From: Carol &lt;carol@...ample.com&gt;
Subject: Unrelated topic

Unrelated body.
</pre>
<a href="2">[&lt;prev]</a> <a href=".">[day]</a>
</body></html>
"""

PAGES = {
    f"{BASE}2026/05/04/": DAY_INDEX_HTML,
    f"{BASE}2026/05/04/1": ROOT_PAGE,
    f"{BASE}2026/05/04/2": REPLY_PAGE,
    f"{BASE}2026/05/04/3": OTHER_PAGE,
}


def _make_fetcher(pages: dict[str, str]):
    calls: list[str] = []

    def fetcher(url: str) -> str:
        calls.append(url)
        if url not in pages:
            raise HTTPError(f"404 {url}")
        return pages[url]

    return fetcher, calls


def test_fetch_oss_security_groups_replies_into_thread():
    fetcher, calls = _make_fetcher(PAGES)
    entries = fetch_oss_security_entries(
        "2026-05-04T00:00:00Z",
        "2026-05-04T23:59:59Z",
        fetcher=fetcher,
    )
    # Two threads: root+reply, and the unrelated message.
    assert len(entries) == 2
    by_id = {entry.entry_id: entry for entry in entries}
    thread = by_id["root@example.com"]
    assert thread.title.startswith("CVE-2026-12345")
    assert thread.source == "oss_security"
    assert thread.published_at and thread.published_at.startswith("2026-05-04T10:00")
    assert thread.updated_at and thread.updated_at.startswith("2026-05-04T12:00")
    assert len(thread.comments) == 1
    assert thread.comments[0]["id"] == "reply@example.com"
    assert len(thread.new_comments) == 1
    assert "CVE-2026-12345" in thread.references
    # Day index + 3 message pages = 4 fetches; thread walk should reuse cache.
    assert calls.count(f"{BASE}2026/05/04/1") == 1
    assert calls.count(f"{BASE}2026/05/04/2") == 1


def test_fetch_oss_security_walks_to_root_from_reply():
    # Day index only contains the reply; fetcher must walk thread-prev to find the root.
    pages = dict(PAGES)
    pages[f"{BASE}2026/05/04/"] = '<a href="2">Re: Subject A</a>'
    fetcher, _calls = _make_fetcher(pages)
    entries = fetch_oss_security_entries(
        "2026-05-04T00:00:00Z",
        "2026-05-04T23:59:59Z",
        fetcher=fetcher,
    )
    assert len(entries) == 1
    assert entries[0].entry_id == "root@example.com"
    assert entries[0].comments[0]["id"] == "reply@example.com"


def test_fetch_oss_security_skips_threads_with_no_in_window_messages():
    fetcher, _calls = _make_fetcher(PAGES)
    entries = fetch_oss_security_entries(
        "2030-01-01T00:00:00Z",
        "2030-01-02T00:00:00Z",
        fetcher=fetcher,
    )
    assert entries == []


def test_cache_path_stays_inside_cache_root():
    from pathlib import Path

    from security_triage.oss_security import _cache_path

    root = Path("cache-root")
    hostile_urls = [
        "https://lists.example/../../etc/passwd",
        "https://lists.example/..%2f..%2fetc/passwd",
        "https://lists.example/a/../../../b",
        "https://lists.example/C:/Windows/System32/evil",  # drive letter must not replace the root
        r"https://lists.example/a\..\..\b",
        "https://lists.example//absolute//path",
        "https://lists.example/...",
    ]
    for url in hostile_urls:
        path = _cache_path(root, url)
        assert not path.is_absolute(), url
        assert root in path.parents, url
        assert ".." not in path.parts, url
        assert not any(
            ":" in part or "/" in part or "\\" in part for part in path.parts[1:]
        ), url


def test_cache_path_keeps_normal_names_readable():
    from pathlib import Path

    from security_triage.oss_security import _cache_path

    root = Path("cache-root")
    assert (
        _cache_path(root, "https://www.openwall.com/lists/oss-security/2026/05/04/1")
        == root / "lists" / "oss-security" / "2026" / "05" / "04" / "1.html"
    )
    assert (
        _cache_path(root, "https://www.openwall.com/lists/oss-security/2026/05/04/")
        == root / "lists" / "oss-security" / "2026" / "05" / "04.html"
    )
    assert _cache_path(root, "https://www.openwall.com/") == root / "index.html"
    assert _cache_path(root, "https://www.openwall.com/page.html") == root / "page.html"
