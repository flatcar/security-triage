import json

from urllib.parse import parse_qs, urlparse

from security_triage.rustsec import fetch_rustsec_entries


RUSTSEC_MARKDOWN = """```toml
[advisory]
id = "RUSTSEC-2026-0118"
package = "hickory-proto"
date = "2026-05-01"
url = "https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-3v94-mw7p-v465"
references = ["https://github.com/hickory-dns/hickory-dns/pull/3000"]
aliases = ["CVE-2026-5555", "GHSA-3v94-mw7p-v465"]
related = ["RUSTSEC-2026-0120"]
categories = ["denial-of-service"]
keywords = ["dns", "dnssec"]
license = "CC-BY-4.0"

[versions]
patched = []
unaffected = ["< 0.25.0-alpha.3", ">= 0.26.0-beta.1"]
```

# NSEC3 closest-encloser proof validation enters unbounded loop

The validator can allocate until the process exhausts memory.
"""


def test_fetch_rustsec_entries_maps_markdown_and_caches(tmp_path):
    json_calls: list[str] = []
    text_calls: list[str] = []

    def fake_json_fetcher(url: str):
        json_calls.append(url)
        parsed = urlparse(url)
        if parsed.path.endswith("/commits"):
            query = parse_qs(parsed.query)
            if query["path"] == ["crates"]:
                return [
                    {
                        "sha": "abc123",
                        "url": "https://api.example.test/repos/RustSec/advisory-db/commits/abc123",
                        "commit": {"committer": {"date": "2026-05-01T13:00:00Z"}},
                    }
                ]
            return []
        if parsed.path.endswith("/commits/abc123"):
            return {
                "sha": "abc123",
                "commit": {"committer": {"date": "2026-05-01T13:00:00Z"}},
                "files": [
                    {
                        "filename": "crates/hickory-proto/RUSTSEC-2026-0118.md",
                        "status": "modified",
                        "raw_url": "https://raw.example.test/RUSTSEC-2026-0118.md",
                    },
                    {"filename": "README.md", "status": "modified"},
                ],
            }
        raise AssertionError(f"unexpected JSON URL {url}")

    def fake_text_fetcher(url: str) -> str:
        text_calls.append(url)
        assert url == "https://raw.example.test/RUSTSEC-2026-0118.md"
        return RUSTSEC_MARKDOWN

    entries = fetch_rustsec_entries(
        "2026-05-01T00:00:00Z",
        "2026-05-02T00:00:00Z",
        cache_dir=tmp_path,
        api_url="https://api.example.test/repos/RustSec/advisory-db",
        json_fetcher=fake_json_fetcher,
        text_fetcher=fake_text_fetcher,
    )
    entries_again = fetch_rustsec_entries(
        "2026-05-01T00:00:00Z",
        "2026-05-02T00:00:00Z",
        cache_dir=tmp_path,
        api_url="https://api.example.test/repos/RustSec/advisory-db",
        json_fetcher=fake_json_fetcher,
        text_fetcher=fake_text_fetcher,
    )

    assert len(entries) == 1
    assert len(entries_again) == 1
    assert text_calls.count("https://raw.example.test/RUSTSEC-2026-0118.md") == 1
    assert any("path=crates" in url for url in json_calls)
    assert any("path=rust" in url for url in json_calls)

    entry = entries[0]
    assert entry.source == "rustsec"
    assert entry.entry_id == "RUSTSEC-2026-0118"
    assert entry.source_url == "https://rustsec.org/advisories/RUSTSEC-2026-0118.html"
    assert entry.published_at == "2026-05-01"
    assert entry.updated_at == "2026-05-01T13:00:00Z"
    assert entry.title == "NSEC3 closest-encloser proof validation enters unbounded loop"
    assert "Package: hickory-proto" in entry.content
    assert "Unaffected versions: < 0.25.0-alpha.3, >= 0.26.0-beta.1" in entry.content
    assert "CVE-2026-5555" in entry.references
    assert "GHSA-3v94-mw7p-v465" in entry.references
    assert "hickory-proto" in entry.references
    assert "https://github.com/hickory-dns/hickory-dns/pull/3000" in entry.references
    assert entry.metadata["package"] == "hickory-proto"
    assert entry.metadata["commit_sha"] == "abc123"
    json.dumps({"metadata": entry.metadata, "raw": entry.raw})
    assert entry.comments == []
    assert entry.new_comments == []


def test_fetch_rustsec_entries_skips_removed_and_out_of_window_files():
    def fake_json_fetcher(url: str):
        parsed = urlparse(url)
        if parsed.path.endswith("/commits"):
            query = parse_qs(parsed.query)
            if query["path"] == ["crates"]:
                return [
                    {
                        "sha": "oldsha",
                        "url": "https://api.example.test/repos/RustSec/advisory-db/commits/oldsha",
                        "commit": {"committer": {"date": "2026-04-01T13:00:00Z"}},
                    }
                ]
            return []
        if parsed.path.endswith("/commits/oldsha"):
            return {
                "sha": "oldsha",
                "commit": {"committer": {"date": "2026-04-01T13:00:00Z"}},
                "files": [
                    {"filename": "crates/example/RUSTSEC-2026-0001.md", "status": "modified"},
                    {"filename": "crates/example/RUSTSEC-2026-0002.md", "status": "removed"},
                ],
            }
        raise AssertionError(f"unexpected JSON URL {url}")

    def fake_text_fetcher(url: str) -> str:
        raise AssertionError("out-of-window or removed advisory should not be fetched")

    entries = fetch_rustsec_entries(
        "2026-05-01T00:00:00Z",
        "2026-05-02T00:00:00Z",
        api_url="https://api.example.test/repos/RustSec/advisory-db",
        json_fetcher=fake_json_fetcher,
        text_fetcher=fake_text_fetcher,
    )

    assert entries == []