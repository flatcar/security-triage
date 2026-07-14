from security_triage.go_vulndb import fetch_go_vulndb_entries


def test_fetch_go_vulndb_entries_maps_osv_record_and_caches(tmp_path):
    calls: list[str] = []

    index = [
        {
            "id": "GO-2026-0001",
            "modified": "2026-05-01T12:00:00Z",
            "aliases": ["CVE-2026-1111"],
        },
        {
            "id": "GO-2026-0002",
            "modified": "2026-04-01T12:00:00Z",
            "aliases": ["CVE-2026-2222"],
        },
    ]
    record = {
        "schema_version": "1.3.1",
        "id": "GO-2026-0001",
        "modified": "2026-05-01T12:00:00Z",
        "published": "2026-04-30T09:00:00Z",
        "aliases": ["CVE-2026-1111", "GHSA-abcd-1234-efgh"],
        "summary": "Denial of service in example.com/mod",
        "details": "A crafted request can exhaust CPU.",
        "affected": [
            {
                "package": {"name": "example.com/mod", "ecosystem": "Go"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "1.2.3"}],
                    }
                ],
                "ecosystem_specific": {
                    "imports": [
                        {"path": "example.com/mod/server", "symbols": ["Serve"]}
                    ]
                },
            }
        ],
        "references": [{"type": "WEB", "url": "https://example.test/go-advisory"}],
        "database_specific": {
            "url": "https://pkg.go.dev/vuln/GO-2026-0001",
            "review_status": "REVIEWED",
        },
    }

    def fake_fetcher(url: str):
        calls.append(url)
        if url.endswith("/index/vulns.json"):
            return index
        if url.endswith("/ID/GO-2026-0001.json"):
            return record
        raise AssertionError(f"unexpected URL {url}")

    entries = fetch_go_vulndb_entries(
        "2026-05-01T00:00:00Z",
        "2026-05-02T00:00:00Z",
        cache_dir=tmp_path,
        base_url="https://vuln.example.test",
        fetcher=fake_fetcher,
    )
    entries_again = fetch_go_vulndb_entries(
        "2026-05-01T00:00:00Z",
        "2026-05-02T00:00:00Z",
        cache_dir=tmp_path,
        base_url="https://vuln.example.test",
        fetcher=fake_fetcher,
    )

    assert len(entries) == 1
    assert len(entries_again) == 1
    assert calls.count("https://vuln.example.test/ID/GO-2026-0001.json") == 1

    entry = entries[0]
    assert entry.source == "go_vulndb"
    assert entry.entry_id == "GO-2026-0001"
    assert entry.source_url == "https://pkg.go.dev/vuln/GO-2026-0001"
    assert entry.published_at == "2026-04-30T09:00:00Z"
    assert entry.updated_at == "2026-05-01T12:00:00Z"
    assert "Package: example.com/mod" in entry.content
    assert "Fixed versions: 1.2.3" in entry.content
    assert "Affected import paths: example.com/mod/server" in entry.content
    assert "CVE-2026-1111" in entry.references
    assert "GHSA-abcd-1234-efgh" in entry.references
    assert "example.com/mod" in entry.references
    assert "https://example.test/go-advisory" in entry.references
    assert entry.metadata["affected_packages"] == ["example.com/mod"]
    assert entry.metadata["fixed_versions"] == ["1.2.3"]
    assert entry.comments == []
    assert entry.new_comments == []


def test_fetch_go_vulndb_entries_uses_modified_window():
    def fake_fetcher(url: str):
        if url.endswith("/index/vulns.json"):
            return [
                {
                    "id": "GO-2026-0001",
                    "modified": "2026-04-01T12:00:00Z",
                    "aliases": [],
                }
            ]
        raise AssertionError("out-of-window advisory detail should not be fetched")

    entries = fetch_go_vulndb_entries(
        "2026-05-01T00:00:00Z",
        "2026-05-02T00:00:00Z",
        base_url="https://vuln.example.test",
        fetcher=fake_fetcher,
    )

    assert entries == []
