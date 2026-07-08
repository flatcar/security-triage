import time

import pytest

from security_triage.sources import SourceSpec, parse_feed_entries

BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY a "aaaaaaaaaaaaaaaaaaaa">
 <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
 <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
 <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
 <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
 <!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">
 <!ENTITY g "&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;">
]>
<rss><channel><item><title>&g;</title></item></channel></rss>"""


def test_feed_parser_rejects_doctype_entity_expansion():
    spec = SourceSpec("evil", "https://evil.example/feed")
    start = time.monotonic()
    with pytest.raises(ValueError, match="DOCTYPE"):
        parse_feed_entries(spec, BILLION_LAUGHS)
    # Must fail fast without materializing the expanded entity.
    assert time.monotonic() - start < 1.0


def test_feed_parser_still_handles_normal_feed():
    rss = """<?xml version="1.0"?>
    <rss><channel><item>
      <title>openssl CVE-2026-1</title>
      <link>https://example.test/advisory</link>
      <description>Package: openssl</description>
    </item></channel></rss>"""
    entries = parse_feed_entries(
        SourceSpec("generic", "https://example.test/feed"), rss
    )
    assert len(entries) == 1
    assert entries[0].title == "openssl CVE-2026-1"
