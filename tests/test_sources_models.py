import json
from urllib.parse import parse_qs, urlparse

import pytest

from security_triage.models import (
    DEFAULT_ENDPOINT,
    DEFAULT_FOUNDRY_API_VERSION,
    DEFAULT_FOUNDRY_DEPLOYMENT,
    DEFAULT_MODEL,
    BaseModelClient,
    FoundryModelsClient,
    GitHubModelsClient,
    HeuristicModelClient,
    ModelConfigError,
    RoutingModelClient,
)
from security_triage.records import Issue
from security_triage.rules import (
    coerce_cleanup_review,
    coerce_discovery_decision,
    coerce_relevance,
)
from security_triage.sources import (
    SourceSpec,
    fetch_gentoo_entries,
    filter_entries_by_window,
    parse_feed_entries,
    parse_html_entries,
    source_entry_from_mapping,
)
from security_triage.time_utils import in_window, parse_datetime


def test_parse_rss_feed_source_entry():
    rss = """<?xml version="1.0"?>
    <rss><channel><item>
      <title>OpenSSL CVE-2026-1</title>
      <link>https://example.test/advisory</link>
      <description>Package: openssl CVE-2026-1</description>
      <pubDate>Wed, 29 Apr 2026 00:00:00 GMT</pubDate>
      <guid>advisory-1</guid>
    </item></channel></rss>
    """
    entries = parse_feed_entries(
        SourceSpec("oss_security", "https://example.test/feed"), rss
    )
    assert len(entries) == 1
    assert entries[0].entry_id == "advisory-1"
    assert entries[0].source_url == "https://example.test/advisory"
    assert "openssl" in entries[0].content
    assert in_window(
        entries[0].published_at, "2026-04-29T00:00:00Z", "2026-04-30T00:00:00Z"
    )


def test_parse_html_source_links_security_entries():
    html = """<html><body>
      <a href="/safe">general post</a>
      <a href="/cve">CVE-2026-2 package advisory</a>
    </body></html>"""
    entries = parse_html_entries(
        SourceSpec("oss_security", "https://example.test/archive"), html
    )
    assert len(entries) == 1
    assert entries[0].source_url == "https://example.test/cve"


def test_discovery_window_prefers_published_time_over_recent_update():
    old_created_recently_changed = source_entry_from_mapping(
        {
            "source": "gentoo",
            "entry_id": "old-bug",
            "title": "old bug with recent metadata change",
            "published_at": "2026-04-01T00:00:00Z",
            "updated_at": "2026-04-29T00:00:00Z",
        }
    )
    fresh_created = source_entry_from_mapping(
        {
            "source": "gentoo",
            "entry_id": "fresh-bug",
            "title": "fresh bug",
            "published_at": "2026-04-28T00:00:00Z",
            "updated_at": "2026-04-29T00:00:00Z",
        }
    )

    filtered = filter_entries_by_window(
        [old_created_recently_changed, fresh_created],
        "2026-04-23T00:00:00Z",
        "2026-04-30T00:00:00Z",
        prefer_published=True,
    )

    assert [entry.entry_id for entry in filtered] == ["fresh-bug"]


def test_window_filter_can_exclude_undated_live_entries():
    undated = source_entry_from_mapping(
        {"source": "oss_security", "entry_id": "undated", "title": "undated"}
    )
    assert filter_entries_by_window(
        [undated], "2026-04-23T00:00:00Z", "2026-04-30T00:00:00Z"
    ) == [undated]
    assert (
        filter_entries_by_window(
            [undated],
            "2026-04-23T00:00:00Z",
            "2026-04-30T00:00:00Z",
            include_undated=False,
        )
        == []
    )


def test_gentoo_bugzilla_fetch_uses_window_and_enriches_comments(monkeypatch):
    requested_urls = []

    def fake_fetch_json(url, accept="application/json"):
        requested_urls.append(url)
        if "/comment" in url:
            return {
                "bugs": {
                    "973999": {
                        "comments": [
                            {
                                "count": 1,
                                "creator": "security@gentoo.org",
                                "creation_time": "2026-04-29T10:00:00Z",
                                "text": "Added CVE alias and upstream severity reference.",
                            },
                            {
                                "count": 0,
                                "creator": "security@gentoo.org",
                                "creation_time": "2026-04-24T10:00:00Z",
                                "text": "Initial Bugzilla description with affected package context.",
                            },
                        ]
                    }
                }
            }
        return {
            "bugs": [
                {
                    "id": 973999,
                    "alias": ["CVE-2026-39999"],
                    "component": "Vulnerabilities",
                    "creation_time": "2026-04-24T10:00:00Z",
                    "creator_detail": {
                        "email": "security@gentoo.org",
                        "name": "security@gentoo.org",
                    },
                    "last_change_time": "2026-04-29T10:00:00Z",
                    "product": "Gentoo Security",
                    "see_also": ["https://openssl.example/advisory"],
                    "severity": "normal",
                    "status": "CONFIRMED",
                    "summary": "dev-libs/openssl: certificate validation vulnerability",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-39999",
                    "weburl": "https://bugs.gentoo.org/973999",
                }
            ]
        }

    monkeypatch.setattr("security_triage.sources.fetch_json", fake_fetch_json)

    entries = fetch_gentoo_entries("2026-04-23T00:00:00Z", "2026-04-30T00:00:00Z")

    query = parse_qs(urlparse(requested_urls[0]).query)
    include_fields = set(query["include_fields"][0].split(","))
    assert query["chfieldfrom"] == ["2026-04-23T00:00:00Z"]
    assert query["chfieldto"] == ["2026-04-30T00:00:00Z"]
    assert {
        "alias",
        "creator_detail",
        "see_also",
        "severity",
        "summary",
        "url",
    }.issubset(include_fields)
    assert parse_qs(urlparse(requested_urls[1]).query)["ids"] == ["973999"]

    entry = entries[0]
    assert entry.metadata["alias"] == ["CVE-2026-39999"]
    assert (
        entry.description
        == "Initial Bugzilla description with affected package context."
    )
    assert entry.comments[0]["is_creator"] is True
    assert entry.new_comments[0]["count"] == 1
    assert "Aliases: CVE-2026-39999" in entry.content
    assert (
        "Severity source: https://nvd.nist.gov/vuln/detail/CVE-2026-39999"
        in entry.content
    )


def test_parse_datetime_supports_rfc_2822_feed_dates():
    parsed = parse_datetime("Wed, 29 Apr 2026 00:00:00 GMT")
    assert parsed is not None
    assert parsed.isoformat() == "2026-04-29T00:00:00+00:00"


def test_heuristic_model_normalizes_malformed_issue_from_title():
    issue = Issue(
        number=99,
        title="update: openssl",
        body="CVEs: CVE-2026-99\nAction Needed: update to >= 3.2.4",
        labels=["advisory", "security"],
        html_url="https://github.com/flatcar/Flatcar/issues/99",
    )
    normalized = HeuristicModelClient().normalize_issue(issue)
    assert normalized["name"] == "openssl"
    assert normalized["valid"] is False
    assert "Name" in normalized["missing_fields"]


def test_model_schema_coercion_falls_back_to_manual_review():
    assert (
        coerce_relevance({"status": "definitely", "scope": "planet"})["status"]
        == "needs_manual_review"
    )
    assert (
        coerce_discovery_decision({"action": "delete_issue"})["action"]
        == "needs_manual_review"
    )
    assert (
        coerce_cleanup_review({"decision": "close_it"})["decision"]
        == "needs_manual_review"
    )


def test_routing_model_uses_primary_client_for_cleanup_review():
    class ReviewClient(BaseModelClient):
        def __init__(self, name):
            self.provider = name
            self.model = name
            self.endpoint = name
            self.calls = 0

        def review_cleanup(self, evidence_bundle):
            self.calls += 1
            return {
                "decision": "needs_manual_review",
                "confidence": "low",
                "reasons": [self.model],
            }

    primary = ReviewClient("primary")
    cheaper = ReviewClient("cheaper")
    client = RoutingModelClient(primary=primary, extraction=cheaper)

    client.review_cleanup({"preliminary_status": "needs_manual_review"})
    client.review_cleanup(
        {"preliminary_status": "remediated_in_current_production_sbom"}
    )

    assert cheaper.calls == 0
    assert primary.calls == 2


def test_github_models_request_matches_github_api(monkeypatch):
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self):
            return json.dumps(
                {"choices": [{"message": {"content": '{"ok": true}'}}]}
            ).encode("utf-8")

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["headers"] = {
            key.lower(): value for key, value in request.header_items()
        }
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("security_triage.models.urllib.request.urlopen", fake_urlopen)

    client = GitHubModelsClient(token="test-token")
    result = client._complete_json("unit_test", "system prompt", {"hello": "world"})

    assert result == {"ok": True}
    assert captured["url"] == DEFAULT_ENDPOINT
    assert captured["method"] == "POST"
    assert captured["headers"]["accept"] == "application/vnd.github+json"
    assert captured["headers"]["authorization"] == "Bearer test-token"
    assert captured["headers"]["x-github-api-version"] == "2022-11-28"
    assert captured["headers"]["content-type"] == "application/json"
    assert captured["payload"]["model"] == DEFAULT_MODEL == "openai/gpt-5"
    assert captured["payload"]["messages"] == [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": '{"hello": "world"}'},
    ]
    assert "reasoning_effort" not in captured["payload"]


def test_foundry_models_request_matches_azure_openai_api(monkeypatch):
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self):
            return json.dumps(
                {"choices": [{"message": {"content": '{"ok": true}'}}]}
            ).encode("utf-8")

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["headers"] = {
            key.lower(): value for key, value in request.header_items()
        }
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("security_triage.models.urllib.request.urlopen", fake_urlopen)

    client = FoundryModelsClient(
        bearer_token="test-token",
        endpoint="https://example-foundry.cognitiveservices.azure.com",
    )
    result = client._complete_json("unit_test", "system prompt", {"hello": "world"})

    assert result == {"ok": True}
    parsed_url = urlparse(captured["url"])
    assert (
        f"{parsed_url.scheme}://{parsed_url.netloc}"
        == "https://example-foundry.cognitiveservices.azure.com"
    )
    assert (
        parsed_url.path
        == f"/openai/deployments/{DEFAULT_FOUNDRY_DEPLOYMENT}/chat/completions"
    )
    assert parse_qs(parsed_url.query) == {"api-version": [DEFAULT_FOUNDRY_API_VERSION]}
    assert captured["method"] == "POST"
    assert captured["headers"]["accept"] == "application/json"
    assert captured["headers"]["authorization"] == "Bearer test-token"
    assert captured["headers"]["content-type"] == "application/json"
    assert captured["payload"]["messages"] == [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": '{"hello": "world"}'},
    ]
    assert captured["payload"]["response_format"] == {"type": "json_object"}
    assert "model" not in captured["payload"]
    assert "temperature" not in captured["payload"]


def test_foundry_models_request_supports_project_openai_v1_endpoint(monkeypatch):
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self):
            return json.dumps(
                {"choices": [{"message": {"content": '{"ok": true}'}}]}
            ).encode("utf-8")

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["headers"] = {
            key.lower(): value for key, value in request.header_items()
        }
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("security_triage.models.urllib.request.urlopen", fake_urlopen)

    client = FoundryModelsClient(
        bearer_token="test-token",
        endpoint="https://example-foundry.services.ai.azure.com/api/projects/example-project",
        deployment="gpt-5.4-mini",
        api_version="2026-03-17",
    )
    result = client._complete_json("unit_test", "system prompt", {"hello": "world"})

    assert result == {"ok": True}
    parsed_url = urlparse(captured["url"])
    assert (
        f"{parsed_url.scheme}://{parsed_url.netloc}"
        == "https://example-foundry.services.ai.azure.com"
    )
    assert parsed_url.path == "/api/projects/example-project/openai/v1/chat/completions"
    assert parsed_url.query == ""
    assert client.metadata()["endpoint_family"] == "openai_v1"
    assert client.metadata()["api_version"] == "v1"
    assert captured["method"] == "POST"
    assert captured["headers"]["authorization"] == "Bearer test-token"
    assert captured["payload"]["model"] == "gpt-5.4-mini"
    assert captured["payload"]["messages"] == [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": '{"hello": "world"}'},
    ]
    assert captured["payload"]["response_format"] == {"type": "json_object"}


def test_foundry_models_requires_endpoint(monkeypatch):
    monkeypatch.delenv("FOUNDRY_ENDPOINT", raising=False)

    with pytest.raises(ModelConfigError, match="FOUNDRY_ENDPOINT"):
        FoundryModelsClient(bearer_token="test-token")


def test_foundry_models_requires_env_auth(monkeypatch):
    monkeypatch.delenv("FOUNDRY_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("FOUNDRY_API_KEY", raising=False)

    with pytest.raises(ModelConfigError, match="FOUNDRY_BEARER_TOKEN"):
        FoundryModelsClient()


def test_github_models_rejects_old_invalid_default_model():
    with pytest.raises(ModelConfigError, match="openai/gpt-5.5"):
        GitHubModelsClient(token="test-token", model="openai/gpt-5.5")
