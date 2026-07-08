import urllib.request

import pytest

from security_triage import http_utils
from security_triage.http_utils import (
    HTTPError,
    _SafeRedirectHandler,
    fetch_json,
    fetch_text,
)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://attacker.example/x",
        "data:text/plain,hello",
        "gopher://attacker.example/",
        "/etc/passwd",
    ],
)
def test_fetch_text_refuses_non_http_schemes(url, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("urlopen must not be called for a rejected scheme")

    monkeypatch.setattr(http_utils.urllib.request, "urlopen", boom)
    with pytest.raises(HTTPError, match="non-HTTP"):
        fetch_text(url)


def test_fetch_json_refuses_non_http_schemes(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("urlopen must not be called for a rejected scheme")

    monkeypatch.setattr(http_utils.urllib.request, "urlopen", boom)
    with pytest.raises(HTTPError, match="non-HTTP"):
        fetch_json("file:///etc/passwd")


def test_fetch_text_rejects_oversized_response(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, amount=None):
            # Return more than the caller asked for to simulate a huge body.
            return b"x" * (amount or 0)

    monkeypatch.setattr(http_utils, "MAX_RESPONSE_BYTES", 10)
    monkeypatch.setattr(http_utils, "open_request", lambda *a, **k: FakeResponse())
    with pytest.raises(HTTPError, match="exceeded"):
        fetch_text("https://example.test/big")


def test_fetch_text_allows_https(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, amount=None):
            return b"ok"

    monkeypatch.setattr(http_utils, "open_request", lambda *a, **k: FakeResponse())
    assert fetch_text("https://example.test/ok") == "ok"


def _redirect(
    original_url: str, new_url: str, headers: dict[str, str]
) -> urllib.request.Request | None:
    handler = _SafeRedirectHandler()
    request = urllib.request.Request(original_url, headers=headers)
    return handler.redirect_request(request, None, 302, "Found", {}, new_url)


def test_redirect_to_other_host_drops_authorization():
    new_request = _redirect(
        "https://api.github.com/repos/x",
        "https://objects.example.net/blob",
        {"Authorization": "Bearer secret", "Accept": "application/json"},
    )
    assert new_request is not None
    assert new_request.get_header("Authorization") is None
    assert new_request.get_header("Accept") == "application/json"


def test_redirect_https_downgrade_drops_authorization():
    new_request = _redirect(
        "https://api.github.com/repos/x",
        "http://api.github.com/repos/x",
        {"Authorization": "Bearer secret"},
    )
    assert new_request is not None
    assert new_request.get_header("Authorization") is None


def test_redirect_same_origin_keeps_authorization():
    new_request = _redirect(
        "https://api.github.com/repos/old",
        "https://api.github.com/repos/new",
        {"Authorization": "Bearer secret"},
    )
    assert new_request is not None
    assert new_request.get_header("Authorization") == "Bearer secret"


@pytest.mark.parametrize("new_url", ["ftp://attacker.example/x", "file:///etc/passwd"])
def test_redirect_to_non_http_scheme_is_refused(new_url):
    with pytest.raises(HTTPError, match="non-HTTP"):
        _redirect("https://example.test/start", new_url, {})
