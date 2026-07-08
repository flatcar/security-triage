from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

ALLOWED_SCHEMES = frozenset({"http", "https"})
# Generous ceiling to stop a hostile/misconfigured server from streaming an
# unbounded body into memory. Real advisory feeds and SBOMs are far smaller.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class HTTPError(RuntimeError):
    pass


def _require_allowed_url(url: str) -> None:
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise HTTPError(
            f"Refusing to fetch non-HTTP(S) URL scheme {scheme or '(none)'!r}: {url}"
        )


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urllib.parse.urlsplit(url)
    return (parts.scheme.lower(), (parts.hostname or "").lower(), parts.port)


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that keeps credentials and schemes under control.

    The stdlib handler re-sends every original header — including
    ``Authorization`` — to the redirect target, so a redirect to another host
    would leak the bearer token. It also follows redirects to ``ftp://``,
    which would bypass the http/https allowlist enforced on the initial URL.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        _require_allowed_url(newurl)
        new_request = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_request is not None and _origin(newurl) != _origin(req.full_url):
            new_request.remove_header("Authorization")
        return new_request


_OPENER = urllib.request.build_opener(_SafeRedirectHandler)


def open_request(request: urllib.request.Request, timeout: int):
    """Open ``request`` with redirect-safe handling (see _SafeRedirectHandler)."""
    return _OPENER.open(request, timeout=timeout)


def fetch_text(
    url: str, token: str | None = None, timeout: int = 30, accept: str = "*/*"
) -> str:
    _require_allowed_url(url)
    headers = {
        "Accept": accept,
        "User-Agent": "security-triage/0.1",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with open_request(request, timeout=timeout) as response:
            data = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise HTTPError(f"HTTP {exc.code} for {url}: {body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise HTTPError(f"Could not fetch {url}: {exc.reason}") from exc
    if len(data) > MAX_RESPONSE_BYTES:
        raise HTTPError(f"Response from {url} exceeded {MAX_RESPONSE_BYTES} bytes")
    return data.decode("utf-8", errors="replace")


def fetch_json(
    url: str,
    token: str | None = None,
    timeout: int = 30,
    accept: str = "application/json",
) -> Any:
    return json.loads(fetch_text(url, token=token, timeout=timeout, accept=accept))
