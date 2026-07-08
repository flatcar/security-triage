"""Simple on-disk JSON cache for GitHub Models prompt responses.

The cache key is a sha256 over a canonical JSON encoding of the request payload
together with the provider, endpoint, model, and prompt version. Hits return the
previously parsed JSON response and avoid hitting the rate-limited endpoint.

Design notes:
- Stored as one JSON file per key under a sharded subdirectory (first 2 hex chars).
- Stale or corrupt entries are treated as cache misses; we never raise on read.
- Writes are best-effort: failures are logged and do not break the request flow.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

CACHE_VERSION = 1


class PromptCache:
    def __init__(self, directory: str | os.PathLike[str]) -> None:
        self.directory = Path(directory)
        self.hits = 0
        self.misses = 0
        self.writes = 0
        self.errors = 0

    def key(
        self,
        *,
        provider: str,
        endpoint: str,
        model: str,
        prompt_version: str,
        request_payload: dict[str, Any],
    ) -> str:
        material = {
            "cache_version": CACHE_VERSION,
            "provider": provider,
            "endpoint": endpoint,
            "model": model,
            "prompt_version": prompt_version,
            "request": request_payload,
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _path_for(self, key: str) -> Path:
        return self.directory / key[:2] / f"{key}.json"

    def get(self, key: str) -> dict[str, Any] | None:
        path = self._path_for(key)
        if not path.is_file():
            self.misses += 1
            return None
        try:
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            self.errors += 1
            self.misses += 1
            return None
        response = payload.get("response")
        if not isinstance(response, dict):
            self.misses += 1
            return None
        self.hits += 1
        return response

    def put(self, key: str, response: dict[str, Any], *, task: str | None = None) -> None:
        path = self._path_for(key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "cache_version": CACHE_VERSION,
                "stored_at": int(time.time()),
                "task": task,
                "response": response,
            }
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=path.parent,
                delete=False,
                prefix=path.name,
                suffix=".tmp",
            ) as handle:
                json.dump(payload, handle, sort_keys=True)
                tmp_name = handle.name
            os.replace(tmp_name, path)
            self.writes += 1
        except OSError:
            self.errors += 1

    def stats(self) -> dict[str, int]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "writes": self.writes,
            "errors": self.errors,
        }
