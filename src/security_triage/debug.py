from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SECRET_MARKERS = ("token", "authorization", "password", "secret")


class DebugLogger:
    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path) if path else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str, **fields: Any) -> None:
        if not self.path:
            return
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **_redact(fields),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if any(marker in key.lower() for marker in _SECRET_MARKERS):
                redacted[key] = "<redacted>"
            else:
                redacted[key] = _redact(item)
        return redacted
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value
