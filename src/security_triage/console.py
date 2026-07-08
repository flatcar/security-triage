from __future__ import annotations

import sys
from datetime import datetime, timezone


class ProgressLogger:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def info(self, message: str) -> None:
        if not self.enabled:
            return
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}", file=sys.stderr, flush=True)

    def section(self, message: str) -> None:
        self.info(message)


class NullProgressLogger(ProgressLogger):
    def __init__(self) -> None:
        super().__init__(enabled=False)
