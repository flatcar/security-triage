from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso_now() -> str:
    return utc_now().isoformat()


def default_processing_window(days: int = 7) -> tuple[str, str]:
    end = utc_now()
    start = end - timedelta(days=days)
    return start.isoformat(), end.isoformat()


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def in_window(
    value: str | None, start: str | None, end: str | None, include_undated: bool = True
) -> bool:
    parsed = parse_datetime(value)
    if parsed is None:
        return include_undated
    start_dt = parse_datetime(start)
    end_dt = parse_datetime(end)
    if start_dt and parsed < start_dt:
        return False
    if end_dt and parsed > end_dt:
        return False
    return True
