from __future__ import annotations

import re
from typing import Any

from .issues import parse_issue_body
from .rules import extract_cves, sanitize_single_line

_FIELD_LINE_RE = re.compile(
    r"^(?P<prefix>\s*(?:\*\*)?(?P<field>Name|CVEs|CVSSs|Action Needed|Summary|refmap\.gentoo)(?:\*\*)?:\s*)(?P<value>.*)$",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s,)\]>]+")
_PLACEHOLDERS = {"", "TBD", "N/A", "NONE"}


def append_field_values(body: str, field: str, values: list[Any]) -> str:
    clean_values = _dedupe_strings(values)
    if not clean_values:
        return body
    lines = body.splitlines()
    field_line = _find_field_line(lines, field)
    if field_line is None:
        return body
    index, match = field_line
    field_text = _field_text(lines, index)
    missing = [value for value in clean_values if _value_missing(field_text, value)]
    if not missing:
        return body

    current_value = match.group("value").strip()
    if _is_placeholder(current_value):
        next_value = ", ".join(missing)
    else:
        separator = " " if current_value.endswith((",", ";")) else ", "
        next_value = f"{current_value}{separator}{', '.join(missing)}"
    lines[index] = f"{match.group('prefix')}{next_value}"
    return "\n".join(lines)


def set_field_if_placeholder(body: str, field: str, value: Any) -> str:
    text = sanitize_single_line(str(value or ""))
    if _is_placeholder(text):
        return body
    lines = body.splitlines()
    field_line = _find_field_line(lines, field)
    if field_line is None:
        return body
    index, match = field_line
    if not _is_placeholder(_field_text(lines, index).strip()):
        return body
    lines[index] = f"{match.group('prefix')}{text}"
    return "\n".join(lines)


def removal_guard_violations(
    existing_body: str,
    updated_body: str | None,
    parsed_issue: dict[str, Any] | None = None,
) -> list[str]:
    if not updated_body or updated_body.strip() == existing_body.strip():
        return []

    violations: list[str] = []
    updated_cves = set(extract_cves(updated_body))
    for cve in extract_cves(existing_body):
        if cve not in updated_cves:
            violations.append(f"existing CVE would be removed: {cve}")

    updated_urls = set(_extract_urls(updated_body))
    for url in _extract_urls(existing_body):
        if url not in updated_urls:
            violations.append(f"existing URL would be removed: {url}")

    parsed = parsed_issue or _parsed_issue_dict(existing_body)
    action_needed = str(parsed.get("action_needed") or "").strip()
    if not _is_placeholder(action_needed) and _compact(action_needed) not in _compact(
        updated_body
    ):
        violations.append("existing Action Needed content would be removed")

    summary = str(parsed.get("summary") or "").strip()
    if not _is_placeholder(summary) and _compact(summary) not in _compact(updated_body):
        violations.append("existing Summary content would be removed")

    return violations


def _find_field_line(lines: list[str], field: str) -> tuple[int, re.Match[str]] | None:
    wanted = _canonical_field(field)
    for index, line in enumerate(lines):
        match = _FIELD_LINE_RE.match(line)
        if match and _canonical_field(match.group("field")) == wanted:
            return index, match
    return None


def _field_text(lines: list[str], start: int) -> str:
    values = [_FIELD_LINE_RE.match(lines[start]).group("value").strip()]  # type: ignore[union-attr]
    for line in lines[start + 1 :]:
        if _FIELD_LINE_RE.match(line):
            break
        if line.strip():
            values.append(line.strip())
    return "\n".join(values).strip()


def _canonical_field(field: str) -> str:
    lowered = field.lower()
    if lowered == "refmap.gentoo":
        return "refmap.gentoo"
    if lowered == "action needed":
        return "Action Needed"
    return field[:1].upper() + field[1:]


def _dedupe_strings(values: list[Any]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = sanitize_single_line(str(value or ""))
        if _is_placeholder(text):
            continue
        key = text.upper()
        if key not in seen:
            deduped.append(text)
            seen.add(key)
    return deduped


def _value_missing(haystack: str, needle: str) -> bool:
    wanted = str(needle or "").strip()
    if not wanted:
        return False

    wanted_upper = wanted.upper()
    if wanted_upper.startswith("CVE-"):
        return wanted_upper not in {cve.upper() for cve in extract_cves(haystack)}

    if _URL_RE.fullmatch(wanted):
        return wanted.casefold() not in {
            url.casefold() for url in _extract_urls(haystack)
        }

    existing_tokens = {
        token.casefold() for token in re.split(r"[\n,;]+", haystack) if token.strip()
    }
    return wanted.casefold() not in existing_tokens


def _is_placeholder(value: str) -> bool:
    return value.strip().upper() in _PLACEHOLDERS


def _extract_urls(text: str) -> list[str]:
    urls: list[str] = []
    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;")
        if url not in urls:
            urls.append(url)
    return urls


def _parsed_issue_dict(body: str) -> dict[str, Any]:
    parsed = parse_issue_body(body)
    return {
        "action_needed": parsed.action_needed,
        "summary": parsed.summary,
    }


def _compact(value: str) -> str:
    return " ".join(value.lower().split())
