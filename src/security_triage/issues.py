from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .http_utils import HTTPError, fetch_json, open_request
from .io_utils import load_structured_file
from .records import Issue, ParsedIssue
from .rules import (
    ADVISORY_ISSUE_QUERY,
    active_markdown_text,
    extract_cves,
    normalize_name,
    parse_cvss_scores,
)

_FIELD_RE = re.compile(
    r"^\s*(?:\*\*)?(Name|CVEs|CVSSs|Action Needed|Summary|refmap\.gentoo)(?:\*\*)?:\s*(.*)$",
    re.IGNORECASE,
)
_TITLE_RE = re.compile(r"^update:\s*(.+)$", re.IGNORECASE)


class GitHubConfigError(RuntimeError):
    pass


class GitHubIssueClient:
    def __init__(self, repo: str = "flatcar/Flatcar", token: str | None = None) -> None:
        self.repo = repo
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.api_base = "https://api.github.com"

    def fetch_open_advisory_issues(
        self, query: str = ADVISORY_ISSUE_QUERY
    ) -> list[Issue]:
        issues: list[Issue] = []
        page = 1
        while True:
            encoded = urllib.parse.urlencode(
                {"q": query, "per_page": "100", "page": str(page)}
            )
            payload = fetch_json(
                f"{self.api_base}/search/issues?{encoded}",
                token=self.token,
                accept="application/vnd.github+json",
            )
            items = payload.get("items", [])
            issues.extend(
                issue_from_api(item) for item in items if "pull_request" not in item
            )
            if len(items) < 100:
                break
            page += 1
        return issues

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict[str, Any]:
        return self._request_json(
            "POST",
            f"/repos/{self.repo}/issues",
            {"title": title, "body": body, "labels": labels},
        )

    def update_issue_body(self, issue_number: int, body: str) -> dict[str, Any]:
        return self._request_json(
            "PATCH", f"/repos/{self.repo}/issues/{issue_number}", {"body": body}
        )

    def post_comment(self, issue_number: int, body: str) -> dict[str, Any]:
        return self._request_json(
            "POST", f"/repos/{self.repo}/issues/{issue_number}/comments", {"body": body}
        )

    def close_issue(self, issue_number: int) -> dict[str, Any]:
        return self._request_json(
            "PATCH", f"/repos/{self.repo}/issues/{issue_number}", {"state": "closed"}
        )

    def _request_json(
        self, method: str, path: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        if not self.token:
            raise GitHubConfigError(
                "GITHUB_TOKEN is required for GitHub write operations"
            )
        request = urllib.request.Request(
            f"{self.api_base}{path}",
            data=json.dumps(payload).encode("utf-8"),
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "security-triage/0.1",
            },
        )
        try:
            with open_request(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))  # type: ignore[no-any-return]
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise HTTPError(
                f"GitHub API HTTP {exc.code} for {path}: {body[:500]}"
            ) from exc


def load_issue_fixture(path: str) -> list[Issue]:
    payload = load_structured_file(path)
    items = payload.get("issues", payload) if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        raise ValueError(
            "Issue fixture must be a list or an object with an 'issues' list"
        )
    return [issue_from_api(item) for item in items]


def issue_from_api(item: dict[str, Any]) -> Issue:
    labels = _labels_from_api(item.get("labels", []))
    return Issue(
        number=int(item.get("number", 0)),
        title=str(item.get("title") or ""),
        body=str(item.get("body") or ""),
        labels=labels,
        html_url=str(item.get("html_url") or item.get("url") or ""),
        state=str(item.get("state") or "open"),
        raw=item,
    )


def parse_issue_body(body: str) -> ParsedIssue:
    fields: dict[str, str] = {}
    current_key: str | None = None
    seen_keys: set[str] = set()
    for line in body.splitlines():
        match = _FIELD_RE.match(line)
        if match:
            key = _canonical_field(match.group(1))
            fields[key] = match.group(2).strip()
            seen_keys.add(key)
            current_key = key
            continue
        if current_key and line.strip():
            separator = "\n" if fields.get(current_key) else ""
            fields[current_key] = (
                f"{fields.get(current_key, '')}{separator}{line.strip()}"
            )

    required = ["Name", "CVEs", "CVSSs", "Action Needed", "Summary", "refmap.gentoo"]
    missing = [field for field in required if field not in seen_keys]
    active_fields = {key: active_markdown_text(value) for key, value in fields.items()}
    cve_field = active_fields.get("CVEs")
    cves = extract_cves(cve_field)
    if not cves and cve_field and cve_field.lower() not in {"n/a", "tbd", "none"}:
        cves = [part.strip() for part in cve_field.split(",") if part.strip()]
    return ParsedIssue(
        name=active_fields.get("Name"),
        cves=cves,
        cvss_scores=parse_cvss_scores(active_fields.get("CVSSs")),
        action_needed=active_fields.get("Action Needed"),
        summary=active_fields.get("Summary"),
        gentoo_ref=active_fields.get("refmap.gentoo"),
        valid=not missing,
        missing_fields=missing,
    )


def parsed_issue_to_dict(parsed: ParsedIssue) -> dict[str, Any]:
    return {
        "name": parsed.name,
        "cves": parsed.cves,
        "cvss_scores": parsed.cvss_scores,
        "action_needed": parsed.action_needed,
        "summary": parsed.summary,
        "gentoo_ref": parsed.gentoo_ref,
        "valid": parsed.valid,
        "missing_fields": parsed.missing_fields,
    }


def issue_package_from_title(title: str) -> str | None:
    match = _TITLE_RE.match(title.strip())
    return match.group(1).strip() if match else None


def find_existing_issue_matches(
    extraction: dict[str, Any], issues: list[Issue]
) -> list[dict[str, Any]]:
    package_name = extraction.get("package_name") or ""
    normalized_package = normalize_name(package_name)
    cves = set(extraction.get("cves") or [])
    matches: list[dict[str, Any]] = []
    for issue in issues:
        parsed = parse_issue_body(issue.body)
        issue_package = parsed.name or issue_package_from_title(issue.title) or ""
        normalized_issue_package = normalize_name(issue_package)
        issue_cves = set(parsed.cves)
        reasons: list[str] = []
        if (
            normalized_package
            and normalized_issue_package
            and normalized_package == normalized_issue_package
        ):
            reasons.append("package_name")
        if cves and issue_cves and cves.intersection(issue_cves):
            reasons.append("cve_overlap")
        if not reasons:
            continue
        matches.append(
            {
                "issue": issue.number,
                "issue_url": issue.html_url,
                "title": issue.title,
                "body": issue.body,
                "state": issue.state,
                "labels": issue.labels,
                "package": issue_package or None,
                "cves": parsed.cves,
                "parsed_issue": parsed_issue_to_dict(parsed),
                "match_reasons": reasons,
            }
        )
    return matches


def _canonical_field(field: str) -> str:
    lowered = field.lower()
    if lowered == "refmap.gentoo":
        return "refmap.gentoo"
    if lowered == "action needed":
        return "Action Needed"
    return field[:1].upper() + field[1:]


def _labels_from_api(labels: Any) -> list[str]:
    if not isinstance(labels, list):
        return []
    names: list[str] = []
    for label in labels:
        if isinstance(label, str):
            name = label
        elif isinstance(label, dict):
            name = str(label.get("name") or "")
        else:
            continue
        if name and name not in names:
            names.append(name)
    return names
