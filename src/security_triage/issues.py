from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, cast

from .http_utils import HTTPError, fetch_json, open_request
from .io_utils import load_structured_file
from .records import Issue, ParsedIssue
from .rules import (
    REVIEW_LABEL,
    active_markdown_text,
    advisory_issue_query,
    extract_cves,
    issue_identity_from_summary,
    package_identities_match,
    parse_cvss_scores,
    validate_repo_name,
)

_FIELD_RE = re.compile(
    r"^\s*(?:\*\*)?(Name|CVEs|CVSSs|Action Needed|Summary|refmap\.gentoo)(?:\*\*)?:\s*(.*)$",
    re.IGNORECASE,
)
_TITLE_RE = re.compile(r"^update:\s*(.+)$", re.IGNORECASE)


class GitHubConfigError(RuntimeError):
    pass


class GitHubIssuePage(list[Issue]):
    """A filtered issue page retaining raw row count for safe pagination."""

    def __init__(self, issues: list[Issue], raw_count: int) -> None:
        super().__init__(issues)
        self.raw_count = raw_count


class GitHubIssueClient:
    def __init__(self, repo: str = "flatcar/Flatcar", token: str | None = None) -> None:
        self.repo = validate_repo_name(repo)
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.api_base = "https://api.github.com"

    def fetch_open_advisory_issues(self, query: str | None = None) -> list[Issue]:
        return self._search_issues(query or advisory_issue_query(self.repo))

    def fetch_open_update_issues(self) -> list[Issue]:
        """List current package-update candidates, including ordinary unlabeled issues."""
        return [
            issue
            for issue in self.list_issues(state="open")
            if issue.state == "open" and is_package_update_issue(issue)
        ]

    def _search_issues(self, query: str) -> list[Issue]:
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

    def get_issue(self, issue_number: int) -> Issue:
        """Fetch a single issue fresh from the API.

        Used by the review-apply path instead of trusting stale webhook
        payload fields or previously cached issue state.
        """
        payload = fetch_json(
            f"{self.api_base}/repos/{self.repo}/issues/{issue_number}",
            token=self.token,
            accept="application/vnd.github+json",
        )
        return issue_from_api(payload)

    def list_issues_by_label(self, label: str, state: str = "all") -> list[Issue]:
        """List issues carrying ``label`` using the Issues List API.

        The Issues List endpoint is immediately consistent (unlike the Search
        API's eventually-consistent index), which makes it the safe choice for
        same-run idempotency and duplicate checks that must observe an issue
        created moments earlier in the same workflow run.
        """
        return self.list_issues(state=state, label=label)

    def list_issues(self, state: str = "open", label: str | None = None) -> list[Issue]:
        """Read immediately consistent repository issues, including unlabeled updates."""
        issues: list[Issue] = []
        page = 1
        while True:
            params = {}
            if label is not None:
                params["labels"] = label
            params.update({"state": state, "per_page": "100", "page": str(page)})
            encoded = urllib.parse.urlencode(params)
            payload = fetch_json(
                f"{self.api_base}/repos/{self.repo}/issues?{encoded}",
                token=self.token,
                accept="application/vnd.github+json",
            )
            if not isinstance(payload, list):
                raise HTTPError("GitHub Issues List returned a non-list response")
            issues.extend(
                issue_from_api(item) for item in payload if "pull_request" not in item
            )
            if len(payload) < 100:
                break
            page += 1
        return issues

    def list_comments(self, issue_number: int) -> list[dict[str, Any]]:
        comments: list[dict[str, Any]] = []
        page = 1
        while True:
            encoded = urllib.parse.urlencode({"per_page": "100", "page": str(page)})
            payload = fetch_json(
                f"{self.api_base}/repos/{self.repo}/issues/{issue_number}/comments?{encoded}",
                token=self.token,
                accept="application/vnd.github+json",
            )
            if not isinstance(payload, list):
                break
            comments.extend(payload)
            if len(payload) < 100:
                break
            page += 1
        return comments

    def list_issues_page(
        self,
        *,
        state: str = "closed",
        label: str | None = REVIEW_LABEL,
        page: int = 1,
        per_page: int = 100,
    ) -> GitHubIssuePage:
        """Read one bounded issue page; raw_count includes filtered pull requests."""
        _validate_page(page, per_page)
        params = {
            "state": state,
            "page": str(page),
            "per_page": str(per_page),
            "sort": "updated",
            "direction": "desc",
        }
        if label is not None:
            params["labels"] = label
        payload = fetch_json(
            f"{self.api_base}/repos/{self.repo}/issues?{urllib.parse.urlencode(params)}",
            token=self.token,
            accept="application/vnd.github+json",
        )
        if not isinstance(payload, list) or not all(
            isinstance(item, dict) for item in payload
        ):
            raise HTTPError("GitHub Issues List returned a malformed page")
        return GitHubIssuePage(
            [issue_from_api(item) for item in payload if "pull_request" not in item],
            raw_count=len(payload),
        )

    def list_comments_page(
        self,
        issue_number: int,
        *,
        page: int,
        per_page: int = 100,
    ) -> list[dict[str, Any]]:
        """Read exactly one comment page without changing unbounded callers."""
        _validate_page(page, per_page)
        params = urllib.parse.urlencode({"page": str(page), "per_page": str(per_page)})
        payload = fetch_json(
            f"{self.api_base}/repos/{self.repo}/issues/{issue_number}/comments?{params}",
            token=self.token,
            accept="application/vnd.github+json",
        )
        if not isinstance(payload, list) or not all(
            isinstance(item, dict) for item in payload
        ):
            raise HTTPError("GitHub Comments List returned a malformed page")
        return cast(list[dict[str, Any]], payload)

    def ensure_label_exists(
        self, name: str, color: str = "6f42c1", description: str = ""
    ) -> None:
        """Create ``name`` as a repository label if it does not already exist.

        Never adds ``advisory``/``security`` semantics; callers choose the
        label name, and this only guarantees the label exists before it is
        attached to an issue.
        """
        encoded_name = urllib.parse.quote(name, safe="")
        try:
            fetch_json(
                f"{self.api_base}/repos/{self.repo}/labels/{encoded_name}",
                token=self.token,
                accept="application/vnd.github+json",
            )
            return
        except HTTPError as exc:
            if "HTTP 404" not in str(exc):
                raise
        try:
            self._request_json(
                "POST",
                f"/repos/{self.repo}/labels",
                {"name": name, "color": color, "description": description},
            )
        except HTTPError as exc:
            # A concurrent run may have created the label between our GET and
            # POST; GitHub reports that race as 422 Unprocessable Entity.
            if "HTTP 422" not in str(exc):
                raise

    def add_labels(self, issue_number: int, labels: list[str]) -> list[dict[str, Any]]:
        return cast(
            list[dict[str, Any]],
            self._request_json(
                "POST",
                f"/repos/{self.repo}/issues/{issue_number}/labels",
                {"labels": labels},
            ),
        )

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            self._request_json(
                "POST",
                f"/repos/{self.repo}/issues",
                {"title": title, "body": body, "labels": labels},
            ),
        )

    def update_issue_body(self, issue_number: int, body: str) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            self._request_json(
                "PATCH", f"/repos/{self.repo}/issues/{issue_number}", {"body": body}
            ),
        )

    def post_comment(self, issue_number: int, body: str) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            self._request_json(
                "POST",
                f"/repos/{self.repo}/issues/{issue_number}/comments",
                {"body": body},
            ),
        )

    def update_comment(self, comment_id: int, body: str) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            self._request_json(
                "PATCH",
                f"/repos/{self.repo}/issues/comments/{comment_id}",
                {"body": body},
            ),
        )

    def close_issue(self, issue_number: int) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            self._request_json(
                "PATCH",
                f"/repos/{self.repo}/issues/{issue_number}",
                {"state": "closed"},
            ),
        )

    def _request_json(
        self, method: str, path: str, payload: dict[str, Any]
    ) -> dict[str, Any] | list[Any]:
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
                parsed: object = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise HTTPError(
                f"GitHub API HTTP {exc.code} for {path}: {body[:500]}"
            ) from exc
        if not isinstance(parsed, (dict, list)):
            raise HTTPError(f"GitHub API returned unexpected JSON payload for {path}")
        return parsed


def load_issue_fixture(path: str) -> list[Issue]:
    payload = load_structured_file(path)
    items = payload.get("issues", payload) if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        raise ValueError(
            "Issue fixture must be a list or an object with an 'issues' list"
        )
    return [issue_from_api(item) for item in items]


def _validate_page(page: int, per_page: int) -> None:
    if (
        type(page) is not int
        or page < 1
        or type(per_page) is not int
        or not 1 <= per_page <= 100
    ):
        raise ValueError("GitHub pagination requires page >= 1 and per_page in 1..100")


def issue_from_api(item: dict[str, Any]) -> Issue:
    labels = _labels_from_api(item.get("labels", []))
    state_reason = item.get("state_reason")
    return Issue(
        number=int(item.get("number", 0)),
        title=str(item.get("title") or ""),
        body=str(item.get("body") or ""),
        labels=labels,
        html_url=str(item.get("html_url") or item.get("url") or ""),
        state=str(item.get("state") or "open"),
        state_reason=str(state_reason) if state_reason else None,
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
    identity = issue_identity_from_summary(
        active_fields.get("Name"), active_fields.get("Summary")
    )
    return ParsedIssue(
        name=active_fields.get("Name"),
        cves=cves,
        cvss_scores=parse_cvss_scores(active_fields.get("CVSSs")),
        action_needed=active_fields.get("Action Needed"),
        summary=active_fields.get("Summary"),
        gentoo_ref=active_fields.get("refmap.gentoo"),
        valid=not missing and identity != "",
        missing_fields=missing,
        package_identity=identity,
    )


def parsed_issue_to_dict(parsed: ParsedIssue) -> dict[str, Any]:
    return {
        "name": parsed.name,
        "package_identity": parsed.identity,
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


def is_package_update_issue(issue: Issue) -> bool:
    return REVIEW_LABEL not in issue.labels and (
        {"advisory", "security"}.issubset(issue.labels)
        or issue_package_from_title(issue.title) is not None
    )


def find_existing_issue_matches(
    extraction: dict[str, Any], issues: list[Issue]
) -> list[dict[str, Any]]:
    package_name = (
        extraction.get("package_purl")
        or extraction.get("package_identity")
        or extraction.get("package_name")
        or ""
    )
    cves = set(extraction.get("cves") or [])
    matches: list[dict[str, Any]] = []
    for issue in issues:
        if not is_package_update_issue(issue):
            continue
        parsed = parse_issue_body(issue.body)
        issue_package = (
            parsed.identity
            if parsed.identity is not None
            else issue_package_from_title(issue.title) or ""
        )
        issue_cves = set(parsed.cves)
        reasons: list[str] = []
        if package_identities_match(package_name, issue_package):
            reasons.append("package_name")
        if not reasons:
            # A shared identifier can affect multiple packages. It is evidence,
            # never authorization to mutate a different package's issue.
            continue
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
