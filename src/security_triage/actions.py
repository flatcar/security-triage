from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .debug import DebugLogger
from .issue_updates import removal_guard_violations
from .issues import GitHubIssueClient


@dataclass(slots=True)
class ActionFlags:
    create_issues: bool = False
    update_existing_issues: bool = False
    post_cleanup_comments: bool = False
    close_issues: bool = False


class GitHubActionRunner:
    def __init__(
        self,
        client: GitHubIssueClient,
        flags: ActionFlags,
        debug_logger: DebugLogger | None = None,
    ) -> None:
        self.client = client
        self.flags = flags
        self.debug_logger = debug_logger or DebugLogger()

    def apply_discovery(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for record in document.get("records", []):
            action = record.get("decision", {}).get("action")
            if action == "create_issue" and record.get("proposed_issue"):
                if not self.flags.create_issues:
                    results.append(
                        _skipped(
                            record, "create_issue", "Issue creation flag is disabled"
                        )
                    )
                    continue
                proposed = record["proposed_issue"]
                response = self.client.create_issue(
                    proposed["title"], proposed["body"], proposed["labels"]
                )
                results.append(
                    {
                        "record_id": record.get("record_id"),
                        "action": "create_issue",
                        "result": response,
                    }
                )
                self.debug_logger.log(
                    "github_create_issue",
                    record_id=record.get("record_id"),
                    response=response,
                )
            elif action == "update_existing_issue" and record.get("proposed_update"):
                if not self.flags.update_existing_issues:
                    results.append(
                        _skipped(
                            record,
                            "update_existing_issue",
                            "Existing issue update flag is disabled",
                        )
                    )
                    continue
                update = record["proposed_update"]
                issue_number = int(update["issue"])
                if update.get("updated_body"):
                    existing_body = str(
                        (update.get("matched_existing_issue") or {}).get("body") or ""
                    )
                    violations = removal_guard_violations(
                        existing_body, update["updated_body"]
                    )
                    if violations:
                        results.append(
                            {
                                "record_id": record.get("record_id"),
                                "issue": issue_number,
                                "action": "update_existing_issue_body",
                                "skipped": True,
                                "reason": "Refusing existing issue body update because it would remove existing content: "
                                + "; ".join(violations),
                            }
                        )
                    else:
                        response = self.client.update_issue_body(
                            issue_number, update["updated_body"]
                        )
                        results.append(
                            {
                                "record_id": record.get("record_id"),
                                "action": "update_existing_issue_body",
                                "result": response,
                            }
                        )
                        self.debug_logger.log(
                            "github_update_existing_issue_body",
                            record_id=record.get("record_id"),
                            response=response,
                        )
                comment_body = update.get("comment_body") or _update_comment_body(
                    record
                )
                if comment_body:
                    response = self.client.post_comment(issue_number, comment_body)
                    results.append(
                        {
                            "record_id": record.get("record_id"),
                            "action": "update_existing_issue_comment",
                            "result": response,
                        }
                    )
                    self.debug_logger.log(
                        "github_update_existing_issue_comment",
                        record_id=record.get("record_id"),
                        response=response,
                    )
        return results

    def apply_cleanup(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for record in document.get("records", []):
            recommended = record.get("recommended_action")
            issue_number = int(record.get("issue"))
            if recommended in {"comment_only", "close_issue"}:
                if not self.flags.post_cleanup_comments:
                    results.append(
                        _skipped(
                            record,
                            "post_cleanup_comment",
                            "Cleanup comment flag is disabled",
                        )
                    )
                else:
                    response = self.client.post_comment(
                        issue_number, record.get("comment_body") or ""
                    )
                    results.append(
                        {
                            "issue": issue_number,
                            "action": "post_cleanup_comment",
                            "result": response,
                        }
                    )
                    self.debug_logger.log(
                        "github_cleanup_comment", issue=issue_number, response=response
                    )
            if recommended == "close_issue":
                if not self.flags.close_issues:
                    results.append(
                        _skipped(
                            record, "close_issue", "Issue closure flag is disabled"
                        )
                    )
                else:
                    response = self.client.close_issue(issue_number)
                    results.append(
                        {
                            "issue": issue_number,
                            "action": "close_issue",
                            "result": response,
                        }
                    )
                    self.debug_logger.log(
                        "github_close_issue", issue=issue_number, response=response
                    )
        return results


def _skipped(record: dict[str, Any], action: str, reason: str) -> dict[str, Any]:
    return {
        "record_id": record.get("record_id"),
        "issue": record.get("issue"),
        "action": action,
        "skipped": True,
        "reason": reason,
    }


def _update_comment_body(record: dict[str, Any]) -> str:
    update = record.get("proposed_update") or {}
    additions = update.get("recommended_additions") or []
    if not additions:
        return ""
    lines = [
        "Security tracking pipeline recommends updating this existing advisory with new upstream context.",
        "",
        "Recommended additions:",
    ]
    lines.extend(f"- {addition}" for addition in additions)
    lines.extend(
        [
            "",
            "This is a guarded automation comment; maintainers should review before editing the advisory body.",
        ]
    )
    return "\n".join(lines)
