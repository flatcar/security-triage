from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from .debug import DebugLogger
from .issue_updates import removal_guard_violations
from .issues import GitHubIssueClient


@dataclass(slots=True)
class ActionFlags:
    create_issues: bool = False
    update_existing_issues: bool = False
    post_cleanup_comments: bool = False
    close_issues: bool = False


CommentPermission = Literal["update_existing_issues", "post_cleanup_comments"]


class GitHubActionRunner:
    def __init__(
        self,
        client: GitHubIssueClient,
        flags: ActionFlags,
        debug_logger: DebugLogger | None = None,
        allowed_action_ids: set[str] | None = None,
    ) -> None:
        self.client = client
        self.flags = flags
        self.debug_logger = debug_logger or DebugLogger()
        # ``None`` means "no allowlist restriction". The review-apply flow
        # always passes an explicit set so a mutation can only ever run for an
        # action ID that was actually checked in the reviewed issue, even if a
        # caller bug elsewhere tried to widen the request.
        self.allowed_action_ids = allowed_action_ids

    def action_allowed(self, action_id: str) -> bool:
        """Return True unless an explicit allowlist excludes ``action_id``.

        Used by the review-apply flow so a resolved action can only mutate
        GitHub when it is both an approved (checked, conflict-free) manifest
        action ID and permitted by this allowlist.
        """
        return self.allowed_action_ids is None or action_id in self.allowed_action_ids

    def create_issue_guarded(
        self, action_id: str, title: str, body: str, labels: list[str]
    ) -> dict[str, Any]:
        """Create an issue for a single approved review action ID.

        Blocked by the action-ID allowlist or the ``create_issues`` flag the
        same way the pre-existing discovery direct-apply path is blocked, so
        the review-apply flow cannot bypass either safety mechanism.
        """
        if not self.action_allowed(action_id):
            return _guarded_result(
                action_id,
                "create_issue",
                blocked=True,
                reason="Action ID is not in the approved allowlist for this apply run",
            )
        if not self.flags.create_issues:
            return _guarded_result(
                action_id,
                "create_issue",
                blocked=True,
                reason="Issue creation flag is disabled",
            )
        response = self.client.create_issue(title, body, labels)
        self.debug_logger.log(
            "github_review_create_issue", action_id=action_id, response=response
        )
        return _guarded_result(action_id, "create_issue", result=response)

    def update_issue_body_guarded(
        self, action_id: str, issue_number: int, current_body: str, updated_body: str
    ) -> dict[str, Any]:
        """Update an issue body after re-checking the additive removal guard.

        ``current_body`` must be freshly fetched by the caller; this method
        does not perform its own fetch so review-apply orchestration stays in
        control of exactly which body was rebased against.
        """
        if not self.action_allowed(action_id):
            return _guarded_result(
                action_id,
                "update_issue_body",
                blocked=True,
                reason="Action ID is not in the approved allowlist for this apply run",
            )
        if not self.flags.update_existing_issues:
            return _guarded_result(
                action_id,
                "update_issue_body",
                blocked=True,
                reason="Existing issue update flag is disabled",
            )
        if updated_body.strip() == current_body.strip():
            return _guarded_result(
                action_id,
                "update_issue_body",
                no_op=True,
                reason="Issue body already reflects the approved additive changes",
            )
        violations = removal_guard_violations(current_body, updated_body)
        if violations:
            return _guarded_result(
                action_id,
                "update_issue_body",
                blocked=True,
                reason="Refusing issue body update because it would remove "
                "existing content: " + "; ".join(violations),
            )
        response = self.client.update_issue_body(issue_number, updated_body)
        self.debug_logger.log(
            "github_review_update_issue_body",
            action_id=action_id,
            issue=issue_number,
            response=response,
        )
        return _guarded_result(action_id, "update_issue_body", result=response)

    def post_comment_guarded(
        self,
        action_id: str,
        issue_number: int,
        body: str,
        *,
        required_permission: CommentPermission,
        already_posted: bool = False,
    ) -> dict[str, Any]:
        if not self.action_allowed(action_id):
            return _guarded_result(
                action_id,
                "post_comment",
                blocked=True,
                reason="Action ID is not in the approved allowlist for this apply run",
            )
        permission_enabled = {
            "update_existing_issues": self.flags.update_existing_issues,
            "post_cleanup_comments": self.flags.post_cleanup_comments,
        }[required_permission]
        if not permission_enabled:
            return _guarded_result(
                action_id,
                "post_comment",
                blocked=True,
                reason=(
                    f"Required comment permission {required_permission!r} is disabled"
                ),
            )
        if already_posted:
            return _guarded_result(
                action_id,
                "post_comment",
                no_op=True,
                reason="A comment carrying this action ID already exists on the issue",
            )
        response = self.client.post_comment(issue_number, body)
        self.debug_logger.log(
            "github_review_post_comment",
            action_id=action_id,
            issue=issue_number,
            response=response,
        )
        return _guarded_result(action_id, "post_comment", result=response)

    def close_issue_guarded(
        self, action_id: str, issue_number: int, *, already_closed: bool = False
    ) -> dict[str, Any]:
        if not self.action_allowed(action_id):
            return _guarded_result(
                action_id,
                "close_issue",
                blocked=True,
                reason="Action ID is not in the approved allowlist for this apply run",
            )
        if not self.flags.close_issues:
            return _guarded_result(
                action_id,
                "close_issue",
                blocked=True,
                reason="Issue closure flag is disabled",
            )
        if already_closed:
            # Closing an already-closed issue is a successful no-op so a
            # resumed apply run after a partial failure never errors here.
            return _guarded_result(
                action_id, "close_issue", no_op=True, reason="Issue is already closed"
            )
        response = self.client.close_issue(issue_number)
        self.debug_logger.log(
            "github_review_close_issue",
            action_id=action_id,
            issue=issue_number,
            response=response,
        )
        return _guarded_result(action_id, "close_issue", result=response)


def _guarded_result(
    action_id: str,
    action: str,
    *,
    result: dict[str, Any] | None = None,
    blocked: bool = False,
    no_op: bool = False,
    reason: str | None = None,
) -> dict[str, Any]:
    return {
        "action_id": action_id,
        "action": action,
        "outcome": "blocked" if blocked else ("no_op" if no_op else "applied"),
        "reason": reason,
        "result": result,
    }
