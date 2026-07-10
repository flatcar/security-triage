from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .actions import ActionFlags, GitHubActionRunner
from .cleanup import CleanupWorkflow
from .console import ProgressLogger
from .debug import DebugLogger
from .discovery import DiscoveryWorkflow
from .env import load_dotenv
from .io_utils import load_structured_file, write_json_file
from .issues import GitHubIssueClient, load_issue_fixture
from .models import (
    DEFAULT_FOUNDRY_API_VERSION,
    DEFAULT_FOUNDRY_DEPLOYMENT,
    DEFAULT_FOUNDRY_EXTRACTION_DEPLOYMENT,
    BaseModelClient,
    FixtureModelClient,
    FoundryModelsClient,
    GitHubModelsClient,
    HeuristicModelClient,
    RoutingModelClient,
)
from .prompt_cache import PromptCache
from .reporting import (
    render_cleanup_markdown,
    render_discovery_markdown,
    write_document,
    write_markdown,
)
from .review import (
    DEFAULT_MAX_PART_BODY_CHARS,
    ApplyContext,
    ReviewContext,
    apply_review_issue,
    build_review_batch,
    create_review_batch,
    render_create_job_summary,
    render_dry_run,
)
from .rules import (
    SCHEMA_VERSION,
    TARGET_REPO,
    validate_cleanup_document,
    validate_discovery_document,
    validate_repo_name,
)
from .sbom import fetch_flatcar_production_sbom, load_sbom_fixture
from .sources import fetch_live_sources, load_source_fixture
from .time_utils import default_processing_window, iso_now


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "discovery":
            return run_discovery_command(args)
        if args.command == "cleanup":
            return run_cleanup_command(args)
        if args.command == "review":
            if args.review_command == "create":
                return run_review_create_command(args)
            if args.review_command == "render":
                return run_review_render_command(args)
            if args.review_command == "apply":
                return run_review_apply_command(args)
        parser.print_help()
        return 2
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="security-triage")
    parser.add_argument(
        "--version",
        action="version",
        version=f"security-triage schema {SCHEMA_VERSION}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    discovery = subparsers.add_parser(
        "discovery", help="Run new vulnerability discovery"
    )
    _add_common_io_args(discovery, "reports/discovery.json")
    _add_model_args(discovery)
    _add_advisory_repo_arg(discovery, "read")
    discovery.add_argument(
        "--source-fixture", help="JSON/YAML fixture containing upstream source entries"
    )
    discovery.add_argument(
        "--issues-fixture", help="JSON/YAML fixture containing GitHub issues"
    )
    discovery.add_argument(
        "--sbom-fixture", help="SPDX JSON fixture for the Stable production SBOM"
    )
    discovery.add_argument(
        "--window-start", help="Processing window start ISO timestamp"
    )
    discovery.add_argument("--window-end", help="Processing window end ISO timestamp")
    discovery.add_argument(
        "--window-days",
        type=int,
        default=7,
        help="Default processing window length when explicit bounds are omitted",
    )
    discovery.add_argument(
        "--include-undated-source-entries",
        action="store_true",
        help="Include live source entries that do not expose published or updated timestamps",
    )
    discovery.add_argument(
        "--include-optional-sources",
        action="store_true",
        help="Include optional Red Hat vulnerability source",
    )
    discovery.add_argument(
        "--oss-security-cache-dir",
        help="Directory to cache fetched oss-security message HTML between runs",
    )
    discovery.add_argument(
        "--go-vulndb-cache-dir",
        help="Directory to cache fetched Go vulnerability database advisory JSON between runs",
    )
    discovery.add_argument(
        "--rustsec-cache-dir",
        help="Directory to cache fetched RustSec advisory Markdown between runs",
    )
    discovery.add_argument(
        "--apply-actions",
        action="store_true",
        help="Apply guarded GitHub actions after producing validated records",
    )
    discovery.add_argument(
        "--enable-create-issues",
        action="store_true",
        help="Allow creating new GitHub issues when --apply-actions is set",
    )
    discovery.add_argument(
        "--enable-update-issues",
        action="store_true",
        help="Allow commenting on existing issues with recommended updates when --apply-actions is set",
    )

    cleanup = subparsers.add_parser(
        "cleanup", help="Run advisory cleanup recommendation"
    )
    _add_common_io_args(cleanup, "reports/cleanup.json")
    _add_model_args(cleanup)
    _add_advisory_repo_arg(cleanup, "read/mutate")
    cleanup.add_argument(
        "--issues-fixture", help="JSON/YAML fixture containing GitHub issues"
    )
    cleanup.add_argument(
        "--sbom-fixture", help="SPDX JSON fixture for the Stable production SBOM"
    )
    cleanup.add_argument(
        "--apply-actions",
        action="store_true",
        help="Apply guarded GitHub actions after producing validated records",
    )
    cleanup.add_argument(
        "--enable-post-cleanup-comments",
        action="store_true",
        help="Allow posting cleanup comments when --apply-actions is set",
    )
    cleanup.add_argument(
        "--enable-close-issues",
        action="store_true",
        help="Allow closing remediated issues when --apply-actions is set",
    )

    _add_review_parser(subparsers)
    return parser


def _add_advisory_repo_arg(parser: argparse.ArgumentParser, verb: str) -> None:
    parser.add_argument(
        "--advisory-repo",
        help=(
            f"Repository whose advisory issues are {verb} "
            f"(env: SECURITY_TRIAGE_ADVISORY_REPO; default: {TARGET_REPO})"
        ),
    )


def _add_review_context_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--discovery-json",
        help=(
            "Path to a discovery JSON/YAML document produced by "
            "`security-triage discovery`"
        ),
    )
    parser.add_argument(
        "--cleanup-json",
        help=(
            "Path to a cleanup JSON/YAML document produced by `security-triage cleanup`"
        ),
    )
    parser.add_argument(
        "--advisory-repo",
        help=(
            "Repository whose advisory issues the batch describes "
            "(env: SECURITY_TRIAGE_ADVISORY_REPO); required, no implicit default"
        ),
    )
    parser.add_argument(
        "--review-repo",
        help=(
            "Repository the review issue lives/would live in "
            "(env: SECURITY_TRIAGE_REVIEW_REPO); required, no implicit default"
        ),
    )
    parser.add_argument(
        "--run-id",
        help=(
            "Stable batch identifier, typically the GitHub Actions run ID "
            "(env: GITHUB_RUN_ID; falls back to a local timestamp)"
        ),
    )
    parser.add_argument(
        "--run-url",
        help=(
            "Workflow run URL shown in the review header (default: derived "
            "from GITHUB_SERVER_URL/GITHUB_REPOSITORY/GITHUB_RUN_ID)"
        ),
    )
    parser.add_argument(
        "--commit-sha", help="Commit SHA shown in the review header (env: GITHUB_SHA)"
    )
    parser.add_argument(
        "--window-start",
        help="Discovery processing window start, shown for context only",
    )
    parser.add_argument(
        "--window-end", help="Discovery processing window end, shown for context only"
    )
    parser.add_argument(
        "--discovery-report-url",
        help="Link to an uploaded discovery report artifact, shown for context only",
    )
    parser.add_argument(
        "--cleanup-report-url",
        help="Link to an uploaded cleanup report artifact, shown for context only",
    )
    parser.add_argument(
        "--max-part-body-chars",
        type=int,
        default=DEFAULT_MAX_PART_BODY_CHARS,
        help=(
            "Soft per-part issue body size budget before splitting into "
            f"additional parts (default: {DEFAULT_MAX_PART_BODY_CHARS})"
        ),
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress progress logging on stderr"
    )


def _add_review_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    review = subparsers.add_parser(
        "review",
        help="Human-gated review-issue workflow (create, local dry-run render, apply)",
    )
    review_subparsers = review.add_subparsers(dest="review_command", required=True)

    review_create = review_subparsers.add_parser(
        "create",
        help=(
            "Render review issue part(s) from discovery/cleanup documents "
            "and create them idempotently"
        ),
    )
    _add_review_context_args(review_create)
    review_create.add_argument(
        "--output",
        default="reports/review-create.json",
        help="Machine-readable JSON output path for created/existing issue URLs",
    )
    review_create.add_argument(
        "--job-summary-output",
        help=(
            "Optional Markdown job-summary path (default: $GITHUB_STEP_SUMMARY if set)"
        ),
    )

    review_render = review_subparsers.add_parser(
        "render",
        help=(
            "Render the exact would-be review issue Markdown to local "
            "file(s); makes no GitHub API calls (dry run)"
        ),
    )
    _add_review_context_args(review_render)
    review_render.add_argument(
        "--output-dir",
        default="reports/review-dry-run",
        help=(
            "Directory to write one Markdown file per review part plus a "
            "dry-run-summary.md (default: reports/review-dry-run)"
        ),
    )

    review_apply = review_subparsers.add_parser(
        "apply", help="Apply a closed review issue's checked, conflict-free actions"
    )
    review_apply.add_argument(
        "--issue-number",
        type=int,
        required=True,
        help=(
            "Review issue number (from the issues.closed webhook or a "
            "workflow_dispatch input)"
        ),
    )
    review_apply.add_argument(
        "--advisory-repo",
        help=(
            "Repository whose advisory issues are mutated "
            "(env: SECURITY_TRIAGE_ADVISORY_REPO); required, no implicit default"
        ),
    )
    review_apply.add_argument(
        "--review-repo",
        help=(
            "Repository the review issue lives in "
            "(env: SECURITY_TRIAGE_REVIEW_REPO); required, no implicit default"
        ),
    )
    review_apply.add_argument(
        "--enable-create-issues",
        action="store_true",
        help="Allow creating new GitHub issues for approved create actions",
    )
    review_apply.add_argument(
        "--enable-update-issues",
        action="store_true",
        help="Allow additive body updates/comments for approved update actions",
    )
    review_apply.add_argument(
        "--enable-post-cleanup-comments",
        action="store_true",
        help="Allow posting cleanup remediation comments for approved cleanup actions",
    )
    review_apply.add_argument(
        "--enable-close-issues",
        action="store_true",
        help=(
            "Allow closing advisory issues for approved comment-and-close "
            "cleanup actions"
        ),
    )
    review_apply.add_argument(
        "--enable-all-review-actions",
        action="store_true",
        help="Shortcut enabling all four --enable-* mutation flags above",
    )
    review_apply.add_argument(
        "--output",
        default="reports/review-apply.json",
        help="Machine-readable JSON output path for the execution summary",
    )
    review_apply.add_argument("--debug-log", help="Optional JSONL debug log path")
    review_apply.add_argument(
        "--quiet", action="store_true", help="Suppress progress logging on stderr"
    )


def run_discovery_command(args: argparse.Namespace) -> int:
    progress = ProgressLogger(enabled=not args.quiet)
    progress.section("Starting Flatcar vulnerability discovery")
    debug_logger = DebugLogger(args.debug_log)
    advisory_repo = _resolve_advisory_repo(args)
    window_start, window_end = _window(args)
    progress.info(f"Processing window: {window_start} to {window_end}")
    progress.info(f"Advisory repository: {advisory_repo}")
    model_client = _model_client(args, debug_logger, progress)
    if args.issues_fixture:
        progress.info(f"Loading issue fixture: {args.issues_fixture}")
        issues = load_issue_fixture(args.issues_fixture)
    else:
        progress.info("Fetching open Flatcar advisory issues from GitHub")
        issues = GitHubIssueClient(repo=advisory_repo).fetch_open_advisory_issues()
    progress.info(f"Loaded {len(issues)} open advisory issue(s)")
    if args.sbom_fixture:
        progress.info(f"Loading SBOM fixture: {args.sbom_fixture}")
        sbom_index = load_sbom_fixture(args.sbom_fixture)
    else:
        progress.info("Fetching current Flatcar production SBOM")
        sbom_index = fetch_flatcar_production_sbom()
    progress.info(f"Loaded SBOM with {len(sbom_index.packages)} package(s)")
    if args.source_fixture:
        fixture_start = window_start if args.window_start else None
        fixture_end = window_end if args.window_end else None
        progress.info(f"Loading source fixture: {args.source_fixture}")
        entries = load_source_fixture(args.source_fixture, fixture_start, fixture_end)
        source_errors: list[dict[str, str]] = []
    else:
        progress.info("Fetching upstream security sources")
        entries, source_errors = fetch_live_sources(
            args.include_optional_sources,
            window_start,
            window_end,
            include_undated=args.include_undated_source_entries,
            progress_logger=progress,
            oss_security_cache_dir=args.oss_security_cache_dir,
            go_vulndb_cache_dir=args.go_vulndb_cache_dir,
            rustsec_cache_dir=args.rustsec_cache_dir,
        )
    progress.info(
        f"Loaded {len(entries)} upstream source entr{'y' if len(entries) == 1 else 'ies'}"
    )
    workflow = DiscoveryWorkflow(
        model_client,
        sbom_index,
        issues,
        debug_logger,
        progress,
        target_repo=advisory_repo,
    )
    document = workflow.run(entries, window_start, window_end)
    document["errors"].extend(source_errors)
    progress.info(f"Writing machine-readable output: {args.output}")
    write_document(args.output, document, _output_format(args))
    if args.markdown_output:
        progress.info(f"Writing Markdown report: {args.markdown_output}")
        write_markdown(args.markdown_output, render_discovery_markdown(document))
    if args.apply_actions:
        progress.info("Applying guarded GitHub discovery actions")
        flags = ActionFlags(
            create_issues=args.enable_create_issues,
            update_existing_issues=args.enable_update_issues,
        )
        runner = GitHubActionRunner(
            GitHubIssueClient(repo=advisory_repo), flags, debug_logger
        )
        action_results = runner.apply_discovery(document)
        debug_logger.log("discovery_action_results", results=action_results)
        progress.info(
            f"Completed {len(action_results)} guarded GitHub action result(s)"
        )
    progress.info("Discovery complete")
    print(f"wrote {args.output}")
    if args.markdown_output:
        print(f"wrote {args.markdown_output}")
    return 0


def run_cleanup_command(args: argparse.Namespace) -> int:
    progress = ProgressLogger(enabled=not args.quiet)
    progress.section("Starting Flatcar advisory cleanup recommendation")
    debug_logger = DebugLogger(args.debug_log)
    advisory_repo = _resolve_advisory_repo(args)
    progress.info(f"Advisory repository: {advisory_repo}")
    model_client = _model_client(args, debug_logger, progress)
    if args.issues_fixture:
        progress.info(f"Loading issue fixture: {args.issues_fixture}")
        issues = load_issue_fixture(args.issues_fixture)
    else:
        progress.info("Fetching open Flatcar advisory issues from GitHub")
        issues = GitHubIssueClient(repo=advisory_repo).fetch_open_advisory_issues()
    progress.info(f"Loaded {len(issues)} open advisory issue(s)")
    if args.sbom_fixture:
        progress.info(f"Loading SBOM fixture: {args.sbom_fixture}")
        sbom_index = load_sbom_fixture(args.sbom_fixture)
    else:
        progress.info("Fetching current Flatcar production SBOM")
        sbom_index = fetch_flatcar_production_sbom()
    progress.info(f"Loaded SBOM with {len(sbom_index.packages)} package(s)")
    workflow = CleanupWorkflow(
        model_client,
        sbom_index,
        issues,
        allow_close=args.enable_close_issues,
        debug_logger=debug_logger,
        progress_logger=progress,
        target_repo=advisory_repo,
    )
    document = workflow.run()
    progress.info(f"Writing machine-readable output: {args.output}")
    write_document(args.output, document, _output_format(args))
    if args.markdown_output:
        progress.info(f"Writing Markdown report: {args.markdown_output}")
        write_markdown(args.markdown_output, render_cleanup_markdown(document))
    if args.apply_actions:
        progress.info("Applying guarded GitHub cleanup actions")
        flags = ActionFlags(
            post_cleanup_comments=args.enable_post_cleanup_comments,
            close_issues=args.enable_close_issues,
        )
        runner = GitHubActionRunner(
            GitHubIssueClient(repo=advisory_repo), flags, debug_logger
        )
        action_results = runner.apply_cleanup(document)
        debug_logger.log("cleanup_action_results", results=action_results)
        progress.info(
            f"Completed {len(action_results)} guarded GitHub action result(s)"
        )
    progress.info("Cleanup recommendation complete")
    print(f"wrote {args.output}")
    if args.markdown_output:
        print(f"wrote {args.markdown_output}")
    return 0


def run_review_create_command(args: argparse.Namespace) -> int:
    progress = ProgressLogger(enabled=not args.quiet)
    progress.section("Building and creating security-triage review issue(s)")
    advisory_repo = _resolve_required_repo(
        args.advisory_repo, "SECURITY_TRIAGE_ADVISORY_REPO", "--advisory-repo"
    )
    review_repo = _resolve_required_repo(
        args.review_repo, "SECURITY_TRIAGE_REVIEW_REPO", "--review-repo"
    )
    _warn_if_cross_repo(advisory_repo, review_repo)
    progress.info(
        f"Advisory repository: {advisory_repo}; review repository: {review_repo}"
    )

    discovery_document = _load_optional_document(
        args.discovery_json, validate_discovery_document
    )
    cleanup_document = _load_optional_document(
        args.cleanup_json, validate_cleanup_document
    )
    context = _build_review_context(args, advisory_repo, review_repo)
    batch = build_review_batch(context, discovery_document, cleanup_document)

    if not batch.groups:
        progress.info(
            "No decision groups were produced by the supplied documents; "
            "skipping review issue creation"
        )
        write_json_file(
            args.output, {"batch_id": batch.batch_id, "created": False, "parts": []}
        )
        print(f"wrote {args.output}")
        return 0

    progress.info(
        f"Built {len(batch.parts)} review part(s) covering "
        f"{len(batch.groups)} decision group(s)"
    )
    client = GitHubIssueClient(repo=review_repo)
    results = create_review_batch(client, batch)
    for result in results:
        verb = "created" if result.created else "already exists (idempotent rerun)"
        progress.info(
            f"Part {result.part_index}/{result.part_count}: "
            f"{verb} -> {result.issue_url}"
        )

    write_json_file(
        args.output,
        {
            "batch_id": batch.batch_id,
            "created": True,
            "parts": [
                {
                    "part_id": result.part_id,
                    "part_index": result.part_index,
                    "part_count": result.part_count,
                    "issue_number": result.issue_number,
                    "issue_url": result.issue_url,
                    "created": result.created,
                }
                for result in results
            ],
        },
    )
    _write_job_summary(args, render_create_job_summary(results))
    print(f"wrote {args.output}")
    return 0


def run_review_render_command(args: argparse.Namespace) -> int:
    progress = ProgressLogger(enabled=not args.quiet)
    progress.section(
        "Rendering security-triage review batch locally (dry run; no GitHub API calls)"
    )
    advisory_repo = _resolve_required_repo(
        args.advisory_repo, "SECURITY_TRIAGE_ADVISORY_REPO", "--advisory-repo"
    )
    review_repo = _resolve_required_repo(
        args.review_repo, "SECURITY_TRIAGE_REVIEW_REPO", "--review-repo"
    )
    progress.info(
        f"Advisory repository: {advisory_repo}; review repository: {review_repo}"
    )

    discovery_document = _load_optional_document(
        args.discovery_json, validate_discovery_document
    )
    cleanup_document = _load_optional_document(
        args.cleanup_json, validate_cleanup_document
    )
    context = _build_review_context(args, advisory_repo, review_repo)
    batch, paths = render_dry_run(
        context, args.output_dir, discovery_document, cleanup_document
    )
    progress.info(
        f"Rendered {len(batch.parts)} review part(s) covering "
        f"{len(batch.groups)} decision group(s); wrote {len(paths)} file(s)"
    )
    for path in paths:
        print(f"wrote {path}")
    return 0


def run_review_apply_command(args: argparse.Namespace) -> int:
    progress = ProgressLogger(enabled=not args.quiet)
    progress.section(f"Applying security-triage review issue #{args.issue_number}")
    debug_logger = DebugLogger(args.debug_log)
    advisory_repo = _resolve_required_repo(
        args.advisory_repo, "SECURITY_TRIAGE_ADVISORY_REPO", "--advisory-repo"
    )
    review_repo = _resolve_required_repo(
        args.review_repo, "SECURITY_TRIAGE_REVIEW_REPO", "--review-repo"
    )
    progress.info(
        f"Advisory repository: {advisory_repo}; review repository: {review_repo}"
    )

    apply_context = ApplyContext(advisory_repo=advisory_repo, review_repo=review_repo)
    review_client = GitHubIssueClient(repo=review_repo)
    advisory_client = GitHubIssueClient(repo=advisory_repo)
    enable_all = args.enable_all_review_actions
    flags = ActionFlags(
        create_issues=args.enable_create_issues or enable_all,
        update_existing_issues=args.enable_update_issues or enable_all,
        post_cleanup_comments=args.enable_post_cleanup_comments or enable_all,
        close_issues=args.enable_close_issues or enable_all,
    )
    runner = GitHubActionRunner(advisory_client, flags, debug_logger)
    result = apply_review_issue(
        review_client,
        advisory_client,
        runner,
        args.issue_number,
        apply_context,
        progress,
        debug_logger,
    )
    write_json_file(args.output, result)
    print(f"wrote {args.output}")
    reason_suffix = f" ({result['reason']})" if result.get("reason") else ""
    progress.info(f"Apply outcome: {result['outcome']}{reason_suffix}")
    return 1 if result["outcome"] in {"failed", "partial_failure"} else 0


def _add_common_io_args(parser: argparse.ArgumentParser, default_output: str) -> None:
    parser.add_argument(
        "--output",
        default=default_output,
        help="Machine-readable JSON/YAML output path",
    )
    parser.add_argument(
        "--format",
        choices=["json", "yaml"],
        help="Output format; inferred from --output by default",
    )
    parser.add_argument(
        "--markdown-output", help="Optional human-readable Markdown report path"
    )
    parser.add_argument("--debug-log", help="Optional JSONL debug log path")
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress progress logging on stderr"
    )


def _add_model_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--model",
        choices=["heuristic", "github", "foundry", "fixture"],
        default="heuristic",
        help="Model provider to use",
    )
    parser.add_argument(
        "--model-fixture",
        help="JSON/YAML fixture with model responses; implies --model fixture",
    )
    parser.add_argument(
        "--extraction-model",
        help="Optional cheap-tier GitHub Models model name used only for the first-pass extract_advisory call (e.g. openai/gpt-4o-mini). Requires --model github.",
    )
    parser.add_argument(
        "--foundry-endpoint",
        help="Microsoft Foundry/Azure OpenAI endpoint base URL (env: FOUNDRY_ENDPOINT; required for --model foundry)",
    )
    parser.add_argument(
        "--foundry-deployment",
        help=f"Foundry deployment for reasoning and cleanup (env: FOUNDRY_DEPLOYMENT; default: {DEFAULT_FOUNDRY_DEPLOYMENT})",
    )
    parser.add_argument(
        "--foundry-extraction-deployment",
        help=f"Foundry deployment for extract_advisory calls (env: FOUNDRY_EXTRACTION_DEPLOYMENT; default: {DEFAULT_FOUNDRY_EXTRACTION_DEPLOYMENT})",
    )
    parser.add_argument(
        "--foundry-api-version",
        help=f"Foundry chat completions API version: dated value for legacy deployment endpoints, v1/preview for OpenAI v1 endpoints (env: FOUNDRY_API_VERSION; default: {DEFAULT_FOUNDRY_API_VERSION})",
    )
    parser.add_argument(
        "--prompt-cache-dir",
        help="Directory to cache model prompt responses between runs (env: FLATCAR_PROMPT_CACHE_DIR)",
    )


def _model_client(
    args: argparse.Namespace, debug_logger: DebugLogger, progress: ProgressLogger
) -> BaseModelClient:
    if args.model_fixture:
        progress.info(f"Using fixture model responses: {args.model_fixture}")
        return FixtureModelClient(args.model_fixture, fallback=HeuristicModelClient())
    if args.model == "fixture":
        raise ValueError("--model fixture requires --model-fixture")
    if args.model == "github":
        progress.info("Using GitHub Models for extraction and reasoning")
        cache = _prompt_cache(args, progress)
        primary = GitHubModelsClient(
            debug_logger=debug_logger, progress_logger=progress, prompt_cache=cache
        )
        extraction_model = getattr(args, "extraction_model", None)
        if extraction_model:
            progress.info(
                f"Using cheap-tier extraction model for first pass: {extraction_model}"
            )
            extraction = GitHubModelsClient(
                model=extraction_model,
                debug_logger=debug_logger,
                progress_logger=progress,
                prompt_cache=cache,
            )
            return RoutingModelClient(primary=primary, extraction=extraction)
        return primary
    if args.model == "foundry":
        if getattr(args, "extraction_model", None):
            raise ValueError(
                "--extraction-model requires --model github; use --foundry-extraction-deployment with --model foundry"
            )
        progress.info("Using Microsoft Foundry for extraction and reasoning")
        cache = _prompt_cache(args, progress)
        primary = FoundryModelsClient(
            endpoint=args.foundry_endpoint,
            deployment=args.foundry_deployment,
            api_version=args.foundry_api_version,
            debug_logger=debug_logger,
            progress_logger=progress,
            prompt_cache=cache,
        )
        extraction_deployment = (
            args.foundry_extraction_deployment
            or os.getenv("FOUNDRY_EXTRACTION_DEPLOYMENT")
            or DEFAULT_FOUNDRY_EXTRACTION_DEPLOYMENT
        )
        progress.info(
            f"Using Foundry extraction deployment for first pass: {extraction_deployment}"
        )
        extraction = FoundryModelsClient(
            endpoint=args.foundry_endpoint,
            deployment=extraction_deployment,
            api_version=args.foundry_api_version,
            debug_logger=debug_logger,
            progress_logger=progress,
            prompt_cache=cache,
        )
        return RoutingModelClient(primary=primary, extraction=extraction)
    if getattr(args, "extraction_model", None):
        raise ValueError("--extraction-model requires --model github")
    progress.info("Using local conservative heuristic model")
    return HeuristicModelClient()


def _prompt_cache(
    args: argparse.Namespace, progress: ProgressLogger
) -> PromptCache | None:
    directory = getattr(args, "prompt_cache_dir", None) or os.getenv(
        "FLATCAR_PROMPT_CACHE_DIR"
    )
    if not directory:
        return None
    progress.info(f"Prompt cache enabled at {directory}")
    return PromptCache(directory)


def _window(args: argparse.Namespace) -> tuple[str, str]:
    if args.window_start and args.window_end:
        return args.window_start, args.window_end
    start, end = default_processing_window(args.window_days)
    return args.window_start or start, args.window_end or end


def _output_format(args: argparse.Namespace) -> str:
    if args.format:
        return str(args.format)
    suffix = Path(args.output).suffix.lower()
    return "yaml" if suffix in {".yaml", ".yml"} else "json"


def _resolve_advisory_repo(args: argparse.Namespace) -> str:
    """Resolve the advisory repository for discovery/cleanup, defaulting to
    ``TARGET_REPO``.

    Preserves existing standalone behavior (``flatcar/Flatcar``) when neither
    ``--advisory-repo`` nor ``SECURITY_TRIAGE_ADVISORY_REPO`` is set.
    """
    return validate_repo_name(
        args.advisory_repo or os.getenv("SECURITY_TRIAGE_ADVISORY_REPO") or TARGET_REPO
    )


def _resolve_required_repo(cli_value: str | None, env_name: str, flag_name: str) -> str:
    """Resolve a repository for the review commands, which require an explicit value.

    Unlike ``_resolve_advisory_repo``, this never silently falls back to
    ``flatcar/Flatcar``: review creation/application must be told exactly
    which repositories to use.
    """
    resolved = cli_value or os.getenv(env_name)
    if not resolved:
        raise ValueError(
            f"{flag_name} is required for this command "
            f"(or set the {env_name} environment variable)"
        )
    return validate_repo_name(resolved)


def _warn_if_cross_repo(advisory_repo: str, review_repo: str) -> None:
    if advisory_repo != review_repo:
        print(
            f"warning: advisory repo {advisory_repo!r} differs from review "
            f"repo {review_repo!r}; "
            "the configured GITHUB_TOKEN must have write access to both repositories "
            "(a same-repository Actions GITHUB_TOKEN cannot mutate a "
            "different repository; "
            "use a narrowly scoped GitHub App installation token instead)",
            file=sys.stderr,
        )


def _load_optional_document(
    path: str | None, validator: Callable[[dict[str, Any]], None]
) -> dict[str, Any] | None:
    if not path:
        return None
    document = load_structured_file(path)
    if not isinstance(document, dict):
        raise ValueError(f"{path} must contain a JSON/YAML object")
    validator(document)
    return document


def _write_job_summary(args: argparse.Namespace, summary: str) -> None:
    job_summary_path = getattr(args, "job_summary_output", None) or os.getenv(
        "GITHUB_STEP_SUMMARY"
    )
    if not job_summary_path:
        return
    Path(job_summary_path).parent.mkdir(parents=True, exist_ok=True)
    with open(job_summary_path, "a", encoding="utf-8") as handle:
        handle.write(summary)


def _default_run_id() -> str:
    run_id = os.getenv("GITHUB_RUN_ID")
    if run_id:
        return run_id
    # Fallback for local/manual invocations without a GitHub Actions run ID:
    # a filesystem- and HTML-comment-safe slug derived from the current UTC
    # timestamp. Reruns of this fallback are not idempotent (unlike a real
    # GITHUB_RUN_ID), which is expected for ad hoc local usage.
    return "local-" + iso_now().translate(str.maketrans("+", "p", ":-."))


def _default_run_url() -> str:
    server = os.getenv("GITHUB_SERVER_URL")
    repo = os.getenv("GITHUB_REPOSITORY")
    run_id = os.getenv("GITHUB_RUN_ID")
    if server and repo and run_id:
        return f"{server}/{repo}/actions/runs/{run_id}"
    return ""


def _build_review_context(
    args: argparse.Namespace, advisory_repo: str, review_repo: str
) -> ReviewContext:
    return ReviewContext(
        advisory_repo=advisory_repo,
        review_repo=review_repo,
        run_id=args.run_id or _default_run_id(),
        generated_at=iso_now(),
        run_url=args.run_url or _default_run_url(),
        commit_sha=args.commit_sha or os.getenv("GITHUB_SHA") or "",
        window_start=args.window_start,
        window_end=args.window_end,
        discovery_report_url=args.discovery_report_url,
        cleanup_report_url=args.cleanup_report_url,
        max_part_body_chars=args.max_part_body_chars,
    )


if __name__ == "__main__":
    raise SystemExit(main())
