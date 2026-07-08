from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .actions import ActionFlags, GitHubActionRunner
from .cleanup import CleanupWorkflow
from .console import ProgressLogger
from .debug import DebugLogger
from .discovery import DiscoveryWorkflow
from .env import load_dotenv
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
from .rules import SCHEMA_VERSION
from .sbom import fetch_flatcar_production_sbom, load_sbom_fixture
from .sources import fetch_live_sources, load_source_fixture
from .time_utils import default_processing_window


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "discovery":
            return run_discovery_command(args)
        if args.command == "cleanup":
            return run_cleanup_command(args)
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
    return parser


def run_discovery_command(args: argparse.Namespace) -> int:
    progress = ProgressLogger(enabled=not args.quiet)
    progress.section("Starting Flatcar vulnerability discovery")
    debug_logger = DebugLogger(args.debug_log)
    window_start, window_end = _window(args)
    progress.info(f"Processing window: {window_start} to {window_end}")
    model_client = _model_client(args, debug_logger, progress)
    if args.issues_fixture:
        progress.info(f"Loading issue fixture: {args.issues_fixture}")
        issues = load_issue_fixture(args.issues_fixture)
    else:
        progress.info("Fetching open Flatcar advisory issues from GitHub")
        issues = GitHubIssueClient().fetch_open_advisory_issues()
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
        model_client, sbom_index, issues, debug_logger, progress
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
        runner = GitHubActionRunner(GitHubIssueClient(), flags, debug_logger)
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
    model_client = _model_client(args, debug_logger, progress)
    if args.issues_fixture:
        progress.info(f"Loading issue fixture: {args.issues_fixture}")
        issues = load_issue_fixture(args.issues_fixture)
    else:
        progress.info("Fetching open Flatcar advisory issues from GitHub")
        issues = GitHubIssueClient().fetch_open_advisory_issues()
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
        runner = GitHubActionRunner(GitHubIssueClient(), flags, debug_logger)
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


if __name__ == "__main__":
    raise SystemExit(main())
