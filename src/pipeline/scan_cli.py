"""`secscan` — the per-project scan command (contracts/cli-contracts.md).

This is the command the installer registers in the target agent (FR-022) and
the one `SKILL.md` instructs the agent to run. It works two ways:

* through the package's unified console script: ``secscan run`` (the commands
  here are re-exported by the installer CLI)
* from an installed skill payload: ``python -m pipeline.scan_cli run``

Subcommands: ``init``, ``run``, ``status``, ``report``, ``data``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NOT_READY = 2
EXIT_AGENT_HANDOFF = 3
#: The report published with narrative section(s) quarantined for referencing a
#: finding id not admitted to it (feature 014, FR-010). Artifacts exist; the
#: defect is declared in the report itself.
EXIT_REPORT_DEFECT = 4
#: Operator interrupt (Ctrl-C); the shell convention for SIGINT.
EXIT_INTERRUPTED = 130


def _parse_set(values: list[str] | None) -> dict[str, Any]:
    """Turn ``--set a.b=c`` pairs into a nested override mapping."""
    overrides: dict[str, Any] = {}
    for raw in values or []:
        if "=" not in raw:
            raise SystemExit(f"--set expects key=value, got: {raw!r}")
        key, value = raw.split("=", 1)
        node = overrides
        parts = [p for p in key.strip().split(".") if p]
        if not parts:
            raise SystemExit(f"--set expects a non-empty key, got: {raw!r}")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = _coerce(value.strip())
    return overrides


def _coerce(value: str) -> Any:
    lowered = value.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    try:
        return int(value) if "." not in value else float(value)
    except ValueError:
        return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="Hierarchical, context-bounded security scanning.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--workdir",
        type=Path,
        default=Path.cwd(),
        help="Scan root (default: current directory).",
    )

    init = sub.add_parser(
        "init",
        parents=[common],
        help="Generate default configuration and check the environment.",
    )
    init.add_argument(
        "--install",
        nargs="?",
        const="all",
        default=None,
        metavar="TOOLS",
        help="Install missing applicable external tools without prompting "
        "('all' or comma-separated ids, e.g. --install=npm-audit,osv-scanner).",
    )
    init.add_argument(
        "--yes",
        action="store_true",
        help="Confirm the full presented install list (equivalent to --install=all).",
    )
    init.add_argument(
        "--no-input",
        dest="no_input",
        action="store_true",
        help="Never prompt; skip installation with a declared note.",
    )

    run = sub.add_parser("run", parents=[common], help="Run a scan.")
    run.add_argument("--profile", default=None, help="quick | full | audit | custom profile name")
    run.add_argument(
        "--tool-timeout",
        type=int,
        default=None,
        metavar="SECONDS",
        help="Per-tool wall-clock ceiling for external tools (overrides tooling.timeout_s).",
    )
    run.add_argument(
        "--policy",
        choices=("auto", "interactive", "batch", "batch-offpeak"),
        default=None,
        help=(
            "Execution policy for this scan (default: config value; "
            "auto = batch when an endpoint is configured)."
        ),
    )
    run.add_argument(
        "--set",
        dest="overrides",
        action="append",
        metavar="KEY=VALUE",
        help="Override a profile setting, e.g. --set report_thresholds.min_confidence=0.8",
    )
    run.add_argument("--segment", default=None, help="Re-run analysis for one segment only.")
    run.add_argument("--full", action="store_true", help="Force a full scan (ignore checkpoints).")
    output = run.add_mutually_exclusive_group()
    output.add_argument(
        "--output",
        choices=("quiet", "default", "verbose"),
        default=None,
        help="Progress output level on stderr (overrides output.level; default: default).",
    )
    output.add_argument(
        "-q", dest="output", action="store_const", const="quiet",
        help="Progress off: final summary only (same as --output quiet).",
    )
    output.add_argument(
        "-v", dest="output", action="store_const", const="verbose",
        help="Per-segment budget/escalation and per-tool detail (same as --output verbose).",
    )

    sub.add_parser("status", parents=[common], help="Show install and scan state.")

    report = sub.add_parser(
        "report", parents=[common], help="Re-render the latest report from artifacts."
    )
    report.add_argument("--repo", default=None, help="Filter to one repository's findings.")
    report.add_argument(
        "--format",
        choices=("markdown", "json", "html"),
        default="markdown",
        help="Output format (default: markdown).",
    )

    data = sub.add_parser(
        "data",
        parents=[common],
        help="Inspect the shipped knowledge bases and their staleness.",
    )
    data.add_argument(
        "--refresh-eol",
        action="store_true",
        help=(
            "Print instructions for refreshing the end-of-support snapshot. "
            "Refresh is always an explicit operator action - the scanner never "
            "fetches over the network on its own."
        ),
    )

    return parser


# ------------------------------------------------------------------ commands


def cmd_data(args: argparse.Namespace) -> int:
    """Report knowledge-base versions and end-of-support staleness (FR-034).

    Staleness is reportable rather than silently tolerated: presenting expired
    support data as current would be the same unearned confidence this feature
    exists to remove.
    """
    from pipeline import applicability, controls, stack_currency, stacks

    age, stale = stack_currency.staleness()
    print("Shipped knowledge bases")
    print(f"  applicability.json      v{applicability.version()} "
          f"({len(applicability.governed_cwes())} weakness classes governed)")
    print(f"  framework_controls.json v{controls.version()} "
          f"({len(controls.frameworks())} frameworks)")
    print(f"  stacks.json             v{stacks.version()} "
          f"({len(stacks.grammar_backed_languages())} languages, "
          f"{len(stacks.ecosystems_for_grammar_backed())} ecosystems)")
    print(f"  eol.json                v{stack_currency.version()} "
          f"dated {stack_currency.dataset_date()} ({age} days old)")
    if stale:
        print(
            f"\n  ! The end-of-support snapshot is older than "
            f"{stack_currency.staleness_threshold_days()} days. Support conclusions "
            "drawn from it may be out of date; the report says so too."
        )
    if args.refresh_eol:
        print(
            "\nTo refresh the end-of-support snapshot (MIT-licensed source):\n"
            "  1. Fetch https://github.com/endoflife-date/release-data\n"
            "  2. Regenerate src/skill_core/data/eol.json from releases/*.json\n"
            "  3. Update dataset_date and re-run the test suite\n"
            "Deliberately manual: an implicit network fetch would break both the "
            "offline guarantee and byte-identical determinism."
        )
    return EXIT_OK


def cmd_init(args: argparse.Namespace) -> int:
    from pipeline.init_cmd import run_init

    report = run_init(
        args.workdir,
        install=args.install,
        yes=args.yes,
        no_input=args.no_input,
    )
    print(report.render())
    return EXIT_OK if report.ready else EXIT_NOT_READY


def cmd_run(args: argparse.Namespace) -> int:
    from config.loader import ConfigError, ConfigNotFound, load
    from pipeline import progress
    from pipeline import run as run_mod
    from pipeline.llm_client import AgentHandoff
    from pipeline.providers import EndpointError
    from pipeline.redact import Redactor
    from pipeline.state import LOG_FILE_NAME, SCAN_DIR_NAME

    overrides = _parse_set(args.overrides)
    environ_overrides = None
    output = getattr(args, "output", None)
    if args.policy or args.tool_timeout or output:
        # Execution policy, tooling timeout and output level are config, not
        # profile: use the documented env overrides (SECSCAN_<SECTION>_<KEY>).
        import os

        environ_overrides = dict(os.environ)
        if args.policy:
            environ_overrides["SECSCAN_EXECUTION_POLICY_MODE"] = args.policy
        if args.tool_timeout:
            environ_overrides["SECSCAN_TOOLING_TIMEOUT_S"] = str(args.tool_timeout)
        if output:
            environ_overrides["SECSCAN_OUTPUT_LEVEL"] = output

    # Config is loaded here, before any progress reporter exists: a project
    # that is not initialised gets today's guidance and nothing else — no
    # reporter, no scan.log, no .secscan/ directory (feature 011, R5).
    store_dir = Path(args.workdir).resolve() / SCAN_DIR_NAME
    try:
        config = load(store_dir, environ=environ_overrides)
    except (ConfigNotFound, ConfigError) as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR

    redactor = Redactor(config.redaction_patterns, **run_mod._entropy_kwargs(config))
    reporter = progress.build_reporter(
        progress.OutputLevel.from_str(config.output_level),
        stream=sys.stderr,
        log_path=store_dir / LOG_FILE_NAME,
    )
    try:
        result = run_mod.run_scan(
            args.workdir,
            profile=args.profile,
            overrides=overrides or None,
            full=args.full,
            only_segment=args.segment,
            environ=environ_overrides,
            progress=reporter,
        )
    except (ConfigNotFound, ConfigError) as exc:
        reporter.failed(str(exc).splitlines()[0])
        reporter.close()
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR
    except ValueError as exc:  # unknown segment / profile
        reporter.failed(str(exc))
        reporter.close()
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR
    except AgentHandoff as handoff:
        reporter.paused(len(handoff.pending))
        reporter.close()
        print(handoff.instructions())
        return EXIT_AGENT_HANDOFF
    except EndpointError as exc:
        # Exhausted retries or a terminal provider error (feature 012, FR-017): one
        # redacted line, no traceback; persisted answers make the re-run resume.
        message = redactor.redact(str(exc)).text
        reporter.failed(message)
        reporter.close()
        print(message, file=sys.stderr)
        where = f" from {exc.request_id}" if exc.request_id else ""
        print(
            "re-run to resume: segments already analysed are kept; the scan continues"
            f"{where}",
            file=sys.stderr,
        )
        return EXIT_ERROR
    except KeyboardInterrupt:
        outstanding = _open_batches(store_dir)
        reporter.interrupted(
            f"re-run to resume; {outstanding} batch(es) still processing at the provider"
            if outstanding
            else None
        )
        reporter.close()
        return EXIT_INTERRUPTED
    except Exception as exc:
        # Anything printed about a failure passes through the redactor first
        # (FR-015); the exception itself propagates exactly as before.
        reporter.failed(redactor.redact(str(exc)).text)
        reporter.close()
        raise
    reporter.close()

    print(f"scan {result.scan_id}: {len(result.reported_findings)} finding(s) reported")
    print(f"report: {result.report_path}")
    if result.warnings:
        print(f"({len(result.warnings)} coverage note(s) recorded in the report)")
    report_payload = result.report if isinstance(result.report, dict) else {}
    if report_payload.get("quarantined_sections"):
        return EXIT_REPORT_DEFECT
    return EXIT_OK


def _open_batches(store_dir: Path) -> int:
    """Provider batches still outstanding in the ledger (feature 012, FR-022)."""
    from pipeline.batch_runner import BatchLedger
    from pipeline.state import ArtifactStore

    try:
        return BatchLedger(ArtifactStore(store_dir.parent)).open_count()
    except (OSError, ValueError):
        return 0


def cmd_status(args: argparse.Namespace) -> int:
    from pipeline.state import SCAN_DIR_NAME, ArtifactStore

    root = Path(args.workdir).resolve()
    scan_dir = root / SCAN_DIR_NAME
    if not (scan_dir / "config.yaml").exists():
        print(f"Not configured: {root}")
        print("Run `secscan init` to generate configuration.")
        return EXIT_NOT_READY

    store = ArtifactStore(root)
    print(f"Scan root: {root}")
    print(f"Scan id:   {store.scan_id}")
    print("")
    print("Stages:")
    for stage, state in store.stage_summary().items():
        print(f"  {stage.ljust(20)} {state}")

    pending = sorted((scan_dir / "handoff" / "requests").glob("*.json"))
    answered = sorted((scan_dir / "handoff" / "responses").glob("*.json"))
    if pending:
        print("")
        print(f"Agent handoff: {len(answered)}/{len(pending)} request(s) answered")
        if len(answered) < len(pending):
            print(f"  answer the rest in {scan_dir / 'handoff' / 'responses'}, then re-run")

    reports = sorted((scan_dir / "reports").glob("*.md"))
    if reports:
        print("")
        print(f"Latest report: {reports[-1]}")
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    from pipeline.report_view import latest_report, render

    try:
        report = latest_report(args.workdir)
        rendered = render(report, repo=args.repo, output_format=args.format)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR
    except ValueError as exc:  # unknown repository, unsupported view
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR

    print(rendered)
    return EXIT_OK


_COMMANDS = {
    "init": cmd_init,
    "run": cmd_run,
    "status": cmd_status,
    "report": cmd_report,
    "data": cmd_data,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return _COMMANDS[args.command](args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
