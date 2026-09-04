"""`secscan` command-line interface — the unified command surface.

    secscan init <dir> [--ai <agent>] install the skill and/or generate config
    secscan run                       run a scan (resumes automatically)
    secscan status <dir>              show what is installed / configured
    secscan report                    re-render the latest report
    secscan data                      inspect the shipped knowledge bases
    secscan agents                    list supported coding agents
    secscan version                   print versions
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import click

from installer import core
from installer.agents import describe, supported
from pipeline.state import SCAN_DIR_NAME, TOOL_VERSION


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(TOOL_VERSION, prog_name="secscan")
def main() -> None:
    """Hierarchical, context-bounded security scanning for large codebases."""


@main.command("init")
@click.argument(
    "project",
    type=click.Path(file_okay=False, path_type=Path),
    default=".",
    required=False,
)
@click.option(
    "--ai",
    "agent",
    default=None,
    type=click.Choice(supported(), case_sensitive=False),
    help="Coding agent to install the skill into (omit to configure only).",
)
@click.option("--force", is_flag=True, help="Allow downgrading an newer installed version.")
@click.option(
    "--commit-artifacts",
    is_flag=True,
    help="Do not gitignore .secscan/ (scan artifacts will be committed).",
)
@click.option(
    "--no-init",
    is_flag=True,
    help="Install the skill without generating configuration or running environment checks.",
)
@click.option(
    "--install",
    default=None,
    metavar="TOOLS",
    help="Install missing applicable external tools without prompting "
    "('all' or comma-separated ids, e.g. --install=npm-audit,osv-scanner).",
)
@click.option(
    "--yes",
    is_flag=True,
    help="Confirm the full presented install list (equivalent to --install=all).",
)
@click.option(
    "--no-input",
    is_flag=True,
    help="Never prompt; skip installation with a declared note.",
)
def init_command(
    project: Path,
    agent: str | None,
    force: bool,
    commit_artifacts: bool,
    no_init: bool,
    install: str | None,
    yes: bool,
    no_input: bool,
) -> None:
    """Set up secscan in PROJECT: install the skill (--ai), generate config, check env."""
    if agent is not None:
        try:
            result = core.install(
                project, agent.lower(), force=force, commit_artifacts=commit_artifacts
            )
        except core.InstallError as exc:
            raise click.ClickException(str(exc)) from None

        click.echo(result.render())
        if no_init:
            return

    from pipeline.init_cmd import run_init

    click.echo("")
    report = run_init(project, install=install, yes=yes, no_input=no_input)
    click.echo(report.render())
    if not report.ready:
        sys.exit(1)


@main.command("run")
@click.option("--profile", default=None, help="quick | full | audit | custom profile name")
@click.option("--segment", default=None, help="Re-run analysis for one segment only.")
@click.option("--full", is_flag=True, help="Force a full scan (ignore checkpoints).")
@click.option(
    "--set",
    "overrides",
    multiple=True,
    metavar="KEY=VALUE",
    help="Override a profile setting, e.g. --set report_thresholds.min_confidence=0.8",
)
@click.option(
    "--policy",
    type=click.Choice(("auto", "interactive", "batch", "batch-offpeak")),
    default=None,
    help=(
        "Execution policy for this scan (default: config value; "
        "auto = batch when an endpoint is configured)."
    ),
)
@click.option(
    "--tool-timeout",
    type=int,
    default=None,
    metavar="SECONDS",
    help="Per-tool wall-clock ceiling for external tools (overrides tooling.timeout_s).",
)
@click.option(
    "--output",
    type=click.Choice(("quiet", "default", "verbose")),
    default=None,
    help="Progress output level on stderr (overrides output.level; default: default).",
)
@click.option(
    "-q", "quiet", is_flag=True, help="Progress off: final summary only (--output quiet)."
)
@click.option(
    "-v", "verbose", is_flag=True,
    help="Per-segment budget/escalation and per-tool detail (--output verbose).",
)
@click.option(
    "--workdir",
    type=click.Path(file_okay=False, path_type=Path),
    default=".",
    help="Scan root (default: current directory).",
)
def run_command(
    profile: str | None,
    segment: str | None,
    full: bool,
    overrides: tuple[str, ...],
    policy: str | None,
    tool_timeout: int | None,
    output: str | None,
    quiet: bool,
    verbose: bool,
    workdir: Path,
) -> None:
    """Run a scan. Progress is printed to stderr; the summary to stdout."""
    from pipeline import scan_cli

    chosen = [name for name, flag in (("-q", quiet), ("-v", verbose), ("--output", output)) if flag]
    if len(chosen) > 1:
        raise click.UsageError(f"{' and '.join(chosen)} cannot be combined")
    if quiet:
        output = "quiet"
    elif verbose:
        output = "verbose"

    args = argparse.Namespace(
        workdir=workdir,
        profile=profile,
        overrides=list(overrides),
        policy=policy,
        tool_timeout=tool_timeout,
        full=full,
        segment=segment,
        output=output,
    )
    sys.exit(scan_cli.cmd_run(args))


@main.command("status")
@click.argument(
    "project",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    required=False,
)
def status_command(project: Path) -> None:
    """Show installed skills and scan state for PROJECT."""
    installs = core.detect_installs(project)
    if not installs:
        click.echo(f"No secscan skill installed in {project}.")
        click.echo(f"Install one with: secscan init {project} --ai <agent>")
        return

    click.echo(f"Installed in {Path(project).resolve()}:")
    for manifest in installs:
        click.echo(
            f"  {manifest['agent']:10} v{manifest['tool_version']}"
            f"  invoke: {manifest['invocation']}"
        )

    scan_dir = Path(project) / SCAN_DIR_NAME
    if not (scan_dir / "config.yaml").exists():
        click.echo("")
        click.echo("Not configured yet. Run: secscan init --ai <agent>  (or python -m "
                   "pipeline.init_cmd --workdir .)")
        return

    from pipeline.state import ArtifactStore

    store = ArtifactStore(project)
    click.echo("")
    click.echo(f"Scan state ({store.scan_id}):")
    for stage, state in store.stage_summary().items():
        click.echo(f"  {stage.ljust(20)} {state}")

    pending = sorted((scan_dir / "handoff" / "requests").glob("*.json"))
    answered = sorted((scan_dir / "handoff" / "responses").glob("*.json"))
    if pending:
        click.echo("")
        click.echo(f"Agent handoff: {len(answered)}/{len(pending)} request(s) answered")
        if len(answered) < len(pending):
            click.echo(f"  answer the rest in {scan_dir / 'handoff' / 'responses'}, then re-run")

    reports = sorted((scan_dir / "reports").glob("*.md"))
    if reports:
        click.echo("")
        click.echo(f"Latest report: {reports[-1]}")


@main.command("report")
@click.option("--repo", default=None, help="Filter to one repository's findings.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(("markdown", "json", "html")),
    default="markdown",
    help="Output format (default: markdown).",
)
@click.option(
    "--workdir",
    type=click.Path(file_okay=False, path_type=Path),
    default=".",
    help="Scan root (default: current directory).",
)
def report_command(repo: str | None, output_format: str, workdir: Path) -> None:
    """Re-render the latest report from artifacts."""
    from pipeline import scan_cli

    args = argparse.Namespace(workdir=workdir, repo=repo, format=output_format)
    sys.exit(scan_cli.cmd_report(args))


@main.command("data")
@click.option(
    "--refresh-eol",
    is_flag=True,
    help="Print instructions for refreshing the end-of-support snapshot.",
)
def data_command(refresh_eol: bool) -> None:
    """Inspect the shipped knowledge bases and their staleness."""
    from pipeline import scan_cli

    args = argparse.Namespace(refresh_eol=refresh_eol)
    sys.exit(scan_cli.cmd_data(args))


@main.command("agents")
def agents_command() -> None:
    """List supported coding agents and where each expects skills."""
    rows = describe()
    width = max(len(key) for key, _, _ in rows)
    label_width = max(len(label) for _, label, _ in rows)
    click.echo("Supported agents (--ai):")
    for key, label, path in rows:
        click.echo(f"  {key.ljust(width)}  {label.ljust(label_width)}  {path}/")


@main.command("version")
def version_command() -> None:
    """Print component versions."""
    from pipeline.schemas import SCHEMA_VERSION

    click.echo(f"secscan            {TOOL_VERSION}")
    click.echo(f"artifact schema    {SCHEMA_VERSION}")
    click.echo(f"config schema      {core.CONFIG_SCHEMA_VERSION}")


if __name__ == "__main__":  # pragma: no cover
    main()
