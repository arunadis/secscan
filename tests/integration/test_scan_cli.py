"""`secscan` command surface (contracts/cli-contracts.md).

Covers the four documented subcommands and every documented flag, so the contract
and the implementation cannot drift apart again.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from installer import core as installer
from pipeline import scan_cli
from pipeline.report_view import filter_by_repo, latest_report
from tests.integration.conftest import oracle_responder, write_config


@pytest.fixture
def scanned(configured_shop: Path):
    from pipeline import run as run_mod

    run_mod.run_scan(configured_shop, responder=oracle_responder, full=True, profile="audit")
    return configured_shop


# ------------------------------------------------------------------ contract


def test_all_documented_subcommands_exist() -> None:
    parser = scan_cli.build_parser()
    actions = [a for a in parser._actions if a.dest == "command"]
    assert actions, "expected a subcommand action"
    assert set(actions[0].choices) == {"init", "run", "status", "report", "data"}


def test_run_accepts_every_documented_flag() -> None:
    args = scan_cli.build_parser().parse_args(
        [
            "run",
            "--workdir", ".",
            "--profile", "audit",
            "--policy", "batch-offpeak",
            "--set", "report_thresholds.min_confidence=0.8",
            "--segment", "seg-x",
            "--full",
        ]
    )
    assert args.profile == "audit"
    assert args.policy == "batch-offpeak"
    assert args.overrides == ["report_thresholds.min_confidence=0.8"]
    assert args.segment == "seg-x"
    assert args.full is True


def test_run_accepts_tool_timeout_flag() -> None:
    """Feature 008 contract: --tool-timeout SECONDS (contracts/cli.md)."""
    args = scan_cli.build_parser().parse_args(
        ["run", "--workdir", ".", "--tool-timeout", "60"]
    )
    assert args.tool_timeout == 60


def test_init_accepts_tooling_flags() -> None:
    """Feature 008 contract: --install / --yes / --no-input on init."""
    parser = scan_cli.build_parser()
    assert parser.parse_args(["init", "--install"]).install == "all"
    subset = parser.parse_args(["init", "--install", "npm-audit,osv-scanner"])
    assert subset.install == "npm-audit,osv-scanner"
    assert parser.parse_args(["init", "--yes"]).yes is True
    assert parser.parse_args(["init", "--no-input"]).no_input is True


def test_tool_timeout_env_override_applies_to_config(tmp_path: Path) -> None:
    """SECSCAN_TOOLING_TIMEOUT_S maps to tooling.timeout_s with validation."""
    from config import loader

    (tmp_path / "config.yaml").write_text("version: 1\n")
    config = loader.load(tmp_path, environ={"SECSCAN_TOOLING_TIMEOUT_S": "45"})
    assert config.tooling_timeout_s == 45
    with pytest.raises(loader.ConfigError):
        loader.load(tmp_path, environ={"SECSCAN_TOOLING_TIMEOUT_S": "0"})


def test_report_accepts_repo_and_format_flags() -> None:
    args = scan_cli.build_parser().parse_args(["report", "--repo", "orders", "--format", "json"])
    assert args.repo == "orders"
    assert args.format == "json"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (["a=1"], {"a": 1}),
        (["a.b=2.5"], {"a": {"b": 2.5}}),
        (["a=true"], {"a": True}),
        (["a=hello"], {"a": "hello"}),
        (["a.b.c=1", "a.b.d=2"], {"a": {"b": {"c": 1, "d": 2}}}),
    ],
)
def test_set_flag_builds_nested_overrides(raw: list[str], expected: dict) -> None:
    assert scan_cli._parse_set(raw) == expected


def test_set_flag_rejects_malformed_input() -> None:
    with pytest.raises(SystemExit):
        scan_cli._parse_set(["no-equals-sign"])


# ------------------------------------------------------------------ behaviour


def test_init_subcommand_generates_config(tmp_path: Path, capsys) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("x = 1\n")

    code = scan_cli.main(["init", "--workdir", str(project)])
    assert code == scan_cli.EXIT_OK
    assert (project / ".secscan" / "config.yaml").exists()
    assert "Ready to scan." in capsys.readouterr().out


def test_run_without_config_exits_with_guidance(tmp_path: Path, capsys) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("x = 1\n")

    code = scan_cli.main(["run", "--workdir", str(project)])
    assert code == scan_cli.EXIT_ERROR
    assert "init" in capsys.readouterr().err


def test_run_hands_off_to_agent_with_exit_code(configured_shop: Path, capsys) -> None:
    code = scan_cli.main(["run", "--workdir", str(configured_shop), "--full"])
    assert code == scan_cli.EXIT_AGENT_HANDOFF
    out = capsys.readouterr().out
    assert "handoff" in out.replace("\\", "/")
    assert "re-run" in out.lower()


def test_status_reports_stages_and_handoff(scanned: Path, capsys) -> None:
    code = scan_cli.main(["status", "--workdir", str(scanned)])
    assert code == scan_cli.EXIT_OK
    out = capsys.readouterr().out
    assert "generate_report" in out
    assert "Latest report:" in out


def test_status_on_unconfigured_project(tmp_path: Path, capsys) -> None:
    project = tmp_path / "bare"
    project.mkdir()
    code = scan_cli.main(["status", "--workdir", str(project)])
    assert code == scan_cli.EXIT_NOT_READY
    assert "init" in capsys.readouterr().out


def test_report_subcommand_rerenders_from_artifacts(scanned: Path, capsys) -> None:
    code = scan_cli.main(["report", "--workdir", str(scanned)])
    assert code == scan_cli.EXIT_OK
    out = capsys.readouterr().out
    assert "# Security Report" in out
    assert "#### Reproduction" in out


def test_report_json_format(scanned: Path, capsys) -> None:
    import json

    code = scan_cli.main(["report", "--workdir", str(scanned), "--format", "json"])
    assert code == scan_cli.EXIT_OK
    document = json.loads(capsys.readouterr().out)
    assert document["findings_by_band"]


def test_report_without_a_scan_is_a_clear_error(tmp_path: Path, capsys) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    write_config(project)
    code = scan_cli.main(["report", "--workdir", str(project)])
    assert code == scan_cli.EXIT_ERROR
    assert "no report found" in capsys.readouterr().err.lower()


def test_single_segment_run_scopes_analysis(configured_shop: Path) -> None:
    """SC-007: one segment can be re-run from artifacts."""
    from pipeline import run as run_mod

    first = run_mod.run_scan(configured_shop, responder=oracle_responder, full=True)
    target = next(s["id"] for s in first.segments if "orders" in s["id"])

    scoped = run_mod.run_scan(
        configured_shop, responder=oracle_responder, only_segment=target
    )
    assert [s["id"] for s in scoped.segments] == [target]
    assert any("single-segment run" in w for w in scoped.warnings)


def test_unknown_segment_is_rejected(configured_shop: Path) -> None:
    from pipeline import run as run_mod

    run_mod.run_scan(configured_shop, responder=oracle_responder, full=True)
    with pytest.raises(ValueError) as exc:
        run_mod.run_scan(configured_shop, responder=oracle_responder, only_segment="seg-nope")
    assert "unknown segment" in str(exc.value)


# --------------------------------------------------------------- repo views


def test_repo_view_is_a_projection_of_the_unified_report(scanned: Path) -> None:
    """FR-018: per-repository views are derivable from the unified report."""
    report = latest_report(scanned)
    repo = report["workspace"]["members"][0]
    view = filter_by_repo(report, repo)

    assert view["view"] == {
        "scope": "repository",
        "repo": repo,
        "derived_from": report["scan_id"],
    }
    assert view["workspace"]["members"] == [repo]
    assert view["coverage"]["repos_analyzed"] == [repo]

    total = sum(len(v) for v in report["findings_by_band"].values())
    kept = sum(len(v) for v in view["findings_by_band"].values())
    assert 0 < kept <= total
    for findings in view["findings_by_band"].values():
        for finding in findings:
            assert finding["location"]["repo"] == repo or any(
                e.get("repo") == repo for e in finding["evidence"]
            )


def test_repo_view_rejects_unknown_repository(scanned: Path) -> None:
    report = latest_report(scanned)
    with pytest.raises(ValueError) as exc:
        filter_by_repo(report, "not-a-member")
    assert "unknown repository" in str(exc.value)


def test_cli_reports_unknown_repo_cleanly(scanned: Path, capsys) -> None:
    """Errors must be actionable messages on stderr, never tracebacks."""
    code = scan_cli.main(["report", "--workdir", str(scanned), "--repo", "ghost"])
    assert code == scan_cli.EXIT_ERROR
    captured = capsys.readouterr()
    assert "unknown repository 'ghost'" in captured.err
    assert "Traceback" not in captured.err


def test_cli_reports_unknown_segment_cleanly(scanned: Path, capsys) -> None:
    code = scan_cli.main(["run", "--workdir", str(scanned), "--segment", "seg-nope"])
    assert code == scan_cli.EXIT_ERROR
    assert "unknown segment" in capsys.readouterr().err


def test_installed_skill_exposes_the_scan_cli(tmp_path: Path) -> None:
    """The scan CLI must travel with the installed payload."""
    project = tmp_path / "proj"
    project.mkdir()
    result = installer.install(project, "claude")
    assert (result.skill_dir / "scripts" / "pipeline" / "scan_cli.py").exists()
    assert (result.skill_dir / "scripts" / "pipeline" / "report_view.py").exists()
