"""Progress output for `secscan run` (feature 011, contracts/progress-output.md).

Covers the three user stories end to end: the stage/segment timeline (US1),
problems surfaced as they happen plus the scan log (US2), and output levels
(US3). The stdout summary is asserted verbatim throughout because installed
skills and scripts parse it.
"""

from __future__ import annotations

import io
import json
import os
import re
import stat
from pathlib import Path

import pytest

from pipeline import build_code_graph, discover_repo, progress, scan_cli
from pipeline import run as run_mod
from pipeline.progress import OutputLevel
from pipeline.state import LOG_FILE_NAME
from tests.integration.conftest import oracle_responder

_TAGS = "start|done |reuse|skip |fail |warn |wait |pause|stop |info "
_LINE = re.compile(rf"^\d{{2}}:\d{{2}}:\d{{2}} \+\d{{2}}:\d{{2}} ({_TAGS}) (.+)$")

#: Stages `run_scan` drives and therefore must announce (research R9).
DRIVEN_STAGES = (
    "discover_repo",
    "build_code_graph",
    "partition_repo",
    "segment_analysis",
    "misconfig",
    "compound",
    "llm_findings",
    "supply_chain",
    "agent_config",
    "external_tooling",
    "dependency_audits",
    "correlate_findings",
    "system_review",
    "generate_report",
)


def _events(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        m = _LINE.match(line)
        assert m, f"malformed progress line: {line!r}"
        out.append((m.group(1).strip(), m.group(2)))
    return out


def _run(root: Path, level: OutputLevel = OutputLevel.DEFAULT, **kwargs):
    stream = io.StringIO()
    reporter = progress.build_reporter(
        level, stream=stream, log_path=root / ".secscan" / LOG_FILE_NAME
    )
    try:
        result = run_mod.run_scan(
            root, responder=kwargs.pop("responder", oracle_responder), progress=reporter, **kwargs
        )
    finally:
        reporter.close()
    return result, stream.getvalue()


def _summary_lines(result) -> list[str]:
    lines = [
        f"scan {result.scan_id}: {len(result.reported_findings)} finding(s) reported",
        f"report: {result.report_path}",
    ]
    if result.warnings:
        lines.append(f"({len(result.warnings)} coverage note(s) recorded in the report)")
    return lines


# =================================================================== US1


def test_first_progress_line_precedes_stage_work(configured_shop: Path, monkeypatch) -> None:
    """FR-007: the operator sees output before any stage does work."""
    stream = io.StringIO()
    seen: list[str] = []
    real = discover_repo.run

    def spy(*args, **kwargs):
        seen.append(stream.getvalue())
        return real(*args, **kwargs)

    monkeypatch.setattr(discover_repo, "run", spy)
    reporter = progress.build_reporter(OutputLevel.DEFAULT, stream=stream, log_path=None)
    try:
        run_mod.run_scan(configured_shop, responder=oracle_responder, full=True, progress=reporter)
    finally:
        reporter.close()
    assert seen, "discover_repo never ran"
    events = _events(seen[0])
    assert events[0][0] == "start" and events[0][1].startswith("scan ")
    assert ("start", "discover_repo") in events


def test_every_driven_stage_is_announced(configured_shop: Path) -> None:
    _, err = _run(configured_shop, full=True)
    events = _events(err)
    for stage in DRIVEN_STAGES:
        started = ("start", stage) in events
        finished = any(
            tag in ("done", "skip") and text.split(" ")[0].rstrip(":") == stage
            for tag, text in events
        )
        assert started or finished, f"{stage} never announced"
        assert finished, f"{stage} started but never completed"


def test_reused_stages_are_reported_not_omitted(configured_shop: Path) -> None:
    _run(configured_shop, full=True)
    _, err = _run(configured_shop)
    events = _events(err)
    for stage in ("discover_repo", "build_code_graph", "partition_repo"):
        assert ("reuse", f"{stage} (checkpoint)") in events, f"{stage} not reported as reused"


def test_segment_progress_shows_index_of_total(configured_shop: Path) -> None:
    result, err = _run(configured_shop, full=True)
    total = len(result.segments)
    assert total >= 1
    events = _events(err)
    for index, segment in enumerate(result.segments, start=1):
        prefix = f"segment_analysis segment {index}/{total} {segment['id']}"
        assert ("start", prefix) in events
        assert any(tag == "done" and text.startswith(prefix + " (") for tag, text in events)


def test_single_segment_run_counts_one_of_one(configured_shop: Path) -> None:
    first, _ = _run(configured_shop, full=True)
    target = first.segments[0]["id"]
    _, err = _run(configured_shop, only_segment=target)
    events = _events(err)
    assert ("start", f"segment_analysis segment 1/1 {target}") in events
    assert any("single-segment run" in text for tag, text in events if tag == "warn")


def _with_oracle(monkeypatch) -> None:
    """Make the CLI path answer segments itself (no agent handoff)."""
    real = run_mod.run_scan
    monkeypatch.setattr(
        run_mod, "run_scan", lambda *a, **kw: real(*a, responder=oracle_responder, **kw)
    )


def test_stdout_summary_is_unchanged(configured_shop: Path, capsys, monkeypatch) -> None:
    """The three summary lines are a de-facto interface for skills and scripts."""
    from pipeline.state import ArtifactStore

    _with_oracle(monkeypatch)
    code = scan_cli.main(["run", "--workdir", str(configured_shop), "--full", "--profile", "audit"])
    captured = capsys.readouterr()
    assert code == scan_cli.EXIT_OK
    store = ArtifactStore(configured_shop)
    out = captured.out.splitlines()
    assert out[0].startswith(f"scan {store.scan_id}: ") and out[0].endswith(" finding(s) reported")
    assert out[1].startswith("report: ")
    assert 2 <= len(out) <= 3
    if len(out) == 3:
        assert re.fullmatch(r"\(\d+ coverage note\(s\) recorded in the report\)", out[2])
    assert all(_LINE.match(line) for line in captured.err.splitlines() if line)
    assert _events(captured.err)[-1][1].startswith("generate_report (")


# =================================================================== US2


def test_malformed_response_warning_is_printed_verbatim(configured_shop: Path) -> None:
    calls = {"n": 0}

    def flaky(request):
        calls["n"] += 1
        return "this is not json" if calls["n"] == 1 else oracle_responder(request)

    result, err = _run(configured_shop, full=True, responder=flaky)
    warned = [text for tag, text in _events(err) if tag == "warn"]
    matching = [w for w in result.warnings if "analysis output" in w.lower() or "json" in w.lower()]
    assert matching, result.warnings
    for message in matching:
        assert any(line.endswith(message) for line in warned), message
    report = (result.report_path).read_text()
    assert matching[0].split(": ", 1)[-1][:40] in report


def test_dependency_audit_and_tool_notes_are_printed(configured_shop: Path) -> None:
    result, err = _run(configured_shop, full=True)
    warned = [text for tag, text in _events(err) if tag == "warn"]
    coverage = result.report["coverage"]
    for gap in coverage.get("blocking_gaps", []):
        assert any(w.endswith(f"Blocking gap: {gap}") for w in warned), gap
    skipped = [text for tag, text in _events(err) if tag == "skip" and " tool " in text]
    for limitation in coverage.get("tool_limitations", []):
        expected = f"External tool: {limitation['tool_id']} — {limitation['status']}"
        assert any(expected in w for w in warned), expected
        # FR-004: the tool itself was announced as skipped, with the same reason,
        # at the moment the decision was made.
        if limitation["status"] in ("missing", "skipped"):
            tail = f"{limitation['tool_id']}: {limitation['reason']}"
            assert any(
                t.startswith("external_tooling tool ") and t.endswith(tail) for t in skipped
            ), tail


def test_handoff_renders_paused_and_exit_3(configured_shop: Path, capsys) -> None:
    code = scan_cli.main(["run", "--workdir", str(configured_shop), "--full"])
    captured = capsys.readouterr()
    assert code == scan_cli.EXIT_AGENT_HANDOFF
    events = _events(captured.err)
    assert events[-1][0] == "pause"
    assert "awaiting agent reasoning" in events[-1][1] and "re-run to resume" in events[-1][1]
    assert "handoff" in captured.out.replace("\\", "/")
    log = (configured_shop / ".secscan" / LOG_FILE_NAME).read_text().splitlines()
    assert log[0].startswith("secscan ") and " started " in log[0]
    assert _LINE.match(log[-1]).group(1).strip() == "pause"


def test_stage_failure_names_stage_and_error(configured_shop: Path, monkeypatch, capsys) -> None:
    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(build_code_graph, "run", boom)
    with pytest.raises(RuntimeError):
        scan_cli.main(["run", "--workdir", str(configured_shop), "--full"])
    events = _events(capsys.readouterr().err)
    assert any(tag == "fail" and text.startswith("build_code_graph after ") for tag, text in events)
    assert events[-1][0] == "fail"
    assert events[-1][1].startswith("scan failed in build_code_graph after ")
    assert events[-1][1].endswith(": boom")
    log = (configured_shop / ".secscan" / LOG_FILE_NAME).read_text().splitlines()
    assert "scan failed in build_code_graph" in log[-1]


def test_interrupt_exits_130_and_logs_stop(configured_shop: Path, monkeypatch, capsys) -> None:
    """FR-008: Ctrl-C names the stage, exits 130, and the log ends with the stop line."""

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(build_code_graph, "run", interrupt)
    code = scan_cli.main(["run", "--workdir", str(configured_shop), "--full"])
    captured = capsys.readouterr()
    assert code == scan_cli.EXIT_INTERRUPTED == 130
    events = _events(captured.err)
    assert events[-1][0] == "stop"
    assert events[-1][1].startswith("interrupted in build_code_graph after ")
    assert events[-1][1].endswith("re-run to resume from checkpoint")
    assert captured.out == ""
    log = (configured_shop / ".secscan" / LOG_FILE_NAME).read_text().splitlines()
    assert "interrupted in build_code_graph" in log[-1]


def test_scan_log_exists_and_is_complete_even_when_quiet(configured_shop: Path) -> None:
    result, err = _run(configured_shop, level=OutputLevel.QUIET, full=True)
    assert err == ""
    log_path = configured_shop / ".secscan" / LOG_FILE_NAME
    lines = log_path.read_text().splitlines()
    assert lines[0].startswith("secscan ") and f"scan {result.scan_id} started" in lines[0]
    events = _events("\n".join(lines[1:]))
    for stage in ("discover_repo", "generate_report"):
        assert ("start", stage) in events
    assert events[-1][0] == "done" and events[-1][1].startswith("generate_report (")


def test_unwritable_scan_log_is_declared_in_report(configured_shop: Path) -> None:
    locked = configured_shop / ".secscan" / "locked"
    locked.mkdir()
    locked.chmod(stat.S_IRUSR | stat.S_IXUSR)
    if os.access(locked, os.W_OK):
        pytest.skip("cannot create a non-writable directory here")
    try:
        stream = io.StringIO()
        reporter = progress.build_reporter(
            OutputLevel.DEFAULT, stream=stream, log_path=locked / LOG_FILE_NAME
        )
        try:
            result = run_mod.run_scan(
                configured_shop, responder=oracle_responder, full=True, progress=reporter
            )
        finally:
            reporter.close()
    finally:
        locked.chmod(stat.S_IRWXU)
    note = next(w for w in result.warnings if w.startswith("scan log unavailable:"))
    assert note in result.report_path.read_text()
    assert any(text.endswith(note) for tag, text in _events(stream.getvalue()) if tag == "warn")


# =================================================================== US3


def test_quiet_stderr_is_empty_and_stdout_unchanged(
    configured_shop: Path, capsys, monkeypatch
) -> None:
    result, _ = _run(configured_shop, full=True, profile="audit")
    capsys.readouterr()
    _with_oracle(monkeypatch)
    code = scan_cli.main(
        ["run", "--workdir", str(configured_shop), "--profile", "audit", "--output", "quiet"]
    )
    captured = capsys.readouterr()
    assert code == scan_cli.EXIT_OK
    assert captured.err == ""
    # Same tree, same input: the summary is identical to the library-level run.
    assert captured.out.splitlines() == _summary_lines(result)


def test_quiet_handoff_prints_only_the_instructions(configured_shop: Path, capsys) -> None:
    code = scan_cli.main(["run", "--workdir", str(configured_shop), "--full", "-q"])
    captured = capsys.readouterr()
    assert code == scan_cli.EXIT_AGENT_HANDOFF
    assert captured.err == ""
    assert "handoff" in captured.out.replace("\\", "/")


def test_short_flags_map_to_levels() -> None:
    parser = scan_cli.build_parser()
    assert parser.parse_args(["run", "-q"]).output == "quiet"
    assert parser.parse_args(["run", "-v"]).output == "verbose"
    assert parser.parse_args(["run", "--output", "verbose"]).output == "verbose"
    assert parser.parse_args(["run"]).output is None
    with pytest.raises(SystemExit):
        parser.parse_args(["run", "-q", "-v"])


def test_verbose_adds_segment_detail(configured_shop: Path) -> None:
    _, default = _run(configured_shop, full=True)
    _, verbose = _run(configured_shop, level=OutputLevel.VERBOSE, full=True)
    assert "level=" not in default and "tokens=" not in default
    done = [t for tag, t in _events(verbose) if tag == "done" and " segment " in t]
    assert done and all(re.search(r" level=\d tokens=\d+$", t) for t in done), done
    assert any(tag == "reuse" and "resume_key=" in text for tag, text in _events(verbose))


def test_env_override_selects_level(configured_shop: Path, capsys, monkeypatch) -> None:
    monkeypatch.setenv("SECSCAN_OUTPUT_LEVEL", "quiet")
    scan_cli.main(["run", "--workdir", str(configured_shop), "--full"])
    assert capsys.readouterr().err == ""


def test_cli_flag_beats_env(configured_shop: Path, capsys, monkeypatch) -> None:
    monkeypatch.setenv("SECSCAN_OUTPUT_LEVEL", "quiet")
    scan_cli.main(["run", "--workdir", str(configured_shop), "--full", "--output", "verbose"])
    err = capsys.readouterr().err
    assert err and _events(err)[0][1].startswith("scan ")


def test_non_tty_output_has_no_escape_sequences(configured_shop: Path, capsys) -> None:
    scan_cli.main(["run", "--workdir", str(configured_shop), "--full"])
    err = capsys.readouterr().err
    assert err
    assert "\x1b" not in err and "\r" not in err


def test_config_level_is_honoured(configured_shop: Path, capsys) -> None:
    import yaml

    path = configured_shop / ".secscan" / "config.yaml"
    raw = yaml.safe_load(path.read_text())
    raw["output"] = {"level": "quiet"}
    path.write_text(yaml.safe_dump(raw, sort_keys=False))
    scan_cli.main(["run", "--workdir", str(configured_shop), "--full"])
    assert capsys.readouterr().err == ""


def test_missing_config_creates_no_log_and_no_scan_dir(tmp_path: Path, capsys) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("x = 1\n")
    code = scan_cli.main(["run", "--workdir", str(project)])
    assert code == scan_cli.EXIT_ERROR
    assert "init" in capsys.readouterr().err
    assert not (project / ".secscan").exists()


def test_artifacts_identical_across_output_levels(tmp_path: Path) -> None:
    """SC-004 / FR-016: the output level changes nothing on disk except scan.log."""
    from tests.fixtures.single_repo_shop import build
    from tests.integration.conftest import write_config
    from tests.integration.test_determinism import _artifacts

    quiet_root, verbose_root = build(tmp_path / "a"), build(tmp_path / "b")
    write_config(quiet_root)
    write_config(verbose_root)
    _run(quiet_root, level=OutputLevel.QUIET, full=True)
    _run(verbose_root, level=OutputLevel.VERBOSE, full=True)
    a, b = _artifacts(quiet_root), _artifacts(verbose_root)
    assert set(a) == set(b)
    for name in sorted(a):
        assert a[name] == b[name], f"{name} differs between output levels"
    assert (quiet_root / ".secscan" / LOG_FILE_NAME).exists()
    assert not any(name.endswith(LOG_FILE_NAME) for name in a)
    # and the log is plain text, never an enveloped artifact
    with pytest.raises(json.JSONDecodeError):
        json.loads((verbose_root / ".secscan" / LOG_FILE_NAME).read_text())


# ============================================================= feature 012


def test_batch_mode_lines_follow_the_grammar(tmp_path: Path, monkeypatch) -> None:
    """contracts/batch-execution.md §3: submitted/processing/ended lines, quiet stays silent."""
    from tests.fixtures.single_repo_shop import build
    from tests.helpers.fake_provider import FakeProvider, Scenario
    from tests.integration.conftest import write_config

    monkeypatch.setenv("PROGRESS_FAKE_KEY", "sk-fake")
    root = build(tmp_path / "shop")
    write_config(
        root,
        {
            "llm": {
                "endpoint": {
                    "provider": "anthropic",
                    "api_key_env": "PROGRESS_FAKE_KEY",
                    "model_map": {"local": "m-local", "segment": "m-segment"},
                }
            },
            # This test pins feature 012's segment-batch line grammar; the triage
            # round's batch lines are covered by the feature-013 suites.
            "triage": {"enabled": "off"},
        },
    )
    now = {"t": 1_700_000_000.0}

    def sleep(seconds: float) -> None:
        now["t"] += seconds

    provider = FakeProvider("anthropic", Scenario(polls_until_ended=2))
    stream = io.StringIO()
    reporter = progress.build_reporter(OutputLevel.DEFAULT, stream=stream, log_path=None)
    try:
        run_mod.run_scan(root, transport=provider, progress=reporter, full=True,
                         clock=lambda: now["t"], sleep=sleep)
    finally:
        reporter.close()
    events = _events(stream.getvalue())
    submitted = [t for tag, t in events if tag == "info"]
    assert len(submitted) == 1
    assert re.fullmatch(
        r"segment_analysis batch 1/1 submitted: \d+ items, model m-local, id batch_\d+",
        submitted[0],
    )
    processing = [t for tag, t in events if tag == "wait" and "processing" in t]
    assert processing and re.fullmatch(
        r"segment_analysis batch 1/1 processing \d+/\d+ \(waited [\d.]+s, next check in 30s\)",
        processing[0],
    )
    ended = [t for tag, t in events if tag == "done" and "batch 1/1 ended" in t]
    assert ended and re.fullmatch(
        r"segment_analysis batch 1/1 ended: \d+ succeeded, 0 errored, 0 expired \(0 fallback\)",
        ended[0],
    )

    quiet = io.StringIO()
    reporter = progress.build_reporter(OutputLevel.QUIET, stream=quiet, log_path=None)
    try:
        run_mod.run_scan(root, transport=FakeProvider("anthropic"), progress=reporter,
                         full=True, clock=lambda: now["t"], sleep=sleep)
    finally:
        reporter.close()
    assert quiet.getvalue() == ""
