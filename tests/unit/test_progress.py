"""Progress reporter, sinks, and heartbeat (feature 011, contracts/progress-output.md)."""

from __future__ import annotations

import io
import os
import re
import stat
import threading
import time
from pathlib import Path

import pytest

from pipeline import progress
from pipeline.progress import (
    EventKind,
    FileSink,
    LiveSink,
    NullReporter,
    OutputLevel,
    PlainSink,
    ProgressReporter,
    build_reporter,
    render_elapsed,
    select_terminal_sink,
)

_TAGS = "start|done |reuse|skip |fail |warn |wait |pause|stop |info "
_LINE = re.compile(rf"^\d{{2}}:\d{{2}}:\d{{2}} \+\d{{2}}:\d{{2}} ({_TAGS}) (.+)$")


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class RecordingSink:
    verbose = True

    def __init__(self) -> None:
        self.events: list[progress.ProgressEvent] = []
        self.lines: list[str] = []
        self.finalized = 0
        self.closed = 0

    def write(self, event: progress.ProgressEvent, rendered: str) -> None:
        self.events.append(event)
        self.lines.append(rendered)

    def finalize(self) -> None:
        self.finalized += 1

    def close(self) -> None:
        self.closed += 1


class FakeTTY(io.StringIO):
    def __init__(self, tty: bool = True) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _reporter(*sinks, clock=None, interval: float = 30.0, level=OutputLevel.DEFAULT):
    return ProgressReporter(
        level,
        list(sinks),
        clock=clock or FakeClock(),
        wall_clock=lambda: 0.0,
        heartbeat_interval_s=interval,
        start_thread=False,
    )


def _payloads(text: str) -> set[str]:
    out = set()
    for chunk in re.split(r"[\r\n]", text.replace("\x1b[2K", "")):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = _LINE.match(chunk)
        # status lines carry only the +MM:SS column; compare the text payload
        out.add(m.group(2) if m else re.sub(r"^\+\d{2}:\d{2} ", "", chunk))
    return out


# ------------------------------------------------------------------ levels


def test_output_level_from_str_accepts_the_three_names() -> None:
    assert OutputLevel.from_str("quiet") is OutputLevel.QUIET
    assert OutputLevel.from_str("default") is OutputLevel.DEFAULT
    assert OutputLevel.from_str("verbose") is OutputLevel.VERBOSE


def test_output_level_from_str_rejects_unknown_values() -> None:
    with pytest.raises(ValueError) as exc:
        OutputLevel.from_str("loud")
    assert "quiet, default, verbose" in str(exc.value)


# -------------------------------------------------------------- null reporter


def test_null_reporter_accepts_every_public_call() -> None:
    r = NullReporter()
    r.scan_started("s1", profile="full", mode="agent-mediated")
    r.stage_started("discover_repo")
    r.stage_done("discover_repo")
    r.stage_reused("build_code_graph", "abc")
    r.stage_skipped("system_review", "disabled by profile")
    r.stage_failed("partition_repo", "boom")
    r.segment_started("segment_analysis", "seg-a", 1, 2)
    r.segment_done("segment_analysis", "seg-a", 1, 2, escalation_level=1, estimated_tokens=10)
    r.tool_started("external_tooling", "semgrep", 1, 1)
    r.tool_done("external_tooling", "semgrep", 1, 1, status="ran")
    r.warning("x", stage="scan")
    r.paused(2)
    r.failed("y")
    r.interrupted()
    r.close()
    assert r.internal_warnings == []


# ---------------------------------------------------------------- reporter


def test_reporter_tracks_position_through_transitions() -> None:
    sink = RecordingSink()
    r = _reporter(sink)
    assert r.current_stage is None
    r.scan_started("s1", profile="full", mode="agent-mediated")
    r.stage_started("segment_analysis")
    assert r.current_stage == "segment_analysis"
    r.segment_started("segment_analysis", "seg-a", 1, 3)
    assert r.current_subject == "seg-a"
    r.segment_done("segment_analysis", "seg-a", 1, 3)
    assert r.current_subject is None
    r.stage_done("segment_analysis")
    assert r.current_stage is None
    r.stage_reused("generate_report", "k")
    assert r.current_stage is None


def test_events_carry_clock_values_and_reach_every_sink() -> None:
    clock = FakeClock()
    a, b = RecordingSink(), RecordingSink()
    r = _reporter(a, b, clock=clock)
    r.scan_started("s1", profile="full", mode="endpoint")
    clock.advance(2.5)
    r.stage_started("discover_repo")
    clock.advance(1.0)
    r.stage_done("discover_repo")
    assert [e.kind for e in a.events] == [
        EventKind.SCAN_STARTED,
        EventKind.STAGE_STARTED,
        EventKind.STAGE_DONE,
    ]
    assert a.events == b.events
    assert a.events[2].since_start_s == pytest.approx(3.5)
    assert a.events[2].elapsed_s == pytest.approx(1.0)


def test_close_is_idempotent_and_finalizes_sinks() -> None:
    sink = RecordingSink()
    r = _reporter(sink)
    r.close()
    r.close()
    assert sink.finalized == 1
    assert sink.closed == 1


# --------------------------------------------------------------- rendering


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [(1.2, "1.2s"), (45, "45s"), (192, "3m12s"), (3720, "1h02m")],
)
def test_render_elapsed(seconds: float, expected: str) -> None:
    assert render_elapsed(seconds) == expected


def _lines_for(level: OutputLevel = OutputLevel.DEFAULT) -> list[str]:
    stream = io.StringIO()
    sink = PlainSink(stream)
    sink.verbose = level is OutputLevel.VERBOSE
    clock = FakeClock()
    r = _reporter(sink, clock=clock, level=level)
    r.scan_started("20260903T000000Z-abc", profile="full", mode="agent-mediated")
    r.stage_started("discover_repo")
    clock.advance(0.3)
    r.stage_done("discover_repo")
    r.stage_reused("build_code_graph", "deadbeef")
    r.stage_skipped("system_review", "disabled by profile")
    r.stage_started("segment_analysis")
    r.segment_started("segment_analysis", "seg-a", 1, 3)
    clock.advance(12)
    r.segment_done("segment_analysis", "seg-a", 1, 3, escalation_level=2, estimated_tokens=8000)
    r.warning("seg-a: rejected non-conforming finding", stage="segment_analysis", subject="seg-a")
    r.stage_started("external_tooling")
    r.tool_started("external_tooling", "semgrep", 1, 2)
    clock.advance(4)
    r.tool_done(
        "external_tooling", "semgrep", 1, 2, status="ran",
        tool_version="1.2.3", invocation="semgrep scan --json",
    )
    r.tool_done("external_tooling", "osv-scanner", 2, 2, status="skipped", reason="not installed")
    r.stage_failed("external_tooling", "boom")
    return stream.getvalue().splitlines()


def test_plain_sink_lines_follow_the_grammar() -> None:
    lines = _lines_for()
    for line in lines:
        assert _LINE.match(line), line
    texts = [_LINE.match(line).group(2) for line in lines]
    assert texts[0] == "scan 20260903T000000Z-abc (full profile, agent-mediated)"
    assert texts[1] == "discover_repo"
    assert texts[2] == "discover_repo (0.3s)"
    assert texts[3] == "build_code_graph (checkpoint)"
    assert texts[4] == "system_review: disabled by profile"
    assert texts[6] == "segment_analysis segment 1/3 seg-a"
    assert texts[7] == "segment_analysis segment 1/3 seg-a (12s)"
    assert texts[8] == "[segment_analysis/seg-a] seg-a: rejected non-conforming finding"
    assert texts[10] == "external_tooling tool 1/2 semgrep"
    assert texts[11] == "external_tooling tool 1/2 semgrep ran (4.0s)"
    assert texts[12] == "external_tooling tool 2/2 osv-scanner: not installed"
    assert texts[13].startswith("external_tooling after ")
    assert texts[13].endswith(": boom")
    tags = [_LINE.match(line).group(1).strip() for line in lines]
    assert tags == [
        "start", "start", "done", "reuse", "skip", "start", "start", "done",
        "warn", "start", "start", "done", "skip", "fail",
    ]


def test_default_level_omits_verbose_detail_and_verbose_includes_it() -> None:
    default = "\n".join(_lines_for(OutputLevel.DEFAULT))
    verbose = "\n".join(_lines_for(OutputLevel.VERBOSE))
    assert "level=" not in default and "tokens=" not in default
    assert "resume_key=" not in default and "1.2.3: semgrep scan" not in default
    assert "seg-a (12s) level=2 tokens=8000" in verbose
    assert "build_code_graph (checkpoint) resume_key=deadbeef" in verbose
    assert "semgrep ran (4.0s) 1.2.3: semgrep scan --json" in verbose


def test_terminal_events_render() -> None:
    stream = io.StringIO()
    clock = FakeClock()
    r = _reporter(PlainSink(stream), clock=clock)
    r.scan_started("s", profile="full", mode="m")
    r.stage_started("segment_analysis")
    r.segment_started("segment_analysis", "seg-a", 2, 5)
    clock.advance(12)
    r.interrupted()
    r2 = _reporter(PlainSink(stream), clock=clock)
    r2.scan_started("s", profile="full", mode="m")
    r2.stage_started("build_code_graph")
    clock.advance(3)
    r2.failed("boom")
    r3 = _reporter(PlainSink(stream), clock=clock)
    r3.scan_started("s", profile="full", mode="m")
    r3.paused(4)
    text = stream.getvalue()
    assert (
        "stop  interrupted in segment_analysis seg-a after 12s; re-run to resume from checkpoint"
        in text
    )
    assert "fail  scan failed in build_code_graph after 3.0s: boom" in text
    assert (
        "pause 4 segment(s) awaiting agent reasoning in .secscan/handoff/ — re-run to resume"
        in text
    )


def test_batch_events_render(tmp_path: Path) -> None:
    """Feature 012 T015: contracts/batch-execution.md §3 grammar."""
    stream = io.StringIO()
    clock = FakeClock()
    r = _reporter(PlainSink(stream), clock=clock)
    r.scan_started("s", profile="full", mode="endpoint-batch (default policy)")
    r.stage_started("segment_analysis")
    r.batch_submitted("segment_analysis", 1, 2, items=255, model="claude-haiku-latest",
                      handle="msgbatch_01AB")
    clock.advance(30)
    r.batch_status("segment_analysis", 1, 2, completed=0, item_total=255, waited_s=30,
                   next_poll_s=45)
    r.batch_done("segment_analysis", 1, 2, succeeded=251, failed=3, expired=1, fallbacks=4)
    r.interrupted(note="re-run to resume; 1 batch(es) still processing at the provider")
    text = stream.getvalue()
    assert ("info  segment_analysis batch 1/2 submitted: 255 items, model claude-haiku-latest, "
            "id msgbatch_01AB") in text
    assert ("wait  segment_analysis batch 1/2 processing 0/255 "
            "(waited 30s, next check in 45s)") in text
    assert ("done  segment_analysis batch 1/2 ended: 251 succeeded, 3 errored, 1 expired "
            "(4 fallback)") in text
    assert ("re-run to resume from checkpoint; re-run to resume; "
            "1 batch(es) still processing") in text
    assert EventKind.BATCH_STATUS in progress.TRANSIENT_KINDS
    assert EventKind.BATCH_SUBMITTED not in progress.TRANSIENT_KINDS
    for line in text.splitlines():
        assert _LINE.match(line), line


def test_batch_status_resets_heartbeat() -> None:
    sink = RecordingSink()
    clock = FakeClock()
    r = _reporter(sink, clock=clock, interval=30)
    r.scan_started("s", profile="full", mode="m")
    r.stage_started("segment_analysis")
    clock.advance(29)
    r.batch_status("segment_analysis", 1, 1, completed=0, item_total=3, waited_s=29, next_poll_s=30)
    clock.advance(5)
    assert r.check_heartbeat() is None


# --------------------------------------------------------------- heartbeat


def test_heartbeat_fires_after_interval_of_silence() -> None:
    clock = FakeClock()
    sink = RecordingSink()
    r = _reporter(sink, clock=clock, interval=0.05)
    r.scan_started("s", profile="full", mode="m")
    r.stage_started("segment_analysis")
    r.segment_started("segment_analysis", "seg-a", 1, 1)
    clock.advance(0.03)
    assert r.check_heartbeat() is None
    clock.advance(0.03)
    silence = r.check_heartbeat()
    assert silence is not None and silence >= 0.05
    beats = [e for e in sink.events if e.kind is EventKind.HEARTBEAT]
    assert len(beats) == 1
    assert beats[0].subject == "seg-a"
    assert "still running segment_analysis seg-a (" in sink.lines[-1]
    clock.advance(0.06)
    r.check_heartbeat()
    assert len([e for e in sink.events if e.kind is EventKind.HEARTBEAT]) == 2
    r.segment_done("segment_analysis", "seg-a", 1, 1)
    clock.advance(0.02)
    r.stage_done("segment_analysis")
    clock.advance(0.06)
    r.check_heartbeat()  # no current stage: nothing to report
    assert len([e for e in sink.events if e.kind is EventKind.HEARTBEAT]) == 2


def test_heartbeat_latency_is_bounded_by_interval() -> None:
    written = threading.Event()
    stamps: list[float] = []

    class Stamp(RecordingSink):
        def write(self, event, rendered):
            super().write(event, rendered)
            if event.kind is EventKind.HEARTBEAT:
                stamps.append(time.monotonic())
                written.set()

    r = ProgressReporter(OutputLevel.DEFAULT, [Stamp()], heartbeat_interval_s=0.2)
    r.scan_started("s", profile="full", mode="m")
    t0 = time.monotonic()
    r.stage_started("segment_analysis")
    assert written.wait(2.0)
    r.close()
    latency = stamps[0] - t0
    assert 0.2 <= latency < 0.3, latency


def test_heartbeat_thread_stops_on_close() -> None:
    r = ProgressReporter(OutputLevel.DEFAULT, [RecordingSink()], heartbeat_interval_s=0.05)
    r.scan_started("s", profile="full", mode="m")
    assert r._thread is not None and r._thread.is_alive()
    r.close()
    assert not r._thread.is_alive()


# ------------------------------------------------------------------- sinks


def test_file_sink_writes_and_flushes_each_line(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "scan.log"
    sink = FileSink(path)
    r = _reporter(sink)
    r.scan_started("sid", profile="full", mode="m")
    assert path.read_text().splitlines()[0].startswith("secscan ")
    assert "scan sid started" in path.read_text()
    r.stage_started("discover_repo")
    assert path.read_text().rstrip().endswith("start discover_repo")
    r.stage_done("discover_repo")
    r.close()
    assert len(path.read_text().splitlines()) == 4


def test_file_sink_open_failure_emits_one_warning_and_disables(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(stat.S_IRUSR | stat.S_IXUSR)
    if os.access(locked, os.W_OK):
        pytest.skip("cannot create a non-writable directory here")
    try:
        sink = FileSink(locked / "scan.log")
        rec = RecordingSink()
        r = _reporter(rec, sink)
        r.scan_started("sid", profile="full", mode="m")
        r.stage_started("discover_repo")
        r.stage_done("discover_repo")
        warnings = [e for e in rec.events if e.kind is EventKind.WARNING]
        assert len(warnings) == 1
        assert warnings[0].message.startswith("scan log unavailable:")
        assert str(locked) not in warnings[0].message
        assert r.internal_warnings == [warnings[0].message]
        r.close()
    finally:
        locked.chmod(stat.S_IRWXU)


def test_live_sink_redraws_transient_and_keeps_permanent_lines() -> None:
    stream = FakeTTY()
    sink = LiveSink(stream, width=80)
    clock = FakeClock()
    r = _reporter(sink, clock=clock)
    r.scan_started("s", profile="full", mode="m")
    r.stage_started("discover_repo")
    out = stream.getvalue()
    assert out.endswith("\r\x1b[2K+00:00 discover_repo")
    assert not out.endswith("\n")
    clock.advance(1)
    r.stage_done("discover_repo")
    out = stream.getvalue()
    assert "\r\x1b[2K" in out
    # a completing event clears the status line instead of redrawing it stale
    assert out.endswith("done  discover_repo (1.0s)\n")
    r.stage_started("build_code_graph")
    r.warning("note", stage="build_code_graph")
    out = stream.getvalue()
    # permanent line erased the status line, then the status line was redrawn after it
    idx_warn = out.rfind("warn  [build_code_graph] note\n")
    assert idx_warn != -1
    assert out[idx_warn:].endswith("\r\x1b[2K+00:01 build_code_graph")
    r.close()
    assert stream.getvalue().endswith("build_code_graph\n")


def test_live_sink_truncates_status_to_width() -> None:
    stream = FakeTTY()
    sink = LiveSink(stream, width=40)
    r = _reporter(sink)
    r.scan_started("s", profile="full", mode="m")
    r.stage_started("a_very_long_stage_name_that_will_not_fit_in_forty_columns_at_all")
    status = stream.getvalue().rsplit("\x1b[2K", 1)[-1]
    assert len(status) == 39


@pytest.mark.parametrize(
    ("tty", "width", "term", "expected"),
    [
        (False, 120, "xterm", PlainSink),
        (True, 39, "xterm", PlainSink),
        (True, 0, "xterm", PlainSink),
        (True, 120, "dumb", PlainSink),
        (True, 40, "xterm", LiveSink),
        (True, 120, "xterm", LiveSink),
    ],
)
def test_select_terminal_sink(monkeypatch, tty, width, term, expected) -> None:
    monkeypatch.setenv("TERM", term)
    sink = select_terminal_sink(FakeTTY(tty), width=width)
    assert type(sink) is expected


def test_live_and_plain_sinks_present_the_same_events() -> None:
    def script(r: ProgressReporter, clock: FakeClock) -> None:
        r.scan_started("s", profile="full", mode="m")
        r.stage_started("discover_repo")
        clock.advance(1)
        r.stage_done("discover_repo")
        r.stage_started("segment_analysis")
        r.segment_started("segment_analysis", "seg-a", 1, 1)
        clock.advance(31)
        r.check_heartbeat()
        r.warning("w1", stage="segment_analysis", subject="seg-a")
        r.segment_done("segment_analysis", "seg-a", 1, 1)
        r.stage_done("segment_analysis")
        r.stage_started("external_tooling")
        r.tool_started("external_tooling", "semgrep", 1, 1)
        r.tool_done("external_tooling", "semgrep", 1, 1, status="skipped", reason="missing")
        r.warning("w2", stage="external_tooling")
        r.paused(1)

    live_stream, plain_stream = FakeTTY(), io.StringIO()
    c1, c2 = FakeClock(), FakeClock()
    script(_reporter(LiveSink(live_stream, width=200), clock=c1), c1)
    script(_reporter(PlainSink(plain_stream), clock=c2), c2)
    assert _payloads(live_stream.getvalue()) == _payloads(plain_stream.getvalue())


# ------------------------------------------------------------ build_reporter


def test_build_reporter_quiet_has_no_terminal_sink_but_keeps_the_log(tmp_path: Path) -> None:
    stream = io.StringIO()
    r = build_reporter(OutputLevel.QUIET, stream=stream, log_path=tmp_path / "scan.log")
    r.scan_started("s", profile="full", mode="m")
    r.stage_started("discover_repo")
    r.close()
    assert stream.getvalue() == ""
    assert "start discover_repo" in (tmp_path / "scan.log").read_text()


def test_build_reporter_default_and_verbose_write_to_stream(tmp_path: Path) -> None:
    for level in (OutputLevel.DEFAULT, OutputLevel.VERBOSE):
        stream = io.StringIO()
        r = build_reporter(level, stream=stream, log_path=tmp_path / "scan.log")
        r.scan_started("s", profile="full", mode="m")
        r.close()
        assert "start scan s" in stream.getvalue()
