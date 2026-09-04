"""Progress events for a running scan (feature 011).

The pipeline emits *events* — stage started/done/reused, segment ``i/N``, tool
outcomes, warnings, heartbeat, pause/failure — through a ``ProgressReporter``.
The reporter fans them out to sinks: a plain line-per-event stream, an
in-place status line for interactive terminals, and the always-on
``.secscan/scan.log``. Nothing here touches pipeline state or artifacts:
progress is a side channel, and timing never enters an artifact.

Content rule (FR-015): events carry stage names, segment/tool identifiers,
repo-relative paths, counts, durations, and the same warning strings that
reach the report. No source text, no packet content, no credential values.
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, TextIO

from pipeline.state import LOG_FILE_NAME, TOOL_VERSION

__all__ = [
    "LOG_FILE_NAME",
    "EventKind",
    "FileSink",
    "LiveSink",
    "NullReporter",
    "OutputLevel",
    "PlainSink",
    "ProgressEvent",
    "ProgressReporter",
    "Sink",
    "build_reporter",
    "render",
    "render_elapsed",
    "select_terminal_sink",
]

HEARTBEAT_INTERVAL_S = 30.0
#: Below this many columns an in-place status line is not worth drawing.
MIN_LIVE_WIDTH = 40


class OutputLevel(StrEnum):
    QUIET = "quiet"
    DEFAULT = "default"
    VERBOSE = "verbose"

    @classmethod
    def names(cls) -> tuple[str, ...]:
        return tuple(level.value for level in cls)

    @classmethod
    def from_str(cls, value: str) -> OutputLevel:
        for level in cls:
            if level.value == value:
                return level
        raise ValueError(f"output level must be one of: {', '.join(cls.names())} (got {value!r})")


class EventKind(StrEnum):
    SCAN_STARTED = "scan_started"
    STAGE_STARTED = "stage_started"
    STAGE_DONE = "stage_done"
    STAGE_REUSED = "stage_reused"
    STAGE_SKIPPED = "stage_skipped"
    STAGE_FAILED = "stage_failed"
    SEGMENT_STARTED = "segment_started"
    SEGMENT_DONE = "segment_done"
    TOOL_STARTED = "tool_started"
    TOOL_DONE = "tool_done"
    WARNING = "warning"
    HEARTBEAT = "heartbeat"
    PAUSED = "paused"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    # provider batch execution (feature 012, contracts/batch-execution.md §3)
    BATCH_SUBMITTED = "batch_submitted"
    BATCH_STATUS = "batch_status"
    BATCH_DONE = "batch_done"


#: Events shown on the transient status line of a live terminal; everything
#: else is a permanent line.
TRANSIENT_KINDS = frozenset(
    {
        EventKind.STAGE_STARTED,
        EventKind.SEGMENT_STARTED,
        EventKind.TOOL_STARTED,
        EventKind.HEARTBEAT,
        EventKind.BATCH_STATUS,
    }
)


@dataclass(frozen=True)
class ProgressEvent:
    kind: EventKind
    stage: str
    subject: str | None = None
    index: int | None = None
    total: int | None = None
    elapsed_s: float | None = None
    message: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    at: float = 0.0
    since_start_s: float = 0.0


# --------------------------------------------------------------- rendering


def render_elapsed(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 10:
        return f"{seconds:.1f}s"
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        minutes, rest = divmod(int(seconds), 60)
        return f"{minutes}m{rest:02d}s"
    hours, rest = divmod(int(seconds), 3600)
    return f"{hours}h{rest // 60:02d}m"


def _since(seconds: float) -> str:
    total = int(max(0.0, seconds))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    return f"+{hours}:{minutes:02d}:{secs:02d}" if hours else f"+{minutes:02d}:{secs:02d}"


def _tag(event: ProgressEvent) -> str:
    kind = event.kind
    if kind in (EventKind.SCAN_STARTED, EventKind.STAGE_STARTED, EventKind.SEGMENT_STARTED,
                EventKind.TOOL_STARTED):
        return "start"
    if kind is EventKind.TOOL_DONE:
        status = event.detail.get("status", "ran")
        return {"ran": "done ", "skipped": "skip "}.get(status, "fail ")
    return {
        EventKind.STAGE_DONE: "done ",
        EventKind.SEGMENT_DONE: "done ",
        EventKind.STAGE_REUSED: "reuse",
        EventKind.STAGE_SKIPPED: "skip ",
        EventKind.STAGE_FAILED: "fail ",
        EventKind.FAILED: "fail ",
        EventKind.WARNING: "warn ",
        EventKind.HEARTBEAT: "wait ",
        EventKind.PAUSED: "pause",
        EventKind.INTERRUPTED: "stop ",
        EventKind.BATCH_SUBMITTED: "info ",
        EventKind.BATCH_STATUS: "wait ",
        EventKind.BATCH_DONE: "done ",
    }[kind]


def _where(event: ProgressEvent) -> str:
    return f"{event.stage} {event.subject}" if event.subject else event.stage


def render_text(event: ProgressEvent, verbose: bool) -> str:
    """The ``<text>`` part of a line (contracts/progress-output.md §3)."""
    kind, d = event.kind, event.detail
    elapsed = render_elapsed(event.elapsed_s or 0.0)
    counter = f"{event.index}/{event.total}" if event.index is not None else ""
    if kind is EventKind.SCAN_STARTED:
        return f"scan {event.message} ({d.get('profile', '?')} profile, {d.get('mode', '?')})"
    if kind is EventKind.STAGE_STARTED:
        return event.stage
    if kind is EventKind.STAGE_DONE:
        return f"{event.stage} ({elapsed})"
    if kind is EventKind.STAGE_REUSED:
        text = f"{event.stage} (checkpoint)"
        return f"{text} resume_key={d['resume_key']}" if verbose and d.get("resume_key") else text
    if kind is EventKind.STAGE_SKIPPED:
        return f"{event.stage}: {event.message}"
    if kind is EventKind.STAGE_FAILED:
        return f"{event.stage} after {elapsed}: {event.message}"
    if kind is EventKind.SEGMENT_STARTED:
        return f"{event.stage} segment {counter} {event.subject}"
    if kind is EventKind.SEGMENT_DONE:
        text = f"{event.stage} segment {counter} {event.subject} ({elapsed})"
        if verbose and "escalation_level" in d:
            text += f" level={d['escalation_level']} tokens={d.get('estimated_tokens', 0)}"
        return text
    if kind is EventKind.TOOL_STARTED:
        return f"{event.stage} tool {counter} {event.subject}"
    if kind is EventKind.TOOL_DONE:
        head = f"{event.stage} tool {counter} {event.subject}"
        if d.get("status", "ran") == "ran":
            text = f"{head} ran ({elapsed})"
            if verbose and (d.get("tool_version") or d.get("invocation")):
                text += f" {d.get('tool_version') or '?'}: {d.get('invocation') or ''}".rstrip()
            return text
        return f"{head}: {d.get('reason') or d.get('status')}"
    if kind is EventKind.WARNING:
        scope = f"{event.stage}/{event.subject}" if event.subject else event.stage
        return f"[{scope}] {event.message}"
    if kind is EventKind.HEARTBEAT:
        return f"still running {_where(event)} ({elapsed})"
    if kind is EventKind.PAUSED:
        return (
            f"{d.get('pending', 0)} segment(s) awaiting agent reasoning in .secscan/handoff/ "
            "— re-run to resume"
        )
    if kind is EventKind.FAILED:
        return f"scan failed in {_where(event)} after {elapsed}: {event.message}"
    if kind is EventKind.INTERRUPTED:
        text = f"interrupted in {_where(event)} after {elapsed}; re-run to resume from checkpoint"
        return f"{text}; {event.message}" if event.message else text
    if kind is EventKind.BATCH_SUBMITTED:
        return (
            f"{event.stage} batch {counter} submitted: {d.get('items', 0)} items, "
            f"model {d.get('model', '?')}, id {d.get('handle', '?')}"
        )
    if kind is EventKind.BATCH_STATUS:
        if d.get("waiting_for_window"):
            return (
                f"{event.stage} waiting for off-peak window {d['waiting_for_window']} "
                f"(starts in {render_elapsed(d.get('starts_in_s', 0))})"
            )
        return (
            f"{event.stage} batch {counter} processing {d.get('completed', 0)}/"
            f"{d.get('item_total', 0)} (waited {render_elapsed(d.get('waited_s', 0))}, "
            f"next check in {render_elapsed(d.get('next_poll_s', 0))})"
        )
    if kind is EventKind.BATCH_DONE:
        return (
            f"{event.stage} batch {counter} ended: {d.get('succeeded', 0)} succeeded, "
            f"{d.get('failed', 0)} errored, {d.get('expired', 0)} expired "
            f"({d.get('fallbacks', 0)} fallback)"
        )
    raise ValueError(f"unknown event kind {kind!r}")  # pragma: no cover


def render(event: ProgressEvent, verbose: bool = False) -> str:
    stamp = time.strftime("%H:%M:%S", time.localtime(event.at))
    return f"{stamp} {_since(event.since_start_s)} {_tag(event)} {render_text(event, verbose)}"


# -------------------------------------------------------------------- sinks


class Sink(Protocol):
    verbose: bool

    def write(self, event: ProgressEvent, rendered: str) -> None: ...

    def finalize(self) -> None: ...

    def close(self) -> None: ...


class PlainSink:
    """One line per event; suitable for pipes, log capture, and agents."""

    def __init__(self, stream: TextIO, verbose: bool = False) -> None:
        self.stream = stream
        self.verbose = verbose

    def write(self, event: ProgressEvent, rendered: str) -> None:
        self.stream.write(rendered + "\n")
        self.stream.flush()

    def finalize(self) -> None:
        return None

    def close(self) -> None:
        return None


_ERASE = "\r\x1b[2K"

#: Permanent events that *complete* what the status line was describing; the
#: status line is cleared rather than redrawn stale underneath them.
_COMPLETING_KINDS = frozenset(
    {
        EventKind.STAGE_DONE,
        EventKind.STAGE_FAILED,
        EventKind.SEGMENT_DONE,
        EventKind.TOOL_DONE,
        EventKind.PAUSED,
        EventKind.FAILED,
        EventKind.INTERRUPTED,
    }
)


class LiveSink:
    """Interactive terminal: one in-place status line plus permanent lines."""

    def __init__(self, stream: TextIO, width: int, verbose: bool = False) -> None:
        self.stream = stream
        self.width = max(int(width), MIN_LIVE_WIDTH)
        self.verbose = verbose
        self._status: str | None = None

    def _status_text(self, event: ProgressEvent) -> str:
        text = f"{_since(event.since_start_s)} {render_text(event, self.verbose)}"
        return text[: self.width - 1]

    def write(self, event: ProgressEvent, rendered: str) -> None:
        if event.kind in TRANSIENT_KINDS:
            self._status = self._status_text(event)
            self.stream.write(_ERASE + self._status)
        else:
            if self._status is not None:
                self.stream.write(_ERASE)
            self.stream.write(rendered + "\n")
            if event.kind in _COMPLETING_KINDS:
                self._status = None
            elif self._status is not None:
                self.stream.write(_ERASE + self._status)
        self.stream.flush()

    def finalize(self) -> None:
        if self._status is not None:
            self.stream.write("\n")
            self.stream.flush()
            self._status = None

    def close(self) -> None:
        self.finalize()


class FileSink:
    """``.secscan/scan.log``: every event at verbose detail, flushed per line.

    Never raises: an ``OSError`` disables the sink and is surfaced once by the
    reporter as a warning (FR-019).
    """

    verbose = True

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.error: str | None = None
        self._handle: TextIO | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = self.path.open("w", encoding="utf-8")
        except OSError as exc:
            self._fail(exc)

    @property
    def disabled(self) -> bool:
        return self._handle is None

    def _fail(self, exc: OSError) -> None:
        # Name and errno text only: a path could carry a user name into the report.
        self.error = f"{type(exc).__name__}: {exc.strerror or 'write failed'}"
        if self._handle is not None:
            try:
                self._handle.close()
            except OSError:
                pass
        self._handle = None

    def _write_line(self, line: str) -> None:
        if self._handle is None:
            return
        try:
            self._handle.write(line + "\n")
            self._handle.flush()
        except OSError as exc:
            self._fail(exc)

    def header(self, scan_id: str) -> None:
        started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._write_line(f"secscan {TOOL_VERSION} scan {scan_id} started {started}")

    def write(self, event: ProgressEvent, rendered: str) -> None:
        self._write_line(rendered)

    def finalize(self) -> None:
        return None

    def close(self) -> None:
        if self._handle is not None:
            try:
                self._handle.close()
            except OSError:
                pass
            self._handle = None


def select_terminal_sink(stream: TextIO, width: int | None = None, verbose: bool = False):
    """Live status line only on a real, wide enough, non-dumb terminal (FR-013a)."""
    try:
        is_tty = bool(stream.isatty())
    except (AttributeError, ValueError):
        is_tty = False
    if width is None:
        width = shutil.get_terminal_size(fallback=(0, 0)).columns
    if not is_tty or width < MIN_LIVE_WIDTH or os.environ.get("TERM", "") == "dumb":
        return PlainSink(stream, verbose=verbose)
    return LiveSink(stream, width, verbose=verbose)


# ----------------------------------------------------------------- reporter


class NullReporter:
    """Default for library callers: accepts every call, emits nothing."""

    internal_warnings: list[str]
    current_stage: str | None = None
    current_subject: str | None = None

    def __init__(self) -> None:
        self.internal_warnings = []

    def __getattr__(self, name: str) -> Callable[..., None]:
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda *args, **kwargs: None


class ProgressReporter:
    """Fans progress events out to sinks and owns the heartbeat thread."""

    def __init__(
        self,
        level: OutputLevel,
        sinks: list[Any],
        *,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        heartbeat_interval_s: float = HEARTBEAT_INTERVAL_S,
        start_thread: bool = True,
    ) -> None:
        self.level = level
        self.sinks = list(sinks)
        self.clock = clock
        self.wall_clock = wall_clock
        self.heartbeat_interval_s = float(heartbeat_interval_s)
        self.internal_warnings: list[str] = []
        self.current_stage: str | None = None
        self.current_subject: str | None = None
        self._index: int | None = None
        self._total: int | None = None
        self._start: float | None = None
        self._stage_started_at: float | None = None
        self._subject_started_at: float | None = None
        self.last_event_at: float = self.clock()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._start_thread = start_thread
        self._closed = False
        self._log_warned = False

    # ----------------------------------------------------------- emission

    def _emit(
        self,
        kind: EventKind,
        *,
        stage: str,
        subject: str | None = None,
        index: int | None = None,
        total: int | None = None,
        elapsed_s: float | None = None,
        message: str = "",
        detail: dict[str, Any] | None = None,
    ) -> ProgressEvent:
        now = self.clock()
        event = ProgressEvent(
            kind=kind,
            stage=stage,
            subject=subject,
            index=index,
            total=total,
            elapsed_s=elapsed_s,
            message=message,
            detail=dict(detail or {}),
            at=self.wall_clock(),
            since_start_s=now - (self._start if self._start is not None else now),
        )
        with self._lock:
            if kind is not EventKind.HEARTBEAT:
                self.last_event_at = now
            plain = render(event, verbose=False)
            verbose = render(event, verbose=True)
            for sink in self.sinks:
                sink.write(event, verbose if getattr(sink, "verbose", False) else plain)
        self._check_log_sinks()
        return event

    def _check_log_sinks(self) -> None:
        if self._log_warned:
            return
        for sink in self.sinks:
            error = getattr(sink, "error", None)
            if error:
                self._log_warned = True
                message = f"scan log unavailable: {error}"
                self.internal_warnings.append(message)
                self._emit(EventKind.WARNING, stage="scan", message=message)
                return

    def _elapsed(self, since: float | None) -> float:
        return self.clock() - since if since is not None else 0.0

    # ---------------------------------------------------------- lifecycle

    def scan_started(self, scan_id: str, *, profile: str, mode: str) -> None:
        self._start = self.clock()
        self.last_event_at = self._start
        for sink in self.sinks:
            header = getattr(sink, "header", None)
            if header:
                header(scan_id)
        self._emit(
            EventKind.SCAN_STARTED, stage="scan", message=scan_id,
            detail={"profile": profile, "mode": mode},
        )
        if self._start_thread and self._thread is None:
            self._thread = threading.Thread(
                target=self._heartbeat_loop, name="secscan-heartbeat", daemon=True
            )
            self._thread.start()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        with self._lock:
            for sink in self.sinks:
                sink.finalize()
            for sink in self.sinks:
                sink.close()

    # -------------------------------------------------------------- stages

    def stage_started(self, stage: str) -> None:
        self.current_stage, self._stage_started_at = stage, self.clock()
        self.current_subject = None
        self._emit(EventKind.STAGE_STARTED, stage=stage)

    def stage_done(self, stage: str) -> None:
        elapsed = self._elapsed(self._stage_started_at)
        self._emit(EventKind.STAGE_DONE, stage=stage, elapsed_s=elapsed)
        self.current_stage = self.current_subject = None
        self._stage_started_at = self._subject_started_at = None

    def stage_reused(self, stage: str, resume_key: str | None = None) -> None:
        self._emit(EventKind.STAGE_REUSED, stage=stage, detail={"resume_key": resume_key or ""})

    def stage_skipped(self, stage: str, reason: str) -> None:
        self._emit(EventKind.STAGE_SKIPPED, stage=stage, message=reason)

    def stage_failed(self, stage: str, message: str) -> None:
        elapsed = self._elapsed(self._stage_started_at)
        self._emit(EventKind.STAGE_FAILED, stage=stage, elapsed_s=elapsed, message=message)

    # ------------------------------------------------------------ subjects

    def _subject_started(self, kind: EventKind, stage: str, subject: str, index: int, total: int):
        self.current_stage = stage
        self.current_subject, self._index, self._total = subject, index, total
        self._subject_started_at = self.clock()
        self._emit(kind, stage=stage, subject=subject, index=index, total=total)

    def _subject_done(
        self, kind: EventKind, stage: str, subject: str, index: int, total: int, detail: dict
    ) -> None:
        elapsed = self._elapsed(self._subject_started_at)
        self._emit(
            kind, stage=stage, subject=subject, index=index, total=total,
            elapsed_s=elapsed, detail=detail,
        )
        self.current_subject = self._index = self._total = None
        self._subject_started_at = None

    def segment_started(self, stage: str, segment_id: str, index: int, total: int) -> None:
        self._subject_started(EventKind.SEGMENT_STARTED, stage, segment_id, index, total)

    def segment_done(
        self, stage: str, segment_id: str, index: int, total: int, **detail: Any
    ) -> None:
        self._subject_done(EventKind.SEGMENT_DONE, stage, segment_id, index, total, detail)

    def tool_started(self, stage: str, tool_id: str, index: int, total: int) -> None:
        self._subject_started(EventKind.TOOL_STARTED, stage, tool_id, index, total)

    def tool_done(
        self,
        stage: str,
        tool_id: str,
        index: int,
        total: int,
        *,
        status: str,
        reason: str | None = None,
        **detail: Any,
    ) -> None:
        payload = {"status": status, "reason": reason or "", **detail}
        if self.current_subject != tool_id:
            # skipped before it started: still a subject-level outcome
            self.current_stage = stage
            self._subject_started_at = self.clock()
        self._subject_done(EventKind.TOOL_DONE, stage, tool_id, index, total, payload)

    # ------------------------------------------------------------ warnings

    def warning(self, message: str, *, stage: str, subject: str | None = None) -> None:
        self._emit(EventKind.WARNING, stage=stage, subject=subject, message=message)

    # ----------------------------------------------------------- terminal

    def _terminal(self, kind: EventKind, message: str = "", detail: dict | None = None) -> None:
        stage = self.current_stage or "scan"
        since = self._subject_started_at if self.current_subject else self._stage_started_at
        self._emit(
            kind, stage=stage, subject=self.current_subject, elapsed_s=self._elapsed(since),
            message=message, detail=detail,
        )
        with self._lock:
            for sink in self.sinks:
                sink.finalize()

    def paused(self, pending: int) -> None:
        self._terminal(EventKind.PAUSED, detail={"pending": pending})

    def failed(self, message: str) -> None:
        self._terminal(EventKind.FAILED, message=message)

    def interrupted(self, note: str | None = None) -> None:
        self._terminal(EventKind.INTERRUPTED, message=note or "")

    # ---------------------------------------------------------------- batch

    def batch_submitted(
        self, stage: str, index: int, total: int, *, items: int, model: str, handle: str
    ) -> None:
        self.current_stage = stage
        self._emit(
            EventKind.BATCH_SUBMITTED, stage=stage, subject=f"batch {index}/{total}",
            index=index, total=total, detail={"items": items, "model": model, "handle": handle},
        )

    def batch_status(
        self,
        stage: str,
        index: int,
        total: int,
        *,
        completed: int,
        item_total: int,
        waited_s: float,
        next_poll_s: float,
        **detail: Any,
    ) -> None:
        self.current_stage = stage
        self._emit(
            EventKind.BATCH_STATUS, stage=stage, subject=f"batch {index}/{total}",
            index=index, total=total, elapsed_s=waited_s,
            detail={"completed": completed, "item_total": item_total, "waited_s": waited_s,
                    "next_poll_s": next_poll_s, **detail},
        )

    def batch_done(
        self,
        stage: str,
        index: int,
        total: int,
        *,
        succeeded: int,
        failed: int,
        expired: int,
        fallbacks: int,
    ) -> None:
        self._emit(
            EventKind.BATCH_DONE, stage=stage, subject=f"batch {index}/{total}",
            index=index, total=total,
            detail={"succeeded": succeeded, "failed": failed, "expired": expired,
                    "fallbacks": fallbacks},
        )

    # ----------------------------------------------------------- heartbeat

    def check_heartbeat(self) -> float | None:
        """Emit a heartbeat if the current subject has been silent long enough.

        Returns the silence duration when a heartbeat was emitted, else ``None``.
        Called by the background thread and directly by tests (injected clock).
        """
        with self._lock:
            active = self.current_stage is not None
            silence = self.clock() - self.last_event_at
        if not active or silence < self.heartbeat_interval_s:
            return None
        since = self._subject_started_at if self.current_subject else self._stage_started_at
        self._emit(
            EventKind.HEARTBEAT,
            stage=self.current_stage or "scan",
            subject=self.current_subject,
            index=self._index,
            total=self._total,
            elapsed_s=self._elapsed(since),
        )
        with self._lock:
            self.last_event_at = self.clock()
        return silence

    def _heartbeat_loop(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                remaining = self.heartbeat_interval_s - (self.clock() - self.last_event_at)
            if remaining <= 0:
                if self.check_heartbeat() is None:
                    # nothing active: wait a full interval before looking again
                    self._stop.wait(self.heartbeat_interval_s)
                continue
            self._stop.wait(max(remaining, 0.01))


def build_reporter(
    level: OutputLevel,
    *,
    stream: TextIO | None = None,
    log_path: Path | None = None,
    width: int | None = None,
    heartbeat_interval_s: float = HEARTBEAT_INTERVAL_S,
    clock: Callable[[], float] | None = None,
) -> ProgressReporter:
    """Assemble sinks for ``level``: terminal (unless quiet) plus the scan log."""
    sinks: list[Any] = []
    if level is not OutputLevel.QUIET:
        sinks.append(
            select_terminal_sink(
                stream if stream is not None else sys.stderr,
                width=width,
                verbose=level is OutputLevel.VERBOSE,
            )
        )
    if log_path is not None:
        sinks.append(FileSink(log_path))
    kwargs: dict[str, Any] = {"heartbeat_interval_s": heartbeat_interval_s}
    if clock is not None:
        kwargs["clock"] = clock
    return ProgressReporter(level, sinks, **kwargs)
