# Data Model: Scan Progress Output

**Feature**: 011-scan-progress-output | **Date**: 2026-09-03

All entities live in `src/pipeline/progress.py`. None is persisted as a scan artifact; the only
on-disk representation is the rendered text of `.secscan/scan.log` (see
[contracts/progress-output.md](contracts/progress-output.md)).

## OutputLevel (enum)

| Value | Terminal sinks installed | Notes |
|---|---|---|
| `quiet` | none | stderr byte-identical to pre-feature (nothing). File sink still installed. |
| `default` | one of Plain / Live | stages, segments, tools, warnings, heartbeat, paused/failed/interrupted |
| `verbose` | one of Plain / Live | default + segment detail (level, tokens), tool detail (command, version), reuse reasons |

Resolution precedence: CLI `--output` → `SECSCAN_OUTPUT_LEVEL` → config `output.level` →
`default`. Invalid values are a `ConfigError` (config/env) or a click/argparse choice error
(CLI). Validation rule: exact lowercase match against the three values.

## ProgressEvent (frozen dataclass)

| Field | Type | Constraints |
|---|---|---|
| `kind` | `EventKind` | see below |
| `stage` | `str` | one of the announced stage names (research R9) or `"scan"`/`"config"` |
| `subject` | `str \| None` | segment id or tool id; `None` for stage-level events |
| `index` | `int \| None` | 1-based ordinal of the subject within its stage (segments, tools) |
| `total` | `int \| None` | count of subjects in the stage; present iff `index` is |
| `elapsed_s` | `float \| None` | seconds since the stage (or subject) started; `None` for `*_started` and `warning` |
| `message` | `str` | human text; for `warning` it is the exact string appended to `warnings`; for `failed` it is redacted exception text |
| `detail` | `dict[str, str \| int]` | verbose-only extras: `escalation_level`, `estimated_tokens`, `status`, `reason`, `invocation`, `tool_version`, `resume_key`, `pending` |
| `at` | `float` | wall-clock epoch seconds (for the `HH:MM:SS` column) |
| `since_start_s` | `float` | monotonic seconds since `scan_started` (for the `+MM:SS` column) |

Content restriction (FR-015): `message` and `detail` values may contain only stage/subject
identifiers, repo-relative paths, counts, durations, status words, and strings that already
reach the report. No field may carry source text or a context packet.

### EventKind

```
scan_started
stage_started   stage_done   stage_reused   stage_skipped   stage_failed
segment_started segment_done
tool_started    tool_done
warning
heartbeat
paused          failed       interrupted
```

`stage_skipped` covers "not applicable for this profile" (e.g. `system_review` when the
profile disables it) as distinct from `stage_reused` (checkpoint hit).

### Rendering class

| Class | Kinds | Live sink behaviour |
|---|---|---|
| transient | `stage_started`, `segment_started`, `tool_started`, `heartbeat` | replaces the status line |
| permanent | everything else | erases status line, prints line, redraws status line |

## ProgressReporter

Owns the sinks, the current position, and the heartbeat thread.

| Attribute | Type | Meaning |
|---|---|---|
| `level` | `OutputLevel` | terminal level; the file sink ignores it |
| `sinks` | `list[Sink]` | 0–1 terminal sink + 0–1 file sink |
| `current_stage` | `str \| None` | last `stage_started` not yet `*_done/failed` |
| `current_subject` | `str \| None` | last `segment_started`/`tool_started` not yet done |
| `stage_started_at`, `subject_started_at` | `float \| None` | monotonic |
| `last_event_at` | `float` | monotonic; reset on every emitted event except `heartbeat` |
| `heartbeat_interval_s` | `float` | default 30.0; injectable |
| `internal_warnings` | `list[str]` | conditions the reporter itself detected (today: only "scan log unavailable: …"); `run_scan` drains this into the report's `warnings` before `build_report` |
| `clock` | `Callable[[], float]` | default `time.monotonic`; injectable |
| `_lock` | `threading.Lock` | serialises all sink writes and state updates |
| `start_thread` (ctor kwarg) | `bool` | default `True`; tests pass `False` and drive `check_heartbeat()` directly with an injected clock |

### State transitions

```
idle ──scan_started──▶ running
running ──stage_started(s)──▶ in_stage(s)
in_stage(s) ──segment_started/tool_started(x)──▶ in_subject(s, x)
in_subject(s, x) ──segment_done/tool_done(x)──▶ in_stage(s)
in_stage(s) ──stage_done/stage_failed(s)──▶ running
running | in_stage | in_subject ──paused/failed/interrupted──▶ closed
closed: heartbeat thread joined, live status line finalised, file sink closed
```

Invariants:
- `stage_reused`/`stage_skipped` are emitted in `running` and do not enter `in_stage`.
- `heartbeat` never changes state and is emitted only in `in_stage` or `in_subject` when
  `clock() - last_event_at >= heartbeat_interval_s`.
- `close()` is idempotent and always runs (called from `finally` in `cmd_run`).

### Public API (stable within the codebase)

```
build_reporter(level, *, stream, log_path, width=None, heartbeat_interval_s=30.0, clock=None) -> ProgressReporter
reporter.scan_started(scan_id, *, profile, mode)
reporter.stage_started(stage) / stage_done(stage) / stage_reused(stage, resume_key) / stage_skipped(stage, reason) / stage_failed(stage, message)
reporter.segment_started(stage, segment_id, index, total) / segment_done(stage, segment_id, index, total, **detail)
reporter.tool_started(stage, tool_id, index, total) / tool_done(stage, tool_id, index, total, status, reason, **detail)
reporter.warning(message, *, stage, subject=None)
reporter.paused(pending) / failed(message) / interrupted()
reporter.internal_warnings -> list[str]      # drained by run_scan into the report's warnings
reporter.check_heartbeat() -> float | None    # emit a heartbeat if silent >= interval; used by the thread and by tests
reporter.close()
```

`NullReporter` implements the same surface as no-ops and is the default for `run_scan`.

## Sink (protocol)

```
write(event: ProgressEvent, rendered: str) -> None
finalize() -> None      # Live: promote status line to permanent; Plain/File: no-op
close() -> None
```

| Implementation | Selection | Failure behaviour |
|---|---|---|
| `PlainSink(stream)` | stderr not a TTY, or width unknown/<40, or `TERM=dumb` | write errors propagate (stderr closed = fatal, as today) |
| `LiveSink(stream, width)` | stderr is a TTY and width ≥ 40 | same as Plain; truncates the status line to `width-1` columns |
| `FileSink(path)` | always (once config has loaded) | `OSError` on open/write → sink disables itself, reporter emits one `warning` and appends the same text to `internal_warnings` so the report declares it |

## Config addition

```yaml
output:
  level: default      # quiet | default | verbose
```

`_ALLOWED[""]` gains `"output"`; `_ALLOWED["output"] = ("level",)`; `validate_config` checks the
enum; `Config.output_level -> str` property; `apply_env_overrides` maps `SECSCAN_OUTPUT_LEVEL`.

## Scan log (on-disk)

`<scan_root>/.secscan/scan.log` — UTF-8 text, one rendered line per event at verbose detail,
header line `secscan <TOOL_VERSION> scan <scan_id> started <ISO-8601 UTC>`. Overwritten per run.
Not an artifact: no envelope, no schema, excluded from determinism comparison, included in the
redaction sweep.
