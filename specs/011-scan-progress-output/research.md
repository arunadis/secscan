# Research: Scan Progress Output

**Feature**: 011-scan-progress-output | **Date**: 2026-09-03

No `NEEDS CLARIFICATION` markers remained in the Technical Context; the questions below are the
design decisions that the spec's clarifications leave to planning.

## R1. Where progress is emitted from

**Decision**: `run_scan(scan_root, *, progress: ProgressReporter | None = None, ...)`. When
`None`, a `NullReporter` is used, so the library API, every existing test, and
`ScanResult` are unchanged. Emission points:

| Event | Emitted from |
|---|---|
| `scan_started` | `run_scan` immediately after `ArtifactStore` is constructed (before `discover_repo`) — satisfies FR-007 (< 1 s) |
| `stage_started` / `stage_done` / `stage_reused` / `stage_failed` | `_stage` and `_stage_list` (`run.py:515-545`) — the only place `should_skip` is consulted, so "reused" is provably true |
| `stage_started`/`stage_done` for stages not driven through `_stage` | explicit calls around `segment_analysis` (`run.py:212`, `409`), the deterministic passes (`misconfig`, `compound`, `llm_findings`, `supply_chain`, `agent_config`), `external_tooling`, `dependency_audits`, `correlate_findings` (`finalize`, which internally runs normalize/verify/correlate/calibrate/reproduce/consistency), `system_review`, `generate_report` |
| `segment_started` / `segment_done` (n/N, id, elapsed, level reached, `estimated_tokens` of last packet) | the loop at `run.py:214-237`; level and tokens come from `SegmentOutcome.escalation_level` and `outcome.packets[-1]["estimated_tokens"]` |
| `tool_started` / `tool_done` (status ran/skipped/failed + reason) | `tooling/execute.run_external_scans` gains `progress` kwarg; emitted per `entry` around `runner.run_tool`, and once per skip branch with the reason string already used for the limitation record |
| `warning` | a `_warn(msg, *, stage, subject=None)` closure in `run_scan` that appends to `warnings` **and** emits — replacing every bare `warnings.append`; `builder.warnings` (populated inside `ContextBuilder`/`EscalationRunner._fit`) are emitted by diffing the list length after each segment, attributed to that segment; tool limitations and audit `blocking_gaps` are emitted as they are returned |
| `paused` (handoff) / `failed` / `interrupted` | `scan_cli.cmd_run`, which already owns the `AgentHandoff`/exception boundary |

**Rationale**: keeps the pipeline dependent only on a narrow interface; warning text is the
same object that reaches the report (FR-006, Principle IV).

**Alternatives considered**: `logging` module with handlers — rejected: would introduce a
second message-formatting path from the report strings, and level semantics (`INFO`/`DEBUG`)
map poorly onto stage/subject events; a module-global reporter — rejected: makes tests order-
dependent and hides the dependency.

## R2. Rendering: stdlib only, three sinks

**Decision**: no new dependency. Three sinks behind one `Sink` protocol:

- `PlainSink(stream)` — one line per event: `HH:MM:SS  +MM:SS  <kind> <text>`.
- `LiveSink(stream, width)` — same permanent lines for `stage_done`, `stage_reused`,
  `warning`, `tool_done`, `segment_done`, `paused`, `failed`; a single transient status line
  (`\r` + `\x1b[2K` erase-line) for `stage_started`, `segment_started`, `tool_started`,
  `heartbeat`. Before writing a permanent line the transient line is erased; after it, the
  status line is redrawn. `finalize()` converts the current status line into a permanent
  line (used on exit/interrupt).
- `FileSink(path)` — `PlainSink` over a text file opened `"w"`, `flush()` after every line.

**Rationale**: the surface is one status line, not a progress bar; `rich`/`tqdm` would add a
runtime dependency to a security tool for cosmetics. `\r`+erase-line is supported by every
terminal the project targets (macOS Terminal/iTerm, Linux VTs, VS Code/Windsurf terminals).

**Alternatives considered**: `rich.live` — rejected (dependency, test complexity, non-TTY
behaviour differs); curses — rejected (takes over the screen, breaks scrollback).

## R3. TTY detection and fallback

**Decision**: `LiveSink` is selected only when `stream.isatty()` is true **and**
`shutil.get_terminal_size(fallback=(0, 0)).columns >= 40` **and** `os.environ.get("TERM") !=
"dumb"`. Otherwise `PlainSink`. Selection happens once, in `scan_cli.cmd_run`, via
`progress.build_reporter(level, stream=sys.stderr, log_path=...)`. Tests inject a fake stream
with `isatty()` returning the desired value and pass `width=` explicitly.

**Rationale**: FR-013a fallback; agents and CI (non-TTY) always get plain lines (FR-013,
clarification 4).

## R4. Heartbeat

**Decision**: `ProgressReporter` owns a daemon `threading.Thread` started on `scan_started`
and stopped in `close()`. The thread loops on a `threading.Event` (`_stop`):
`remaining = interval - (clock() - last_event_at)`; if `remaining <= 0` and a stage is
current, it emits `heartbeat(stage, subject, elapsed_since_subject_started)` and resets
`last_event_at`; otherwise it `_stop.wait(timeout=max(remaining, 0.01))`. Because the wait is
computed from the actual moment of the last event rather than a fixed poll, the first
heartbeat lands at **exactly `interval` (30 s) of silence**, never later — this is what makes
SC-001's "never longer than 30 seconds" hold, where a naive `interval/2` poll would allow a 45 s
gap. `close()` sets `_stop` and joins. A `Lock` guards `last_event_at`, the current
stage/subject, and all sink writes, so a heartbeat and a pipeline event never interleave
mid-line. Interval and clock (`time.monotonic` by default) are constructor parameters so unit
tests use `interval=0.05` and a fake clock.

**Rationale**: the blocking points (`urllib.request.urlopen(timeout=120)` in
`llm_client._http_transport`, `subprocess.run(timeout=...)` in tooling and audits) cannot be
made to yield without restructuring them; a side thread that only writes to sinks is the
minimal, isolated change. It never touches `ArtifactStore` or pipeline state, so it cannot
affect artifacts (Principle I).

**Alternatives considered**: `signal.setitimer`/`SIGALRM` — rejected (POSIX-only, unsafe with
subprocess handling); polling inside transports — rejected (spreads progress logic into
transport code; agent-mediated mode has no transport to poll).

## R5. Output level selection and precedence

**Decision**: `OutputLevel` enum `quiet | default | verbose`. Sources, highest precedence
first: CLI `--output LEVEL` (with `-q` ≡ `--output quiet`, `-v` ≡ `--output verbose`) → env
`SECSCAN_OUTPUT_LEVEL` → config `output.level` → `default`. The CLI passes the flag to
`cmd_run` via the existing `environ_overrides` mechanism (`scan_cli.py:211-220` precedent for
`--policy`/`--tool-timeout`), so `config.loader` remains the single resolver.

**Load order in `cmd_run`** (fixes the analysis finding I1): `cmd_run` calls
`config.loader.load(store_dir, environ=environ_overrides)` *itself*, before any reporter
exists. If that raises `ConfigNotFound`/`ConfigError`, behaviour is exactly today's — message
on stderr, `EXIT_ERROR`, **no reporter, no `scan.log`, no `.secscan/` directory created** in a
project that was never initialised (Principle VI). Only after the config loads does `cmd_run`
resolve `OutputLevel.from_str(config.output_level)`, build the reporter (which opens the log),
and call `run_scan(progress=reporter)`. `run_scan` still loads the config internally so its
library signature is unchanged; the duplicate load is a few milliseconds.

**Rationale**: matches the documented `SECSCAN_<SECTION>_<KEY>` convention and the
`_ALLOWED`/`validate_config` strict-key pattern (`loader.py:35-47`, `337-513`). Additive
config key; no `schema_version` impact (config is not an artifact).

**Alternatives considered**: `--verbose`/`--quiet` flags only — rejected: no config/env path
for agents; count-style `-vv` — rejected: three named levels are what the spec defines.

## R6. Level filtering

**Decision**: filtering is per sink at emission time:

| Event kind | quiet | default | verbose | scan.log |
|---|---|---|---|---|
| scan_started, stage_started/done/reused/failed | – | yes | yes | yes |
| segment_started/done (n/N, id, elapsed) | – | yes | yes | yes |
| segment_done details (level reached, tokens) | – | – | yes | yes |
| tool_started/done (status, reason) | – | yes | yes | yes |
| tool invocation detail (command, version) | – | – | yes | yes |
| stage_reused reason (resume key matched) | – | – | yes | yes |
| warning | – | yes | yes | yes |
| heartbeat | – | yes | yes | yes |
| paused / failed / interrupted | – | yes | yes | yes |

Quiet installs no terminal sink at all (so stderr output is byte-identical to today: nothing).
The file sink is always installed at verbose (FR-019).

## R7. `scan.log` lifecycle and safety

**Decision**: path `store.dir / "scan.log"` (`LOG_FILE_NAME = "scan.log"` beside
`SCAN_DIR_NAME` in `state.py`). Created by `FileSink.__init__` at reporter construction —
before `run_scan` — with `store.dir.mkdir(parents=True, exist_ok=True)` (mirrors
`save_state`). Opened `"w"`, `encoding="utf-8"`, flushed per line; closed in
`reporter.close()` from a `finally` in `cmd_run`. If open or write raises `OSError`, the sink
disables itself and the reporter emits one `warning` ("scan log unavailable: <reason>") **and**
records the same string in `reporter.internal_warnings`. The reporter has no access to
`run_scan`'s `warnings` list, so `run_scan` drains `reporter.internal_warnings` into `warnings`
immediately before `generate_report.build_report(...)`; that is how the report declares the
gap (FR-019, Principle V) without the reporter ever reaching into pipeline state. `<reason>` is
`type(exc).__name__` plus `exc.strerror` — never the full path, which could carry a user
name (the report is redaction-swept).

Determinism: `tests/integration/test_determinism.py::_artifacts` and
`test_tooling_determinism.py` glob `*.json` only — the log is naturally excluded; a new test
asserts artifacts are identical across levels and that `scan.log` differs only in timestamps
(so nobody later "fixes" the glob to include it). Redaction:
`tests/contract/test_artifact_redaction.py::_artifacts` (`*.json|*.md|*.html`) is extended to
include `scan.log`; `test_nvd_key_redaction.py::_sweep` already walks every file.

**Alternatives considered**: JSON-lines log — rejected: the file's purpose is human post-
mortem; the plain rendered line is what the operator saw. Append/rotate — rejected by
clarification 1 (overwrite per run).

## R8. Failure, interruption, and handoff rendering

**Decision**: in `cmd_run`:

- `AgentHandoff` → `reporter.paused(pending=len(handoff.pending))` then the existing
  `print(handoff.instructions())` on stdout and `EXIT_AGENT_HANDOFF`.
- `ConfigNotFound`/`ConfigError` → raised by `cmd_run`'s own `load()` before any reporter
  exists (R5): unchanged stderr message and `EXIT_ERROR`, nothing else written.
- `ValueError` (unknown segment/profile, raised inside `run_scan`) → unchanged stderr message
  and `EXIT_ERROR`; the reporter emits `failed(message)` first since it already exists.
- any other `Exception` → `reporter.failed(message)` with
  `message = redactor.redact(str(exc)).text` (the config is guaranteed loaded once a reporter
  exists, see R5); the reporter supplies stage/subject/elapsed from its own position tracking;
  then re-raise so behaviour/exit status is unchanged.
- `KeyboardInterrupt` → `reporter.interrupted(stage, subject, elapsed)`, `finalize()`, exit
  code 130 (shell convention). Today Ctrl-C produces a traceback; this is a strict
  improvement and the checkpoint state already makes re-run resume.

The reporter tracks `current_stage`, `current_subject`, and their start times, so
`cmd_run` does not need pipeline internals to say where the scan died (FR-008, SC-002).

**Rationale**: `cmd_run` already owns the exception boundary; `_stage` already calls
`mark_failed` and re-raises, so stage_failed and failed events line up with checkpoint state.

## R9. Which "stages" are announced

**Decision**: announce what `run_scan` actually drives, in order — `discover_repo`,
`build_code_graph`, `partition_repo`, `segment_analysis` (with segments), `misconfig`,
`compound`, `llm_findings`, `supply_chain`, `agent_config`, `external_tooling` (with tools),
`dependency_audits`, `correlate_findings`, `system_review` (only when the profile enables it;
otherwise reported as `skipped: profile`), `generate_report`. Names reuse the
`produced_by.stage` strings already written into artifacts so the log and the artifacts agree.
The finer `STAGES` entries executed inside `correlate_findings.finalize` (normalize, verify,
calibrate, reproduce, consistency) are **not** announced individually in this feature: they
are deterministic, fast, and not separately checkpointed by the driver; announcing them would
require threading the reporter into `finalize`. Recorded as a possible follow-up.

## R10. Parity for the payload-internal CLI

**Decision**: `--output/-q/-v` are added to `scan_cli.build_parser`'s `run` subparser (the
argparse surface installed skills call) and to `installer/cli.py run_command` (click), which
already builds an `argparse.Namespace` for `cmd_run`. `run.py:main()` (the `pragma: no cover`
wrapper) is left as is; it is not a documented entry point. `SKILL.md` gains a sentence telling
the agent that progress arrives on stderr, that `.secscan/scan.log` holds the full trace, and
that `--output quiet` exists.

## R11. Test strategy

- **Unit (`tests/unit/test_progress.py`)**: level filtering table (R6) as a parametrised test;
  `PlainSink` line format; `LiveSink` erase/redraw sequence and `finalize()`; TTY/width
  fallback matrix; heartbeat fires after `interval` of silence and not before, with a fake
  clock and `interval=0.05`; `FileSink` write failure → warning, scan continues; thread is
  stopped by `close()`.
- **Unit (`tests/unit/test_config_output_level.py`)**: `output.level` accepted values,
  rejection of unknown value with the existing `ConfigError` style, env override, CLI >
  env > config precedence.
- **Integration (`tests/integration/test_scan_progress.py`)** on `single_repo_shop` with a
  scripted `responder`: first stderr line before any stage work (assert via a responder that
  records whether stderr already has content when first called); every driven stage announced;
  reused stages on a second run; `segment i/N`; a malformed response produces the identical
  warning string on stderr and in `result.warnings`; handoff renders `paused` and exit 3;
  injected exception in a stage → last lines name stage + error, `scan.log` exists and ends
  with the failure; `--output quiet` stderr is empty and stdout equals the pre-feature lines.
- **Extensions**: `test_determinism.py` — artifacts identical between quiet and verbose runs;
  `test_artifact_redaction.py` — sweep includes `scan.log`; `test_scan_cli.py` — stdout
  assertions unchanged.

Test-first per constitution: each test file is written and fails before the module exists.
