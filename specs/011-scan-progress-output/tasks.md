# Tasks: Scan Progress Output

**Input**: Design documents from `/specs/011-scan-progress-output/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/progress-output.md, quickstart.md

**Tests**: Included. The constitution's Development Workflow mandates test-first ("Tests are
written before implementation and MUST fail first"), so every story phase begins with its
tests. Verify each test fails before implementing the task that makes it pass.

**Organization**: Tasks are grouped by user story so each story is an independently testable
increment. Requirement ids (FR-xxx / SC-xxx) cite spec.md; R-numbers cite research.md.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: US1 = alive/where-it-is, US2 = problems-as-they-happen, US3 = output levels
- Every task names the exact file(s) it touches

## Path Conventions

Single project: `src/` and `tests/` at repository root (see plan.md "Source Code").

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Constants and the module skeleton every later task imports from.

- [X] T001 Add `LOG_FILE_NAME = "scan.log"` beside `SCAN_DIR_NAME` in `src/pipeline/state.py` (no behavioural change; the reporter and tests import it)
- [X] T002 Create `src/pipeline/progress.py` with module docstring, `OutputLevel` enum (`QUIET`, `DEFAULT`, `VERBOSE`, with `from_str()` that accepts the three lowercase names and raises `ValueError` listing them), `EventKind` string enum (all kinds in data-model.md), frozen `ProgressEvent` dataclass (fields per data-model.md), and a `Sink` `Protocol` (`write(event, rendered)`, `finalize()`, `close()`)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The reporter core and its plumbing into `run_scan`/`cmd_run`. Every story emits
through this; nothing user-visible yet except that the pipeline accepts a reporter.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

- [X] T003 [P] Write failing unit tests in `tests/unit/test_progress.py` for the reporter core: `NullReporter` accepts every public call and does nothing; `ProgressReporter` tracks `current_stage`/`current_subject`/start times through the state transitions in data-model.md; `close()` is idempotent; events are delivered to every registered sink with `at`/`since_start_s` populated from an injected clock; `PlainSink` renders the `HH:MM:SS +MM:SS <tag> <text>` grammar from contracts/progress-output.md §3 for `scan_started`, `stage_started`, `stage_done`, and `warning`; `render_elapsed()` yields `1.2s`, `45s`, `3m12s`, `1h02m`
- [X] T004 Implement in `src/pipeline/progress.py`: `render_elapsed(seconds)`; `render(event) -> str` implementing the full text grammar of contracts §3 (all kinds, verbose-only bracketed extras driven by `event.detail`); `PlainSink(stream)`; `NullReporter`; `ProgressReporter(level, sinks, *, clock=time.monotonic, wall_clock=time.time, heartbeat_interval_s=30.0)` with `threading.Lock`, position tracking, `_emit()` that builds the `ProgressEvent`, applies per-sink level filtering (table in research R6 — file sink is unfiltered), and writes under the lock; all public methods listed in data-model.md "Public API" (heartbeat thread and `FileSink`/`LiveSink` are added in later phases — leave `close()` a no-op join hook for now)
- [X] T005 Implement `build_reporter(level, *, stream, log_path, width=None, heartbeat_interval_s=30.0, clock=None)` in `src/pipeline/progress.py` that returns a `ProgressReporter` with a `PlainSink(stream)` for `DEFAULT`/`VERBOSE` and no terminal sink for `QUIET` (log sink wiring comes in T024; TTY selection in T036)
- [X] T006 Add `progress: ProgressReporter | None = None` keyword to `run_scan()` in `src/pipeline/run.py`; bind `reporter = progress or NullReporter()`; pass `reporter` into `_stage()` and `_stage_list()` as a new keyword argument (no events emitted yet); confirm `pytest -q tests/integration` still passes unchanged
- [X] T007 Restructure `src/pipeline/scan_cli.py::cmd_run` so config is loaded **before** the reporter exists: (1) `store_dir = Path(args.workdir).resolve() / SCAN_DIR_NAME`; (2) `config = load(store_dir, environ=environ_overrides)` inside the existing `except (ConfigNotFound, ConfigError)` handler — on failure keep today's stderr message and `EXIT_ERROR` with **no reporter and no `scan.log` created**; (3) `reporter = progress.build_reporter(OutputLevel.DEFAULT, stream=sys.stderr, log_path=store_dir / LOG_FILE_NAME)` (level becomes `config.output_level` in T039); (4) call `run_scan(..., progress=reporter)` inside `try/finally: reporter.close()` so the reporter is closed before the stdout summary is printed (ordering guarantee, contracts §2). `run_scan` still calls `load()` itself — the double load is cheap and keeps the library API unchanged. Assert `tests/integration/test_scan_cli.py::test_run_without_config_exits_with_guidance` still passes and that no `.secscan/` directory is created by it

**Checkpoint**: `pytest -q` green; stderr still empty because no stage emits yet.

---

## Phase 3: User Story 1 — See that the scan is alive and where it is (Priority: P1) 🎯 MVP

**Goal**: Every driven stage announces start/done (or reused/skipped) with elapsed time; the
segment stage shows `i/N <segment_id>`; the first line appears before any stage work.

**Independent Test**: Run a full scan on `single_repo_shop` with a scripted responder and
assert on `capsys.readouterr().err`: a `start scan` line precedes the first stage; every
stage in research R9 has a `start` and a `done`; a second run shows `reuse` for checkpointed
stages; `segment i/N` lines exist for every segment. stdout is unchanged.

### Tests for User Story 1

- [X] T008 [P] [US1] Write failing integration tests in `tests/integration/test_scan_progress.py` (new file; reuse the `configured_shop`/responder helpers from `tests/integration/test_scan_cli.py`): `test_first_progress_line_precedes_stage_work`: build `buf = io.StringIO()` and `reporter = progress.build_reporter(OutputLevel.DEFAULT, stream=buf, log_path=tmp_path / "scan.log")`, monkeypatch `pipeline.discover_repo.run` with a wrapper that asserts `"start" in buf.getvalue()` and that the lines so far contain `scan <id>` **and** `start discover_repo` before delegating to the real function, then call `run_scan(root, progress=reporter, responder=…)`; this proves FR-007 without timing assumptions; `test_every_driven_stage_is_announced` (all R9 stage names appear with `start` then `done`/`skip`); `test_reused_stages_are_reported_not_omitted` (second `run_scan` on the same tree prints `reuse` for `discover_repo`, `build_code_graph`, `partition_repo`); `test_segment_progress_shows_index_of_total` (`segment 1/N`, …, `segment N/N` with N = `len(result.segments)`); `test_stdout_summary_is_unchanged` (stdout equals exactly the three pre-feature summary lines)
- [X] T009 [P] [US1] Extend `tests/unit/test_progress.py` with render cases for `stage_reused` (`reuse <stage> (checkpoint)`), `stage_skipped` (`skip <stage>: <reason>`), `segment_started`/`segment_done` (`<stage> segment i/N <id> (<elapsed>)`), `scan_started` (`scan <id> (<profile> profile, <mode>)`), and a test that `segment_done` at `DEFAULT` omits `level=`/`tokens=` while `VERBOSE` includes them

### Implementation for User Story 1

- [X] T010 [US1] In `src/pipeline/run.py::run_scan`, emit `reporter.scan_started(store.scan_id, profile=active_profile.name, mode=resolution.mode.value)` immediately after `active_profile` is resolved and before the `discover_repo` stage (FR-007)
- [X] T011 [US1] In `src/pipeline/run.py::_stage` and `_stage_list`, emit `reporter.stage_reused(name, resume_key)` on the `should_skip` path, otherwise `reporter.stage_started(name)` before `run()`, `reporter.stage_failed(name, str(exc))` in the `except` (message will be redacted in T029), and `reporter.stage_done(name)` after `mark_done` (FR-001, FR-002)
- [X] T012 [US1] In `src/pipeline/run.py::run_scan`, wrap the stages not driven through `_stage` with explicit `reporter.stage_started(...)`/`stage_done(...)` pairs using the artifact `produced_by.stage` names: `segment_analysis` (`stage_started` beside `store.mark_running("segment_analysis")`, `stage_done` once the per-segment `findings/local/*.json` are written — the checkpoint `mark_done` stays where it is, after tooling and audits), `misconfig`, `compound`, `llm_findings`, `supply_chain`, `agent_config`, `external_tooling`, `dependency_audits`, `correlate_findings` (around `finalize`+`write`), `system_review` (emit `stage_skipped("system_review", "disabled by profile")` when `analysis_depth.system_review` is false), `generate_report` (research R9)
- [X] T013 [US1] In the segment loop of `src/pipeline/run.py::run_scan`, emit `reporter.segment_started("segment_analysis", segment["id"], index, total)` before `runner.run(...)` and `reporter.segment_done(..., escalation_level=outcome.escalation_level, estimated_tokens=outcome.packets[-1]["estimated_tokens"] if outcome.packets else 0)` after it, using `enumerate(segments, start=1)` and `len(segments)` so `--segment` runs show `1/1` (FR-003, edge case "single-segment re-run")
- [X] T014 [US1] Run `pytest -q tests/integration/test_scan_progress.py tests/unit/test_progress.py tests/integration/test_scan_cli.py` and make T008/T009 pass without changing any stdout assertion in `test_scan_cli.py`

**Checkpoint**: `secscan run --full` on a fixture shows a live stage/segment timeline on stderr; stdout unchanged. This is the MVP.

---

## Phase 4: User Story 2 — Learn about problems while they happen (Priority: P2)

**Goal**: Warnings, tool skips/failures, audit gaps, failures, interruptions and handoff are
printed the moment they occur with report-identical wording; `.secscan/scan.log` records
everything; a 30 s heartbeat proves liveness during long single steps.

**Independent Test**: With fixtures that trigger a malformed model response, an unavailable
external tool, and an injected stage exception: each condition prints a `warn`/`skip`/`fail`
line before the summary, the warning text equals the report's coverage note verbatim,
`scan.log` exists and ends with the terminal event, and a handoff renders `pause` + exit 3.

### Tests for User Story 2

- [X] T015 [P] [US2] Extend `tests/integration/test_scan_progress.py` with: `test_malformed_response_warning_is_printed_verbatim` (responder returns non-JSON for one segment; the `warn` line's message equals the corresponding entry in `result.warnings` and appears in `report.md` coverage notes); `test_dependency_audit_and_tool_notes_are_printed` (for every `tool_limitations` entry in the report a `warn` line carries the report's `External tool: …` wording **and**, for `missing`/`skipped` tools, a `skip external_tooling tool i/N <id>: <reason>` line was emitted at decision time; for every `blocking_gaps` entry a `warn` line carries `Blocking gap: …`); `test_handoff_renders_paused_and_exit_3` (stderr ends with the `pause N segment(s) …` line, `scan_cli.main([...])` returns `EXIT_AGENT_HANDOFF`, stdout still contains `handoff.instructions()`); `test_stage_failure_names_stage_and_error` (monkeypatch `build_code_graph.run` to raise `RuntimeError("boom")`; last stderr lines contain `fail build_code_graph` and `scan failed in build_code_graph`; exception still propagates as today); `test_interrupt_exits_130_and_logs_stop` (monkeypatch `build_code_graph.run` to raise `KeyboardInterrupt`; `scan_cli.main` returns `EXIT_INTERRUPTED == 130`, stdout is empty, last stderr line is `stop interrupted in build_code_graph …`, and `scan.log` ends with it)
- [X] T016 [P] [US2] Extend `tests/integration/test_scan_progress.py` with `test_scan_log_exists_and_is_complete_even_when_quiet` for the success case, plus log assertions inside the failure, interrupt and handoff tests of T015: `<root>/.secscan/scan.log` exists, first line matches `secscan <ver> scan <id> started <iso>`, last line matches the terminal event, and the file has every `start`/`done` line even when the level is `QUIET` (pass `OutputLevel.QUIET` via `build_reporter`); plus `test_unwritable_scan_log_is_declared_in_report` (point `log_path` at a path under a read-only directory; the scan completes, `result.warnings` contains a `scan log unavailable:` entry, and it appears in the report's coverage notes)
- [X] T017 [P] [US2] Extend `tests/unit/test_progress.py` with: `test_heartbeat_fires_after_interval_of_silence` (`heartbeat_interval_s=0.05`, fake clock advanced past interval, `wait still running <stage> <subject> (<elapsed>)` written once, then again after another interval, and not at all while events keep arriving); `test_heartbeat_latency_is_bounded_by_interval` (real clock, `heartbeat_interval_s=0.2`: measure wall time from `stage_started` to the first heartbeat write on a recording sink and assert it is `>= 0.2` and `< 0.3` — proves SC-001's bound rather than the 1.5× a fixed poll would give); `test_heartbeat_thread_stops_on_close` (thread `is_alive()` false after `close()`); `test_file_sink_writes_and_flushes_each_line` (tmp path; read back after each write without closing); `test_file_sink_open_failure_emits_one_warning_and_disables` (path inside a non-writable dir → one `warning` event whose message starts with `scan log unavailable:`, the same string is in `reporter.internal_warnings`, the message contains no path component, and later writes do not raise); `test_terminal_events_render` (grammar for `stop`, `fail scan failed in …`, and `pause`)
- [X] T018 [P] [US2] Extend `tests/contract/test_artifact_redaction.py::_artifacts` to also include `.secscan/scan.log` and add `test_scan_log_is_seen_by_the_sweep` asserting the log is among the swept files; run the existing `test_no_artifact_contains_anything_the_redactor_would_flag` against it (must fail until the log exists, then pass)

### Implementation for User Story 2

- [X] T019 [US2] In `src/pipeline/run.py::run_scan`, add a local `_warn(message: str, *, stage: str, subject: str | None = None)` closure that does `warnings.append(message)` **and** `reporter.warning(message, stage=stage, subject=subject)`; replace every `warnings.append(...)` in `run_scan` with `_warn(...)` carrying the correct stage (`segment_analysis` with `segment["id"]` for the normalizer/rejected/secret cases, `llm_findings` for `llm_undetermined`, `partition_repo` for depth-change and single-segment notes); additionally, immediately before `generate_report.build_report(...)`, do `warnings.extend(reporter.internal_warnings)` so a reporter-detected condition (log unavailable) is declared in the report (FR-005, FR-006, FR-019)
- [X] T020 [US2] In the segment loop of `src/pipeline/run.py::run_scan`, after each `runner.run(...)`, emit `reporter.warning(msg, stage="segment_analysis", subject=segment["id"])` for every entry in `builder.warnings[seen:]` and advance `seen`; keep the existing `warnings.extend(builder.warnings)` at the end (it is the report's source of truth) but guard against double-emission by emitting only, not appending, in the loop (research R1)
- [X] T021 [US2] Add `progress: ProgressReporter | None = None` to `src/pipeline/tooling/execute.py::run_external_scans`; for each applicable `entry` (enumerate with index/total) emit `tool_started("external_tooling", entry.id, i, n)` before `runner.run_tool(...)` and `tool_done("external_tooling", entry.id, i, n, status=run.status, reason=run.reason, tool_version=run.tool_version, invocation=run.invocation)` after it; on the pre-run skip branches (scanner disabled, not installed, lockfile missing) emit `tool_done(..., status="skipped", reason=<the same string placed in the limitation record>)`; pass `progress=reporter` from `run.py` (FR-004)
- [X] T022 [US2] In `src/pipeline/run.py::run_scan`, after `tooling_execute.run_external_scans(...)` returns `tool_limitations`, emit `reporter.warning(limitation_text, stage="external_tooling", subject=tool_id)` for each limitation (use the same rendered text the report shows); after `run_dependency_audits` returns `audit_gaps`, emit `reporter.warning(gap, stage="dependency_audits")` for each gap (FR-005)
- [X] T023 [US2] Implement `FileSink(path)` in `src/pipeline/progress.py`: `mkdir(parents=True, exist_ok=True)` on the parent, open `"w"` UTF-8, write the header `secscan {TOOL_VERSION} scan {scan_id} started {ISO-8601 UTC}` on `scan_started`, write+`flush()` per event at verbose detail (no level filtering), `close()` closes the handle; on `OSError` at open or write set `self.disabled = True` and return the error to the reporter, which emits one `warning("scan log unavailable: <ExcName>: <strerror>", stage="scan")` **and** appends the same string to `reporter.internal_warnings` (a `list[str]` attribute added to `ProgressReporter`; `NullReporter.internal_warnings` is an empty list) (FR-019, research R7)
- [X] T024 [US2] Wire `FileSink(log_path)` into `build_reporter()` in `src/pipeline/progress.py` for **every** level including `QUIET`; ensure `ProgressReporter.close()` calls `finalize()` then `close()` on each sink
- [X] T025 [US2] Implement the heartbeat in `src/pipeline/progress.py::ProgressReporter`: a daemon `threading.Thread` started in `scan_started()` whose loop computes `remaining = heartbeat_interval_s - (clock() - last_event_at)`; when `remaining <= 0` and `current_stage` is set it emits `EventKind.HEARTBEAT` with the current stage/subject and elapsed since the subject (or stage) started and resets `last_event_at`; otherwise it waits on a `threading.Event` with `timeout=max(remaining, 0.01)` so the heartbeat fires at exactly the interval, never later (SC-001); every non-heartbeat emit resets `last_event_at`; `close()` sets the event and joins the thread (FR-020, research R4)
- [X] T026 [US2] Add `paused(pending: int)`, `failed(message: str)`, `interrupted()` to `ProgressReporter` in `src/pipeline/progress.py`, rendering per contracts §3 with the tracked stage/subject/elapsed, and have each call `finalize()` on the sinks so a live status line (T037) is promoted before exit
- [X] T027 [US2] In `src/pipeline/scan_cli.py::cmd_run`: on `AgentHandoff` call `reporter.paused(len(handoff.pending))` before printing `handoff.instructions()`; on `ValueError` (unknown segment/profile, raised inside `run_scan`) call `reporter.failed(str(exc))` (already user-safe) before the existing stderr print — `ConfigNotFound`/`ConfigError` are raised by T007's own `load()` before any reporter exists and keep today's behaviour unchanged; on any other `Exception` call `reporter.failed(message)` then re-raise; on `KeyboardInterrupt` call `reporter.interrupted()` and `return 130` (FR-008, FR-009, research R8)
- [X] T028 [US2] Add `EXIT_INTERRUPTED = 130` to `src/pipeline/scan_cli.py` beside the other `EXIT_*` constants and use it in T027
- [X] T029 [US2] Redact failure text before it is emitted: in `src/pipeline/scan_cli.py::cmd_run`, when the config loaded successfully, build a `Redactor(config.redaction_patterns, **_entropy_kwargs(config))` (import `_entropy_kwargs` from `pipeline.run` or move it to a shared helper) and pass `redactor.redact(str(exc)).text` to `reporter.failed()` (config is guaranteed loaded at that point per T007). Apply the same treatment to the `stage_failed` message in `_stage`/`_stage_list` by giving `run_scan` access to the redactor it already constructs (FR-015)
- [X] T030 [US2] Run `pytest -q tests/unit/test_progress.py tests/integration/test_scan_progress.py tests/contract/test_artifact_redaction.py` and make T015–T018 pass

**Checkpoint**: Mid-run problems are visible on stderr as they happen, `scan.log` is a complete trace, heartbeats appear during long silent steps, and handoff/failure/interrupt are unambiguous.

---

## Phase 5: User Story 3 — Control the amount of output (Priority: P3)

**Goal**: `quiet | default | verbose` selectable via CLI, env, or config; quiet is byte-identical
to today; non-TTY output is plain lines; TTY output uses a live status line with permanent
lines for completions/warnings.

**Independent Test**: Run the same scan at the three levels: quiet writes nothing to stderr
and stdout equals the pre-feature lines; default prints stages/segments/tools/warnings;
verbose adds `level=`/`tokens=` and tool invocation detail. With a fake TTY stream, `start`
lines are redrawn with `\r\x1b[2K` and `done`/`warn` lines are permanent; with a non-TTY
stream no escape sequences appear.

### Tests for User Story 3

- [X] T031 [P] [US3] Write failing unit tests in `tests/unit/test_config_output_level.py`: `output.level` accepts `quiet|default|verbose`; an unknown value raises `ConfigError` whose message contains `output.level must be one of: quiet, default, verbose`; an unknown key under `output` is rejected by `_check_unknown_keys`; `SECSCAN_OUTPUT_LEVEL=verbose` overrides a config `output.level: quiet`; `Config.output_level` defaults to `"default"` when the section is absent
- [X] T032 [P] [US3] Extend `tests/integration/test_scan_progress.py` with: `test_quiet_stderr_is_empty_and_stdout_unchanged` (`scan_cli.main(["run", "--workdir", …, "--full", "--output", "quiet"])`: `err == ""`, `out` equals the pre-feature summary lines); `test_short_flags_map_to_levels` (`-q` behaves as quiet, `-v` as verbose); `test_verbose_adds_segment_and_tool_detail` (`level=` and `tokens=` present; a `ran` tool line includes the version/invocation suffix when a tool is available, else assert the skip reason path); `test_env_override_selects_level` (`SECSCAN_OUTPUT_LEVEL=quiet` in `monkeypatch.setenv` → empty stderr); `test_cli_flag_beats_env` (`SECSCAN_OUTPUT_LEVEL=quiet` + `--output verbose` → verbose output); `test_non_tty_output_has_no_escape_sequences` (`"\x1b" not in err and "\r" not in err`)
- [X] T033 [P] [US3] Extend `tests/unit/test_progress.py` with `LiveSink` tests using a fake stream whose `isatty()` returns `True`: transient events write `\r\x1b[2K+MM:SS <text>` without newline; a permanent event first erases the status line, writes the permanent line + `\n`, then redraws the status line; `finalize()` writes `\n` promoting the status line; the status line is truncated to `width - 1`; `select_terminal_sink(stream, width)` returns `PlainSink` when `isatty()` is `False`, when `width < 40`, when `width == 0` (unknown), or when `TERM=dumb` (monkeypatch env), and `LiveSink` otherwise; and `test_live_and_plain_sinks_present_the_same_events` (FR-013b/SC-009): feed an identical scripted event sequence — stages, segments, a tool, two warnings, a heartbeat, `paused` — to one reporter with a `LiveSink` over a fake TTY and one with a `PlainSink`, strip `\r\x1b[2K` and split on `\n`/`\r`, and assert the set of rendered `<kind-tag> <text>` payloads is identical between the two
- [X] T034 [P] [US3] Extend `tests/integration/test_determinism.py` with `test_artifacts_identical_across_output_levels`: scan two copies of `single_repo_shop`, one with `OutputLevel.QUIET` and one with `OutputLevel.VERBOSE` reporters, and assert `_artifacts()` maps are equal; also assert `scan.log` exists in both and is **not** in `_artifacts()` (SC-004, FR-016)
- [X] T035 [P] [US3] Write failing tests in `tests/integration/test_installer_run_flags.py` (new file) using `click.testing.CliRunner` against `installer.cli.main` with `scan_cli.cmd_run` monkeypatched to capture its `argparse.Namespace` and return `0`: `run --output verbose` → `ns.output == "verbose"`; `run -q` → `"quiet"`; `run -v` → `"verbose"`; no flag → `ns.output is None`; `run -q -v` and `run -q --output verbose` → exit code 2 with a usage error mentioning both flags (FR-011, FR-017)

### Implementation for User Story 3

- [X] T036 [US3] Implement `LiveSink(stream, width)` and `select_terminal_sink(stream, width=None)` in `src/pipeline/progress.py` per research R2/R3 (`isatty()`, `shutil.get_terminal_size(fallback=(0, 0)).columns`, `TERM != "dumb"`, width ≥ 40; `\r\x1b[2K` erase-line; truncate to `width - 1`; `finalize()` promotes the status line); make `build_reporter()` use `select_terminal_sink` for `DEFAULT`/`VERBOSE` (FR-013, FR-013a, FR-013b)
- [X] T037 [US3] Ensure verbose-only detail rendering in `src/pipeline/progress.py::render`: `segment_done` appends ` level={L} tokens={T}`, `tool_done` (ran) appends ` {tool_version}: {invocation}`, `stage_reused` appends ` resume_key={key}`, only when the sink's level is `VERBOSE` or the sink is the file sink (FR-010 verbose contents)
- [X] T038 [US3] Add the `output` config section to `src/config/loader.py`: `"output"` in `_ALLOWED[""]`, `_ALLOWED["output"] = ("level",)`, a `validate_config` block producing `ConfigError("output.level must be one of: quiet, default, verbose (got '…')")`, `Config.output_level -> str` property defaulting to `"default"`, and `OUTPUT` in the recognised env-section prefixes of `apply_env_overrides` so `SECSCAN_OUTPUT_LEVEL` maps to `raw["output"]["level"]` (FR-011)
- [X] T039 [US3] Add `--output {quiet,default,verbose}`, `-q` (`store_const` quiet) and `-v` (`store_const` verbose) to the `run` subparser in `src/pipeline/scan_cli.py::build_parser` as a mutually exclusive group; in `cmd_run` inject the chosen value as `environ_overrides["SECSCAN_OUTPUT_LEVEL"]` (same pattern as `--policy`) **before** the `load()` call introduced in T007, then replace the hard-coded `OutputLevel.DEFAULT` in T007's `build_reporter` call with `OutputLevel.from_str(config.output_level)`; an invalid level is therefore reported through the existing `ConfigError` path with no reporter created (FR-011, FR-017)
- [X] T040 [US3] Add `--output` (`click.Choice(["quiet", "default", "verbose"])`), `-q`, and `-v` flags to `run_command` in `src/installer/cli.py`; reject `-q`/`-v` together or with `--output` via `click.UsageError`; add `output=<resolved value or None>` to the `argparse.Namespace` handed to `scan_cli.cmd_run`; makes T035 pass (FR-011)
- [X] T041 [US3] Run `pytest -q tests/unit/test_config_output_level.py tests/unit/test_progress.py tests/integration/test_scan_progress.py tests/integration/test_determinism.py tests/integration/test_installer_run_flags.py` and make T031–T035 pass

**Checkpoint**: All three stories work independently; quiet reproduces today's terminal experience exactly.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Documentation currency (constitution gate — blocking), agent guidance, and full verification.

- [X] T042 [P] Update `docs/cli-reference.md`: add `--output` / `-q` / `-v` rows to the `secscan run` options table, a "Progress output" subsection describing the stderr/stdout split and the `scan.log`, and add exit code `130` (interrupted) to the exit-code table
- [X] T043 [P] Update `docs/configuration.md`: document the `output.level` key and `SECSCAN_OUTPUT_LEVEL` in the env-override section with the precedence order (CLI → env → config → default)
- [X] T044 [P] Update `docs/artifacts.md`: add `scan.log` to the `.secscan/` layout with an explicit "diagnostic file, not an artifact — overwritten per run, excluded from determinism comparison, included in the redaction sweep" note
- [X] T045 [P] Update `docs/getting-started.md`: after the first `secscan run --full`, show a short sample of the progress lines the operator will see, mention `-q` for scripts, and mention `.secscan/scan.log` in the "exit code 3" section as the place to look when a scan stops
- [X] T046 [P] Update `README.md`: one sentence in Quick start about progress on stderr / `-q`, add `scan.log` to the `.secscan/` layout block, and add `130` to the exit-code line
- [X] T047 [P] Update `src/skill_core/SKILL.md`: note that `run` prints progress to stderr, that `.secscan/scan.log` holds the full trace for diagnosing a stopped scan, and that `--output quiet` is available when only the summary is wanted
- [X] T048 Add `Progress output` bullets to `AGENTS.md` under Non-negotiables/Layout as appropriate: progress goes to stderr and `scan.log`, never into artifacts; `pipeline/progress.py` is the only module that may write to the terminal during a scan
- [X] T049 Run the full gates: `pytest -q`, `pytest -q -m slow`, `ruff check src tests`; fix any failures without altering stdout summary strings or artifact content
- [X] T050 Execute `specs/011-scan-progress-output/quickstart.md` §1–§3 and §5 manually against a built `single_repo_shop` fixture and record any grammar deviations back into `contracts/progress-output.md`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: none — start immediately
- **Foundational (Phase 2)**: depends on Phase 1 — **blocks all stories**
- **US1 (Phase 3)**: depends on Phase 2
- **US2 (Phase 4)**: depends on Phase 2; T026/T027 (`paused`/`failed`/`interrupted` finalising the live line) are exercised fully only after T036, but are independently testable with `PlainSink`
- **US3 (Phase 5)**: depends on Phase 2; T037 (verbose detail) needs the `segment_done` detail produced by T013 (US1) to be observable in integration tests
- **Polish (Phase 6)**: depends on all stories

### User Story Dependencies

- **US1**: independent after Phase 2
- **US2**: independent after Phase 2 (its integration tests assert on warnings/tools/log, not on US1 stage lines)
- **US3**: independent after Phase 2 for the level/CLI/config/TTY machinery; verbose-detail assertions reference US1's segment events

### Within Each Story

Tests first and failing → `progress.py` changes → `run.py`/`execute.py` emission → `scan_cli.py`/`installer/cli.py` surface → run the story's tests.

### Parallel Opportunities

- Phase 2: T003 alongside T004–T007 (test file vs implementation files)
- US1: T008 ‖ T009 (different test files)
- US2: T015 ‖ T016 ‖ T017 ‖ T018 (four different test files); T021 (`execute.py`) ‖ T023 (`progress.py`) ‖ T028 (`scan_cli.py` constant)
- US3: T031 ‖ T032 ‖ T033 ‖ T034 ‖ T035; T038 (`loader.py`) ‖ T040 (`installer/cli.py`) once T036/T037 land
- Polish: T042–T047 all touch different files

---

## Parallel Example: User Story 2

```bash
# Write all US2 tests together (four files, no shared state):
Task: "T015 integration warnings/tools/handoff/failure tests in tests/integration/test_scan_progress.py"
Task: "T016 scan.log lifecycle tests in tests/integration/test_scan_progress.py"   # same file as T015 — sequence after it
Task: "T017 heartbeat/FileSink/render unit tests in tests/unit/test_progress.py"
Task: "T018 redaction sweep extension in tests/contract/test_artifact_redaction.py"

# Then implement across independent modules:
Task: "T021 tool events in src/pipeline/tooling/execute.py"
Task: "T023 FileSink in src/pipeline/progress.py"
Task: "T028 EXIT_INTERRUPTED in src/pipeline/scan_cli.py"
```

---

## Implementation Strategy

### MVP First (User Story 1 only)

1. Phase 1 → Phase 2 → Phase 3 (T001–T014)
2. **STOP and VALIDATE**: `secscan run --full` on a fixture shows the stage/segment timeline; `pytest -q` green; stdout unchanged
3. Ship — the "is it stuck?" complaint is answered at this point

### Incremental Delivery

1. + US2 (T015–T030): problems visible as they happen, `scan.log`, heartbeat, clean failure/handoff/interrupt
2. + US3 (T031–T041): levels, config/env/CLI, live TTY rendering, quiet parity guaranteed by test
3. + Polish (T042–T050): docs (blocking under the constitution's documentation-currency gate), agent guidance, full gates

### Notes

- Never change the three stdout summary strings in `scan_cli.py::cmd_run` (`test_stdout_summary_is_unchanged`, `test_installed_payload.py` depend on them)
- Never write timing or level into an artifact; `scan.log` is the only new file and it is not an artifact
- Warning text must be the same string object appended to `warnings` — do not paraphrase in the reporter
- Anything printed on failure passes through the `Redactor` first
- Commit after each phase checkpoint
