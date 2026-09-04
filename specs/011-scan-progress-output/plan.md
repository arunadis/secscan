# Implementation Plan: Scan Progress Output

**Branch**: `011-scan-progress-output` | **Date**: 2026-09-03 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/011-scan-progress-output/spec.md`

## Summary

`secscan run` prints nothing between invocation and the final two-line summary: `cmd_run`
(`src/pipeline/scan_cli.py:222-245`) calls `run_scan` and every one of the ~12 driver stages in
`src/pipeline/run.py` — including the per-segment model loop whose HTTP transport blocks up to
120 s per call, and external scanner subprocesses — runs silently. Coverage notes are appended
to in-memory lists and surface only in the report. The fix is a single **progress event
stream**: a new `pipeline/progress.py` module defines a `ProgressEvent` record, an
`OutputLevel`, and a `ProgressReporter` that fans events out to three stdlib-only sinks — a
plain line-per-event stderr sink, a TTY in-place status-line sink, and an always-on verbose
`.secscan/scan.log` file sink. `run_scan` gains an optional `progress` argument (default: a
no-op reporter, so every existing caller and test is unchanged); the `_stage`/`_stage_list`
helpers emit `stage_started`/`stage_done`/`stage_reused`; the segment loop, external-tooling
loop and dependency-audit call emit subject-level events; every `warnings.append` is routed
through the reporter so the exact report wording is printed the moment it is recorded. A
daemon heartbeat thread inside the reporter emits a `heartbeat` for the current subject after
30 s of silence. The level is chosen by `--output quiet|default|verbose` on both CLIs, the
`SECSCAN_OUTPUT_LEVEL` env override, or a new `output.level` config key; the stdout summary
lines are untouched, so quiet is byte-identical to today.

## Technical Context

**Language/Version**: Python 3.11+ (constitution technology constraint)

**Primary Dependencies**: stdlib only — `sys`, `time`, `threading`, `shutil` (terminal size), `os`. No `rich`/`tqdm`/`logging`: the codebase has none of these today, the render surface is one status line plus permanent lines, and a new runtime dependency is not justified for that (research R2)

**Storage**: `.secscan/scan.log` — plain text, overwritten per run, written incrementally. Explicitly *not* an artifact: no envelope, no schema, excluded from determinism comparison (which already globs `*.json`) and added to the redaction sweep

**Testing**: pytest (unit for reporter/sinks/heartbeat with injected clock and fake streams; integration for `cmd_run` stderr/stdout contract via `capsys`, log-file presence on failure/handoff, determinism and redaction sweeps extended), ruff

**Target Platform**: CLI tool run locally (macOS/Linux terminal) or non-interactively (agent skill via `python -m pipeline.scan_cli`, CI)

**Project Type**: CLI security scanner (offline, deterministic pipeline + bounded LLM analysis)

**Performance Goals**: first progress line < 1 s after invocation (emitted before `discover_repo`); no event gap > 30 s (heartbeat); negligible scan wall-time overhead (one lock + one write per event)

**Constraints**: byte-identical artifacts regardless of level (timing never enters an artifact); quiet-level stdout byte-identical to pre-feature; stderr for progress, stdout for summary; no credential values in any line (messages are the already-redacted report strings plus identifiers/paths/counts/durations); TTY sink falls back to plain when width unknown/<40 or stderr not a TTY

**Scale/Scope**: one new module (`pipeline/progress.py`), edits in `run.py`, `scan_cli.py`, `installer/cli.py`, `tooling/execute.py`, `config/loader.py`; one new config key; docs updates in `README.md`, `docs/cli-reference.md`, `docs/configuration.md`, `docs/artifacts.md`, `docs/getting-started.md`, `src/skill_core/SKILL.md`

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Evaluation | Result |
|-----------|-----------|--------|
| I. Determinism Before Intelligence | Progress is a side channel. Events carry wall-clock durations but are written only to stderr and `scan.log`, never to an enveloped artifact; `state.json` (already excluded from the two-run comparison because of `updated_at`) is not touched by the reporter. No stage logic changes; the reporter is observe-only. Determinism tests gain an explicit assertion that `.secscan/**/*.json`, `*.md`, `*.html` are unchanged by level. | PASS |
| II. Context Is a Managed Resource | No packet, budget, or partitioning change. Verbose level *reports* per-segment `estimated_tokens` and escalation level already computed by `EscalationRunner`. | PASS |
| III. Secrets Never Reach a Model | Progress never feeds a model. Content is restricted to stage names, segment ids, tool ids, repo-relative paths, counts, durations, and the warning strings that already pass the artifact redaction sweep. `scan.log` is added to `tests/contract/test_artifact_redaction.py`'s sweep so the same recall gate applies to it. Exception text printed on failure goes through the `Redactor` before emission (research R8). | PASS |
| IV. Evidence Over Assertion | FR-006: warning lines are the *same string objects* appended to `warnings` — emitted by the one `_warn` helper that also appends — so terminal and report cannot disagree. Stage events derive from the checkpoint helpers, so "reused" is only printed when `should_skip` actually returned true. | PASS |
| V. Honest Uncertainty | Surfacing coverage notes, tool skips and `could-not-check` audit gaps at the moment they occur makes declared unknowns *more* visible, never less. Handoff is rendered as `paused`, distinct from `failed`. Nothing is suppressed by level: quiet only silences the terminal; the log always has everything. | PASS |
| VI. Observe, Never Attack | The only new write is `.secscan/scan.log`, inside the directory the scanner already owns and excludes from analysis; the project's manifests/lockfiles hash-check is unaffected. No new subprocesses or network. | PASS |

No violations. Complexity Tracking is empty.

**Post-design re-check (2026-09-03)**: Phase 0/1 artifacts hold the gates. The event model
(data-model.md) has no field that can carry file content; the log sink writes the same rendered
lines as the plain sink, so one redaction sweep covers both (R7). The heartbeat thread only
*reads* reporter state under a lock and writes to sinks — it never touches the store or the
pipeline (R4), so it cannot introduce ordering nondeterminism into artifacts. `output.level` is a
single additive config key with strict validation (R6). The one place a *new* string enters the
stream — exception text on failure — is passed through the redactor first (R8).

## Project Structure

### Documentation (this feature)

```text
specs/011-scan-progress-output/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/
│   └── progress-output.md   # CLI flag/env/config, event grammar, scan.log format
├── checklists/requirements.md
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created by /speckit-plan)
```

### Source Code (repository root)

```text
src/
├── pipeline/
│   ├── progress.py          # NEW: ProgressEvent, OutputLevel, ProgressReporter, sinks, heartbeat
│   ├── run.py               # run_scan(progress=...); _stage/_stage_list emit; _warn helper;
│   │                        #   segment/tool/audit events; ScanResult unchanged
│   ├── scan_cli.py          # --output flag; build reporter; failure/handoff/interrupt events;
│   │                        #   summary lines unchanged
│   ├── state.py             # LOG_FILE_NAME constant only (no behavioural change)
│   └── tooling/execute.py   # run_external_scans(..., progress=...) emits tool events
├── installer/cli.py         # --output / -q / -v options on `secscan run`
├── config/loader.py         # output.level key: _ALLOWED, validate_config, Config.output_level,
│                            #   SECSCAN_OUTPUT_LEVEL env mapping
└── skill_core/SKILL.md      # documents progress on stderr, scan.log, --output quiet

tests/
├── unit/test_progress.py               # NEW: reporter, level filtering, plain/live/file sinks,
│                                       #   heartbeat with injected clock, TTY fallback, log-write failure
├── unit/test_config_output_level.py    # NEW: config key validation, env override, precedence
├── integration/test_scan_progress.py   # NEW: cmd_run stderr contract, first line <1s, per-segment
│                                       #   n/N, reused stages, warnings verbatim, tool skips,
│                                       #   handoff=paused, failure/interrupt last lines, scan.log,
│                                       #   quiet == today, levels via CLI/env/config, artifacts
│                                       #   identical across levels (reuses test_determinism._artifacts)
├── integration/test_installer_run_flags.py  # NEW: click --output/-q/-v surface (CliRunner)
└── contract/test_artifact_redaction.py # extend: sweep includes scan.log

docs/
├── cli-reference.md     # --output row, stderr/stdout split, exit codes unchanged
├── configuration.md     # output.level, SECSCAN_OUTPUT_LEVEL
├── artifacts.md         # scan.log in the .secscan/ layout, "not an artifact"
├── getting-started.md   # what a running scan looks like
└── README.md            # quick start note; .secscan/ layout
```

**Structure Decision**: single project, existing layout. All progress logic lives in one new
`pipeline/progress.py` module so the pipeline stages depend on a narrow `ProgressReporter`
interface and never on a terminal. No new package, no new dependency.

## Complexity Tracking

No constitution violations to justify.
