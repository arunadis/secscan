# Feature Specification: Scan Progress Output

**Feature Branch**: `011-scan-progress-output`

**Created**: 2026-09-03

**Status**: Draft

**Input**: User description: "when run `secscan run --full` it does not give any progress update. user may feel it is stuck. need to provide progress/logs that can be helpful to identify if there is any issue in the middle as well"

## Problem Statement

Today a scan prints nothing from the moment it starts until the moment it finishes. On a
large repository a full scan can run for many minutes across a dozen stages — repository
discovery, code-graph construction, partitioning, per-segment model analysis, deterministic
rule passes, external scanner runs, dependency audits, verification and correlation, and
report generation — and the operator sees a blank terminal throughout. Two consequences:

1. **Perceived hang.** The operator cannot tell a healthy long-running scan from a stuck
   one, and may kill a scan that was about to finish.
2. **Undiagnosable mid-run problems.** Coverage notes, rejected findings, tool failures,
   and slow stages are recorded only in the final report. If the scan is interrupted or
   fails partway, the operator has no trail explaining where it was or what went wrong.

This feature gives the operator continuous, honest visibility into what the scan is doing,
without changing what the scan produces.

## Clarifications

### Session 2026-09-03

- Q: Should the scan also write progress/warning lines to a persistent log file inside
  `.secscan/`, in addition to the terminal? → A: Yes, always. Every run writes
  `.secscan/scan.log` at verbose detail regardless of the terminal output level; it is
  overwritten per run and excluded from the determinism comparison.
- Q: When a single step has no natural sub-progress and takes a long time, should the scan
  print periodic heartbeat lines? → A: Yes. While a stage, segment, or tool is in progress
  with no new event, print a "still running" line with elapsed time every 30 seconds at the
  default level.
- Q: On an interactive terminal, how should progress be rendered at the default level? →
  A: Live redraw. On a TTY the current status line updates in place; when output is piped or
  redirected, plain one-line-per-event text is emitted.
- Q: When invoked non-interactively without an explicit output level, which level applies?
  → A: The default level everywhere. Callers wanting silence pass the quiet option
  explicitly.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - See that the scan is alive and where it is (Priority: P1)

An operator runs `secscan run --full` on a real repository. As the scan proceeds, the
terminal shows each stage as it starts and finishes, with elapsed time, so the operator
always knows which stage is running and that the scan has not stalled. For the longest
stage — per-segment analysis — the operator sees per-segment progress (`segment 7/23 ...`)
rather than one silent multi-minute block.

**Why this priority**: This is the direct complaint. Without it, users abandon scans that
are working correctly. Everything else in this feature builds on stage-level visibility.

**Independent Test**: Run a full scan on a fixture repository and confirm that at least one
progress line appears before the scan finishes, that every stage that executes announces
its start and completion, and that the segment stage reports per-segment progress with a
running count out of the total.

**Acceptance Scenarios**:

1. **Given** a repository that has never been scanned, **When** the operator runs
   `secscan run --full`, **Then** a line naming the first stage appears within a second of
   invocation, and each subsequent stage announces its start and completion with elapsed
   time before the final summary is printed.
2. **Given** a scan with N segments, **When** the segment-analysis stage runs, **Then** the
   operator sees a progress line for each segment including its index out of N and the
   segment identifier, updated as each segment completes.
3. **Given** a scan in which a stage was skipped because a valid checkpoint exists,
   **When** that stage is reached, **Then** the operator sees it reported as reused from
   the checkpoint (not silently omitted), so the stage list is complete on every run.
4. **Given** the scan is running, **When** the operator checks the terminal at any
   moment, **Then** the most recent line tells them which stage (and, where applicable,
   which segment or tool) is currently in progress.

---

### User Story 2 - Learn about problems while they happen (Priority: P2)

While the scan runs, anything that will end up as a coverage note, rejected finding,
skipped tool, budget exhaustion, or model-response problem is surfaced at the moment it
occurs, attributed to the stage and segment or tool it concerns. The operator can act on it
(e.g., install a missing scanner, fix a config value, widen a budget) rather than
discovering it after the scan completes — or never, if the scan is interrupted.

**Why this priority**: The second half of the user's request. Mid-run diagnostics turn a
black box into something an operator can troubleshoot; but they are only useful once the
stage timeline (P1) exists to anchor them.

**Independent Test**: Run a scan against a fixture that deliberately triggers a coverage
gap (e.g., an oversized file dropped whole), a malformed model response, and an
unavailable external tool. Confirm that each condition produces a clearly labelled warning
line on the terminal during the run, before the final summary, and that the same condition
still appears in the final report exactly as it does today.

**Acceptance Scenarios**:

1. **Given** a segment whose model response cannot be parsed, **When** that segment
   completes, **Then** a warning naming the segment and the reason is printed immediately,
   and the scan continues to the next segment.
2. **Given** an external scanner that is applicable but not installed, **When** the
   external tooling stage runs, **Then** the operator sees which tool was skipped and why,
   at the time it is skipped.
3. **Given** a stage that fails with an error that stops the scan, **When** the failure
   occurs, **Then** the last lines printed identify the failing stage, the elapsed time
   into it, and the error, so the operator does not have to guess where the scan died.
5. **Given** a scan that was interrupted or failed, **When** the operator opens
   `.secscan/scan.log`, **Then** it contains every progress event and warning up to the
   point of interruption at verbose detail, regardless of the terminal output level that
   was in effect.
6. **Given** a single model request or external tool run that takes longer than 30
   seconds, **When** no other event occurs, **Then** the operator sees a "still running"
   line naming the stage and subject with elapsed time at least every 30 seconds.
4. **Given** the scan ends with a handoff (reasoning requests written for the agent to
   answer), **When** the scan exits, **Then** the progress output clearly states how many
   segments are pending and that re-running the scan will resume — distinguishing this
   from a failure.

---

### User Story 3 - Control the amount of output (Priority: P3)

Operators and automated callers have different needs. An agent invoking the scan as a
skill, or a CI job capturing output, may want only the final summary; an operator
debugging a slow or failing scan may want more detail than the default (per-tool commands,
budget usage per segment, escalation decisions, checkpoint keys). The default level must
serve the interactive user in Story 1 without drowning them.

**Why this priority**: Verbosity control is a quality-of-life refinement of Stories 1 and
2. The feature is valuable without it, but shipping progress output with no way to silence
it would regress the existing agent-facing and scripted usage.

**Independent Test**: Run the same scan three times with quiet, default, and verbose
levels. Confirm quiet prints only the final summary (matching today's output exactly),
default prints stage and segment progress plus warnings, and verbose additionally prints
per-segment detail (budget consumed, escalation level reached) and per-tool detail.

**Acceptance Scenarios**:

1. **Given** the operator requests quiet output, **When** the scan runs, **Then** nothing
   is printed until the final summary, and the final summary is identical to today's.
2. **Given** the operator requests verbose output, **When** the scan runs, **Then**
   every default line appears plus per-segment budget usage, escalation level reached,
   and each external tool's invocation and outcome.
3. **Given** output is not attached to an interactive terminal (piped, redirected, or
   invoked by an agent skill or CI job) and no output level was specified, **When** the
   scan runs, **Then** the default level applies and progress lines are emitted one per
   event in a plain line-oriented form suitable for log capture (no in-place redrawing or
   control sequences).
5. **Given** output is attached to an interactive terminal, **When** the scan runs at the
   default level, **Then** the current status (stage, segment or tool, elapsed time)
   updates in place on a single line, while completed stages, warnings, and failures are
   written as permanent lines that remain in the scrollback.
4. **Given** an existing script or agent skill that invokes `secscan run` and parses the
   final summary lines, **When** the feature ships, **Then** those final summary lines are
   unchanged in content and remain the last lines printed to standard output.

---

### Edge Cases

- **Very fast scans**: On a tiny repository the whole scan may complete in under a second.
  Progress lines must still appear (they may all print at once); they must not be
  suppressed on the grounds that the scan was quick.
- **Single-segment re-run** (`--segment <id>`): the segment counter must reflect the
  narrowed scope (1/1), and the existing single-segment coverage note must appear as a
  warning line, not only in the report.
- **Checkpoint reuse on a non-`--full` run**: reused stages are reported as reused with
  no elapsed time attributed to work that was not performed.
- **Interruption** (operator presses Ctrl-C): the output must already contain the stage
  and segment that was in progress; no additional buffered output should be lost because
  progress lines were held back. On an interactive terminal the in-place status line must
  be finalised as a permanent line so the terminal is left in a clean state. The scan log
  must be flushed up to the moment of interruption. The process exits with status 130
  (the shell convention for an interrupt) rather than a traceback.
- **Live redraw and permanent lines**: on an interactive terminal, warnings, failures, and
  stage completions must never be overwritten by the in-place status line; they are
  written as permanent lines and the status line resumes below them.
- **Narrow or unusual terminals**: if the terminal width cannot be determined or is too
  narrow for the status line, the scan falls back to plain one-line-per-event output
  rather than producing garbled redraws.
- **Heartbeat and real events**: a heartbeat line is emitted only when 30 seconds pass
  with no other event for the current subject; a real event resets the interval. On an
  interactive terminal the heartbeat updates the in-place status line rather than adding
  permanent lines; in plain output it is a normal line.
- **Scan log on failure**: `.secscan/scan.log` is created at scan start and written
  incrementally, so it is present and useful even when the scan fails before its first
  stage completes. A failure to write the log must not abort the scan.
- **Warnings containing sensitive content**: warning lines are derived from the same
  redacted messages that reach the report. A warning must never print a credential value,
  file content, or anything the redactor would block from a context packet — only names,
  paths, identifiers and reasons.
- **Handoff versus failure**: exit for agent handoff must read as "paused, awaiting
  answers", never as an error.
- **Output ordering**: progress lines and final summary must not interleave in a way that
  puts summary lines before the last progress line.
- **Determinism of artifacts**: progress output includes wall-clock timing, which is
  legitimately non-deterministic. This timing must never be written into any scan artifact;
  artifacts must remain byte-identical across runs regardless of verbosity level. The scan
  log is a diagnostic side file, not an artifact: it is excluded from the byte-identical
  comparison and from any manifest or hash of artifacts.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The scan MUST announce each pipeline stage when it starts and when it
  completes, including elapsed time for the stage, so that the operator can see which stage
  is current at any moment.
- **FR-002**: A stage that is satisfied from an existing checkpoint MUST be announced as
  reused rather than omitted, so the stage sequence shown is the same on every run.
- **FR-003**: During per-segment analysis, the scan MUST report progress per segment,
  including the segment's ordinal position out of the total, its identifier, and elapsed
  time for that segment.
- **FR-004**: During external scanner execution, the scan MUST report each tool as it
  starts and finishes, including whether it ran, was skipped, or failed, and the reason
  for any skip or failure.
- **FR-005**: Every condition that will be recorded as a coverage note, rejected finding,
  declared tool limitation, or dependency-audit gap in the final report MUST also be
  emitted as a warning line at the time it is detected, attributed to the stage and (where
  applicable) segment or tool concerned.
- **FR-006**: Warning lines MUST reproduce exactly the message text that reaches the report
  for the same condition; no new wording may be introduced that could disagree with the
  report.
- **FR-007**: The first progress line MUST appear within one second of invocation, before
  any potentially long-running work begins.
- **FR-008**: When the scan terminates abnormally, the final progress lines MUST identify
  the stage that was running, how long it had been running, and the error, before the
  process exits. Existing exit statuses are unchanged; an operator interrupt (Ctrl-C) MUST
  exit with status 130 and MUST state that re-running resumes from the checkpoint.
- **FR-009**: When the scan exits for agent handoff, the progress output MUST state the
  number of pending segments and that re-running will resume, and MUST be visually
  distinct from a failure.
- **FR-010**: Operators MUST be able to select at least three output levels: quiet (final
  summary only), default (stages, segments, tools, warnings), and verbose (default plus
  per-segment budget consumption and escalation level, per-tool invocation details, and
  checkpoint reuse reasons).
- **FR-011**: The output level MUST be selectable both as a command-line option on
  `secscan run` and via the existing environment-override mechanism, following the same
  precedence rules as other configuration. When no level is specified, the default level
  applies regardless of whether output is attached to an interactive terminal.
- **FR-012**: Progress and warning lines MUST be written to the standard error stream;
  the final summary MUST remain on standard output with unchanged content, so existing
  callers that parse the summary are unaffected.
- **FR-013**: When output is not an interactive terminal, progress MUST be emitted as
  plain, one-line-per-event text with no in-place redrawing, cursor movement, or colour
  codes, so that captured logs are readable.
- **FR-013a**: When output is an interactive terminal, the current status (stage, subject,
  elapsed time) MUST be rendered as a single in-place updating line. Stage completions,
  warnings, failures, and the handoff notice MUST be written as permanent lines that are
  never overwritten by the status line. If terminal capabilities or width cannot be
  determined, the scan MUST fall back to the plain output of FR-013.
- **FR-013b**: Both render paths MUST present the same set of events at a given output
  level; only the rendering differs.
- **FR-014**: Each progress line MUST carry a timestamp or elapsed-time marker so that a
  captured log can be used to identify slow stages after the fact.
- **FR-015**: Progress output MUST never include credential values, redacted content, or
  raw file contents. It is limited to stage names, segment and tool identifiers, file
  paths, counts, durations, and the same reason strings already permitted in the report.
- **FR-016**: Progress output MUST NOT alter any scan artifact. Timing values and
  verbosity level MUST NOT be persisted into artifacts; artifacts MUST remain byte-identical
  for identical input regardless of output level.
- **FR-017**: Progress output MUST be available identically for `secscan run` and for the
  payload-internal invocation used by installed skills, so agents relaying the scan to a
  user see the same information.
- **FR-018**: The quiet level MUST produce terminal output byte-identical to the
  pre-feature behaviour, so that upgrading does not change the experience of callers who
  opt out. The scan log (FR-019) is still written at the quiet level.
- **FR-019**: Every scan MUST write a scan log at `.secscan/scan.log` containing all
  progress events and warnings at verbose detail, independent of the terminal output
  level. The log is created at scan start, written incrementally as events occur, and
  overwritten by each new run. It MUST be excluded from the artifact determinism
  comparison and from any artifact manifest or hash, and it is subject to the same content
  restrictions as terminal output (FR-015). Failure to write the log MUST NOT abort the
  scan; it MUST be reported as a warning.
- **FR-020**: When 30 seconds elapse with no progress event for the stage, segment, or
  tool currently in progress, the scan MUST emit a heartbeat line naming the stage and
  subject with the elapsed time, and MUST continue to do so every 30 seconds until the next
  real event. Heartbeats are shown at the default and verbose levels and recorded in the
  scan log; on an interactive terminal they update the in-place status line rather than
  adding permanent lines.

### Key Entities

- **Progress Event**: A single observable occurrence during a scan — stage started, stage
  completed, stage reused from checkpoint, segment started/completed, tool started/
  completed/skipped, warning raised, scan paused for handoff, scan failed. Carries the
  stage name, an optional subject (segment id or tool name), an outcome, an elapsed
  duration where applicable, and a message.
- **Output Level**: The operator's chosen verbosity — quiet, default, or verbose — that
  determines which progress events are rendered on the terminal. Does not affect which
  events occur, what is recorded in artifacts, or what is written to the scan log.
- **Scan Log**: A plain-text diagnostic file at `.secscan/scan.log` holding every progress
  event and warning of the most recent run at verbose detail, with timestamps. Written
  incrementally, overwritten per run, and explicitly not a scan artifact.
- **Heartbeat**: A progress event emitted when the current subject has produced no other
  event for 30 seconds; carries the stage, subject, and elapsed time.
- **Stage**: One of the named pipeline phases that already exist in the scan's checkpoint
  state (discovery, code graph, partitioning, segment analysis, deterministic rule passes,
  external tooling, dependency audits, verification and correlation, review, report).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On any repository, an operator sees the first progress line within 1 second
  of starting a scan, and never goes longer than 30 seconds without the displayed status
  changing (a new event or a heartbeat).
- **SC-002**: For a scan that fails or is interrupted at any point, an operator can
  identify the stage (and segment or tool, where applicable) that was in progress from the
  terminal output alone, without opening any artifact.
- **SC-003**: 100% of coverage notes, rejected findings, and tool limitations that appear
  in the final report were also printed during the run at the default output level, with
  identical wording.
- **SC-004**: Running the same scan twice at different output levels produces
  byte-identical scan artifacts; the determinism test suite passes unchanged.
- **SC-005**: At the quiet level, terminal output is byte-identical to the current
  release, and every existing integration test that inspects scan output passes without
  modification.
- **SC-006**: No progress line, at any output level, contains a string that the redaction
  sweep used in the existing safety tests would flag.
- **SC-007**: In a captured (non-interactive) log of a full scan, an operator can rank
  stages and segments by elapsed time using only the printed durations.
- **SC-008**: After any scan — successful, failed, interrupted, or paused for handoff —
  `.secscan/scan.log` exists and its last entry identifies the stage (and subject) that
  was in progress when the scan ended, even when the terminal level was quiet.
- **SC-009**: Running the same scan on an interactive terminal and piped to a file yields
  the same set of events (stages, segments, tools, warnings) at the default level; only
  the rendering differs.

## Assumptions

- The pipeline's existing stage names and checkpoint state are the authoritative list of
  what to announce; this feature adds visibility, not new stages.
- The default output level applies whether or not a terminal is attached; it serves a
  human at a terminal and an agent relaying output to a human alike. Automated callers
  who want silence opt into quiet explicitly.
- The scan log lives inside `.secscan/`, which the scanner already owns and which is
  already excluded from analysis, so writing it does not violate the read-only guarantee
  toward the scanned project.
- A 30-second heartbeat interval is a fixed default; making it configurable is out of
  scope for this feature.
- The existing final summary (findings count, report path, coverage-note count) is a
  de-facto interface used by installed skills and scripts and is therefore frozen.
- Warning wording is owned by the report; progress output re-emits it rather than
  paraphrasing, to honour the principle that the report never disagrees with what the
  pipeline observed.
- Standard error is the appropriate channel for progress because standard output already
  carries the machine-consumable summary and, for `secscan report --format json`, raw
  JSON.
- Agent-handoff (exit code 3) semantics are unchanged; this feature only makes the
  handoff state legible while it is happening.
- Per-stage timing shown to the operator is informational and is not a performance
  contract; the scan is not required to get faster.
- Existing documentation for the `run` command (`README.md`, `docs/getting-started.md`,
  `docs/configuration.md`) will be updated in the same change to describe the new option
  and output levels, per the constitution's documentation-currency gate.
