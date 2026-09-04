# Feature Specification: Provider Batch API Execution

**Feature Branch**: `012-provider-batch-api`

**Created**: 2026-09-03

**Status**: Draft

**Input**: User description: "Getting HTTP 429 Too Many Requests in CLI (endpoint) mode
partway through segment analysis on a 255-segment repository; the scan aborts with a
traceback. What can be done to prevent these kinds of issues and limit the number of API
requests? The original specification asked to use batch APIs where possible — can the CLI
mode use the provider's batch API to reduce cost and avoid these issues when the provider
offers one?"

## Problem Statement

When an operator configures an external analysis endpoint, every segment of the repository
is analysed with its own live request, one after another, with no spacing. On a large
repository that is several hundred requests in a row. Providers meter requests per minute,
so a long scan eventually receives a "too many requests" refusal. Today that refusal is
fatal: the scan stops with a stack trace, and because per-segment analysis is recorded only
when the whole stage finishes, every segment already analysed in that run is discarded — the
next run repeats all of those requests and is likely to hit the same limit at the same
place.

The original product specification (feature 001, FR-007a / FR-016b / FR-019) promised a
cost-optimised execution policy in which analysis requests are submitted through the
provider's batch facility, with interactive re-execution for items the batch could not
complete, and a report showing the batch/interactive split. The configuration surface,
documentation, and report fields for this exist, but the batch path itself was never
connected to any provider: selecting the batch policy today behaves identically to
interactive mode while the documentation advertises a cost discount. This feature closes
that gap.

Both supported provider families offer a batch facility that accepts a whole set of
requests in one submission, processes them asynchronously within a window of up to a day,
and charges roughly half the interactive price. Using it turns hundreds of metered requests
into a handful of submissions and status checks — which removes the rate-limit failure mode
and halves the analysis cost at the same time.

## Clarifications

### Session 2026-09-03

- Q: When a re-run finds a persisted answer for a segment, what must still match for that
  answer to be reused instead of re-requesting? → A: Content + prompt + model + escalation
  level — an answer is reused only when the serialized request would be identical and the
  same model tier would answer it.
- Q: How long should the scan wait for a provider batch before treating its outstanding
  items as expired, and where is that limit set? → A: A new duration setting
  `execution_policy.batch.window_hours`, default 24, matching the providers' own
  completion guarantee; overridable through the environment mechanism like other keys.
- Q: What should the default retry limits be for an interactive request that hits a rate
  limit or transient fault? → A: 5 attempts, waits growing with jitter to a 60-second cap,
  about 3 minutes total per request; a provider-suggested wait is honoured as a minimum
  even if it exceeds the cap.
- Q: When a round's requests exceed what the provider accepts in a single batch, should the
  scan split the round or refuse? → A: Split into as few batches as the provider's limits
  allow, submitted together and waited on together; the batch count is reported.
- Q: How should the "estimated saving relative to interactive pricing" be computed, given
  the scanner ships no price list? → A: Token-based: saving = 50% × (tokens answered via
  batch ÷ total analysis tokens), labelled as an estimate assuming the published batch
  discount; no currency amounts and no price table.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Analyse a large repository through the provider's batch facility (Priority: P1)

An operator with an external endpoint configured runs a full scan of a large repository
with the batch policy in effect (the default whenever an endpoint is configured). Instead of one live request per segment, the scan
gathers all segment analysis requests for the stage and submits them together as a single
batch to the provider. The scan then waits for the provider to finish, showing progress as
items complete, and continues with the rest of the pipeline once results are in. The final
report shows that analysis was performed in batch and what it saved.

**Why this priority**: This is the feature. It is the only change that both eliminates the
per-request rate limit as a failure mode and delivers the cost reduction the configuration
already promises.

**Independent Test**: Run a full scan against a fixture repository with the batch policy
selected and a stand-in provider that accepts batch submissions. Confirm that exactly one
batch submission is made for the segment-analysis stage (per escalation round), that no
interactive analysis request is made while the batch is healthy, that findings are identical
to those produced by an interactive run of the same fixture, and that the report's usage
summary shows all segment analyses as batch invocations.

**Acceptance Scenarios**:

1. **Given** an endpoint is configured and the batch policy is selected, **When** a full
   scan reaches segment analysis with N segments, **Then** the N requests are submitted to
   the provider as one batch rather than N individual requests, and the operator sees a
   progress line stating that a batch of N items was submitted.
2. **Given** a batch has been submitted, **When** the provider is still processing it,
   **Then** the operator sees periodic status lines (items completed out of total, time
   waiting) and the scan does not send any further analysis requests until the batch
   resolves.
3. **Given** a batch completes with every item answered, **When** the scan continues,
   **Then** each item's answer is treated exactly as an interactive answer would be
   (parsed, normalised, rejected if non-conforming) and the resulting findings are
   byte-identical to an interactive run of the same input.
4. **Given** a segment's first-round answer declares that more evidence is needed,
   **When** the escalation round runs, **Then** the escalated requests for all such
   segments are again gathered into a single batch rather than sent individually.
5. **Given** a scan completed in batch mode, **When** the operator reads the report's
   usage summary, **Then** it shows the number of batch invocations, the number of
   interactive invocations, the number of fallbacks, and the estimated saving relative to
   interactive pricing.

---

### User Story 2 - A batch that cannot complete never costs coverage or repeats work (Priority: P2)

A batch may take hours, the operator may interrupt the scan while it waits, the provider may
answer some items and fail others, or the batch window may expire. In every case the scan
must neither lose the answers it already has nor silently drop a segment. Items the batch
did complete are kept; items it did not are re-executed interactively, and each such
fallback is recorded and shown.

**Why this priority**: Without this the batch path is a gamble — a long wait followed by a
restart from zero. The original specification (FR-016b) already requires automatic
interactive fallback; this story also makes the wait resumable so the operator can walk
away from a multi-hour batch.

**Independent Test**: With a stand-in provider scripted to (a) answer half the items and
fail the rest, (b) expire, and (c) still be processing when the scan is interrupted,
confirm respectively that (a) only the failed half is re-run interactively and each is
recorded as a fallback with its reason, (b) all items fall back and are recorded, and
(c) re-running the scan resumes waiting on the same batch instead of submitting a new one,
and no segment is analysed twice.

**Acceptance Scenarios**:

1. **Given** a submitted batch, **When** the operator interrupts the scan while it is
   waiting, **Then** the batch reference is preserved and re-running the scan resumes by
   checking that same batch — no new submission, no repeated requests.
2. **Given** a batch that finishes with some items failed or unanswered, **When** the scan
   processes the outcome, **Then** every answered item is used as-is, every unanswered
   item is re-executed interactively, and each fallback appears as a warning during the
   run and as an entry in the report's fallback list with its reason.
3. **Given** a batch that exceeds the configured window without completing, **When** the
   scan next checks it, **Then** all outstanding items fall back to interactive execution
   with "window expired" as the recorded reason; the scan MUST NOT wait indefinitely.
4. **Given** a scan whose segment analysis was completed partly by batch and partly by
   fallback, **When** the scan completes, **Then** every segment has exactly one recorded
   analysis result and the report states the split.
5. **Given** answers that have already been received (from batch or fallback), **When** the
   scan is interrupted before the stage completes and then re-run, **Then** those answers
   are reused and only segments without an answer are requested again.

---

### User Story 3 - Interactive requests survive transient rate limits (Priority: P3)

The interactive path remains in use: operators may select it explicitly, and it is the
fallback for batch items that the provider could not complete. When a provider refuses a
request because of rate limiting or a transient server fault, the scan should wait and try
again a bounded number of times, respecting the provider's advice on how long to wait,
rather than aborting. If the limit persists, the scan stops cleanly with the work so far
preserved, so that re-running continues rather than restarts.

**Why this priority**: This story does not deliver the cost saving, but it is required for
the batch fallback path to be reliable, and it turns the original crash into a recoverable
pause for operators who stay on the interactive policy.

**Independent Test**: With a stand-in provider scripted to refuse the first two attempts of
a request with a rate-limit response (with and without a suggested wait) and accept the
third, confirm that the scan succeeds, that each retry was shown as a warning with its wait
time, and that the request is counted once in the usage summary. With a provider that
refuses every attempt, confirm the scan exits with an error naming the rate limit, that
previously analysed segments are preserved, and that re-running resumes at the failed
segment.

**Acceptance Scenarios**:

1. **Given** a provider answers a request with a rate-limit refusal that includes a
   suggested wait, **When** the scan retries, **Then** it waits at least the suggested time
   before the next attempt and prints a warning naming the segment, the attempt number, and
   the wait.
2. **Given** a provider answers with a rate-limit refusal without a suggested wait, or with
   a transient server fault, **When** the scan retries, **Then** the wait grows with each
   attempt (with randomised jitter) up to a bounded ceiling.
3. **Given** every retry is exhausted for one request, **When** the scan stops, **Then**
   the failure names the segment and the provider's refusal, the analyses completed so far
   in this run are preserved, and the operator is told that re-running resumes from that
   point.
4. **Given** a request that fails for a non-transient reason (authentication, malformed
   request, unknown model), **When** the failure occurs, **Then** the scan does not retry
   and reports the error immediately.

---

### Edge Cases

- **Batch policy selected without an endpoint**: already rejected by configuration
  validation (feature 001). Unchanged: batch requires an endpoint; in agent-mediated mode
  batch is reported as unavailable.
- **Provider without a batch facility** (a compatible gateway that speaks the interactive
  shape but not the batch shape): the first batch submission fails with "not supported";
  the scan records one fallback reason for the whole stage, continues interactively, and
  the report states that batch was requested but unavailable. It MUST NOT retry the batch
  submission on every escalation round.
- **Round larger than one batch**: when a round is split across several batches (FR-001),
  expiry, resumption, and fallback apply per batch; one batch failing does not affect the
  answers received from its siblings, and a resumed scan re-checks every outstanding batch
  of the round.
- **Very small scans**: a single-segment scan (or `--segment <id>`) under the batch policy
  still submits a one-item batch; the policy is honoured regardless of size.
- **Budget enforcement**: every item in a batch is checked against the token budget
  individually before submission, exactly as an interactive request is; the batch itself
  MUST NOT be a way to bypass per-invocation budgets.
- **Redaction**: the same redacted context packet that would be sent interactively is the
  one placed in the batch. No new content path to the provider is introduced.
- **Off-peak window**: when the `batch-offpeak` policy is selected, submission waits for the
  configured time-of-day window (this waiting is implemented by this feature; the setting
  existed before but was never acted on); batch expiry is governed solely by
  `batch.window_hours` measured from submission, not from scan start and not by the end of
  the off-peak window.
- **Partial results arriving out of order**: item answers are matched to segments by a
  stable identifier, never by position, and are persisted as they are observed.
- **Duplicate answers**: if a resumed scan observes an answer for a segment that already
  has one persisted, the persisted answer wins and the duplicate is ignored (results are
  deterministic; the first observed answer is kept).
- **Interrupt during fallback**: interactive fallbacks are persisted per segment as they
  complete, so an interrupt during fallback loses at most the request in flight.
- **Cost summary with zero interactive requests**: the estimated-saving figure is still
  computed per FR-013 (100% batch share ⇒ 50% saving) and shown; with zero analysis tokens
  overall it reads 0%, never a blank or an error.
- **Stale batch reference**: if the persisted batch reference no longer exists at the
  provider (deleted, wrong account, expired beyond retention), the scan treats every item
  as failed with that reason and falls back; it MUST NOT crash on an unknown reference.
- **Determinism**: batch/interactive choice, wait times, and retry counts are execution
  details. Findings artifacts MUST be byte-identical whether a segment was answered by
  batch, by fallback, or interactively. Only the usage summary records the split, and the
  usage summary is already declared non-deterministic across execution modes.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: When the batch execution policy is in effect, the scan MUST gather all
  analysis requests of a segment-analysis round and submit them to the provider in batch
  form instead of as individual requests. A round is one batch unless the provider's
  per-batch item-count or total-size limit would be exceeded, in which case the round is
  split deterministically (stable request order, greedy fill) into as few batches as the
  limits allow; all batches of a round are submitted together, waited on together, and
  the number submitted is stated in the progress output.
- **FR-002**: Each escalation round MUST be batched independently: requests for segments
  needing more evidence are collected after the previous round resolves and submitted
  together.
- **FR-003**: The scan MUST persist the provider's batch reference, the set of item
  identifiers it contains, and the submission time inside `.secscan/` immediately upon
  submission, before waiting begins.
- **FR-004**: While a batch is outstanding, the scan MUST check its status at a bounded
  interval (no more often than once per 30 seconds, backing off to no less than once per
  5 minutes). Every check that finds the batch still processing MUST emit a progress line
  stating items completed out of total and time waited; the check that finds it resolved is
  reported by the completion line of FR-007 instead, so no check passes unreported.
- **FR-005**: Answers MUST be persisted per request as soon as they are observed, whatever
  their source — batch, interactive, or fallback — so that an interruption at any point
  loses at most the answers not yet received.
- **FR-006**: Re-running a scan that has a persisted, unresolved batch MUST resume by
  checking that batch; it MUST NOT submit a new batch for the same items.
- **FR-007**: Items that the batch reports as failed, that are missing from a completed
  batch, or that remain outstanding when the configured window expires MUST be re-executed
  interactively; each such fallback MUST be recorded with its reason and surfaced as a
  warning during the run and in the report (feature 001 FR-016b).
- **FR-008**: Items already answered — by the batch or by an earlier fallback — MUST NOT
  be requested again on resume. A persisted answer is reusable only when its answer key
  matches: the serialized request (redacted context packet plus prompt) is byte-identical,
  the model tier that would answer it is the same, and the escalation level is the same.
  Any mismatch invalidates that answer alone; other segments' answers are unaffected. A
  persisted batch whose items no longer match their answer keys is abandoned (not
  resumed) and those items are requested afresh.
- **FR-009**: The batch window is a duration configured as
  `execution_policy.batch.window_hours` (default 24, overridable through the existing
  environment mechanism; must be a positive number). It MUST be enforced from submission
  time; a batch still outstanding at expiry is treated as failed for every outstanding
  item. The `offpeak_window` time-of-day setting governs only *when* submission happens
  and has no bearing on expiry.
- **FR-010**: If the provider rejects batch submission as unsupported, the scan MUST fall
  back to interactive execution for the whole stage, record a single fallback reason, and
  MUST NOT attempt batch submission again in the same scan.
- **FR-011**: Every batched item MUST pass the same per-invocation token-budget check and
  the same redaction as an interactive request; batching MUST NOT change what content
  reaches the provider.
- **FR-012**: Answers received via batch MUST be parsed, normalised, and validated by the
  same path as interactive answers, and MUST produce byte-identical findings artifacts for
  identical input.
- **FR-013**: The usage summary MUST report batch invocations, interactive invocations,
  fallbacks with reasons, and an estimated saving relative to interactive pricing
  (feature 001 FR-019); the batch invocation count MUST be non-zero when the batch path
  was used. The saving is computed from tokens, not currency: saving percentage =
  50% × (analysis tokens answered via batch ÷ total analysis tokens), and is labelled in
  the report as an estimate assuming the provider's published batch discount. No price
  table is shipped or consulted.
- **FR-014**: Interactive requests (including fallbacks) that receive a rate-limit refusal
  or a transient server fault MUST be retried with a growing, jittered wait, honouring any
  provider-suggested wait time as a minimum, up to a bounded number of attempts and a
  bounded total wait. Defaults: 5 attempts in total (1 initial + 4 retries), waits
  starting at 2 seconds, doubling with jitter and capped at 60 seconds per wait, under a
  hard total-wait ceiling of 180 seconds per request. Backoff alone therefore spends about
  30 seconds across four retries; the ceiling binds only when the provider asks for longer
  waits. A provider-suggested wait longer than the per-wait cap is still honoured, once,
  for that attempt.
- **FR-015**: Each retry MUST be surfaced as a warning naming the stage, segment, attempt
  number, and wait; a request that eventually succeeds MUST be counted once in usage.
- **FR-016**: Failures that are not transient (authentication, malformed request, unknown
  model, unsupported provider) MUST NOT be retried and MUST be reported immediately.
- **FR-017**: When retries are exhausted, the scan MUST stop with an error that names the
  segment and the provider's refusal, MUST preserve all segment analyses completed in the
  run, and MUST state that re-running resumes from the failed segment. A stack trace MUST
  NOT be the operator-facing output.
- **FR-018**: A resumed scan MUST re-request only segments without a persisted answer
  (FR-005), and the normalised per-segment findings MUST be written as each segment is
  judged rather than when the stage finishes, so that an interruption mid-stage keeps the
  work already done. This applies to the interactive policy as well as to batch fallback.
- **FR-019**: The retry attempt count and per-wait ceiling (FR-014 defaults: 5 and 60
  seconds) MUST be configurable through the existing configuration and
  environment-override mechanism; a rate-limit refusal MUST never abort a scan on the
  first attempt under default settings.
- **FR-020**: Documentation that describes the batch policy (`README.md`,
  `docs/configuration.md`, the generated configuration template) MUST describe the
  behaviour actually implemented — waiting, resumption, fallback, retries — and MUST NOT
  advertise a discount the scan does not obtain.
- **FR-021**: Batch submission MUST be available for both supported provider families
  (the Anthropic-style and the OpenAI-compatible endpoint shapes). A compatible gateway
  that does not implement the batch shape is handled by FR-010.
- **FR-022**: While a batch is outstanding the scan MUST stay in the foreground and wait,
  reporting status per FR-004, until the batch resolves or its window expires. An operator
  interrupt (Ctrl-C) MUST exit cleanly with the batch reference preserved (FR-003) and
  MUST state that re-running resumes waiting on the same batch. No submit-and-exit mode is
  provided in this feature.
- **FR-023**: When an external endpoint is configured and the operator has not set an
  execution policy explicitly, the batch policy MUST apply by default (the cost-optimised
  default intended by feature 001 FR-007a). Operators who want live per-request analysis
  set the interactive policy explicitly. The resolved policy MUST be stated at scan start
  and in the report's execution-mode line, so the default is never silent.

### Key Entities

- **Analysis Batch**: One submission of many analysis requests to the provider. Carries the
  provider's reference, the ordered list of item identifiers, the round it belongs to,
  submission time, window expiry, and current status (submitted, in progress, completed,
  failed, expired, unsupported). A round has one or more batches. Persisted inside
  `.secscan/` and not a scan artifact.
- **Batch Item**: One analysis request inside a batch, identified by the same stable
  request identifier used interactively (segment identifier plus escalation level). Has an
  outcome: answered, failed (with reason), or outstanding.
- **Segment Answer**: The persisted model answer for one request identifier, regardless of
  whether it arrived by batch, by fallback, or interactively. Carries an answer key derived
  from the serialized request content, the model tier, and the escalation level. The unit
  of resumption: a request whose persisted answer key matches is never sent again; a
  mismatched key invalidates only that answer.
- **Fallback Record**: An entry stating that work was re-executed interactively, with an
  item and a reason. Already part of the usage summary (feature 001). The item is the
  analysis request identifier for a per-item fallback; for the single stage-wide fallback —
  a gateway that does not implement batch submission (FR-010) — it is the stage name,
  because no individual request caused it and the whole stage degraded.
- **Retry Policy**: The attempt count (default 5), base wait (2s), per-wait ceiling (60s),
  and resulting total-wait bound (~3 minutes) applied to transient interactive failures.
  Attempt count and ceiling are configurable; execution detail, never written into
  findings artifacts.
- **Usage Summary**: The existing per-scan cost report, extended so that its batch and
  fallback fields reflect real batch execution.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Under the batch policy, a full scan of a repository with N segments makes at
  most (number of escalation rounds × ceil(N / provider per-batch limit)) batch
  submissions plus bounded status checks for the segment-analysis stage — never N
  individual analysis requests — when the provider batch is healthy. For repositories
  within the provider limit this is exactly one submission per round.
- **SC-002**: On the repository from the originating report (255 segments), a batch-policy
  scan completes without a rate-limit failure and its usage summary shows an estimated
  saving of at least 40% (FR-013 formula), i.e. at least 80% of analysis tokens answered
  via batch.
- **SC-003**: Findings artifacts from a batch-policy scan and an interactive scan of the
  same fixture at the same tool version are byte-identical; the determinism suite passes
  with the batch policy selected.
- **SC-004**: Interrupting a scan while a batch is outstanding and re-running it results in
  zero additional batch submissions and zero repeated analysis requests for that stage.
- **SC-005**: When a stand-in provider fails a fixed subset of batch items, 100% of the
  failed items — and only those — appear as fallbacks in the report with a reason, and
  every segment ends with exactly one recorded analysis.
- **SC-006**: When a stand-in provider refuses a request with a rate-limit response twice
  and then accepts, the scan completes successfully with two retry warnings and one counted
  invocation for that request. When it refuses every attempt, the scan stops after exactly
  5 attempts and no more than ~3 minutes of waiting for that request under default
  settings.
- **SC-007**: When a scan stops because retries are exhausted at segment K of N, re-running
  it re-requests only segments K..N; segments 1..K-1 are reused from persisted answers.
- **SC-008**: No batch item, status check, retry, or fallback ever transmits content that
  differs from what the interactive path would send for the same request; the existing
  redaction sweep passes over all persisted batch state.
- **SC-009**: The configuration documentation, generated template, and `secscan init`
  output describe the batch behaviour exactly as implemented; the accuracy benchmark shows
  no regression in any defect class.

## Assumptions

- Both supported provider families expose an asynchronous batch facility that accepts a
  set of requests, processes them within a window of up to 24 hours, and prices them at
  roughly half the interactive rate. The exact request and result shapes are a planning
  concern.
- The existing configuration keys (`execution_policy.mode`, `execution_policy.batch.enabled`,
  `execution_policy.offpeak_window`, `execution_policy.batch.fallback`) remain the operator
  surface; this feature gives them their intended behaviour rather than introducing new
  policy keys, plus one new duration key `execution_policy.batch.window_hours` (FR-009).
  Retry tuning is added under the existing `llm` or `execution_policy` sections with safe
  defaults.
- Because batch becomes the default when an endpoint is configured (FR-023),
  `execution_policy.mode` gains the value `auto` (the new shipped default, meaning "batch
  when an endpoint is configured") alongside a new explicit `batch` value;
  `execution_policy.batch.enabled` is retained only as a compatibility override. Existing
  configurations, which contain an explicit `mode: interactive`, keep their interactive
  behaviour; only newly generated configurations get the batch default. The generated
  template and `secscan init` output state this. Small repositories will take longer under
  the default (batch latency is minutes at minimum) and the documentation tells operators
  how to opt into interactive for quick scans.
- Waiting on a batch happens in the foreground (FR-022); a scheduler or CI job that cannot
  hold a process open for the batch window should use the interactive policy. A
  submit-and-exit mode may be specified later if demand appears.
- Batch state lives inside `.secscan/`, which the scanner already owns; writing it does not
  affect the read-only guarantee toward the scanned project. It is diagnostic/resumption
  state, not a scan artifact, and is excluded from the determinism comparison in the same
  way as `.secscan/scan.log`.
- The system-level review stage is deterministic and makes no endpoint request; segment
  analysis is the only stage that talks to the provider, so it is the only stage this
  feature changes.
- Agent-mediated mode is unchanged: batch and retry are endpoint-only capabilities and
  continue to be reported as unavailable there.
- Progress lines introduced here are emitted through the progress reporter of feature 011
  and follow its levels, heartbeat, and scan-log rules.
- The CWE-312 rejection seen in the originating report is a shipped-dataset gap and is out
  of scope for this feature; it should be handled as a data update.
- Reducing the number of segments (coarser partitioning) is not in scope; segment size is
  governed by the token budget and security-boundary rules of feature 001.
