# Research: Provider Batch API Execution

**Feature**: 012-provider-batch-api | **Date**: 2026-09-03

Sources: current provider documentation (Anthropic `platform.claude.com`, OpenAI
`platform.openai.com` / `developers.openai.com`) retrieved 2026-09-03; the repository's own
code (`src/pipeline/llm_client.py`, `escalate.py`, `run.py`, `state.py`, `progress.py`,
`config/loader.py`, `config/mode.py`, `usage.py`).

## R1. Where the 429 becomes fatal today

**Finding**: `_http_transport` (`llm_client.py:401-406`) issues one `urlopen`; `HTTPError`
(a `URLError` subclass) is wrapped in `RuntimeError` and propagates through
`EscalationRunner.run` → `run_scan` → `cmd_run`, whose generic `except Exception` calls
`reporter.failed(...)` then `raise` — hence the traceback. `segment_analysis` is
`mark_running` at `run.py:235` and `mark_done` only at `run.py:492`; findings are written per
segment only after the loop (`run.py:306-312`). A crash therefore loses every segment of the
run.

**Decision**: introduce `EndpointError(RuntimeError)` with fields `provider`, `status`,
`error_type`, `transient`, `retry_after_s`, `attempts`; `cmd_run` catches it, marks the stage
failed, prints one redacted line + "re-running resumes from segment X", exits `EXIT_ERROR`.
Persist each segment's answer as it arrives (R4) so the resume claim is true.

## R2. Transient vs terminal HTTP failures

**Finding**: Anthropic documents 429 (`rate_limit_error`, `retry-after` header), 529
(`overloaded_error`), 500/502/503/504 as retryable; a spend-cap 429 carries no `retry-after`
and never clears. OpenAI documents 429 (with `Retry-After` and `x-ratelimit-*`), 500, 503 as
retryable; 502/504 are gateway errors retried by convention. Both SDKs retry connection errors.
400/401/403/404/405/413/422 are terminal. 501 is terminal for interactive calls but means
"batch not implemented" on `/v1/batches` (vLLM without `--enable-batch-api`).

**Decision**: `RetryPolicy.classify(status)`: transient = {408, 409, 429, 500, 502, 503, 504,
529} ∪ {connection error, timeout}; everything else terminal. For *batch submission only*,
{404, 405, 501} → `BatchUnsupported` (FR-010), not a retry. Rationale: matches both providers'
published guidance; 408/409 are added because gateways emit them for transient contention.

**Alternatives**: retrying only 429 (would still die on a 529 overload mid-scan); retrying all
non-2xx (would hammer an endpoint on a 401 and hide misconfiguration).

## R3. Backoff shape and defaults (spec FR-014/FR-019)

**Decision**: attempts = 5 (1 + 4 retries); wait_n = min(60, 2 · 2^(n−1)) · U(0.5, 1.0)
seconds (2, 4, 8, 16 → jittered); if the response carries `Retry-After` (seconds or HTTP-date),
wait_n = max(wait_n, retry_after); hard total-wait bound 180 s — if the next wait would exceed
the remaining budget the policy stops and raises with `attempts` recorded. `sleep` and `rng`
are constructor-injected so tests run in zero wall time and are deterministic. Config:
`llm.retry.attempts` (int ≥ 1, default 5) and `llm.retry.max_wait_s` (int ≥ 1, default 60);
env `SECSCAN_LLM_RETRY_ATTEMPTS`, `SECSCAN_LLM_RETRY_MAX_WAIT_S` via the existing
`apply_env_overrides` (`LLM` section already mapped; nested key `retry` needs the two-level
lookup the loader already uses for `endpoint`).

**Alternatives**: decorrelated jitter (more complex, no measurable benefit at 5 attempts);
unbounded retries with heartbeat (violates FR-017 — a dead endpoint must stop the scan).

## R4. Persisting answers and choosing the answer key (spec FR-008 clarification)

**Finding**: `AgentMediatedClient` already persists per-request answers to
`handoff/responses/<id>.json` and reads them back on resume — the exact resumption pattern the
spec wants, but only for agent mode. `AnalysisRequest.context_text` is the serialized request
(prompt + sorted-key payload JSON) and is what the budget is enforced against.

**Decision**: `pipeline/answers.py` — `AnswerStore(store.dir / "analysis" / "answers")`.
`answer_key(request, model_tier) = hash_text(request.context_text + "\n" + model_tier)`
(`hash_text` = sha256[:16], already used for resume keys; escalation level is embedded in
`request.id` = `<segment>-l<level>` so it is part of the key by construction). File
`<request-id>.json` = `canonical_json({"request_id", "answer_key", "content"})`. `get(request,
tier)` returns content only when the stored key matches; a mismatch is a miss (and the file is
overwritten on the next put). Deliberately *not* stored: source (batch/interactive/fallback),
tokens, timestamps — those vary by policy and would break the cross-policy byte-identity of
SC-003; they are recorded in `UsageTracker` and the ledger instead. `--full` and any
`invalidate("segment_analysis")` clear the directory.

**Determinism check**: the two-run comparison globs `.secscan/**/*.json` minus `state.json`
(`test_determinism.py:33`); answer files are deterministic given the deterministic test
responder, so they can stay *inside* the comparison — a stronger guarantee than excluding them.

**Alternatives**: keying on segment content only (would reuse an answer after a prompt or
model change — rejected in clarification); reusing `handoff/responses/` (conflates
agent-authored and provider-authored answers and the agent-mode reader has no key check).

## R5. Rounds versus per-segment ladders

**Finding**: `EscalationRunner.run` walks levels 1..max per segment, calling `client.run`
inside the loop; `_fit` is the only place request content is shaped and the budget enforced;
`_needs_escalation` is the only judge of insufficiency. Batching requires all segments' level-L
requests to exist before any is sent.

**Decision**: extract from `EscalationRunner` two side-effect-free-except-packet-write methods:
`prepare(segment, level, flows) -> (AnalysisRequest, packet)` (builds, fits, writes packet,
calls `on_packet`) and `absorb(outcome, response, level, packet) -> bool` (records usage +
fallback, sets content/level, returns whether escalation continues — including the "packet
already holds the whole segment" stop at level ≥ 3). `run()` becomes a loop over those two.
`BatchRoundRunner.run(segments, flows_for) -> dict[segment_id, SegmentOutcome]` iterates
levels; in each round it calls `prepare` for every active segment, skips those with a stored
answer, groups the rest by model tier, splits (R6), submits, waits (R8), absorbs, falls back
(R9), and computes the next round's active set from `absorb`'s return value. Interactive
policy keeps `EscalationRunner.run` (with the answer-store check inside) — see plan
Complexity Tracking for why.

## R6. Provider batch shapes, limits and the single-model constraint

**Anthropic Message Batches** (GA, no beta header): `POST /v1/messages/batches` with
`{"requests":[{"custom_id","params":{model,max_tokens,messages}}]}`; `custom_id` must match
`^[a-zA-Z0-9_-]{1,64}$`; ≤ 100 000 requests and ≤ 256 MB per batch; `GET
/v1/messages/batches/{id}` → `processing_status ∈ {in_progress, canceling, ended}`,
`request_counts {processing, succeeded, errored, canceled, expired}`, `results_url`,
`expires_at` (24 h); `GET .../results` streams JSONL `{custom_id, result:{type: succeeded|
errored|canceled|expired, message?|error?}}`, unordered; results retained 29 days; 50 % price.
Mixed models allowed.

**OpenAI Batch**: two steps — `POST /v1/files` (`multipart/form-data`, fields `purpose=batch`,
`file=<jsonl>`; ≤ 200 MB) then `POST /v1/batches` `{input_file_id, endpoint:"/v1/chat/
completions", completion_window:"24h"}`; ≤ 50 000 requests; **all requests in one input file
must use the same model and endpoint**; `GET /v1/batches/{id}` → `status ∈ {validating, failed,
in_progress, finalizing, completed, expired, cancelling, cancelled}`, `request_counts {total,
completed, failed}`, `output_file_id`, `error_file_id`; results via `GET
/v1/files/{id}/content` JSONL `{custom_id, response:{status_code, body}, error}` unordered;
expired items not billed; 50 % price. Batch queue has its own token-enqueue limits per model
and tier (e.g. 90 000 enqueued tokens at tier 1) — a submission over the limit fails at
validation with a descriptive error.

**Decision**: `ProviderAdapter` protocol with `interactive_request(...)`, `parse_interactive`,
`batch_limits() -> (max_items, max_bytes)`, `submit_batch(items, model) -> handle`,
`batch_status(handle) -> BatchStatus`, `batch_results(handle) -> dict[custom_id,
ItemResult]`, `classify(status, path) -> transient|terminal|unsupported`. Items in a round are
grouped by model tier before splitting; since one round = one escalation level = one tier, this
is a single group in practice but keeps OpenAI's constraint enforced structurally. Item
`custom_id` = request id (segment ids are `seg-<slug>` plus `-l<level>`; the adapter
validates against the Anthropic regex and hashes to a 64-char-safe form if ever violated,
recording the mapping in the ledger). Conservative internal caps: items = provider max,
bytes = 90 % of provider max measured on the serialized submission body. An OpenAI
enqueued-token validation failure is a terminal batch failure → whole-batch fallback with
the provider's message as the reason (FR-007), and is called out in docs as the reason to
lower `max_context_tokens` or raise the tier.

**Alternatives**: one adapter with `if provider ==` branches (what `build_endpoint_request`
does today; acceptable at two code paths, unreadable at eight); pulling an SDK (forbidden).

## R7. Storing the batch ledger

**Decision**: `state.json` → `meta.analysis_batches` = `{ "<round-key>": [BatchRecord...] }`
where `round-key = f"{level}:{model_tier}"`. `BatchRecord` = `{handle, provider, base_url,
model, items: {request_id: answer_key}, submitted_at, expires_at, status, reason?,
custom_id_map?}`. Written via `store.set_meta` immediately after each submission (FR-003) and
after each terminal status. Rationale: `state.json` is the existing resume record, already
excluded from determinism, already re-read on every run, and `--full` invalidation is a
single place. On resume the runner re-derives the round's requests, compares each item's
current `answer_key` with the ledger's; any mismatch → the batch is *abandoned* (status
`abandoned`, reason `request changed`) and its items are requested afresh (FR-008). Stale
handle at the provider (404 on status) → every item failed with reason `batch reference not
found`, fallback (spec edge case).

**Alternatives**: a separate `batches.json` (needs a new determinism exclusion and a second
resume file); an enveloped artifact (would make non-deterministic handles an artifact).

## R8. Waiting, polling and progress

**Decision**: poll interval schedule 30 s · 1.5^k capped at 300 s, reset per round; each poll
emits `batch_status` (transient event → live status line; plain line otherwise) with `done/
total` and time waited; submission emits `batch_submitted` (permanent, "batch k/m: N items,
model X"); resolution emits `batch_done` (permanent, counts by outcome). Polls reset the
011 heartbeat so no duplicate "still running" lines appear. `sleep`/`clock` injected.
Expiry check = `now ≥ submitted_at + window_hours·3600` evaluated *locally* before each poll
so a provider that never ends a batch cannot stall the scan (FR-009); the provider's own
`expired` outcome is also honoured per item. Ctrl-C during the wait propagates
`KeyboardInterrupt` to `cmd_run` (exit 130) — the ledger is already durable, so nothing
extra is needed beyond the resume hint text in `reporter.interrupted()`. The provider's
cancel endpoint is never called (paid work would be forfeited; resume is the point).

**Off-peak**: `in_window`/`parse_window` exist in `llm_client.py` but nothing calls them —
off-peak scheduling was also never wired. Minimal implementation in this feature: under
`batch-offpeak`, before submitting a round, wait until `in_window()` using the same waiter and
a `batch_status`-style event ("waiting for off-peak window HH:MM-HH:MM"); expiry still counts
from submission. This is a few lines on top of the poll waiter and makes the existing config
key truthful (constitution: honest documentation).

## R9. Fallback semantics

**Decision**: after a batch reaches a terminal state (or local expiry), items are classified:
`succeeded` → absorb as batch (usage `batch=True`); `errored|canceled|expired|missing from
results|batch failed at validation|batch abandoned|handle not found` → fallback list with the
specific reason. Fallbacks run through `EndpointClient.run` (retrying interactive, R3) in
stable request-id order, each persisted on success; `usage.record_fallback(request_id,
reason)` and a `warning` event per item (FR-007). `BatchUnsupported` on the first submission of
the scan sets `runner.batch_available = False`; the remainder of the stage runs interactively
with exactly one recorded fallback reason `provider does not support batch submission (HTTP
501)` and one warning (FR-010).

## R10. Policy default and configuration surface (spec FR-023 clarification)

**Finding**: `execution_policy.mode` accepts `interactive|batch-offpeak`; `batch.enabled`
defaults `false`; `mode.resolve` chooses `ENDPOINT_BATCH` iff `batch_enabled or mode ==
"batch-offpeak"`. The generated template writes `mode: interactive` explicitly, so an
existing config cannot be told apart from an operator's explicit choice — which is the
correct outcome: existing projects keep their behaviour, new ones get the new default.

**Decision**: `execution_policy.mode ∈ {auto, interactive, batch, batch-offpeak}`, default
`auto`; `auto` ⇒ batch when `llm.endpoint` is configured, agent-mediated otherwise (no-op).
`batch.enabled` is kept for compatibility: `true` forces batch (equivalent to `mode: batch`),
`false` forces interactive; `mode: batch|batch-offpeak` together with `enabled: false` is a
conflict rejected by `validate_config` (FR-026 style). New keys: `execution_policy.batch.
window_hours` (positive number, default 24) and `llm.retry.{attempts, max_wait_s}`. `--policy`
gains `auto` and `batch`. `Resolution` gains `policy_source` ("explicit"/"default") so
`scan_started` and the report's execution-mode line can say `endpoint-batch (default policy)`.
Template text updated; `secscan init` echoes the resolved default.

## R11. Estimated saving (spec FR-013 clarification)

**Decision**: `UsageTracker` gains `batch_input_tokens`, `batch_output_tokens`;
`estimated_saving_percent = round(50 * (batch_in + batch_out) / (total_in + total_out), 1)`
(0.0 when the denominator is 0). Rendered as `Estimated saving vs interactive pricing: 50.0%
(assumes the provider's published 50% batch discount)` in Markdown/HTML; JSON
`batch_share.estimated_saving_percent` + `batch_share.assumption` string. `usage.schema.json`
change is additive (no `schema_version` bump). The existing `savings_factor` (maximal-context
baseline) is unrelated and untouched.

## R12. Fake provider for tests

**Decision**: `tests/helpers/fake_provider.py` implements an in-process `HttpTransport`
(the protocol the adapters call: `(method, url, headers, body) -> (status, headers, body)`)
that speaks both wire shapes, scripted by a small scenario object: per-item outcome
(`succeed|error|expire|omit`), number of polls before `ended`, submission response
(`ok|unsupported|validation_failed`), interactive responses per request id including
`[429 retry_after=N, 429, 200]` sequences. Injected through the existing `transport=` seam of
`run_scan` (currently a `**kwargs -> str` callable; the seam becomes the `HttpTransport`
protocol, and the old callable shape is adapted for the two unit tests that use it). No socket
is opened in any test.

## R13. What is *not* in scope (confirmed against code)

- The system-level review is deterministic (`_system_review_narrative`) and makes no model
  call; the spec's assumption that it stays interactive is moot — no endpoint work there.
- Parallel interactive requests (001 SC-006) are not added; batch is the concurrency answer.
- CWE-312 missing from the dataset: data-only fix, separate change.
