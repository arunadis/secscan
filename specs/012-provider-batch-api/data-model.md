# Data Model: Provider Batch API Execution

**Feature**: 012-provider-batch-api | **Date**: 2026-09-03

Two storage classes, deliberately separated (research R4, R7):

- **Deterministic resumption state** — answer files. Identical across policies for identical
  model output; inside the two-run determinism comparison; swept for redaction.
- **Non-deterministic bookkeeping** — the batch ledger and retry counters. Live only in
  `state.json` meta and `UsageTracker`; never in an enveloped artifact.

## Entities

### AnalysisRequest (existing, `llm_client.py`)

Unchanged. Relevant fields: `id` = `<segment-id>-l<level>` (stable, unique per scan);
`prompt`, `payload` (redacted context packet), `budget`, `level` (`local|segment|system`),
`escalation_level`. Derived: `context_text` (the serialized request the budget is enforced
against).

### AnalysisResponse (existing, extended)

New field `cached: bool = False` — true when the content came from a persisted Segment Answer
rather than a request made in this run. `EscalationRunner.absorb()` records **no** usage
(invocation or tokens) for a cached response, so the usage summary describes only what this
run actually sent (Principle IV). `batch`/`fell_back` are always false on a cached response.

### Segment Answer (new file, `pipeline/answers.py`)

Path: `.secscan/analysis/answers/<request-id>.json`, canonical JSON.

| Field | Type | Rule |
|---|---|---|
| `request_id` | string | equals the file stem |
| `answer_key` | string (16 hex) | `hash_text(request.context_text + "\n" + model_tier)` |
| `content` | string | raw model text as returned; may be empty only if the provider returned empty |

Rules: written atomically (temp + rename) the moment an answer is observed, from any source;
read hit only when `answer_key` matches the key recomputed for the current request and tier
(FR-008); on mismatch treated as absent and overwritten by the next answer; directory cleared
by `--full` and by any invalidation of `segment_analysis`. Nothing else is stored here — no
source, tokens, or timestamps (SC-003).

### Batch Ledger (new, `state.json` → `meta.analysis_batches`, key `state.BATCH_LEDGER_META`)

```json
{
  "1:claude-haiku-latest": [ BatchRecord, ... ],
  "2:claude-sonnet-latest": [ BatchRecord, ... ]
}
```

Key = `"<escalation_level>:<model_tier>"` (one round may hold several records when split).

### BatchRecord

| Field | Type | Rule |
|---|---|---|
| `handle` | string | provider batch id (`msgbatch_…` / `batch_…`) |
| `provider` | `anthropic` \| `openai-compatible` | from `Resolution.provider` |
| `base_url` | string \| null | endpoint root actually used |
| `model` | string | single model for every item (OpenAI constraint) |
| `items` | object `{request_id: answer_key}` | sorted keys; the key recorded *at submission* |
| `custom_id_map` | object `{custom_id: request_id}` \| absent | only when an id had to be hashed to satisfy the provider's `custom_id` grammar |
| `submitted_at` | float (epoch s) | local clock at successful submission |
| `expires_at` | float | `submitted_at + window_hours × 3600` |
| `status` | enum | see lifecycle |
| `reason` | string \| absent | provider message or local reason for terminal non-success |
| `polls` | int | diagnostic count |

Lifecycle:

```
submitted ──poll──▶ in_progress ──poll──▶ ended        (results fetched; per-item outcomes)
    │                    │
    │                    ├──local expiry──▶ expired     (all outstanding items → fallback)
    │                    └──status 404───▶ not_found   (all items → fallback)
    ├──validation error─▶ failed                        (all items → fallback, provider reason)
    └──key mismatch on resume──▶ abandoned              (all items requested afresh, no fallback record)
unsupported                                             (never written: BatchUnsupported disables batch for the scan)
```

Terminal: `ended | expired | not_found | failed | abandoned`. A resumed scan re-polls only
`submitted | in_progress` records whose item keys all still match.

### BatchItem outcome (in memory, `batch_runner.py`)

| Field | Type | Rule |
|---|---|---|
| `request_id` | string | |
| `outcome` | `answered` \| `failed` \| `outstanding` | |
| `reason` | string \| null | required when `failed` (`errored: <type>`, `expired`, `canceled`, `missing from results`, `batch failed: <msg>`, `batch reference not found`) |
| `content` | string \| null | when `answered` |

Invariant: after a round resolves, every item is `answered` (by batch or by fallback) or the
scan has stopped with `EndpointError`. `outstanding` never survives a round.

### Round (in memory)

| Field | Type |
|---|---|
| `level` | int 1..4 |
| `active` | list[segment_id] — segments whose previous answer needed escalation (level 1: all) |
| `requests` | list[(AnalysisRequest, packet)] from `EscalationRunner.prepare` |
| `groups` | dict[model_tier, list[request]] → split into ≤ limit chunks, stable order |

### RetryPolicy (new, `llm_client.py`)

| Field | Default | Config |
|---|---|---|
| `attempts` | 5 | `llm.retry.attempts` (int ≥ 1) |
| `base_wait_s` | 2 | fixed |
| `max_wait_s` | 60 | `llm.retry.max_wait_s` (int ≥ 1) |
| `total_wait_s` | 180 | fixed |
| `jitter` | U(0.5, 1.0) | injected rng |

`wait(n, retry_after)` = `max(min(max_wait_s, base·2^(n−1))·jitter, retry_after or 0)`,
refused if it would exceed the remaining `total_wait_s`.

### EndpointError (new exception)

| Field | Meaning |
|---|---|
| `provider`, `path` | endpoint family and URL path (never query/body) |
| `status` | HTTP status or null (connection/timeout) |
| `error_type` | provider error type string when parseable |
| `transient` | classification result |
| `retry_after_s` | parsed header, if any |
| `attempts` | how many were made |
| `request_id` | analysis request id when known |

Subclass `BatchUnsupported(EndpointError)` for 404/405/501 on batch submission.

### UsageTracker (extended, `usage.py`)

New counters: `batch_input_tokens`, `batch_output_tokens`. New derived:
`estimated_saving_percent = round(50 · (batch_in+batch_out) / (total_in+total_out), 1)`
(0.0 if denominator 0). Serialized additively under `batch_share` with
`assumption: "provider's published 50% batch discount"`.

### Resolution (extended, `config/mode.py`)

New fields: `policy_source: "explicit" | "default"`, `batch_window_hours: float`,
`retry_attempts: int`, `retry_max_wait_s: int`, and `offpeak_window: str | None` (set only
under the `batch-offpeak` policy, so the runner needs no second config read). New property
`mode_label` = the mode value plus ` (default policy)` when `policy_source == "default"`;
`describe()` and the report's execution-mode line both use it.

## Progress events (extended, `progress.py`)

| Kind | Transient? | Subject | Detail |
|---|---|---|---|
| `batch_submitted` | no | `batch k/m` | `items`, `model`, `handle` |
| `batch_status` | yes | `batch k/m` | `completed`, `total`, `waited_s`, `next_poll_s` |
| `batch_done` | no | `batch k/m` | `succeeded`, `failed`, `expired`, `fallbacks` |
| `warning` (existing) | no | request id | retry: `attempt`, `wait_s`, `status`; fallback: reason |

## Configuration (extended, `config/loader.py`)

| Key | Values | Default | Notes |
|---|---|---|---|
| `execution_policy.mode` | `auto` \| `interactive` \| `batch` \| `batch-offpeak` | `auto` | `auto` ⇒ batch iff `llm.endpoint` configured |
| `execution_policy.offpeak_window` | `"HH:MM-HH:MM"` | — | required iff `batch-offpeak` |
| `execution_policy.batch.enabled` | bool | absent | compat: `true` ⇒ batch, `false` ⇒ interactive; conflicts with `mode: batch*` when `false` |
| `execution_policy.batch.fallback` | `interactive` | `interactive` | unchanged |
| `execution_policy.batch.window_hours` | number > 0 | 24 | expiry from submission |
| `llm.retry.attempts` | int ≥ 1 | 5 | |
| `llm.retry.max_wait_s` | int ≥ 1 | 60 | |

Env overrides follow the existing pattern: `SECSCAN_EXECUTION_POLICY_MODE`,
`SECSCAN_EXECUTION_POLICY_BATCH_WINDOW_HOURS` (nested key), `SECSCAN_LLM_RETRY_ATTEMPTS`,
`SECSCAN_LLM_RETRY_MAX_WAIT_S`.

## Relationships

```
Segment ──1..4──▶ AnalysisRequest (one per level reached)
AnalysisRequest ──0..1──▶ Segment Answer (persisted; keyed)
Round ──1..n──▶ BatchRecord (grouped by model, split by limits)
BatchRecord ──1..n──▶ BatchItem ──▶ AnalysisRequest (by request_id / custom_id_map)
BatchItem.failed ──▶ fallback ──▶ EndpointClient.run (RetryPolicy) ──▶ Segment Answer
UsageTracker ◀── every absorbed answer (batch flag, tokens) and every fallback
```
