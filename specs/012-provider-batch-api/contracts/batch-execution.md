# Contract: Batch Execution Policy

**Feature**: 012-provider-batch-api | **Status**: Draft

This contract covers the operator-visible surfaces: configuration keys, CLI behaviour,
progress output, persisted state, exit codes, and report fields. Wire-level provider shapes
are in [provider-batch-adapters.md](provider-batch-adapters.md).

## 1. Configuration

```yaml
llm:
  endpoint:
    provider: anthropic | openai-compatible
    api_key_env: ANTHROPIC_API_KEY
    base_url: https://…            # optional
    model_map: { local: …, segment: …, system: … }
  retry:                           # NEW (endpoint mode only)
    attempts: 5                    # int >= 1; total attempts per interactive request
    max_wait_s: 60                 # int >= 1; ceiling for one wait

execution_policy:
  mode: auto                       # auto | interactive | batch | batch-offpeak   (default auto)
  # offpeak_window: "02:00-06:00"  # REQUIRED when mode is batch-offpeak
  batch:
    enabled: true                  # optional compat switch; see rules
    fallback: interactive          # only valid value
    window_hours: 24               # NEW; number > 0; expiry measured from submission
```

Resolution rules (`config/mode.py`):

| `llm.endpoint` | `mode` | `batch.enabled` | Resolved execution mode |
|---|---|---|---|
| absent | any | absent/false | `agent-mediated` (batch features "unavailable") |
| absent | any | `true` | **config error** (existing rule) |
| present | `auto` | absent | `endpoint-batch` — *policy_source = default* |
| present | `auto` | `true` | `endpoint-batch` |
| present | `auto` | `false` | `endpoint-interactive` |
| present | `interactive` | absent/false | `endpoint-interactive` |
| present | `interactive` | `true` | **config error**: conflicting settings |
| present | `batch` | absent/true | `endpoint-batch` |
| present | `batch` / `batch-offpeak` | `false` | **config error**: conflicting settings |
| present | `batch-offpeak` | absent/true | `endpoint-batch` + wait for window before each submission |

Validation additions (all reported together, FR-026 style):

- `execution_policy.mode must be one of auto, interactive, batch, batch-offpeak`
- `execution_policy.batch.window_hours must be a positive number (found …)`
- `llm.retry.attempts must be a positive integer` / `llm.retry.max_wait_s must be a positive integer`
- `execution_policy.mode is 'batch' but execution_policy.batch.enabled is false - conflicting settings`
- `llm.retry is only meaningful with llm.endpoint` → *warning-free acceptance*: retry keys are
  allowed without an endpoint (they are inert), matching how `model_map` is treated today.

Env overrides: `SECSCAN_EXECUTION_POLICY_MODE`, `SECSCAN_EXECUTION_POLICY_BATCH_WINDOW_HOURS`,
`SECSCAN_LLM_RETRY_ATTEMPTS`, `SECSCAN_LLM_RETRY_MAX_WAIT_S`. Precedence unchanged: env >
file > default.

Backward compatibility: a config written by an earlier `secscan init` contains
`mode: interactive` explicitly and therefore **keeps interactive behaviour**. Only new
configurations (which write `mode: auto`) get batch by default. Documentation states this.

## 2. CLI

`secscan run [--policy auto|interactive|batch|batch-offpeak] …` — `--policy` sets
`SECSCAN_EXECUTION_POLICY_MODE` exactly as today, with the two new values accepted. Same on
`python -m pipeline.scan_cli run`.

Behaviour under `endpoint-batch`:

1. Stage `segment_analysis` starts; scan header line reads
   `mode=endpoint-batch (default policy)` or `mode=endpoint-batch` (explicit).
2. For each escalation round: requests built → those with a matching persisted answer are
   skipped → remaining grouped by model and split → each chunk submitted →
   `batch_submitted` event → ledger written → poll loop → `batch_status` events →
   `batch_done` event → answers persisted → fallbacks (if any) executed interactively with
   one `warning` per item → next round from segments whose answer asked for escalation.
3. Stage completes; pipeline continues unchanged.

Interrupt (Ctrl-C) at any point: existing `interrupted` event, exit **130**, final line
includes `re-run to resume; N batch(es) still processing at the provider`. No cancel request
is sent to the provider.

Exhausted retries on an interactive request (including a fallback): `failed` event naming the
stage, request id, provider, HTTP status and attempt count; one line on stderr; exit **1**; no
traceback. `state.json` records `segment_analysis: failed` with the same message. Re-running
resumes: persisted answers are reused, only unanswered requests are sent.

Terminal failure (401/403/400/unknown model): same surface, no retry, `attempts=1`.

Exit codes are otherwise unchanged (`0`, `1`, `2`, `3` handoff, `130`).

## 3. Progress output (extends feature 011)

Plain rendering (piped) — one line per event; live rendering updates the status line for
`batch_status` only.

```
HH:MM:SS +MM:SS start segment_analysis
HH:MM:SS +MM:SS info  segment_analysis batch 1/1 submitted: 255 items, model claude-haiku-latest, id msgbatch_01AB…
HH:MM:SS +MM:SS wait  segment_analysis batch 1/1 processing 0/255 (waited 30s, next check in 45s)
HH:MM:SS +MM:SS wait  segment_analysis batch 1/1 processing 198/255 (waited 4m30s, next check in 5m)
HH:MM:SS +MM:SS done  segment_analysis batch 1/1 ended: 251 succeeded, 3 errored, 1 expired (4 fallback)
HH:MM:SS +MM:SS warn  [segment_analysis/seg-x-l1] batch item fell back to interactive: errored: invalid_request_error
HH:MM:SS +MM:SS warn  [segment_analysis/seg-y-l1] rate limited (HTTP 429), attempt 2/5, waiting 7s
HH:MM:SS +MM:SS done  segment_analysis segment 12/255 seg-x (L1)            # per absorbed answer, verbose level shows tokens
HH:MM:SS +MM:SS info  segment_analysis batch 1/1 submitted: 23 items, model claude-sonnet-latest, id msgbatch_02CD…   # round 2
```

Guarantees: `batch_status` is emitted on every status check *while the batch is still
processing* — at least every 5 minutes while waiting, and the 011 heartbeat is reset by it;
the check that finds the batch terminal is reported by the `batch_done` line instead. Every
fallback and every retry is a `warning` at the default level with the exact string that
reaches the report's fallback list / coverage notes; no event carries request or response
content.

Under `batch-offpeak`, before submission:
`wait  segment_analysis waiting for off-peak window 02:00-06:00 (starts in 3h12m)`.

## 4. Persisted state

| Path | Class | Written when | Cleared when |
|---|---|---|---|
| `.secscan/analysis/answers/<request-id>.json` | deterministic resumption state; **in** determinism comparison; **in** redaction sweep | each answer observed (batch, interactive, fallback) | `--full`; `segment_analysis` invalidation |
| `state.json` → `meta.analysis_batches` | non-deterministic bookkeeping (already excluded) | after each submission and each terminal status | same |
| `context-packets/*.json` (existing) | artifact | unchanged | unchanged |

Answer file schema (exact):

```json
{
  "answer_key": "9f2c…",
  "content": "{ … model output … }",
  "request_id": "seg-prism-bi-bi-core-v2-p73-l1"
}
```

`docs/artifacts.md` gains a row for `analysis/answers/` labelled "resumption state, not a
scan artifact: safe to delete; deleting forces re-analysis of those segments".

## 5. Report and usage summary

`usage.json` (`schema usage`, additive):

```json
"batch_share": {
  "batch_invocations": 274,
  "interactive_invocations": 4,
  "fallbacks": 4,
  "batch_input_tokens": 2911034,
  "batch_output_tokens": 401877,
  "estimated_saving_percent": 49.3,
  "assumption": "provider's published 50% batch discount"
},
"fallback_log": [{"item": "seg-x-l1", "reason": "errored: invalid_request_error"}, …]
```

Markdown/HTML usage table gains
`| Estimated saving vs interactive pricing | 49.3% (assumes the provider's published 50% batch discount) |`.
Report header's execution-mode line reads `endpoint-batch (default policy)` when defaulted.
When batch was requested but unsupported by the gateway, the coverage notes contain exactly:
`batch execution requested but the endpoint does not support batch submission (HTTP 501); all
analysis ran interactively`.

## 6. Test-visible seams

- `run_scan(..., transport=HttpTransport)` — the adapters' only I/O; the fake provider plugs in
  here. `HttpTransport(method, url, headers, body: bytes | None) -> (status: int, headers:
  dict[str, str], body: bytes)`; it raises `ConnectionError`/`TimeoutError` for network faults.
- `run_scan(..., clock=..., sleep=...)` — injected into `RetryPolicy` and the poll waiter so
  tests run without wall time.
- `RetryPolicy(rng=random.Random(0))` — deterministic jitter in tests.
