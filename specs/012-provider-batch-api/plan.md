# Implementation Plan: Provider Batch API Execution

**Branch**: `012-provider-batch-api` | **Date**: 2026-09-03 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/012-provider-batch-api/spec.md`

## Summary

In endpoint mode every segment is analysed by one blocking HTTP call issued back-to-back from
the serial loop in `run.py:240-282`; `_http_transport` (`llm_client.py:381-407`) makes a single
attempt and converts any HTTP error into a fatal `RuntimeError` that `cmd_run` re-raises as a
traceback. `segment_analysis` is checkpointed only after the whole stage (`run.py:492`), so a
429 at segment 163/255 discards 162 paid answers. The batch path promised by feature 001 is a
stub: `EndpointClient.submit_batch` mints a local handle, `poll` always returns `pending`, and
`run_batch_with_fallback` is never called.

The design has four parts, all stdlib-only:

1. **Provider adapters + resilient transport** (`pipeline/providers.py`, `llm_client.py`): a
   `ProviderAdapter` per endpoint family (Anthropic Messages / Message Batches; OpenAI Chat
   Completions / Files + Batches) builds and parses both interactive and batch wire shapes; a
   `RetryPolicy` wraps the raw HTTP call, classifies failures as transient (429/5xx/529/
   connection/timeout) or terminal, honours `Retry-After`, and surfaces each retry to the
   progress reporter. A typed `EndpointError` replaces the bare `RuntimeError` so `cmd_run` can
   print it and exit 1 instead of tracebacking.
2. **Persisted answers** (`pipeline/answers.py`): every model answer — interactive, batch, or
   fallback — is written to `.secscan/analysis/answers/<request-id>.json` the moment it is
   observed, keyed by `sha256(serialized request + model tier)`. Both execution paths consult
   the store before sending, so a resumed scan never repeats an answered request (FR-005/008/018).
3. **Round-based batch runner** (`pipeline/batch_runner.py`): the escalation ladder is
   re-expressed as rounds — level 1 for every segment, then level 2 for the segments whose
   answer said `needs_escalation`, and so on. Each round's requests are grouped by model,
   split deterministically under provider limits, submitted, recorded in a ledger in
   `state.json`, polled with a backing-off interval (30 s → 5 min) that emits `batch_status`
   events, and absorbed; failed/expired/missing items fall back to the retrying interactive
   path and are recorded via `UsageTracker.record_fallback`. `EscalationRunner` keeps the
   per-segment ladder for the interactive policy, gaining only answer persistence and
   retries, so feature 011's per-segment progress contract is unchanged there.
4. **Policy resolution and reporting** (`config/loader.py`, `config/mode.py`, `usage.py`,
   report renderers): `execution_policy.mode` gains `auto` (new default; batch whenever an
   endpoint is configured) and `batch`; `execution_policy.batch.window_hours` (default 24) is
   added; the usage summary gains batch token share and the token-based estimated saving.
   Documentation is corrected to describe what the scan actually does.

## Technical Context

**Language/Version**: Python 3.11+ (constitution technology constraint)

**Primary Dependencies**: stdlib only — `urllib.request`, `json`, `uuid`/`email`-free
hand-built `multipart/form-data` for the OpenAI file upload, `hashlib`, `time`, `random`
(seeded/injectable for tests). No provider SDK: the codebase has none, the two wire shapes
are small, and an SDK would add a build-time dependency the constitution forbids.

**Storage**: `.secscan/analysis/answers/<request-id>.json` (persisted answers; raw canonical
JSON, deterministic given deterministic model output — swept by the redaction contract,
included in the two-run determinism comparison); batch ledger under `state.json` →
`meta.analysis_batches` (provider handles, timestamps, per-item answer keys — already excluded
from determinism because `state.json` is). Nothing new is written outside `.secscan/`.

**Testing**: pytest — unit (retry classification and backoff with injected sleep/rng;
adapters' request/response shaping against recorded fixtures; answer store keying; round
splitting; ledger resume) and integration (full scan against a scripted in-process fake
provider that implements both wire shapes: happy batch, partial failure, expiry, unsupported
gateway, interrupt-and-resume, rate-limit-then-succeed, rate-limit-exhausted; determinism suite
run under the batch policy; redaction sweep over the answers directory). ruff.

**Target Platform**: CLI (`secscan run`, `python -m pipeline.scan_cli run`) on macOS/Linux,
run by an operator in a terminal or by an agent skill.

**Project Type**: CLI security scanner (offline deterministic pipeline + bounded LLM analysis).

**Performance Goals**: segment-analysis stage makes ≤ (rounds × ceil(N / provider item limit))
batch submissions + status checks (SC-001); status checks ≥ 30 s apart; interactive retry
adds at most ~3 min per request under default settings (SC-006); zero repeated requests on
resume (SC-004, SC-007).

**Constraints**: byte-identical findings artifacts across policies (SC-003); every batch item
budget-checked and redacted exactly as an interactive request (FR-011); no new content path to
the provider; batch state and answers never carry credential values; foreground wait with
Ctrl-C → exit 130 and resumable ledger (FR-022); traceback-free failure on exhausted retries
(FR-017); OpenAI batches must contain a single model (research R6) — satisfied structurally
because a round has one escalation level and therefore one model tier.

**Scale/Scope**: two new modules (`pipeline/providers.py`, `pipeline/batch_runner.py`,
`pipeline/answers.py` — three, counting the answer store); edits in `llm_client.py`,
`escalate.py`, `run.py`, `scan_cli.py`, `installer/cli.py`, `config/loader.py`,
`config/mode.py`, `usage.py`, `progress.py` (three event kinds), `render_html.py`,
`generate_report.py`, `skill_core/schemas/usage.schema.json` (additive); docs in `README.md`,
`docs/configuration.md`, `docs/cli-reference.md`, `docs/artifacts.md`, `docs/getting-started.md`,
`src/skill_core/SKILL.md`, `AGENTS.md`.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Evaluation | Result |
|-----------|-----------|--------|
| I. Determinism Before Intelligence | Batch vs interactive is an execution detail: the request content is built by the same `_fit`, answers are absorbed by the same `FindingNormalizer`, and the answer file records only `{request_id, answer_key, content}` — no source, timestamps, or handles — so it is identical across policies for identical model output. Round splitting is a deterministic greedy fill over stably-ordered request ids grouped by model. Non-deterministic state (provider handles, submission times, poll counts) lives only in `state.json` meta, already excluded from the two-run comparison. `usage.json` already varies by mode and is already excluded from cross-mode comparison. No network in the default (agent-mediated) path: adapters are only constructed when `llm.endpoint` is configured. | PASS |
| II. Context Is a Managed Resource | Every batch item is produced by `EscalationRunner._fit`, which sheds whole files until the *serialized* request fits and calls `budget.check` — the same code as interactive (FR-011). Rounds preserve the escalation ladder: a segment only enters round L+1 if its round-L answer declared insufficiency. Batching changes *when* requests go out, never *what* is in them. | PASS |
| III. Secrets Never Reach a Model | The payload placed in a batch item is the redacted context packet already written to `context-packets/`; `build_endpoint_request` is reused for the per-item body. The answers directory and (via `state.json`) the ledger are added to the redaction sweep. `EndpointError` messages contain status code, provider name, URL path and the provider's error *type* — never the request body or headers; `cmd_run` still passes the text through the redactor before printing (011 R8). API keys are read from the env var at call time and never persisted (ledger stores `provider` and `base_url` only). | PASS |
| IV. Evidence Over Assertion | Batch answers go through `normalizer.parse`/`normalize` exactly as interactive ones (FR-012); rejected non-conforming findings are warned identically. The usage summary reports batch/interactive/fallback counts from `UsageTracker` records made at absorb time, and the saving figure is derived arithmetically from recorded tokens with its assumption labelled (FR-013) — no unsourced claim. | PASS |
| V. Honest Uncertainty | No item can vanish: a batch item is `answered`, `failed(reason)`, or `outstanding`; outstanding-at-expiry and missing-from-results both become fallbacks with a reason, surfaced during the run and in the report (FR-007). Unsupported gateway → one declared fallback reason for the stage and the report states batch was requested but unavailable (FR-010). Exhausted retries stop the scan with the segment named and prior work preserved — never a partial report presented as complete (FR-017). The resolved policy is printed at scan start so a defaulted batch is never silent (FR-023). | PASS |
| VI. Observe, Never Attack | New writes are confined to `.secscan/analysis/answers/` and `state.json`; the scanned project's manifests/lockfiles hash-check is untouched. Network calls go only to the operator-configured endpoint. The batch cancel endpoint is *not* called on interrupt (the ledger keeps the batch resumable; cancelling would forfeit paid work) — documented in the contract. | PASS |

No violations. Complexity Tracking is empty.

**Post-design re-check (2026-09-03)**: Phase 0/1 hold the gates. The data model separates
deterministic answer files from non-deterministic ledger entries by construction
(data-model.md §Segment Answer vs §Batch Ledger); the contract fixes the answer-file schema to
three fields. The adapter contract (contracts/provider-batch-adapters.md) shows that the
per-item body is `build_endpoint_request(...)[2]` — the same function the interactive path
uses — so Principle III's "no new content path" is a code-level identity, not a promise. The
only new terminal-bound strings are `EndpointError` messages (status/provider/path/error type)
and `batch_status` counters, both free of request content. Redaction-sweep coverage of
`analysis/answers/**` is a listed test, not an intention.

## Project Structure

### Documentation (this feature)

```text
specs/012-provider-batch-api/
├── plan.md                              # This file
├── research.md                          # Phase 0 output
├── data-model.md                        # Phase 1 output
├── quickstart.md                        # Phase 1 output
├── contracts/
│   ├── batch-execution.md               # config keys, CLI behaviour, persisted state, events, exit codes
│   └── provider-batch-adapters.md       # wire shapes per provider family, error classification
├── checklists/requirements.md
└── tasks.md                             # Phase 2 output (/speckit-tasks — NOT created by /speckit-plan)
```

### Source Code (repository root)

```text
src/
├── pipeline/
│   ├── providers.py         # NEW: ProviderAdapter protocol; AnthropicAdapter, OpenAICompatibleAdapter
│   │                        #   (interactive + batch wire shapes, limits, error classification,
│   │                        #   multipart upload); HttpTransport protocol; EndpointError
│   ├── answers.py           # NEW: AnswerStore — answer_key(), get(), put(), clear(); path layout
│   ├── batch_runner.py      # NEW: BatchRoundRunner — rounds, grouping/splitting, ledger, poll loop,
│   │                        #   absorb, fallback; BatchLedger read/write on ArtifactStore meta
│   ├── llm_client.py        # RetryPolicy; EndpointClient.run() via adapter+retry+answer store;
│   │                        #   remove stub submit_batch/poll/run_batch_with_fallback;
│   │                        #   AgentMediatedClient unchanged
│   ├── escalate.py          # extract prepare(segment, level, flows) -> (request, packet) and
│   │                        #   absorb(...) -> continue?; per-segment ladder consults AnswerStore
│   ├── run.py               # choose EscalationRunner (interactive) or BatchRoundRunner (batch);
│   │                        #   per-segment findings persisted as answers arrive; --full clears
│   │                        #   answers + ledger; EndpointError marks stage failed
│   ├── scan_cli.py          # catch EndpointError -> reporter.failed + message + EXIT_ERROR;
│   │                        #   --policy choices auto|interactive|batch|batch-offpeak
│   ├── progress.py          # EventKind.BATCH_SUBMITTED / BATCH_STATUS (transient) / BATCH_DONE;
│   │                        #   reporter.batch_submitted/batch_status/batch_done; retry warning helper
│   ├── usage.py             # batch_input/output_tokens; estimated_saving_percent; render
│   ├── generate_report.py   # usage section shows saving % + assumption label; execution-mode line
│   ├── render_html.py       # same for HTML
│   └── state.py             # ANSWERS_DIR constant; invalidate() also clears answers/ledger when
│                            #   segment_analysis is invalidated
├── config/
│   ├── loader.py            # execution_policy.mode: auto|interactive|batch|batch-offpeak (default
│   │                        #   auto); batch.window_hours; llm.retry.{attempts,max_wait_s};
│   │                        #   conflict rules; template text; Config accessors
│   └── mode.py              # resolve(): auto -> ENDPOINT_BATCH when endpoint configured;
│                            #   Resolution.batch_window_hours, retry settings, policy_source
├── installer/cli.py         # --policy choices
└── skill_core/
    ├── schemas/usage.schema.json   # additive: batch_share.{batch_input_tokens,batch_output_tokens,
    │                               #   estimated_saving_percent,assumption}
    └── SKILL.md                    # endpoint-mode note: batch default, waiting, resume

tests/
├── unit/test_retry_policy.py            # NEW: classification, backoff/jitter with injected rng,
│                                        #   Retry-After as minimum, total-wait bound, attempt count
├── unit/test_providers.py               # NEW: request/response shaping both families, multipart body,
│                                        #   results parsing (out of order, errored, expired), limits,
│                                        #   unsupported detection (404/405/501)
├── unit/test_answers.py                 # NEW: key composition, hit/miss, invalidation on model change
├── unit/test_batch_runner.py            # NEW: grouping by model, deterministic split, ledger
│                                        #   round-trip, resume w/ stale key, poll interval schedule
├── unit/test_llm_client.py              # update: remove stub-batch tests; EndpointClient via adapter
├── unit/test_config_execution_policy.py # NEW: auto default, explicit interactive, conflicts,
│                                        #   window_hours validation, env overrides
├── integration/test_batch_scan.py       # NEW: fake provider server-in-process; US1/US2/US3 scenarios;
│                                        #   exit codes; progress lines; usage summary; SC-001..SC-007
├── integration/test_determinism.py      # extend: run under batch policy; answers dir compared
├── contract/test_artifact_redaction.py  # extend: sweep sees analysis/answers/**
├── contract/test_schemas.py             # extend: new additive usage fields validate
└── helpers/fake_provider.py             # NEW: scripted Anthropic/OpenAI fake (interactive + batch)

docs/
├── configuration.md     # execution_policy.mode auto/batch, window_hours, llm.retry; corrected claims
├── cli-reference.md     # --policy values; waiting/interrupt/resume behaviour; exit codes
├── artifacts.md         # analysis/answers/, ledger in state.json — "resumption state, not artifacts"
├── getting-started.md   # what an endpoint-mode scan looks like (batch by default)
└── README.md            # status claim for batch API becomes true
```

**Structure Decision**: single project, existing layout. Provider wire knowledge is isolated in
`pipeline/providers.py` so `llm_client.py` and `batch_runner.py` never mention a URL; the
round runner depends on `EscalationRunner`'s extracted `prepare`/`absorb` so interactive and
batch paths cannot drift in what they send or how they judge an answer. No new package, no new
dependency.

## Complexity Tracking

No constitution violations to justify.

One deliberate duplication is recorded for reviewers: the interactive policy keeps the
per-segment ladder in `EscalationRunner` while the batch policy uses rounds in
`BatchRoundRunner`. A single round-based driver for both would change the interactive
progress stream (a segment would announce once per level rather than once), breaking feature
011's `segment n/N` contract and its tests for no user benefit. Both drivers share
`prepare`/`absorb`/`AnswerStore`/`UsageTracker`, so the shared surface is the one that decides
content and judgement.
