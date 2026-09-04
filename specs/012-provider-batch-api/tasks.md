# Tasks: Provider Batch API Execution

**Input**: Design documents from `/specs/012-provider-batch-api/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md,
contracts/batch-execution.md, contracts/provider-batch-adapters.md, quickstart.md

**Tests**: Included. The constitution's Development Workflow mandates test-first ("Tests are
written before implementation and MUST fail first"), so every phase begins with its tests.
Verify each test fails before implementing the task that makes it pass.

**Organization**: Tasks are grouped by user story so each story is an independently testable
increment. Requirement ids (FR-xxx / SC-xxx) cite spec.md; R-numbers cite research.md;
§-references cite the contracts.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: US1 = batch execution, US2 = batch resilience/resume/fallback, US3 = interactive
  retries + per-segment persistence
- Every task names the exact file(s) it touches

## Path Conventions

Single project: `src/` and `tests/` at repository root (see plan.md "Source Code").

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Constants, the module skeletons, and the test double every later task imports.

- [X] T001 Add `ANSWERS_DIR = "analysis/answers"` beside `LOG_FILE_NAME` in `src/pipeline/state.py`; extend `ArtifactStore.invalidate()` so that when `"segment_analysis"` is among the names it also deletes every file under `self.dir / ANSWERS_DIR` and removes `meta.analysis_batches` from state (research R4/R7; FR-008 "--full clears")
- [X] T002 [P] Create `src/pipeline/providers.py` skeleton: module docstring; `HttpTransport` `Protocol` (`__call__(method, url, headers, body: bytes | None, *, timeout: float) -> tuple[int, dict[str, str], bytes]`); frozen dataclasses `BatchLimits`, `BatchStatus`, `ItemResult`, `BatchItemSpec` exactly as in contracts/provider-batch-adapters.md §Protocol; `EndpointError(RuntimeError)` with fields from data-model.md (`provider, path, status, error_type, transient, retry_after_s, attempts, request_id`) and a `__str__` of the form `analysis endpoint request failed (<provider> <path>): HTTP <status> <error_type> after <attempts> attempt(s)` — never including body or headers; `BatchUnsupported(EndpointError)`; `ProviderAdapter` `Protocol` with the seven methods of the contract
- [X] T003 [P] Create `src/pipeline/answers.py` skeleton: `answer_key(request: AnalysisRequest, model_tier: str) -> str` = `hash_text(request.context_text + "\n" + model_tier)` (import `hash_text` from `pipeline.state`); `class AnswerStore(root: Path)` with method stubs `get(request, model_tier) -> str | None`, `put(request, model_tier, content) -> Path`, `path_for(request_id) -> Path`, `clear()` (data-model.md §Segment Answer)
- [X] T004 [P] Create `tests/helpers/fake_provider.py`: an `HttpTransport` implementation `FakeProvider(family: "anthropic" | "openai-compatible", scenario: Scenario)` speaking both wire shapes of contracts/provider-batch-adapters.md. `Scenario` dataclass fields: `interactive: dict[str, list[int | str]]` (per request id, a sequence of responses — an int is an HTTP status to return with optional `retry_after` via `(429, 7)` tuple, a str is a 200 body), `interactive_default: str`, `submit: "ok" | "unsupported" | "validation_failed"`, `polls_until_ended: int`, `items: dict[str, "succeed" | "error" | "expire" | "omit"]`, `status_after_resume: "same" | "not_found"`. Record every call in `self.calls: list[(method, path)]`; expose `.batch_submissions`, `.interactive_calls` counters; results JSONL is emitted in *reverse* request order to prove ordering independence. For OpenAI, implement `POST /files` (parse the multipart body, store JSONL by returned `file-<n>` id), `POST /batches`, `GET /batches/{id}`, `GET /files/{id}/content`; for Anthropic, `POST /v1/messages/batches`, `GET .../{id}`, `GET .../{id}/results`. Also a `legacy_adapter(fn)` helper that wraps the existing `**kwargs -> str` fake transport shape used by `tests/unit/test_llm_client.py`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Provider adapters, the retry-free resilient error surface, the answer store,
the configuration/mode surface, and the transport seam. Nothing user-visible changes yet
except that endpoint calls go through adapters and typed errors.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

### Tests (write first, must fail)

- [X] T005 [P] Write failing unit tests in `tests/unit/test_providers.py`: for both adapters — `interactive()` returns the same `(url, headers, body)` as today's `build_endpoint_request` for the same inputs (byte-identical body; Principle III); `parse_interactive` handles Anthropic content blocks and OpenAI string / text-parts content; `classify()` implements the table in contracts/provider-batch-adapters.md §Error classification including `unsupported` only for 404/405/501 on the batch-create path (and OpenAI `files` path); `Retry-After` parsing for integer seconds and HTTP-date; Anthropic `submit_batch` body shape `{"requests":[{"custom_id","params":{model,max_tokens,messages}}]}`; OpenAI two-step submit produces a `multipart/form-data` body with exactly `purpose=batch` and `file` parts and JSONL lines `{custom_id, method:"POST", url:"/v1/chat/completions", body:{model, messages, max_completion_tokens}}` with a single model (mixed models → `ValueError`); `batch_status` maps every provider state per contract tables including 404 → `not_found` and OpenAI `failed` with joined `errors.data[*].message`; `batch_results` parses out-of-order JSONL, maps `errored/canceled/expired`, truncates reasons to 200 chars, and for OpenAI merges output + error files and marks `batch_expired` as `expired`; `custom_id` grammar substitution returns a mapping; `batch_limits()` values per contract
- [X] T006 [P] Write failing unit tests in `tests/unit/test_answers.py`: `answer_key` changes when prompt, payload, or model tier changes and is stable otherwise; `put` then `get` round-trips; `get` with a different tier is a miss; file content is exactly `canonical_json({"answer_key","content","request_id"})` (three keys, sorted); `put` is atomic (temp + rename — assert no `*.tmp` remains); `clear()` empties the directory; `AnswerStore` on a missing directory behaves as empty
- [X] T007 [P] Write failing unit tests in `tests/unit/test_config_execution_policy.py`: every row of the resolution table in contracts/batch-execution.md §1 via `config.mode.resolve()` (including `policy_source` = `default` for `auto`+endpoint, `explicit` otherwise); `validate_config` reports each new problem string verbatim (`mode` enum with `auto`/`batch`, `window_hours` ≤ 0, `retry.attempts` 0, `retry.max_wait_s` 0, `mode: batch` + `enabled: false` conflict, `mode: interactive` + `enabled: true` conflict) and reports several at once; `Config.batch_window_hours` default 24.0, `Config.retry_attempts` default 5, `Config.retry_max_wait_s` default 60; env overrides `SECSCAN_EXECUTION_POLICY_BATCH_WINDOW_HOURS=1`, `SECSCAN_LLM_RETRY_ATTEMPTS=2`, `SECSCAN_LLM_RETRY_MAX_WAIT_S=5` land on the nested keys; `default_config_yaml()` contains `mode: auto` and a `window_hours` line; `_ALLOWED` accepts `llm.retry` and `execution_policy.batch.window_hours` and rejects `llm.retry.bogus`
- [X] T008 [P] Update `tests/unit/test_llm_client.py`: delete `test_batch_submission_returns_job_handle`, `test_expired_batch_falls_back_to_interactive_and_is_recorded`, `test_pending_batch_still_completes_every_item` (they test the stub being removed, R1); rewrite `fake_transport`-based tests to construct `EndpointClient(resolution, key, transport=FakeProvider(...))` or the `legacy_adapter` from T004; add failing tests: a 401 from the transport raises `EndpointError` with `transient=False`, `attempts=1`, `status=401`, and `str(exc)` contains neither the request body nor the API key; a successful call persists the answer via an injected `AnswerStore` and a second identical call returns the stored content with `cached=True` without touching the transport (transport call count unchanged)

### Implementation

- [X] T009 Implement `AnthropicAdapter` and `OpenAICompatibleAdapter` in `src/pipeline/providers.py` per contracts/provider-batch-adapters.md (all seven protocol methods; hand-built multipart body with a `uuid4().hex` boundary; JSONL parsing tolerant of blank lines; `parse_retry_after(headers)`; `classify`); add `adapter_for(provider: str, base_url: str | None, api_key: str) -> ProviderAdapter` raising `RuntimeError("unsupported analysis endpoint provider: ...")` as today; add `urllib_transport(method, url, headers, body, *, timeout)` implementing `HttpTransport` over `urllib.request` that returns `(status, headers, body)` for both 2xx and `HTTPError` responses and raises `ConnectionError`/`TimeoutError` for `URLError`/`socket.timeout` (`# pragma: no cover` as today's transport)
- [X] T010 Implement `AnswerStore` in `src/pipeline/answers.py` (T003 stubs): `get` reads the file, returns `content` only if `answer_key` matches; `put` writes `canonical_json` to `<id>.json.tmp` then `os.replace`; `clear` removes files; `mkdir(parents=True, exist_ok=True)` on first write
- [X] T011 Rework `EndpointClient` in `src/pipeline/llm_client.py`: constructor `EndpointClient(resolution, api_key, *, transport: HttpTransport | None = None, answers: AnswerStore | None = None, retry: RetryPolicy | None = None, on_retry=None, clock=time.monotonic, sleep=time.sleep)`; build `self.adapter = adapter_for(...)` and `self.transport = transport or urllib_transport`; `run()` = budget check → `answers.get` hit returns `AnalysisResponse(cached=True)` with `model_tier` and estimated tokens (add `cached: bool = False` to `AnalysisResponse`) → otherwise `adapter.interactive(...)` → one transport call (retry loop arrives in US3, T034) → non-2xx → `EndpointError` via `adapter.classify` → `parse_interactive` → `answers.put` → response. Delete `BatchJob`, `submit_batch`, `poll`, `run_batch_with_fallback`, `batch_window_seconds`. Keep `build_endpoint_request`/`parse_endpoint_response` as thin delegations to the adapters (other modules import them). Keep `AgentMediatedClient`, `AgentHandoff`, `parse_window`, `in_window` unchanged. Update `build_client(...)` to accept and forward `answers`, `retry`, `on_retry`, `clock`, `sleep`
- [X] T012 Extend `src/config/loader.py`: `VALID_EXECUTION_MODES = ("auto", "interactive", "batch", "batch-offpeak")`; `_ALLOWED["llm"] += ("retry",)`, `_ALLOWED["llm.retry"] = ("attempts", "max_wait_s")`, `_ALLOWED["execution_policy.batch"] += ("window_hours",)`; `DEFAULT_CONFIG["execution_policy"] = {"mode": "auto", "batch": {"fallback": "interactive", "window_hours": 24}}` (no `enabled` key); `Config.execution_mode` default `"auto"`, new properties `batch_enabled_explicit -> bool | None`, `batch_window_hours -> float`, `retry_attempts -> int`, `retry_max_wait_s -> int`; validation problems exactly as listed in contracts/batch-execution.md §1 (mode enum message, `window_hours` positive number, retry positive integers, the two conflict messages; keep the existing `enabled requires llm.endpoint` rule); `default_config_yaml()` text: `mode: auto  # auto | interactive | batch | batch-offpeak — auto = batch when an endpoint is configured`, `window_hours: 24  # batch expiry, measured from submission`, `# retry:` block under `llm` with the two keys and defaults; `apply_env_overrides` must map `SECSCAN_LLM_RETRY_<KEY>` → `llm.retry.<key>` and `SECSCAN_EXECUTION_POLICY_BATCH_<KEY>` → `execution_policy.batch.<key>` (extend the `sections` handling with an explicit nested-prefix list before the flat match)
- [X] T013 Extend `src/config/mode.py`: `Resolution` gains `policy_source: str = "explicit"`, `batch_window_hours: float = 24.0`, `retry_attempts: int = 5`, `retry_max_wait_s: int = 60`; `resolve()` implements the table (`auto` + endpoint → `ENDPOINT_BATCH` with `policy_source="default"`; `batch_enabled_explicit` overrides `auto`; explicit modes as listed); `describe()` appends ` (default policy)` to the mode line when `policy_source == "default"`; keep `ENDPOINT_ONLY_FEATURES` text but change `"batch-api"` description to `"provider batch API submission (published 50% discount)"`
- [X] T014 Thread the seams through `src/pipeline/run.py::run_scan`: new keywords `clock: Callable[[], float] | None = None`, `sleep: Callable[[float], None] | None = None`; construct `answers = AnswerStore(store.dir / ANSWERS_DIR)`; pass `answers`, `clock`, `sleep` to `build_client`; the existing `transport` keyword now expects an `HttpTransport` (update the docstring); wrap `EndpointError` raised inside the segment loop: `store.mark_failed("segment_analysis", str(exc))` then re-raise (FR-017 half — the CLI surface is T036)
- [X] T015 Add three `EventKind`s to `src/pipeline/progress.py`: `BATCH_SUBMITTED`, `BATCH_STATUS` (added to `TRANSIENT_KINDS`), `BATCH_DONE`; reporter methods `batch_submitted(stage, index, total, *, items, model, handle)`, `batch_status(stage, index, total, *, completed, item_total, waited_s, next_poll_s)`, `batch_done(stage, index, total, *, succeeded, failed, expired, fallbacks)`; extend `render_text` with the grammar of contracts/batch-execution.md §3 (`info … batch k/m submitted: N items, model X, id H`, `..... … batch k/m processing c/N (waited …, next check in …)`, `done … batch k/m ended: …`); `batch_status` must reset the heartbeat timer like any other event; `NullReporter` needs no change. Add failing render tests for the three lines to `tests/unit/test_progress.py` first
- [X] T016 Run `pytest -q tests/unit/test_providers.py tests/unit/test_answers.py tests/unit/test_config_execution_policy.py tests/unit/test_llm_client.py tests/unit/test_progress.py` — all green; run `pytest -q` — the full suite must still be green (existing endpoint-mode integration tests, if any, now go through `FakeProvider`/`legacy_adapter`)

**Checkpoint**: Endpoint calls flow through adapters with typed errors and persisted answers; config accepts the new keys; `mode: auto` resolves. No batch has been submitted yet.

---

## Phase 3: User Story 1 — Analyse a large repository through the provider's batch facility (Priority: P1) 🎯 MVP

**Goal**: Under `endpoint-batch`, each escalation round's requests are grouped by model, split
under provider limits, submitted as batches, recorded in the ledger, polled with progress, and
absorbed through the normal normaliser; the usage summary shows the batch share and saving.

**Independent Test**: `pytest -q tests/integration/test_batch_scan.py -k happy_path` — with the
`FakeProvider` scenario `submit=ok, items=all succeed, polls_until_ended=2`, a full scan of the
`single_repo_shop` fixture makes exactly one batch submission per escalation round and zero
interactive calls; stderr carries `batch_submitted`/`batch_status`/`batch_done` lines; findings
artifacts are byte-identical to an interactive run; `usage.json.batch_share` shows all
invocations as batch and `estimated_saving_percent == 50.0` (SC-001, SC-003, FR-001/002/003/
004/011/012/013).

### Tests (write first, must fail)

- [X] T017 [P] [US1] Write failing unit tests in `tests/unit/test_batch_runner.py` for the pure parts: `group_and_split(requests, limits, body_size_of)` groups by model tier, preserves request-id order, splits when `max_items` or `max_bytes` would be exceeded, and is deterministic (same input → same chunks); `poll_schedule()` yields 30, 45, 67.5, … capped at 300; `BatchLedger` round-trips a `BatchRecord` through `ArtifactStore.set_meta/get_meta` under key `"<level>:<model>"` with sorted `items`; `plan_round(level, segments, outcomes)` returns only segments whose previous `absorb` asked for escalation (level 1 → all); `check_budgets(requests)` calls `request.budget.check(request.estimated_tokens(), f"{stage}/{request.id}")` for every item and an over-budget item raises **before** any `submit_batch` call is made (FR-011, Constitution II)
- [X] T018 [P] [US1] Write failing unit tests in `tests/unit/test_escalate.py` (create if absent) for the extracted `EscalationRunner.prepare(segment, level, flows, on_packet) -> (AnalysisRequest, packet)` (writes the packet, applies `_fit`, calls `on_packet`) and `absorb(outcome, request, response, packet) -> bool` (records usage with the response's `batch` flag and fallback, records **nothing** in usage when `response.cached` is true, sets `content`/`escalation_level`/`pending`, returns `True` when escalation should continue — including `False` at level ≥ 3 when the packet already holds every file); assert `run()` still produces the same `SegmentOutcome` as before for a scripted responder (regression guard for the interactive path)
- [X] T019 [P] [US1] Write failing unit tests in `tests/unit/test_usage.py` (extend or create): `record(..., batch=True, input_tokens, output_tokens)` increments `batch_input_tokens`/`batch_output_tokens`; `estimated_saving_percent` = 50.0 for all-batch, 0.0 for none or for zero tokens, 25.0 for a 50/50 token split; `to_dict()["batch_share"]` has the four new keys with `assumption == "provider's published 50% batch discount"`; `from_dict` round-trips; `render_markdown()` contains `Estimated saving vs interactive pricing | 50.0% (assumes the provider's published 50% batch discount)`
- [X] T020 [P] [US1] Extend `tests/contract/test_schemas.py` (the existing usage-schema coverage around its `usage` cases) with a failing test that a `UsageTracker().to_dict()` containing the new `batch_share` keys validates against `src/skill_core/schemas/usage.schema.json`
- [X] T021 [US1] Write failing integration tests in `tests/integration/test_batch_scan.py` — fixture helper `_batch_config(root, family)` writes `.secscan/config.yaml` with `llm.endpoint` (`api_key_env: FAKE_KEY`) and `execution_policy.mode: auto`, sets `FAKE_KEY` in `environ`; `_run(root, provider, **kw)` calls `run_scan(root, transport=provider, environ=..., progress=reporter, clock=fake_clock, sleep=fake_sleep)` with a `PlainSink` into a `StringIO`. Tests: `test_happy_path_submits_one_batch_per_round[anthropic|openai-compatible]` (exactly `rounds` submissions, `interactive_calls == 0`, `batch_status` lines ≥ 1, `batch_done` line present, per-segment `segment_done` lines equal to segment count); `test_batch_findings_identical_to_interactive` (compare `findings/**.json`, `report.json` payloads between `mode: auto` and `mode: interactive` runs with the same scripted answers); `test_usage_summary_reports_batch_share` (`batch_invocations == invocations`, `fallbacks == 0`, `estimated_saving_percent == 50.0`); `test_resumed_run_does_not_count_cached_answers` (interrupt after the round is absorbed, re-run → `usage.invocations` counts only requests actually sent in the second run); `test_scan_header_states_default_policy` (`scan_started` line contains `endpoint-batch (default policy)`); `test_single_segment_run_submits_one_item_batch` (`only_segment=...` → one submission with 1 item)

### Implementation

- [X] T022 [US1] Refactor `src/pipeline/escalate.py`: extract `prepare()` and `absorb()` from `EscalationRunner.run()` per T018; `run()` becomes `for level in 1..max: request, packet = prepare(...); cached = client answers hit? (handled inside client) ; response = client.run(request); if not absorb(...): return outcome`; `absorb` records `usage.record(..., batch=response.batch, ...)` and `record_fallback` exactly as today **except** when `response.cached` is true — a cached answer was not sent this run, so it MUST NOT count as an invocation or as tokens in this run's usage summary (Principle IV: the report asserts only what this run did); export `needs_escalation = _needs_escalation` for the batch runner
- [X] T023 [US1] Extend `src/pipeline/usage.py`: fields `batch_input_tokens`, `batch_output_tokens`; `record()` adds to them when `batch=True`; property `estimated_saving_percent`; `to_dict`/`from_dict`/`render_markdown` per T019; keep every existing key
- [X] T024 [P] [US1] Add the four additive properties under `batch_share` in `src/skill_core/schemas/usage.schema.json` (`batch_input_tokens`, `batch_output_tokens` integers ≥ 0; `estimated_saving_percent` number 0–50; `assumption` string) — no `schema_version` bump (additive)
- [X] T025 [P] [US1] Show the saving line in `src/pipeline/generate_report.py` (usage section of the Markdown/JSON report: add `estimated_saving_percent` + `assumption` to the JSON usage block if it copies `usage.to_dict()`, and render the Markdown row) and in `src/pipeline/render_html.py` (add row `("Estimated saving vs interactive pricing", f"{usage.estimated_saving_percent}% (assumes the provider's published 50% batch discount)")` after `Batch fallbacks`); make the execution-mode line read `<mode> (default policy)` when `resolution.policy_source == "default"` — `build_report` gains a `policy_source: str = "explicit"` kwarg
- [X] T026 [US1] Create `src/pipeline/batch_runner.py` with: `BatchLedger(store)` (`load() -> dict`, `record(round_key, BatchRecord)`, `update(round_key, handle, **fields)`, `open_records(round_key)`), `BatchRecord` dataclass + `to_dict/from_dict` (data-model.md), `group_and_split(...)`, `poll_schedule()`, `plan_round(...)` (T017), and `class BatchRoundRunner(client: EndpointClient, escalation: EscalationRunner, adapter, transport, ledger, answers, usage, reporter, *, window_hours, clock, sleep, stage="segment_analysis")` whose `run(segments, flows_for, on_packet) -> dict[str, SegmentOutcome]` implements: for each level → `plan_round` → `prepare` each active segment → skip requests with an `answers.get` hit (absorb them immediately with `AnalysisResponse(cached=True)`; `absorb()` records no usage for cached answers — see T022) → `check_budgets(requests)` on every remaining item (FR-011; raises before any submission) → `group_and_split` → for each chunk: `adapter.submit_batch(...)` → `ledger.record(...)` **before** waiting (FR-003) → `reporter.batch_submitted(...)` → `_wait(records)` polling every chunk of the round on `poll_schedule()`, emitting `reporter.batch_status(...)` per poll, until every record is terminal → `_absorb(records)`: fetch results, `answers.put` each `succeeded` item, `escalation.absorb(...)` with `AnalysisResponse(batch=True)`, emit `reporter.segment_done(stage, segment_id, index, total, escalation_level=level, estimated_tokens=...)` per absorbed segment → collect non-succeeded items into `fallbacks: list[(request, reason)]` (execution of fallbacks is US2, T030 — for US1 raise `NotImplementedError` guarded by `if fallbacks:` so happy-path tests pass and the gap is explicit) → `reporter.batch_done(...)`. Local expiry check (`clock() >= submitted_at + window_hours*3600`) is evaluated before each poll and marks the record `expired` (absorption of expired items is US2)
- [X] T027 [US1] Wire the runner into `src/pipeline/run.py`: after `runner = EscalationRunner(...)`, if `resolution.mode is ExecutionMode.ENDPOINT_BATCH`: build `BatchRoundRunner(...)` with `client.adapter`, `client.transport`, `BatchLedger(store)`, `answers`, `usage`, `reporter`, `window_hours=resolution.batch_window_hours`, `clock`, `sleep`; call `reporter.stage_started("segment_analysis")`, `outcomes = batch_runner.run(segments, lambda s: dataflow.flows_for_segment(graph, s, flows), on_packet=packets.append)`, then iterate `segments` in order applying the existing per-segment post-processing (builder warnings, `normalizer.parse/normalize`, rejected warnings, `per_segment[...]`) from the dict — factor that post-processing into a local `_absorb_outcome(segment, outcome)` used by both branches so the two paths cannot diverge; interactive branch keeps the existing loop with `reporter.segment_started/segment_done`. Pass `policy_source=resolution.policy_source` to `generate_report.build_report`; include `resolution.describe()`'s first line in `reporter.scan_started(..., mode=f"{resolution.mode.value}{' (default policy)' if resolution.policy_source == 'default' else ''}")`
- [X] T028 [US1] Update `src/pipeline/scan_cli.py` (`--policy` choices `("auto", "interactive", "batch", "batch-offpeak")`) and `src/installer/cli.py` (same `click.Choice`); help text: `execution policy (default: config value; auto = batch when an endpoint is configured)`
- [X] T029 [US1] Run `pytest -q tests/integration/test_batch_scan.py -k "happy_path or identical or usage_summary or header or single_segment"` and `pytest -q tests/unit/test_batch_runner.py tests/unit/test_escalate.py tests/unit/test_usage.py tests/contract` — green; then `pytest -q` — full suite green (011 per-segment progress tests must be unaffected in interactive mode)

**Checkpoint**: A batch-policy scan against the fake provider completes end-to-end with zero interactive calls and a truthful usage summary. Fallbacks are not yet executed (explicit `NotImplementedError`).

---

## Phase 4: User Story 2 — A batch that cannot complete never costs coverage or repeats work (Priority: P2)

**Goal**: Failed/expired/missing items fall back interactively with recorded reasons; an
interrupted wait resumes the same batch on re-run; stale handles and unsupported gateways are
handled; stale answer keys abandon a batch rather than reuse wrong answers.

**Independent Test**: `pytest -q tests/integration/test_batch_scan.py -k "partial or expiry or resume or stale_handle or unsupported or key_mismatch"` — scenarios from quickstart.md §B and §D pass: only failed items fall back and are recorded with reasons; expiry falls everything back; interrupt-then-rerun makes zero new submissions; 404 on status falls back with `batch reference not found`; 501 on submit runs the stage interactively with exactly one fallback record and the contract's coverage-note wording (FR-005/006/007/008/009/010, SC-004, SC-005).

### Tests (write first, must fail)

- [X] T030 [P] [US2] Add failing unit tests to `tests/unit/test_batch_runner.py`: `classify_items(record, results)` yields `answered` for `succeeded`, `failed` with reasons `errored: <type>` / `canceled` / `expired` / `missing from results` for the rest, and `failed("batch failed: <msg>")` for a `failed` record, `failed("batch reference not found")` for `not_found`, `failed("expired")` for locally expired; `BatchLedger.open_records` ignores terminal records; `resume_check(record, current_keys)` returns `abandon` when any item's current answer key differs from the recorded one and `resume` otherwise; `BatchUnsupported` on the first submit sets `runner.batch_available = False` and no further `submit_batch` call is made in the same runner
- [X] T031 [US2] Add failing integration tests to `tests/integration/test_batch_scan.py`: `test_partial_failure_falls_back_only_failed_items` (3 `error` + 1 `omit` → `fallback_log` has exactly those 4 with the contract reasons, `interactive_calls == 4`, every segment has one answer file, 4 `warning` lines `batch item fell back to interactive: …`); `test_expiry_falls_back_all_outstanding` (fake clock jumps past `window_hours` before the first poll → all items `expired`, no further polls of that record); `test_interrupt_during_wait_then_resume_polls_same_batch` (fake `sleep` raises `KeyboardInterrupt` on the 2nd call → `run_scan` propagates it; `state.json` has the record with status `in_progress`; second `run_scan` on the same root → `batch_submissions` unchanged, scan completes, answers directory byte-identical to an uninterrupted run); `test_stale_handle_falls_back` (`status_after_resume="not_found"` → all items fall back with `batch reference not found`, no exception); `test_unsupported_gateway_runs_interactively` (`submit="unsupported"` → one submit attempt total across all rounds, `interactive_calls == total requests`, `fallbacks == 1`, `warnings` contains exactly `batch execution requested but the endpoint does not support batch submission (HTTP 501); all analysis ran interactively`, `batch_share.batch_invocations == 0`); `test_changed_prompt_abandons_batch_and_requests_afresh` (interrupt during wait, then re-run with a different `model_map.local` → ledger record status `abandoned`, a new submission is made, no fallback recorded); `test_validation_failed_batch_falls_back_with_provider_reason` (`submit="validation_failed"` → record `failed`, all items fall back with `batch failed: <msg>`)

### Implementation

- [X] T032 [US2] Implement in `src/pipeline/batch_runner.py`: `classify_items`, `resume_check`, `BatchLedger.open_records`; in `run()`, before submitting a round, load open records for the round key, run `resume_check` against the current requests' keys — `resume` → skip submission for those items and poll the existing handle; `abandon` → `ledger.update(status="abandoned", reason="request changed")` and submit afresh; replace the T026 `NotImplementedError` with `_fallback(fallbacks)`: for each `(request, reason)` in request-id order → `usage.record_fallback(request.id, reason)` → `reporter.warning(f"{request.id}: batch item fell back to interactive: {reason}", stage=..., subject=request.id)` (append the same string to the runner's `warnings` list which `run.py` merges into the report's coverage notes) → `response = client.run(request)` (persists via `AnswerStore`) → `response.fell_back = True; response.fallback_reason = reason` → `escalation.absorb(...)`; handle `BatchUnsupported` from `submit_batch`: set `batch_available = False`, record one fallback `provider does not support batch submission (HTTP <status>)`, append the exact coverage-note string from contracts §5 to `warnings`, and run every remaining request of the scan via `client.run` in the same round loop (no further `submit_batch`); handle `BatchStatus.state == "failed"` → `ledger.update(status="failed", reason=...)`, all items fall back; `not_found` → status `not_found`, all items fall back; local expiry → status `expired`
- [X] T033 [US2] In `src/pipeline/run.py`: merge `batch_runner.warnings` into `warnings` via `_warn` semantics (they were already reported live by the runner, so append to the list only — mirror how `builder.warnings` is handled) and pass `--full`'s invalidation through `store.invalidate(*_ANALYSIS_STAGES)` (T001 already clears answers + ledger when `segment_analysis` is invalidated — assert in a test in `tests/integration/test_batch_scan.py::test_full_rerun_clears_answers_and_ledger`); in `src/pipeline/progress.py::ProgressReporter.interrupted()` accept an optional `note: str | None` and append it to the rendered line; in `src/pipeline/scan_cli.py::cmd_run` `except KeyboardInterrupt`: read `store.get_meta("analysis_batches")` and pass `note=f"re-run to resume; {n} batch(es) still processing at the provider"` when any record is non-terminal
- [X] T034 [US2] Run `pytest -q tests/integration/test_batch_scan.py tests/unit/test_batch_runner.py` — green; `pytest -q` — green

**Checkpoint**: Every batch item ends `answered` or as a recorded fallback; interrupted waits resume without resubmission; unsupported gateways degrade to interactive with one declared note.

---

## Phase 5: User Story 3 — Interactive requests survive transient rate limits (Priority: P3)

**Goal**: Interactive requests (interactive policy and batch fallbacks) retry transient failures
with jittered backoff honouring `Retry-After`, surface each retry as a warning, stop cleanly
with work preserved when exhausted, and never retry terminal errors; the interactive policy
persists per-segment answers so a resumed scan re-requests only unanswered segments.

**Independent Test**: `pytest -q tests/unit/test_retry_policy.py tests/integration/test_batch_scan.py -k rate_limit` — `[ (429,7), 429, 200 ]` succeeds with two retry warnings and one counted invocation; all-429 stops after exactly 5 attempts with exit code 1, no traceback, prior segments' answers preserved, and a re-run re-requests only the failed segment onward; 401 is not retried (FR-014–FR-019, SC-006, SC-007).

### Tests (write first, must fail)

- [X] T035 [P] [US3] Write failing unit tests in `tests/unit/test_retry_policy.py`: `RetryPolicy(attempts=5, base_wait_s=2, max_wait_s=60, total_wait_s=180, rng=random.Random(0), sleep=recorder, clock=fake)`; `wait_for(n, retry_after)` = `min(60, 2·2^(n-1)) · U(0.5,1.0)` and `>= retry_after`; sequence of four waits for a `[429,429,429,429,200]` transport is monotone non-decreasing before jitter and each ≤ 60; `Retry-After: 90` → wait exactly ≥ 90 even though > cap; total wait never exceeds 180 (a `Retry-After: 200` after 100 s already waited → stop with `EndpointError(attempts=n)`); `attempts=1` → no retry; terminal status → no sleep, `attempts == 1`; `on_retry(request_id, attempt, wait_s, status)` callback invoked once per retry; connection error/timeout treated as transient
- [X] T036 [US3] Add failing integration tests to `tests/integration/test_batch_scan.py` (interactive policy via `mode: interactive`): `test_rate_limit_then_success_retries_and_counts_once` (scenario `interactive={"seg-…-l1": [(429, 7), 429, "<answer>"]}` → two `warning` lines matching `rate limited \(HTTP 429\), attempt [23]/5, waiting \d+s`, first recorded sleep ≥ 7, `usage.invocations` counts that request once); `test_rate_limit_exhausted_stops_cleanly_and_resumes` (all 429 for segment K → `run_scan` raises `EndpointError` with `attempts == 5`; `state.json` `segment_analysis.status == "failed"`; answer files exist for segments 1..K-1; second run with a healthy provider → `interactive_calls` equals only segments K..N (per level)); `test_terminal_error_not_retried` (401 → `EndpointError(attempts=1)`, zero sleeps); and a CLI-level test using `scan_cli.cmd_run` with `monkeypatch` on `run_mod.run_scan` to raise `EndpointError(...)` → return code `1`, stderr contains the stage, request id, `HTTP 429`, `5 attempt(s)` and `re-run to resume`, and does **not** contain `Traceback`
- [X] T037 [P] [US3] Add a failing integration test `test_interactive_policy_persists_answers_per_segment` in `tests/integration/test_batch_scan.py`: with `mode: interactive` and a transport that raises `KeyboardInterrupt` at segment 3 of N, answer files for segments 1–2 exist; re-run makes `interactive_calls == (N - 2) × levels`

### Implementation

- [X] T038 [US3] Implement `RetryPolicy` in `src/pipeline/llm_client.py` (dataclass per data-model.md with `rng`, `sleep`, `clock` injected; `wait_for()`, `execute(fn, *, request_id, on_retry) -> result` that catches `EndpointError` with `transient=True` and `ConnectionError`/`TimeoutError`, computes the wait, refuses when the total bound would be exceeded, calls `on_retry`, sleeps, re-invokes; re-raises the last `EndpointError` with `attempts` filled in); `EndpointClient.run()` wraps the transport call in `self.retry.execute(...)`; `build_client` constructs `RetryPolicy(attempts=resolution.retry_attempts, max_wait_s=resolution.retry_max_wait_s, ...)` when none is injected
- [X] T039 [US3] In `src/pipeline/run.py`: pass `on_retry=lambda rid, attempt, wait_s, status: reporter.warning(f"{rid}: rate limited (HTTP {status}), attempt {attempt}/{attempts}, waiting {round(wait_s)}s" if status == 429 else f"{rid}: transient endpoint error (HTTP {status or 'connection'}), attempt {attempt}/{attempts}, waiting {round(wait_s)}s", stage="segment_analysis", subject=rid)` to `build_client` (retry warnings are progress-only, not coverage notes — do not append to `warnings`); ensure the interactive branch persists per segment: `EndpointClient.run` already `answers.put`s on success (T011), so verify `EscalationRunner.run` hits the store on resume (covered by T037) and that `findings/local/<segment>.json` is written inside the loop rather than after it — move the `store.write("findings/local/…")` call into `_absorb_outcome` so a crash preserves normalised findings too
- [X] T040 [US3] In `src/pipeline/scan_cli.py::cmd_run`: add `except EndpointError as exc:` before the generic handler → `reporter.failed(redactor.redact(str(exc)).text)`, `reporter.close()`, print to stderr: the redacted message, then `re-run to resume: segments already analysed are kept; the scan continues from <request_id>` (use `exc.request_id` when set), return `EXIT_ERROR` (no re-raise). Import `EndpointError` from `pipeline.providers`. Also in `src/pipeline/run.py::main()` (the payload-internal wrapper) catch `EndpointError` → print message → `raise SystemExit(1) from None`
- [X] T041 [US3] Run `pytest -q tests/unit/test_retry_policy.py tests/integration/test_batch_scan.py` — green; `pytest -q` — green

**Checkpoint**: The originating failure (429 at segment 163/255) now retries, and if the limit persists the scan stops with one line and resumes from segment 163 on the next run.

---

## Phase 6: Off-peak, determinism, safety sweeps, documentation

**Purpose**: Cross-cutting guarantees and the documentation-currency gate.

- [X] T042 Implement off-peak waiting in `src/pipeline/batch_runner.py`: when `resolution.execution_mode == "batch-offpeak"` (pass `offpeak_window: str | None` into the runner), before submitting a round call `_wait_for_window()` which loops `while not in_window(window, now=datetime.fromtimestamp(wall_clock()))`: emit `reporter.batch_status(...)`-style event with message `waiting for off-peak window HH:MM-HH:MM (starts in …)` (reuse `BATCH_STATUS` with `detail={"waiting_for_window": window}` and extend `render_text` accordingly) and `sleep(min(300, seconds_until_start))`. Add a failing unit test first in `tests/unit/test_batch_runner.py` with an injected wall clock that starts outside the window and enters it after two sleeps (R8)
- [X] T043 [P] Extend `tests/integration/test_determinism.py`: parametrize the two-run byte-identity test over `mode: interactive` and `mode: auto` (endpoint + `FakeProvider`), asserting `.secscan/**/*.json` minus `state.json` — including `analysis/answers/*.json` — are identical; add `test_answer_files_identical_across_policies` comparing the answers directory of a batch run and an interactive run of the same fixture (SC-003)
- [X] T044 [P] Extend `tests/contract/test_artifact_redaction.py`: add `test_answers_and_ledger_are_seen_by_the_sweep` asserting at least one file under `analysis/answers/` is swept and that `state.json`'s serialized `meta.analysis_batches` contains no seeded secret and nothing the redactor would flag (SC-008); the `scanned` fixture must run once under the batch policy with `FakeProvider`
- [X] T045 [P] Extend `tests/integration/test_scan_progress.py` with a batch-mode case asserting the exact stderr grammar of contracts/batch-execution.md §3 for `batch_submitted`, `batch_status`, `batch_done`, fallback warnings, and retry warnings (plain sink), and that `batch_status` lines are absent at `quiet` and present at `default`
- [X] T046 [P] Update `docs/configuration.md`: `execution_policy.mode` values with `auto` default and the backward-compatibility paragraph (configs with explicit `mode: interactive` keep interactive), `batch.window_hours`, `llm.retry.*`, env override names, the resolution table from contracts §1, and rewrite the "Endpoint scheduling: interactive vs batch" section to describe waiting, resumption, fallback, and the saving formula with its assumption; remove any sentence claiming a discount without qualification (FR-020)
- [X] T047 [P] Update `docs/cli-reference.md`: `--policy` values; the "what happens while a batch waits" paragraph; Ctrl-C/resume; exit code 1 on exhausted retries with the resume hint; note that the provider's cancel endpoint is never called
- [X] T048 [P] Update `docs/artifacts.md`: add `analysis/answers/<request-id>.json` (resumption state, not an artifact, safe to delete, forces re-analysis) and `state.json → meta.analysis_batches` (ledger) rows; note both are inside the determinism/redaction coverage as described
- [X] T049 [P] Update `docs/getting-started.md` and `README.md`: what an endpoint-mode scan looks like under the default batch policy (submit → wait → results), how to opt into interactive for quick scans, and make the README status line for "batch API" true (no "planned" label)
- [X] T050 [P] Update `src/skill_core/SKILL.md`: endpoint-mode note — batch is the default with an endpoint, the scan waits in the foreground, Ctrl-C is resumable, exit 1 with resume hint on exhausted retries; and `AGENTS.md` non-negotiables: add "Endpoint calls only through `pipeline/providers.py` adapters; never build provider URLs or bodies elsewhere" and "Answer files hold only `{request_id, answer_key, content}`"
- [X] T051 Update `src/pipeline/init_cmd.py` so the `secscan init` environment report prints the resolved execution policy line (`resolution.describe()`), including `(default policy)`; extend `tests/integration/test_tooling_init.py` (its `run_init(root, environ={...})` helper) with a test that writes an endpoint config, passes the fake key in `environ`, and asserts the rendered report contains `endpoint-batch (default policy)`
- [X] T052 Run the full verification per quickstart.md §F: `pytest -q`, `pytest -q -m slow`, `ruff check src tests`; fix any failures; confirm `grep -rn "50% cost discount" README.md docs src` returns only qualified statements

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies; T002–T004 in parallel after T001
- **Foundational (Phase 2)**: depends on Phase 1; T005–T008 (tests) in parallel; T009/T010/T012/T013/T015 in parallel (different files); T011 after T009+T010; T014 after T011–T013; T016 last. **Blocks all stories.**
- **US1 (Phase 3)**: after Phase 2. T017–T021 tests in parallel; T022, T023, T024, T025 in parallel; T026 after T022–T023; T027 after T026; T028 parallel with T026; T029 last
- **US2 (Phase 4)**: after US1 (extends `batch_runner.py` and the integration test module)
- **US3 (Phase 5)**: after Phase 2 only — independent of US1/US2 (touches `llm_client.py` retry, `run.py` interactive branch, `scan_cli.py`); can proceed in parallel with US1 by a second developer. Note T033 (US2) and T040 (US3) both edit `scan_cli.py::cmd_run` — coordinate or sequence
- **Polish (Phase 6)**: T042 after US2; T043–T045 after US3; docs T046–T050 after the behaviour they describe is final; T051 after Phase 2; T052 last

### Within Each Story

- Tests written and failing before the implementation task they cover
- `batch_runner.py` pure helpers (T017/T026) before the runner loop; runner before `run.py` wiring
- Story complete (checkpoint green) before moving to the next priority

### Parallel Opportunities

- Phase 1: T002, T003, T004
- Phase 2: T005, T006, T007, T008 (tests); T009, T010, T012, T013, T015 (implementation)
- US1: T017, T018, T019, T020 (tests); T022, T023, T024, T025 (implementation); T028 alongside T026
- US3 as a whole alongside US1/US2 (different modules), except the shared `scan_cli.py` edit
- Phase 6: T043, T044, T045 (tests) and T046–T050 (docs) all in parallel

---

## Parallel Example: User Story 1

```bash
# Tests first, together:
Task: "Unit tests for group_and_split / poll_schedule / BatchLedger / plan_round in tests/unit/test_batch_runner.py"
Task: "Unit tests for EscalationRunner.prepare/absorb in tests/unit/test_escalate.py"
Task: "Unit tests for UsageTracker batch tokens and saving in tests/unit/test_usage.py"
Task: "Contract test for additive usage schema fields in tests/contract/test_schemas.py"

# Then the independent implementation slices:
Task: "Extract prepare/absorb in src/pipeline/escalate.py"
Task: "Batch token counters + saving in src/pipeline/usage.py"
Task: "Additive fields in src/skill_core/schemas/usage.schema.json"
Task: "Saving row + default-policy label in src/pipeline/generate_report.py and src/pipeline/render_html.py"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Phase 1 + Phase 2 (adapters, typed errors, answer store, config, seams)
2. Phase 3: batch rounds, ledger, polling, absorption, usage summary
3. **STOP and VALIDATE**: quickstart §A — one submission per round, zero interactive calls, byte-identical findings, truthful usage summary
4. Ship behind `mode: auto` — note that fallbacks still raise `NotImplementedError` until US2, so the MVP is demo-able against a healthy provider only; do not release before US2

### Incremental Delivery

1. Setup + Foundational → typed errors and persisted answers already improve the interactive path's diagnostics
2. US1 → batch execution works for healthy batches (MVP)
3. US2 → batch is safe to rely on (fallback, resume, unsupported gateways) — **minimum releasable scope is US1 + US2**
4. US3 → the originating 429 crash is fixed for the interactive policy and for fallbacks
5. Phase 6 → off-peak, determinism/redaction coverage, documentation currency gate

### Parallel Team Strategy

- Developer A: Phase 2 → US1 → US2
- Developer B: Phase 2 (T005–T008 tests, T012–T013 config) → US3 → T043–T045
- Docs (T046–T050) by whoever finishes first, after behaviour is final

---

## Notes

- Never add a provider URL or body outside `src/pipeline/providers.py`
- Answer files: exactly three keys; anything policy-dependent goes to `UsageTracker` or the ledger
- No test may open a socket; every endpoint interaction goes through `FakeProvider`
- Every new stderr line must be free of request/response content and pass the redaction sweep
- Commit after each checkpoint; `pytest -q` and `ruff check src tests` green at every checkpoint
