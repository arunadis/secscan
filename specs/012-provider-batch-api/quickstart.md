# Quickstart: Validating Provider Batch API Execution

**Feature**: 012-provider-batch-api

Every scenario below runs without a network: the fake provider in
`tests/helpers/fake_provider.py` implements both wire shapes
([contracts/provider-batch-adapters.md](contracts/provider-batch-adapters.md)) and is injected
through `run_scan(transport=…)`. Wall-clock waits are removed by injecting `clock`/`sleep`.

## Prerequisites

```bash
uv venv --python 3.11 && uv pip install -e ".[dev]" && source .venv/bin/activate
pytest -q                       # baseline must be green before starting
```

## Scenario A — Large repository analysed in batch (US1, SC-001, SC-003)

```bash
pytest -q tests/integration/test_batch_scan.py -k "happy_path"
```

Expected: fixture with N segments and an endpoint config (`mode: auto`) → the fake provider
records exactly one `POST …/batches` (or `files`+`batches` for OpenAI) per escalation round,
zero interactive calls, `batch_submitted`/`batch_status`/`batch_done` lines on stderr, and
`usage.json.batch_share.batch_invocations == total invocations`, `estimated_saving_percent ==
50.0`. Findings artifacts equal those from the same fixture run with `--policy interactive`.

Manual (real provider, optional): in a project with `llm.endpoint` configured and the key
exported, `secscan run --full` → header shows `mode=endpoint-batch (default policy)`; a status line
updates at least every 5 minutes; the report's usage section shows the batch share.

## Scenario B — Partial failure, expiry, resume (US2, SC-004, SC-005)

```bash
pytest -q tests/integration/test_batch_scan.py -k "partial or expiry or resume or stale_handle"
```

Expected:
- `partial`: provider scripted to `errored` 3 items and omit 1 → exactly those 4 appear in
  `fallback_log` with reasons `errored: …` / `missing from results`; every segment has one
  answer; 4 interactive calls recorded.
- `expiry`: injected clock jumps past `window_hours` → all outstanding items fall back with
  reason `expired`; scan finishes.
- `resume`: `KeyboardInterrupt` injected on the second poll → exit 130, ledger has status
  `in_progress`; second `run_scan` on the same root → **zero** new submissions, polls the same
  handle, completes; answers directory identical to a straight run.
- `stale_handle`: provider returns 404 on status → all items fall back with reason
  `batch reference not found`; no traceback.

## Scenario C — Interactive rate limits (US3, SC-006, SC-007)

```bash
pytest -q tests/integration/test_batch_scan.py -k "rate_limit"
pytest -q tests/unit/test_retry_policy.py
```

Expected:
- `[429 retry-after=7, 429, 200]` → two `warning` lines `rate limited (HTTP 429), attempt n/5,
  waiting …s` (first wait ≥ 7 s via the injected clock), one recorded invocation.
- All-429 → `EndpointError` after exactly 5 attempts; `cmd_run` exit code 1; stderr's last
  lines name `segment_analysis`, the request id, `HTTP 429`, `5 attempts`, and `re-run to
  resume`; no `Traceback` substring; `state.json` marks the stage failed; a second run
  re-requests only the failed segment onward (answers for earlier segments reused).
- 401 → no retry (`attempts == 1`), exit 1.

## Scenario D — Gateway without batch support (FR-010)

```bash
pytest -q tests/integration/test_batch_scan.py -k "unsupported"
```

Expected: first `POST …/batches` → 501; one warning + one coverage note with the exact
contract wording; the whole stage runs interactively; no further batch submission in the scan;
`batch_share.batch_invocations == 0`, `fallbacks == 1`.

## Scenario E — Configuration and defaults (FR-023, FR-009, FR-019)

```bash
pytest -q tests/unit/test_config_execution_policy.py
secscan init --no-input       # in a scratch dir: template shows `mode: auto`
```

Expected: the resolution table in
[contracts/batch-execution.md §1](contracts/batch-execution.md) holds row by row; conflicts
are reported together; `window_hours: 0` and `retry.attempts: 0` are rejected;
`SECSCAN_EXECUTION_POLICY_BATCH_WINDOW_HOURS=1` overrides the file value.

## Scenario F — Safety invariants

```bash
pytest -q tests/integration/test_determinism.py          # includes batch-policy run
pytest -q tests/contract/test_artifact_redaction.py      # sweep covers analysis/answers/**
pytest -q tests/contract/test_schemas.py -k usage
pytest -q -m slow                                        # scale scan still within budgets
ruff check src tests
```

Expected: two batch-policy runs are byte-identical across `.secscan/**/*.json` (minus
`state.json`); no seeded secret appears in any answer file or ledger; the additive `usage`
schema fields validate.

## Documentation check (constitution: documentation currency)

`docs/configuration.md`, `docs/cli-reference.md`, `docs/artifacts.md`,
`docs/getting-started.md`, `README.md`, `src/skill_core/SKILL.md` describe: `mode: auto`
default and its backward-compatibility note, `window_hours`, `llm.retry`, waiting/Ctrl-C/resume
behaviour, the answers directory, and the saving formula with its assumption. No sentence
claims a discount the scan does not obtain.
