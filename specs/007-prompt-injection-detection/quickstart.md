# Quickstart: Prompt Injection Detection — Validation Guide

**Feature**: `007-prompt-injection-detection` | **Date**: 2026-09-01

Runnable scenarios proving the feature end-to-end. Implementation detail lives in `tasks.md`; see [contracts/data-contracts.md](contracts/data-contracts.md) for data/schema shapes and [data-model.md](data-model.md) for entity semantics.

## Prerequisites

- Python 3.11+, repo deps installed (`uv pip install -e .` per README), `pytest` and `ruff` available.
- A model credential available only by environment-variable reference (existing scan requirement), for the LLM-analysis scenarios. Deterministic scenarios (3–5) require no model.

## Scenario 1 — Direct prompt injection detected (SC-001)

1. Fixture repo: a chat handler concatenates request body into the system prompt and calls an SDK chat completion.
2. Run: `secscan scan tests/fixtures/llm_workspace --profile quick` (from repo root, with fixture path per tasks.md).
3. **Expect**: a finding with `cwe: CWE-1427`, `verification.status: verified` or `plausible`, evidence naming the untrusted source, prompt assembly, and model call; report appears in JSON/Markdown/HTML.

## Scenario 2 — Safe structured prompts produce nothing (SC-002)

1. Fixture repo: fixed system prompt; user input passes only as a separate user-turn message (no path into instruction text).
2. Run the scan.
3. **Expect**: zero prompt-injection findings; the scan still lists the LLM integration in artifacts (recognition without a finding).

## Scenario 3 — Indirect injection exposure (deterministic visible parts; SC-001)

1. Fixture repo: fetches a third-party document and inserts its text into model context; the model declaration grants tool access.
2. Run the scan.
3. **Expect**: a CWE-1427 finding categorized indirect, evidence names the ingestion point and reachable capability; a fixture with demonstrated boundary labeling yields no finding or an explicit `mitigation.state: demonstrated`.

## Scenario 4 — Over-privileged agent config flagged (deterministic; SC-006)

1. Fixture repo ships an `mcp.json` granting a shell tool with arbitrary args and no approval field, and an agent rule file granting unrestricted write with auto-approve.
2. Run the scan (offline ok).
3. **Expect**: `findings/agent_config.json` exists; report contains CWE-250 findings citing each artifact and granted capability; the scoped-counterpart fixture produces none.

## Scenario 5 — Supply-chain exposure (deterministic; SC-008)

1. Fixture repo: `package.json` with an internal-namespace dependency, no lockfile, no registry pinning; plus a `latest`-style mutable reference.
2. Run the scan (offline ok).
3. **Expect**: `findings/supply_chain.json` exists; CWE-829 finding with `guard state: undetermined`; CWE-494 finding for the mutable reference. Hardened counterpart (committed lockfile + `.npmrc` private registry) produces zero findings.

## Scenario 6 — Undetermined posture, honestly declared (Principle V; FR-001)

1. Fixture repo: brokered/queue-triggered inference (no recognized integration pattern).
2. Run the scan.
3. **Expect**: no false finding; report/artifacts record the undetermined integration posture for the call site — silent absence is a defect.

## Scenario 7 — Redaction and determinism invariants (SC-005, SC-006)

1. Fixture: prompt artifact embeds a credential.
2. Run the scan twice over identical input.
3. **Expect**: embedded-secret finding reported; the credential value appears in **no** artifact (sweep enforced, HTML included); both runs produce byte-identical artifacts.

## Scenario 8 — Benchmark gate (SC-001, SC-002, SC-008)

1. Run: `pytest tests/benchmark -q`.
2. **Expect**: new `llm-detection` and `supply-chain-detection` defect classes pass per-class assertions (including must-not-report fixtures); no regressions in existing classes.

## Full gate

`pytest` green; `ruff check src tests` clean; contract tests pass for every schema; benchmark non-regression holds.
