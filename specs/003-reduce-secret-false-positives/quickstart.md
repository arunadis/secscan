# Quickstart: Validate Reduced Credential False Positives

Prerequisites: repo checkout with the feature branch; the pinned tool environment
(`uv tool run secscan` / the project's existing pytest setup). All commands run from the
repository root.

## Scenario 1 — Identifier FPs are gone, recall intact (US1, FR-001–FR-007)

```bash
pytest -q tests/unit/test_redact.py -k "identifier or message or recall"
```

**Expected**: green. The credential-word identifier fixtures (SEC-0085 class:
`openaiModelInputTokenCostGpt51ChatLatest`-style declarations) produce no hits; every seeded
credential in `tests/fixtures/credential_corpus.py` — including a readable passphrase assigned
to a password variable — is still detected. See contracts C1–C3.

## Scenario 2 — Heuristic findings are honestly graded (US2, FR-008–FR-010)

```bash
pytest -q tests/unit/test_secret_findings.py tests/unit/test_verify.py -k "provenance or confidence or test_code or heuristic"
```

**Expected**: green. Format-matched findings keep 0.95-class confidence and auto-verification;
heuristic findings carry lower confidence, never `verified`; a seeded credential under a test
path (e.g. `src/test/...`) is reported at reduced confidence with the test-code context named in
its description. See contract C4.

## Scenario 3 — False-positive corpus is silent (US3, FR-011)

```bash
pytest -q tests/unit -k "false_positive_corpus"
```

**Expected**: green — zero credential findings across the entire corpus (identifiers with
credential words, UI message constants, import specifiers, module paths), with every suppression
recorded as an inspectable Detection Decision.

## Scenario 4 — Benchmark gate and audited baseline (FR-012, SC-001–SC-003)

```bash
pytest -q tests/benchmark/test_accuracy_benchmark.py -k "credential"
```

**Expected**: green. The credential-precision defect class passes; the audited baseline labels
for scan `20260831T081536Z-438706` assert entry-by-entry that confirmed false positives
(SEC-0085, SEC-0091, SEC-0092, SEC-0093 class) are no longer reported and confirmed true
positives (SEC-0076, SEC-0084 class) still are — the measured realization of SC-003's
"≥80% FP reduction, zero TP lost".

## Scenario 5 — End-to-end scan over the reference fixture

```bash
pytest -q tests/integration -k "credential"
```

**Expected**: green. A full scan over the reference fixture workspace publishes only
format-confirmed and genuinely ambiguous credential findings; suppression decisions appear in
the scan artifacts with file, line, rule, and reason (FR-004); no artifact contains a credential
value (existing redaction sweep, contract C5).

## Full gate (pre-merge)

```bash
pytest -q && ruff check src tests
```

**Expected**: green; no reduction in credential-detection recall across any suite (constitution
gate).
