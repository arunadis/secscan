# Quickstart: Validate Missed-Detection Reduction

Prerequisites: repository checkout with the feature work; the pinned tool environment
(`.venv/bin/python -m pytest`). All commands run from the repository root.

## Scenario 1 — Misconfiguration rules fire (US1, D1)

```bash
.venv/bin/python -m pytest -q tests/unit/test_misconfig.py
```

**Expected**: green. A Spring fixture with `csrf().disable()` and `allowedOrigins("*")`
produces CWE-352 and CWE-942 findings at exact lines — including the variant where the same
file has a redaction-blocked value elsewhere. Every rule's must-find and must-not-find fixtures
pass. See contract D1.

## Scenario 2 — Compound findings assemble across files (US2, D2)

```bash
.venv/bin/python -m pytest -q tests/unit/test_compound.py
```

**Expected**: green. The GraphQL fixture (permitAll endpoint + cyclic schema + no depth-limit
config) publishes a plausible-or-better CWE-400 finding citing all three legs and the searched
config space; adding a depth-limit config retracts it. The seed-data fixture (migration +
public login) publishes the shared-password finding with no password value in any artifact.
A rule with an undetermined leg publishes as plausible naming that leg.

## Scenario 3 — Dependency advisories as first-class findings (US3, D3)

```bash
.venv/bin/python -m pytest -q tests/unit/test_advisories.py tests/contract -k "advisory or advisories"
```

**Expected**: green. Each ecosystem fixture (npm/maven/pypi/go) pinning a known-vulnerable
version — including `marked@1.1.1` — produces a distinct finding per package with advisory ids,
affected range, and manifest location; fixed versions stay silent; a stale snapshot reads as
could-not-check, never clean. Fully offline (no native tool invoked).

## Scenario 4 — Coverage gaps are structured and ranked (US4, D4)

```bash
.venv/bin/python -m pytest -q tests/unit/test_coverage_gaps.py tests/integration -k "coverage"
```

**Expected**: green. A fixture engineered to force a blocked value inside a security-config
file yields a `gap_details` record with cause, security-critical flag, and concrete impact,
rendered first in the Markdown coverage section; audit outcomes and blocking gaps render too.

## Scenario 5 — End-to-end reference scan (SC-001)

```bash
.venv/bin/python -m pytest -q tests/benchmark/test_accuracy_benchmark.py::test_defect_class_missed_detection
```

**Expected**: green. A full scan over each must-find fixture workspace publishes all five
previously missed issue classes (GraphQL depth DoS, seed-data password, CORS wildcard, CSRF
disablement, marked ReDoS advisories), alongside — not instead of — the findings already
detected before this feature.

## Scenario 6 — Mutual gate with feature 003 (D5, FR-012)

```bash
.venv/bin/python -m pytest -q tests/benchmark -k "credential or must_find"
```

**Expected**: green. The must-find corpus (004 recall) and the credential-precision /
false-positive corpus (003 precision) pass in the same run — neither can regress the other.

## Full gate (pre-merge)

```bash
.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests
```

**Expected**: green; two-run byte-identical determinism unchanged; artifact redaction sweep
passes over all new artifacts (constitution gates).
