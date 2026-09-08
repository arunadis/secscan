# Quickstart — validating Flow & Graph Completeness (feature 016)

Prerequisites: repo dev environment per `AGENTS.md`
(`uv venv --python 3.11 && uv pip install -e ".[dev]"`).

Every scenario is deterministic validation; scenario 1 additionally runs the
segment-analysis round in agent-mediated mode (or with the test oracle).

## Scenario 1 — the original miss (CWE-290 middleware finding)

Reference fixture (new): `tests/fixtures/workspaces/header-identity-app/` —
Express-style service mirroring the timesheet-app shape: `router.use(authenticateUser)`
in route modules, `firebase`-free sqlite-style `db.get/db.run` calls, identity read
from `req.headers['x-user-email']`. Ground truth declares:
- one finding anchored at the middleware trust function (CWE-290, Critical/High),
- deliberate safe patterns (a JWT-verifying guard, a route module matching
  siblings) that MUST NOT be reported.

Validate:

```bash
pytest -q tests/integration/test_header_identity_fixture.py
```

Expected: pipeline finds the anchor finding; verification shows `basis: "traced"`
when the wiring edges connect entry point → guard → datastore (the strong case),
otherwise `basis: "presence"`;
safe patterns stay unreported; the report contains no reachability gap for this
fixture (wiring edges connect entry point → guard → datastore).

## Scenario 2 — degraded-substrate declaration (FR-007/FR-008/FR-009)

Fixture with endpoints and data access written in idioms no recognizer knows (e.g.
an invented `store.fetch(...)` driver). Validate:

```bash
pytest -q tests/integration/test_reachability_gap.py
```

Expected: report Coverage contains the reachability declaration with counts; the
executive summary splits verified counts into traced vs presence; CWE-306 findings
in that run are `plausible` with the named gap; no claim of a complete path is made
for presence-confirmed findings.

## Scenario 3 — self-refutation gate (FR-020)

Unit suite:

```bash
pytest -q tests/unit/test_verify.py tests/unit/test_triage_apply.py
```

Expected: implicated guard cannot disprove at the verify gate; a triage
`refuted`/`downgraded` verdict citing implicated locations is rejected as untriaged;
an independent control on the path still refutes.

## Scenario 4 — subdivision keeps reachability context (FR-011/FR-012)

Fixture forcing subdivision with alphabetically-first `__tests__`:

```bash
pytest -q tests/unit/test_partition_repo.py
```

Expected: every part's packet carries the module route enumeration; production files
precede test files in part ordering; test-only endpoints are marked test-scoped.

## Scenario 5 — determinism + safety invariants

```bash
pytest -q tests/integration/test_determinism.py  # two-run byte-identical artifacts
pytest -q                                         # full suite
ruff check src tests                              # lint gate
```

Expected: byte-identical artifacts across two runs of the header-identity fixture —
including the reachability-gap declaration when it fires; full suite green.

## Benchmark gate (FR-018)

```bash
pytest -q tests/benchmark/  # accuracy benchmark incl. the new defect class
```

Expected: the new defect class asserted per class; zero regression in existing
classes; zero reports against the fixture's deliberate safe patterns.
