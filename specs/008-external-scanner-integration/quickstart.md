# Quickstart: Validating External Scanner Tooling Integration

Runnable end-to-end validation for feature 008. Each scenario maps to acceptance scenarios in [spec.md](spec.md) and is exercised by an automated test (`tests/integration/test_tooling_*.py`, `tests/contract/test_tooling_*.py`, `tests/benchmark/test_external_tooling.py`); the commands below are the manual path. Fixtures live under `tests/fixtures/tooling_workspace/` and recorded tool output under `tests/fixtures/tooling_workspace/recorded/` so validation is fully offline and deterministic.

## Prerequisites

- Repo venv active; `pytest` runnable (`pip install -e .` if needed)
- No external security tools required — scenarios fake tool availability via `PATH` shims and recorded-output executables, which is exactly how tests exercise provisioning/execution without network

## Scenario 1 — Init detects ecosystems and offers only applicable tools (US1, SC-001)

```bash
python -m pipeline.init_cmd --workdir tests/fixtures/tooling_workspace/multi_eco   # Node manifest + Maven pom
```

**Expect**: applicable tool list covers npm-audit, osv-scanner, and OWASP Dependency-Check entries; no pypi/go tools offered; each tool shows source (project-provided / system-installed / missing) and network requirement; exit 0.

## Scenario 2 — Project-provided tools are used directly, never reinstalled (US1, FR-003a, SC-007)

```bash
python -m pipeline.init_cmd --workdir tests/fixtures/tooling_workspace/project_provided  # pom.xml declares org.owasp:dependency-check-maven
```

**Expect**: OWASP Dependency-Check reported `project-provided` with wrapper invocation `./mvnw ...`; it does not appear on the install list; no prompt nor installation occurs for it.

## Scenario 3 — Install list confirmed before anything installs; selective deselection (US1, FR-003)

```bash
python -m pipeline.init_cmd --workdir tests/fixtures/tooling_workspace/multi_eco --no-input
printf 'deselect osv-scanner, confirm rest\n' | python -m pipeline.init_cmd --workdir tests/fixtures/tooling_workspace/multi_eco
python -m pipeline.init_cmd --workdir tests/fixtures/tooling_workspace/multi_eco --install=npm-audit
```

**Expect**: `--no-input` prints the exact list and installs nothing, declaring skips; interactive run installs only the confirmed subset via the provision shim, deselected tool reported skipped; flag form installs only the named tool. Project manifests/lockfiles byte-identical before/after every run.

## Scenario 4 — Tool run + normalize + dedupe into merged report (US2, FR-005/006)

```bash
python -m pipeline.scan_cli --workdir tests/fixtures/tooling_workspace/vuln_dep  # PATH includes recorded-output npm/osv shims
```

**Expect**: seeded advisory beyond the bundled snapshot appears exactly once in the report with `sources` recording every contributor; `tooling/runs.json` shows `status: ran`, `read_only_guard: passed`; coverage-limitation section names each tool not available.

## Scenario 5 — Cross-check suppression and retained unknowns (US3, FR-007/008, SC-004)

```bash
python -m pipeline.scan_cli --workdir tests/fixtures/tooling_workspace/crosscheck  # recorded report: absent package, mismatched version, unresolvable location, reachable-true finding
```

**Expect**: absent-package, version-mismatch, and unresolvable-location findings land only in `tooling/suppressions.json` with grounds and evidence; the true finding survives; a reachability-only-doubt finding is retained as `undetermined`; suppression section renders count + reasons.

## Scenario 6 — Zero-tool fallback and failing-tool resilience (FR-010, SC-005/006)

```bash
env -i PATH=/usr/bin:/bin python -m pipeline.scan_cli --workdir tests/fixtures/tooling_workspace/vuln_dep
python -m pipeline.scan_cli --workdir tests/fixtures/tooling_workspace/crash_tool  # shim exits 137 / emits garbage
```

**Expect**: first run matches today's findings output with every external contribution declared as a limitation; second run completes with a full report, `status: failed` + reason in `runs.json`, and zero partial merges.

## Gates

- `pytest tests/integration/test_tooling_*.py tests/contract/test_tool_registry.py` — feature scenarios above
- `pytest` (full) — no regressions; benchmark gates per FR-013
- `ruff check src tests` clean
- Two identical `scan_cli` runs over `crosscheck` fixture produce byte-identical artifacts (Principle I invariant test)
