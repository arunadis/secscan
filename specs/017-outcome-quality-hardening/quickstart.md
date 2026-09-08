# Quickstart — validating Outcome-Quality Hardening (feature 017)

Prereqs per AGENTS.md (venv + `pytest`, `ruff`).

## S1 — grading contract (FR-001/FR-005)

```bash
pytest -q tests/unit/test_verify.py tests/unit/test_report_grading.py
```
- format CWE-290 + no flow ⇒ `verified` `basis: presence`; same case under active
  gap ⇒ `plausible` with named gap.
- The plausible presence block renders "Weakness proven at this location; exposure
  path unconfirmed".

## S2 — resume-version integrity (FR-002)

```bash
pytest -q tests/integration/test_upgrade_resume.py
```
- artifial stale recognizer stamp ⇒ `build_code_graph` rebuilds; current stamp ⇒
  resume/reuse.

## S3 — deterministic provenance (FR-003)

```bash
pytest -q tests/integration/test_identity_pack_coexistence.py
```
- pack + oracle-model finding at one trust point ⇒ deterministic rule's provenance
  is visible (Detection: format + rule id).

## S4 — family grouping + question batching (FR-004/FR-008)

```bash
pytest -q tests/unit/test_family_grouping.py tests/unit/test_awaiting_batches.py
pytest -q tests/integration/test_family_report.py
```
- header-identity findings render with anchor + dependents; one Awaiting entry per
  distinct question; one declaration resolves the group.

## S5 — report hygiene (FR-006/FR-007)

```bash
pytest -q tests/unit/test_generate_report.py::test_budget_drops_deduped_by_file
```
- doubled budget-drop note collapses; npm-audit wording names exclusion vs absence.

## S6 — full gates

```bash
pytest -q && pytest -q -m slow && ruff check src tests
```
- Full suite green, slow scale scan green, lint clean.
