# Tasks: Outcome-Quality Hardening

**Input**: Design documents from `/specs/017-outcome-quality-hardening/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: INCLUDED — constitution mandates test-first (write, watch fail, then implement).

## Format: `[ID] [P?] [Story] Description` — paths repository-relative

---

## Phase 1: Setup

- [X] T001 [P] Author spec/checklist/contracts/quickstart under specs/017-outcome-quality-hardening/ (done in Phase A)

---

## Phase 2: Foundational — reproduce before fixing (blocks US1 B3)

- [X] T002 [US1] Reproduce the pack-finding disappearance in tests/integration/test_identity_pack_coexistence.py: scan the header-identity fixture with an oracle answer that reports CWE-290 at `authenticateUser` (same weakness, same location as the deterministic rule) — assert the report shows the deterministic provenance (currently expected to FAIL by dropping evidence of the pack rule); locate the failing seam via findings/local/*.json artifacts first

---

## Phase 3: US1 — Grading integrity (P1)

**Tests (fail first)**

- [X] T003 [P] [US1] tests/unit/test_verify.py additions: format CWE-290 + no flow → verified/basis presence; under active reachability gap → plausible + gap named; heuristic CWE-290 stays on the standard trace path (contracts/verification-grades.md)
- [X] T004 [P] [US1] tests/integration/test_upgrade_resume.py: scan fixture under an older recognizer stamp → invalidated stages rebuild, wiring edges reappear; stamp equal → resume
- [X] T005 [US1] based on T002's located seam: normalization or correlation fix test asserting provenance continuity (Detection: format + identity-archetype rule id survive to the report)

**Implementation**

- [X] T006 [US1] verify.py: `PRESENCE_VALID_CWES` (+ pack members via no_refute_cwes) + `_REACHABILITY_SENSITIVE_PRESENCE {"CWE-306","CWE-290"}`; demotion rule extended (FR-001)
- [X] T007 [US1] state.py + run.py: `EXTRACTOR_VERSION` constant; build_code_graph resume key composition per contracts/resume-keys.md (FR-002)
- [X] T008 [US1] pipeline fix located by T002/T005: **no defect found** — normalization preserves provenance fields (asserted in tests/unit/test_identity_provenance.py); the observed absence traced to stale-artifact resume, fixed by T007. Pack provenance gets stronger through the FR-004 work anyway (the pack's evidence now names the matched channel token).

---

## Phase 4: US2 — Presentation integrity (P2)

**Tests (fail first)**

- [X] T009 [P] [US2] tests/unit/test_family_grouping.py: dependent links created for same-channel evidence sets; anchor = trust-decision finding; generic channel names (non-identity) never link
- [X] T010 [P] [US2] tests/unit/test_generate_report.py (new tests): Awaiting Verification batching by question; coverage notes deduped by (file, cause); npm-audit wording present-vs-absent distinction
- [X] T011 [US2] tests/integration/test_family_report.py: header-identity scan report renders anchor plus folded dependents; proven-presence wording shown for the demoted case

**Implementation**

- [X] T012 [US2] correlate_findings.py family detection + dependent links (FR-004; contracts/provenance-and-families.md)
- [X] T013 [US2] generate_report.py: anchor/dependent rendering; presence-proven wording (FR-005); awaiting batching (FR-008); coverage dedupe by (segment, cause, files) (FR-006)
- [X] T014 [US2] tooling limitation reasons for audit tools: presence-vs-excluded wording (FR-007)

---

## Phase 5: US3 — Triage batching (P2)

- [X] T015 [US3] triage_declarations.py: fan-out an answered question text across bindings of identical text; tests in tests/unit/test_triage_declarations.py for group resolve + lapse-on-drift (existing) + per-finding admission respected (edge case)

---

## Phase 6: US4 — Regression net (P3)

- [X] T016 [P] [US4] Folded by design: `grading-integrity` defect class registered in tests/benchmark/__init__.py with its expectation folded into tests/benchmark/cases/guard_hidden_trust_boundary.json and pinned via test_defect_class_grading_integrity in tests/benchmark/test_accuracy_benchmark.py (no separate case files needed — analysis F2)
- [X] T017 [US4] benchmark: upgrade-simulation covered by tests/integration/test_upgrade_resume.py (bump ⇒ rebuild; same version ⇒ resume) — per-class expectations wired via the folded case

---

## Phase 7: Polish

- [X] T018 [P] README/docs surfaces updated in the same change set (artifacts.md awaiting-verification note, security-model.md presence wording if it exists)
- [X] T019 Re-run quickstart S1–S6; full gates: `pytest -q`, `-m slow`, `ruff check src tests`
- [X] T020 Re-scan timesheet-app from a clean workspace (no prior `.secscan`) and verify SC-001 shape end to end (sanity; artifact evidence attached to the spec's Background note)

---

## Dependencies

- Phase 2 before Phase 3 (B3 diagnosis informs T008's seam)
- Phase 3 before Phase 4/5/6 (grading contract feeds rendering and batching)
- Phase 7 after everything

## Parallel opportunities

- T003/T004 parallel; T009/T010 parallel; Phase 4 vs Phase 5 & 6 independent of each other after US1

## MVP scope

US1 (grading integrity) alone releases value: the Critical reads at Critical. All stories are independent increments.
