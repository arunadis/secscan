---

description: "Task list for feature 004 implementation"
---

# Tasks: Reduce Missed Detections (False Negatives)

**Input**: Design documents from `/specs/004-reduce-missed-detections/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md,
contracts/missed-detection-contracts.md, quickstart.md

**Tests**: INCLUDED — the constitution mandates test-first ("Tests are written before
implementation and MUST fail first"); every test task must be verified failing before its
implementation task begins.

**Organization**: Tasks are grouped by user story (US1 P1, US2 P1, US3 P2, US4 P3). Every task
cites the requirement/contract/decision it discharges: FR from spec.md, D1–D5 from
`contracts/missed-detection-contracts.md`, R1–R6 from `research.md`.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1–US4)

## Path Conventions

- Single project: `src/pipeline/`, `src/skill_core/data/`, `tests/` at repository root

---

## Phase 1: Setup

**Purpose**: Verified-green starting point (feature 003 landed at 605 tests green).

- [X] T001 Run `.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests` from the repository root and confirm green before any change — 003's false-positive corpus, credential recall, and credential-precision benchmark are the mutual gate (FR-012, D5) and must stay green throughout

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The must-find corpus and its build gate that every story's fixtures feed.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T002 Create `tests/benchmark/cases/must_find.json` per `data-model.md` "Must-Find Corpus Entry" with the five evidenced misses from the reference scans: `graphql-depth-dos` and `seeded-shared-password` (scan 20260831T071644Z-c3b48b), `spring-csrf-disabled`, `spring-cors-wildcard` (WebSecurityConfig.java:38-40), and the `marked@1.1.1` ReDoS advisories — each with reference, rule_id, expected, rationale (FR-011, D5)
- [X] T003 Wire the gate in `tests/benchmark/__init__.py` and `tests/benchmark/test_accuracy_benchmark.py`: add `must_find.json` to `NON_CASE_FILES`, add a `missed-detection` defect class to `DEFECT_CLASSES`, and add `test_defect_class_missed_detection` asserting every must-find corpus entry is produced by the corresponding fixture — red until the stories land (FR-011, FR-012, D5)

**Checkpoint**: The gate exists and fails for all five entries; story implementation turns entries green one by one

---

## Phase 3: User Story 1 - Dangerous security configuration is always detected (Priority: P1) 🎯 MVP

**Goal**: `csrf().disable()`, wildcard CORS, sensitive-endpoint permitAll, and exposed dev consoles are detected deterministically — every time, regardless of redaction elsewhere in the file.

**Independent Test**: `.venv/bin/python -m pytest -q tests/unit/test_misconfig.py` — every rule fires on its must-find fixture, none on its must-not-find fixture, and a blocked value in the same file changes nothing (D1; SC-001).

### Tests for User Story 1 ⚠️ WRITE FIRST, VERIFY THEY FAIL

- [X] T010 [P] [US1] Create misconfiguration fixture sources in `tests/fixtures/misconfig_sites.py`: per-rule must-find and must-not-find pairs for the initial rule set (Spring CSRF/CORS/permitAll/console; Node wildcard CORS + credentials and cookie flags; Django DEBUG/ALLOWED_HOSTS/CORS_ALLOW_ALL/csrf_exempt; Go InsecureSkipVerify/CORS), including the WebSecurityConfig-shaped case and a variant whose security config also contains an unclassifiable high-entropy value that redaction blocks (FR-001, FR-002, D1)
- [X] T011 [P] [US1] Add failing unit tests in `tests/unit/test_misconfig.py` asserting D1: each rule fires on its must-find fixture with exact file/line, never fires on must-not-find, the blocked-value variant fires identically, no matched text appears in any finding field, and the two evidenced cases produce CWE-352/CWE-942 (FR-001, FR-002; D1)
- [X] T012 [P] [US1] Add a failing contract test in `tests/contract/test_rule_data.py` asserting rule-data integrity: unique ids, patterns compile, CWEs validate against the catalogue, every rule's fixtures exist, and adding a rule is data-only (D1)

### Implementation for User Story 1

- [X] T013 [US1] Author `src/skill_core/data/misconfig_rules.json` per `data-model.md` "Control Check" — version/dataset_date/_doc convention plus the initial rule set listed there (FR-001, FR-003; R1)
- [X] T014 [US1] Implement `src/pipeline/misconfig.py`: load-time validation (T012's contract), glob file selection over enumerated repo files, raw-text pattern evaluation emitting findings with file/line/rule id and no matched values (R1; FR-001, FR-002)
- [X] T015 [US1] Wire misconfig findings into the pipeline in `src/pipeline/run.py` after segment analysis completes (~run.py:258), appending to `raw_findings` so they flow through normalization, location resolution, verification, and calibration (R2 stage-placement precedent)
- [X] T016 [US1] Verify via `.venv/bin/python -m pytest -q tests/unit/test_misconfig.py tests/contract/test_rule_data.py tests/benchmark/test_accuracy_benchmark.py` that T011–T012 pass and the T003 gate's two misconfig entries (`spring-csrf-disabled`, `spring-cors-wildcard`) turn green; full suite stays green (FR-012, D5)

**Checkpoint**: User Story 1 complete — the CORS/CSRF miss class is closed and build-gated

---

## Phase 4: User Story 2 - Compound findings are assembled across files (Priority: P1)

**Goal**: The GraphQL depth-DoS and seed-data shared-password weaknesses — invisible to segment-local analysis — are assembled from deterministic whole-repo evidence legs, with absence claims citing the searched space.

**Independent Test**: `.venv/bin/python -m pytest -q tests/unit/test_compound.py` — both seed rules fire on their fixtures, retract when the control is present, and degrade to plausible naming the weak leg when a leg is undetermined (D2; SC-001, SC-003).

### Tests for User Story 2 ⚠️ WRITE FIRST, VERIFY THEY FAIL

- [X] T020 [P] [US2] Create compound fixtures in `tests/fixtures/compound_sites.py`: (a) cyclic `.graphql` schema + permitAll security config + no depth-limit config, (b) same with a depth-limit config present (retraction case), (c) `.sql` seed migration provisioning accounts with a documented shared password + public login endpoint, (d) a rule fixture with an unevaluatable leg (undetermined case) (FR-004, FR-005; D2)
- [X] T021 [P] [US2] Add failing unit tests in `tests/unit/test_compound.py` asserting D2: leg-level outcomes (evidenced/absent-proven/undetermined) with locations and recorded search space, both rules publish on their fixtures, config presence retracts the DoS finding, no password value appears in any artifact, and data-only rule addition works (FR-004–FR-006; D2)

### Implementation for User Story 2

- [X] T022 [US2] Enumerate GraphQL schemas: add `.graphql`/`.graphqls` to `src/pipeline/state.py` `_SOURCE_SUFFIXES` and `src/pipeline/discover_repo.py` `LANGUAGE_BY_SUFFIX`, so schema files become file-tier graph nodes and segment-assigned (R3)
- [X] T023 [US2] Implement the line-based GraphQL schema fact extractor in `src/pipeline/extract/graphql_schema.py`: type definitions, field→type references, and cycle detection over the type-reference graph — no new grammar dependency (R3)
- [X] T024 [US2] Implement `src/pipeline/compound.py`: the leg evaluator vocabulary (`endpoint-unauthenticated`, `graphql-schema-cycle`, `config-absent`, `seeded-credential-pattern`, `public-auth-entrypoint` per `data-model.md`) and the rule engine evaluating rules to findings with per-leg states (R2, R6; FR-004–FR-006)
- [X] T025 [US2] Author `src/skill_core/data/compound_rules.json` with the two seed rules (`graphql-depth-dos` CWE-400, `seeded-shared-password` CWE-1391) per `data-model.md`, including the `config-absent` leg's declared search space (R2; FR-005)
- [X] T026 [US2] Wire the compound stage into `src/pipeline/run.py` after segment analysis completes (~run.py:258), before dependency audits, appending to `raw_findings` (R2)
- [X] T027 [US2] Verify via `.venv/bin/python -m pytest -q tests/unit/test_compound.py tests/benchmark/test_accuracy_benchmark.py` that T021 passes and the T003 gate's `graphql-depth-dos` and `seeded-shared-password` entries turn green; full suite stays green (FR-012, D5)

**Checkpoint**: User Story 2 complete — both evidenced compound misses are closed and build-gated

---

## Phase 5: User Story 3 - Known-vulnerable dependencies are first-class findings (Priority: P2)

**Goal**: Every supported ecosystem matches pinned dependencies against bundled advisory snapshots — offline — and each vulnerable package is its own finding with advisory ids, range, and location.

**Independent Test**: `.venv/bin/python -m pytest -q tests/unit/test_advisories.py` — per-ecosystem fixtures (incl. `marked@1.1.1`) produce distinct findings; fixed versions silent; stale snapshot reads could-not-check; no native tool invoked (D3; SC-004).

### Tests for User Story 3 ⚠️ WRITE FIRST, VERIFY THEY FAIL

- [X] T030 [P] [US3] Create per-ecosystem dependency fixtures in `tests/fixtures/advisory_sites.py`: manifests + lockfiles pinning vulnerable and fixed versions for npm (marked@1.1.1 ReDoS), maven, pypi, and go, plus a two-vulnerable-packages-one-manifest case (dedupe regression) and a stale-snapshot case (FR-007, FR-008; D3)
- [X] T031 [P] [US3] Add failing unit tests in `tests/unit/test_advisories.py` asserting D3: range matching (introduced/fixed/affected_range), one finding per vulnerable package with `location.symbol` set, advisory ids/range/manifest location in the finding (and lockfile location cited where the pin comes from a lockfile), offline-only baseline (assert no subprocess), staleness → could-not-check never clean (FR-007, FR-008; D3)

### Implementation for User Story 3

- [X] T032 [US3] Author curated advisory snapshots `src/skill_core/data/advisories/npm.json`, `maven.json`, `pypi.json`, `go.json` per `data-model.md` "Dependency Advisory snapshot" — covering the reference repositories' dependency trees (at minimum the marked ReDoS advisories) plus fixture needs, with version/dataset_date/source/staleness_threshold_days and refresh notes mirroring the eol.json convention (R4; FR-007, FR-008)
- [X] T033 [US3] Implement deterministic manifest/lockfile version extraction in `src/pipeline/audits/offline.py`: Component Instances (package, version, ecosystem, manifest path, exposure) for all four ecosystems without invoking native tools (R4)
- [X] T034 [US3] Implement the bundled-snapshot matcher and staleness handling in `src/pipeline/audits/offline.py`, producing Advisory objects compatible with `audits/__init__.py:100-172` `to_findings`, and wire it as the always-on baseline in `src/pipeline/ingest_findings.py` with native-tool audits remaining as augmentation (R4; FR-007, FR-008)
- [X] T035 [US3] Fix the dedupe collapse in `src/pipeline/audits/__init__.py`: dependency findings carry `location.symbol = <package>` so distinct vulnerable packages in one manifest remain distinct findings (D3)
- [X] T036 [US3] Verify via `.venv/bin/python -m pytest -q tests/unit/test_advisories.py tests/benchmark/test_accuracy_benchmark.py` that T031 passes and the T003 gate's `marked` advisory entry turns green; full suite stays green (FR-012, D5)

**Checkpoint**: User Story 3 complete — dependency CVEs are first-class, offline, per-package findings

---

## Phase 6: User Story 4 - Coverage gaps can never hide a finding silently (Priority: P3)

**Goal**: Every blocked value and budget-dropped file produces a structured, security-impact-assessed gap record, with security-critical gaps ranked first in the report.

**Independent Test**: `.venv/bin/python -m pytest -q tests/unit/test_coverage_gaps.py` — a fixture with a blocked value in a security-config file yields a critical `gap_details` record with concrete impact, rendered first; audit outcomes render in Markdown (D4; SC-006).

### Tests for User Story 4 ⚠️ WRITE FIRST, VERIFY THEY FAIL

- [X] T040 [P] [US4] Add failing unit tests in `tests/unit/test_coverage_gaps.py` asserting D4: gap_details records carry cause/file/segment/security_critical/impact, criticality classification follows the data-driven conventions, Markdown renders critical gaps first plus audit outcomes/blocking gaps, and the legacy `coverage.gaps` strings are unchanged (FR-009, FR-010; D4)
- [X] T041 [P] [US4] Add a failing contract test in `tests/contract/test_rule_data.py` (created by T012) asserting the report schema accepts `gap_details` additively and existing report fixtures still validate (D4)

### Implementation for User Story 4

- [X] T042 [US4] Thread structured gap records through `src/pipeline/build_context.py`: replace/augment warning strings with records carrying cause (`blocked-value` | `budget-dropped` | `unparsed-format`), file, and segment id (R5)
- [X] T043 [US4] Implement criticality classification and impact rendering in `src/pipeline/generate_report.py`: additive `coverage.gap_details` in the JSON report, security-critical gaps first in Markdown, and render `audit_outcomes`/`blocking_gaps` (R5; FR-010)
- [X] T044 [US4] Add the additive `gap_details` definition to `src/skill_core/schemas/report.json` per `data-model.md` "Coverage Gap Detail" (R5)
- [X] T045 [US4] Verify via `.venv/bin/python -m pytest -q tests/unit/test_coverage_gaps.py tests/contract` that T040–T041 pass; full suite stays green (FR-012, D5)

**Checkpoint**: User Story 4 complete — coverage section is an actionable, ranked work list

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Full-gate verification across all stories

- [X] T050 Run `.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests` from the repository root — all green, including all of feature 003's suites (FR-012, D5)
- [X] T051 [P] Run the two-run byte-identical artifact comparison over a fixture scan exercising all four new stages (constitution Safety Invariant; Principle I)
- [X] T052 [P] Review `README.md` status claims and update for the shipped capabilities (misconfiguration rules, compound findings, offline advisories, structured coverage gaps) per the honest-documentation gate
- [X] T053 Execute every scenario in `quickstart.md` end-to-end and confirm each expected outcome (SC-001 through SC-006)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately
- **Foundational (Phase 2)**: Depends on T001 — BLOCKS all user stories
- **US1 (Phase 3)**, **US2 (Phase 4)**, **US3 (Phase 5)**, **US4 (Phase 6)**: each depends on Phase 2 only
- **Polish (Phase 7)**: Depends on all completed stories

### User Story Dependencies

- **US1 (P1)**: No story dependencies — MVP
- **US2 (P1)**: No story dependencies — its `endpoint-unauthenticated` leg reads security-config raw text directly; it may *reuse* US1's glob-scanning helper if US1 lands first, but must not require it
- **US3 (P2)**: No story dependencies
- **US4 (P3)**: No story dependencies; its criticality classification reuses the misconfig file-glob conventions as data if US1 exists, with a standalone fallback

### Within Each User Story

- Fixtures and failing tests before implementation; verify each test fails for the intended reason
- Data files before the evaluators that load them
- The story's must-find corpus entries turn green at the story's verification task
- Recall/precision mutual gate (003 suites) green at every checkpoint

### Parallel Opportunities

- T010 ∥ T011 ∥ T012 (fixtures, unit tests, contract test — different files)
- T020 ∥ T021; T030 ∥ T031; T040 ∥ T041
- US1 ∥ US2 ∥ US3 ∥ US4 as whole stories if staffed (disjoint new modules; shared files are run.py wiring points — sequence those)
- T051 ∥ T052 in Polish

---

## Parallel Example: User Story 1

```bash
# Launch fixtures + failing tests together:
Task: "Create misconfiguration fixture sources in tests/fixtures/misconfig_sites.py"  # T010
Task: "Add failing unit tests in tests/unit/test_misconfig.py"                        # T011
Task: "Add a failing contract test in tests/contract/test_rule_data.py"               # T012

# Then T013 (data) → T014 (evaluator) → T015 (wiring) → T016 (verify)
```

## Parallel Example: User Story 3

```bash
# Launch fixtures + failing tests together:
Task: "Create per-ecosystem dependency fixtures in tests/fixtures/advisory_sites.py"  # T030
Task: "Add failing unit tests in tests/unit/test_advisories.py"                       # T031

# Then T032 (snapshots) → T033 (extraction) → T034 (matcher+wiring) → T035 (dedupe) → T036
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 (T001) + Phase 2 (T002–T003)
2. Complete Phase 3 (T010–T016)
3. **STOP and VALIDATE**: `test_misconfig.py` green; the two config-misconfig corpus entries green; 003 suites green
4. Demoable: the both-scanners-missed CORS/CSRF class is closed

### Incremental Delivery

1. Setup + Foundational → must-find gate red on five entries
2. US1 → config checks → validate → deliver (MVP)
3. US2 → compound findings → validate → deliver
4. US3 → offline advisories → validate → deliver
5. US4 → structured coverage gaps → validate → deliver

---

## Notes

- [P] tasks = different files, no dependencies on incomplete tasks
- [USn] label maps each task to its spec user story for traceability
- Tests MUST fail before implementation; verify the failure is for the intended reason
- Honest uncertainty is non-negotiable: undetermined legs and stale advisory data are recorded third states, never silence and never inflation
- The feature-003 suites are the standing mutual gate; run them at every checkpoint
- Commit after each task or logical group; stop at any checkpoint to validate the story independently
