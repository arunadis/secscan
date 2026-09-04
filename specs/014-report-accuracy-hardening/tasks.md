# Tasks: Report Accuracy Hardening

**Input**: Design documents from `/specs/014-report-accuracy-hardening/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: INCLUDED — the constitution mandates test-first ("Tests are written before implementation and MUST fail first", accuracy regressions release-blocking). Every story ships with benchmark ground truth.

**Organization**: Tasks grouped by user story; US1 is the MVP.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story (US1–US4 from spec.md)
- Exact file paths in every task

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Scaffold the new versioned data file and benchmark harness slots all stories draw from.

- [X] T001 Create `src/skill_core/data/usage_patterns.json` v1 (npm ecosystem: module↔package mapping incl. scoped packages and python dist≠module names, config-file reference rules for bundler aliases/plugin lists, dynamic-import literal forms for js/ts/python, and `dev_markers` path patterns per ecosystem classifying test/build-only sources for the `role` field — see data-model.md §6) with load-time validation following the `framework_controls.json` pattern in `src/pipeline/controls.py:35-52`; go/maven mappings intentionally absent in v1 — their ecosystems evaluate as `undetermined` until mapped (spec Assumptions)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Persist imports into the code graph — the sole shared substrate for
US1's usage pass and any future evidence passes. No story work may start first.

- [X] T002 [P] Contract test: `code_graph.json` schema accepts optional sorted `imports` array on `type:"file"` nodes and rejects non-string/empty entries in `tests/contract/test_schemas.py`
- [X] T003 [P] Determinism test: graph with imports byte-identical across two runs in `tests/integration/test_determinism.py` (extended the existing two-run suite — test_graph_persists_imports_deterministically)
- [ ] T004 Populate `FileFacts.imports` onto file nodes in `src/pipeline/build_code_graph.py` (add `imports=facts.imports` to `add_file`, mirroring the existing `annotations` propagation) and add the additive `imports` property to `src/skill_core/schemas/code_graph.json`; absent (not empty) when the file had no parser

**Checkpoint**: Graph nodes carry imports; T002/T003 green. Stories may begin.

---

## Phase 3: User Story 1 - Dependency findings state their usage evidence (Priority: P1) 🎯 MVP

**Goal**: Every dependency/currency finding carries a three-state `usage` block; every misconfig finding carries a three-state `integration` block; none-found/none-integrated never suppress, undetermined never inflates, severity never adjusted (FR-001–004).

**Independent Test**: quickstart.md Scenarios 1–2 — fixtures: vulnerable package with zero imports; permissive `database.rules.json` with no Firebase SDK. Findings retained, states declared, confidence capped, removal-first remediation.

### Tests for User Story 1 ⚠️ WRITE FIRST, MUST FAIL

- [X] T005 [P] [US1] Unit tests for the usage pass (found with sorted locations and runtime/development role; none-found gating on completed detection forms; undetermined with reason for unparseable manifests/unmapped module names/unattributable dynamic forms; severity untouched) in `tests/unit/test_usage_evidence.py`
- [X] T006 [P] [US1] Benchmark case `tests/benchmark/cases/usage_none_found.json` + fixture builder in `tests/fixtures/` asserting: finding retained, `usage.state=="none-found"`, confidence ≤ 0.5, no exploitation narrative asserted as fact — plus found-variant and undetermined-variant assertions; ALSO add a cross-fixture invariant assertion (SC-002): every dependency/currency finding in every benchmark fixture carries a `usage` block with a valid state
- [X] T007 [P] [US1] Unit tests for misconfig integration states (integrated with evidence; no-integration-found; undetermined for marker-less rule classes) in `tests/unit/test_misconfig_integration.py`
- [X] T008 [P] [US1] Integration test: end-to-end scan of the stale-Firebase-rules fixture yields `integration.state=="no-integration-found"` and removal-led remediation in `tests/integration/test_integration_evidence.py`

### Implementation for User Story 1

- [X] T009 [US1] Dynamic-import and config-reference capture driven by `usage_patterns.json` rules — implemented inside `src/pipeline/usage_evidence.py` (raw-text per rule kind; literal-only dynamic forms, unattributable forms flag undetermined) rather than the tree-sitter extractor: same data-driven contract, no extractor changes needed
- [X] T010 [US1] Implement `src/pipeline/usage_evidence.py`: per `(member, package)` three-state detection over graph `imports`, config rules, and dynamic forms; emits sorted `locations` with `kind` (import|config|dynamic) and `role` (runtime|development); `none-found` only when all applicable forms completed; depends on T001, T004, T009
- [X] T011 [US1] Wire the usage pass into `src/pipeline/correlate_findings.py` `finalize()` after `resolve_and_dedupe`, before `calibrate.apply_calibration`; apply the existing `UNCONFIRMED_CONFIDENCE_CEILING` and conditional impact narrative for `none-found` in `src/pipeline/calibrate.py` without touching severity
- [X] T012 [P] [US1] Add `integration_markers` (packages / imports / config_presence) to every rule entry in `src/skill_core/data/misconfig_rules.json`; entries without markers evaluate as undetermined
- [X] T013 [US1] Attach the `integration` block per finding in `src/pipeline/misconfig.py` (exact-string marker matching only; evidence sorted; three states per contracts/integration-evidence.md)
- [X] T014 [US1] Render `usage` state/locations on dependency findings and removal-first remediation for `no-integration-found` findings in `src/pipeline/generate_report.py` `_render_finding()`; pre-014 reports (absent blocks) render unchanged

**Checkpoint**: US1 standalone — Scenarios 1–2 pass; `pytest -q` green with no benchmark regressions.

---

## Phase 4: User Story 2 - Framework escaping mitigations engage on template sinks (Priority: P2)

**Goal**: Sinks in `type:"template"` nodes match shipped control sink lists; deterministic credit requires zero member-wide bypasses plus full parse coverage; hedged cases route to triage as candidates (FR-005–007, hybrid per clarification Q2).

**Independent Test**: quickstart.md Scenario 3 — escaped-binding fixture without bypass gets the control engaged (credited or citation-verified refute/downgrade); with a bypass call the finding stands.

### Tests for User Story 2 ⚠️ WRITE FIRST, MUST FAIL

- [X] T015 [P] [US2] Unit tests for template sink matching, member-wide bypass scan, and parse-coverage gating in `src/pipeline/controls.py` (bypassed ⇒ bypass_site evidence; unparsed member file ⇒ unassessed; sink not in list ⇒ not applicable) in `tests/unit/test_controls_template.py`
- [X] T016 [P] [US2] Benchmark case `tests/benchmark/cases/template_sink_escaping.json` + fixture: escaped `[innerHTML]` bindings without bypass MUST NOT report executable XSS (credited or refuted with verified citations); bypass variant must retain standing

### Implementation for User Story 2

- [X] T017 [US2] Emit binding annotations on `type:"template"` nodes during template extraction and propagate them in `src/pipeline/build_code_graph.py` `add_template()` (binding names matched against shipped `sinks` lists; deterministic)
- [X] T018 [US2] Extend `src/pipeline/controls.py` `evaluate()` with the template branch: sink admission via binding annotations, member-wide `control_bypass` scan, member parse-coverage check; existing path-scoped behavior for non-template findings unchanged
- [X] T019 [US2] Route `unassessed` template-control hedges into the triage round as `candidate_controls` in `src/pipeline/triage.py` `collect_candidate_controls()` (existing citation re-verification gates apply; no packet-shape changes)

**Checkpoint**: US2 standalone; `pytest -q -m slow` confirms no member-scan perf regression on the scale fixture.

---

## Phase 5: User Story 3 - Currency findings for the same product cycle merge (Priority: P3)

**Goal**: One currency finding per `(member, product, cycle)` — the key SC-001 needs; all signals and packages as evidence; highest contributing severity; IDs assigned after merge; never merged with CVE findings (FR-008–009).

**Independent Test**: quickstart.md Scenario 4 — fixture with one package attracting two currency signals yields a single merged finding; distinct packages stay distinct.

### Tests for User Story 3 ⚠️ WRITE FIRST, MUST FAIL

- [X] T020 [P] [US3] Unit tests for currency merge (merge key, evidence preservation — no signal lost, highest-severity retention, per-member isolation, no advisory mixing, stable IDs post-merge) in `tests/unit/test_currency_merge.py`
- [X] T021 [P] [US3] Benchmark case `tests/benchmark/cases/currency_merge.json` + fixture asserting finding counts and merged evidence

### Implementation for User Story 3

- [X] T022 [US3] Add a `dependency` block (`ecosystem, package, packages[], product, cycle, signals[]`) to currency findings and roll up per `(member, product, cycle)` inside `src/pipeline/audits/__init__.py` `stack_currency_findings()` before sequential ID assignment; merged finding keeps max severity and per-package evidence

**Checkpoint**: US3 standalone; benchmark counts updated wherever currency findings appear in existing fixtures.

---

## Phase 6: User Story 4 - Reports cannot reference findings that do not exist (Priority: P3)

**Goal**: Dangling `SEC-\d+` references in narrative sections are quarantined: section omitted, defect declared in-report, exit code 4; residual strict check keeps the invariant on what ships (FR-010, clarification Q5).

**Independent Test**: quickstart.md Scenario 5 — system review naming nonexistent SEC-0006 publishes without that section, declares the omission, exits 4; clean report exits 0 byte-identical to pre-014.

### Tests for User Story 4 ⚠️ WRITE FIRST, MUST FAIL

- [X] T023 [P] [US4] Unit tests for `resolve_narrative_references` (reference extraction across system review/cross-system/attack paths/recommendations; quarantine list sorted and deduplicated) and for the residual consistency rule in `tests/unit/test_consistency_references.py`
- [X] T024 [P] [US4] Integration test: dangling-reference fixture ⇒ artifacts written, omission declared inline, exit code 4, three stdout lines unchanged in `tests/integration/test_report_quarantine.py`
- [X] T025 [P] [US4] Benchmark case `tests/benchmark/cases/dangling_reference.json` + fixture; clean-report byte-identity assertion vs pre-014 baseline

### Implementation for User Story 4

- [X] T026 [US4] Implement `resolve_narrative_references()` pre-gate in `src/pipeline/generate_report.py` `write()` (scan sections, remove offenders, record `quarantined_sections`, render inline omission notices in Markdown/HTML); field absent on clean reports
- [X] T027 [US4] Add the residual dangling-reference rule family to `src/pipeline/consistency.py` `check()` (raises `ReportInconsistent` — pipeline bug, unreachable from user data)
- [X] T028 [US4] Add `EXIT_REPORT_DEFECT = 4` in `src/pipeline/scan_cli.py`, return it from `cmd_run` when `quarantined_sections` is non-empty, log via the progress reporter only; extend `src/pipeline/report_view.py` `filter_by_repo()` to elide narrative references to filtered-out findings consistently

**Checkpoint**: US4 standalone; `ReportInconsistent` behavior for all pre-existing contradiction rules unchanged.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Documentation (blocking per the honesty gates) and full verification.

- [X] T029 [P] Document exit code 4 (report published with quarantined sections) alongside exit code 3 in `README.md`, `docs/`, and `docs/getting-started.md`; document `usage`/`integration` blocks and `quarantined_sections` in the report format docs
- [X] T030 [P] Update `AGENTS.md` non-negotiables with the exit-4 meaning and the new data file ownership rule if agent guidance is affected
- [X] T031 Run full verification: `pytest -q`, `pytest -q -m slow`, `ruff check src tests`; execute every quickstart.md scenario including the determinism gate
- [ ] T032 Re-scan the repository that produced `20260904T085653Z-7ab7bd.md` and verify against spec SC-001 — BLOCKED: target repo is external and not available in this workspace; its defect classes are encoded as release-blocking gates (usage_evidence.json, template_sink_escaping.json, currency_merge.json, dangling_reference.json): usage-qualified CVE narrative, credited/refuted template XSS, merged EOL findings, no dangling references

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: none — start immediately.
- **Foundational (Phase 2)**: T001 done; blocks US1 only (US2–US4 do not depend on graph imports).
- **US1 (Phase 3)**: needs Phase 2. Touchpoints shared with other stories: `generate_report.py` (also US4), `calibrate.py`, `correlate_findings.py`.
- **US2 (Phase 4)**: independent of US1; shared file `build_code_graph.py` with Phase 2 — start after T004 to avoid conflicts.
- **US3 (Phase 5)**: independent; isolated to `audits/__init__.py` + fixtures.
- **US4 (Phase 6)**: shares `generate_report.py` with US1 (T014/T026) — sequence after T014, or partition the file carefully if parallelized.
- **Polish (Phase 7)**: after all desired stories complete; T032 after everything.

### Within Each Story

- Tests (T0xx) written first, verified FAILING, before implementation tasks.
- Data/schema changes before passes that consume them.
- Pipeline wiring after the pass module exists.

### Parallel Opportunities

- T002 ∥ T003 (different files); T005 ∥ T006 ∥ T007 ∥ T008 (all test files).
- T012 is standalone data while T009–T011 progress.
- T020 ∥ T021; T023 ∥ T024 ∥ T025 across US3/US4 (disjoint files).
- US2 and US3 can run fully in parallel after Phase 2; US4 in parallel except its `generate_report.py` tasks must wait on T014.

---

## Parallel Example: User Story 1

```bash
# Launch all US1 tests together:
Task: "Unit tests for the usage pass in tests/unit/test_usage_evidence.py"
Task: "Benchmark case usage_none_found.json + fixture builder"
Task: "Unit tests for misconfig integration states in tests/unit/test_misconfig_integration.py"
Task: "Integration test for integration evidence in tests/integration/test_integration_evidence.py"

# Then implementation, sequentially where files are shared:
Task: "Extractor dynamic/config capture in src/pipeline/extract/__init__.py"
Task: "usage_evidence.py" → Task: "wire finalize() + calibrate.py"
Task: "integration_markers data" ∥ extractor work
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. T001 → Phase 2 (T002–T004) → Phase 3 (T005–T014)
2. **STOP and VALIDATE**: Scenarios 1–2 of quickstart.md
3. Delivers the highest-value cross-check fixes (speculative CVE narrative + stale-config false positive) on its own.

### Incremental Delivery

1. Setup + Foundational → graph carries imports
2. US1 → usage/integration evidence live (MVP)
3. US2 → template controls engage
4. US3 ∥ US4 → merge + quarantine (low-risk, disjoint-ish)
5. Polish → docs + full verification + re-scan of the cross-checked repo

---

## Notes

- [P] tasks = different files, no dependencies on incomplete tasks.
- Every benchmark case is a deliberate-false-positive regression guard per the constitution; do not weaken assertions to make them pass.
- Commit after each task or logical group; `pytest -q` must stay green throughout.
- New fields are additive only — no `schema_version` bump, no breaking changes.
