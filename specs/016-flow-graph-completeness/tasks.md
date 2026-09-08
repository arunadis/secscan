# Tasks: Flow & Graph Completeness

**Input**: Design documents from `/specs/016-flow-graph-completeness/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: INCLUDED — the constitution mandates test-first (tests MUST be written and
fail before implementation) and fixture-declared ground truth, including deliberate
safe patterns that MUST NOT be reported. Accuracy-benchmark regressions are
release-blocking.

**Prior work**: Feature 016's verify-side half of FR-020 (implicated guard can never
disprove at the deterministic gate) already landed in `src/pipeline/verify.py` with
tests in `tests/unit/test_verify.py` (task T008A equivalent) — nothing re-opens it;
the triage-side half is T033 here.

**Organization**: Tasks grouped by user story (US1–US5 from spec.md) so each story
ships as an independently testable increment.

**Remediation note (2026-09-07, /speckit-analyze)**: addresses findings U1 (guard
matrix channel into the system review — T044/T046), U2 (explicit unresolved-wiring
record — T005 schema, T043/T045), I1 (rule-pack module fixed to
`src/pipeline/identity_rules.py` — T006), A1 (FR-007 exact-zero threshold wording —
spec.md), U3 (reachability flag derived inside `finalize()` so pipeline/resume/CLI
agree — T022), C1 (presence-confirmed terminology — T017).

**Post-implementation note (2026-09-07, second /speckit-analyze)**: T032 additionally
required extending the shipped CWE dataset — `src/skill_core/cwe_map.json` v2 → v3,
adding CWE-290 (Authentication Bypass by Spoofing, OWASP A07, 9.1, PCI-DSS 8.1) —
the pack's weakness id must exist in the dataset for normalization to accept it.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3, US4, US5)
- All paths are repository-relative

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: New data file, fixtures, and schema stubs every story builds on.
Existing project; no dependency installation needed.

- [X] T001 [P] Create stub versioned rule pack `src/skill_core/data/identity_archetype_rules.json` per contracts/identity-archetype-rules.md §1: `{version: "0", dataset_date: "2026-09-07", rules: [], guard_names: [<guard-name catalogue families from research R8>]}` — the shared guard-name catalogue lands here immediately because US1's FR-006 consumes it
- [X] T002 [P] Create fixture workspace `tests/fixtures/workspaces/header-identity-app/` mirroring the timesheet shape: `middleware/auth.js` reading `req.headers['x-user-email']` and auto-creating users with `db.get/db.run`, route modules attaching it via `router.use(authenticateUser)` and `router.get('/me', authenticateUser, …)`, one JWT-verifying guard module and one guard-consistent route group as deliberate safe patterns; declare ground truth in the fixture manifest format used by existing fixtures (one CWE-290 anchor finding at the trust function; both safe patterns MUST NOT be reported)
- [X] T003 [P] Create fixture workspace `tests/fixtures/workspaces/unwired-connectivity-app/` with endpoints and data access written in idioms no recognizer covers (e.g. invented `store.fetch(...)` receivers) so the FR-007 gap condition reproducibly fires, ground truth declaring zero expected findings plus the expected reachability-gap coverage note

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Schema extensions and the rule-pack loader that all stories consume.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T004 Add additive `basis` field (`traced` | `presence`) to `verification` in `src/skill_core/schemas/finding.json` per contracts/traceability-contract.md §1 — keep `additionalProperties: false`, keep `status` enum unchanged, add description noting presence required when status == "verified" and old artifacts without it stay valid; add contract test asserting the enum values and closed properties in tests/contract/
- [X] T005 Add annotation enum value `unattached_security_guard` to `src/skill_core/schemas/code_graph.json` per contracts/graph-wiring-contract.md §3, plus the additive top-level `unresolved_wiring` array property per contracts/graph-wiring-contract.md §6 (required fields file/line/name/reason; present even when empty); extend the contract test to cover both
- [X] T006 Implement the rule-pack loader/validator for `identity_archetype_rules.json` in `src/pipeline/identity_rules.py` (dedicated new module — reused by T028/T033): mirror `misconfig.load_rules`/`InvalidRuleData` discipline, duplicate id or missing required field fails the build, never the scan; expose `load_guard_names()` and `load_identity_rules()`; unit-test validation failures in tests/unit/test_identity_rules.py
- [X] T007 Extend `dataflow.Flow` so `complete` reports construction truth (path begins at the traced source and ends at a sink — `trace()` emits only such paths), eliminating the label-vs-id comparison that silently marked every endpoint-anchored flow incomplete (research R3); unit-test an endpoint-sourced flow and a symbol-sourced flow in tests/unit/test_dataflow.py

**Checkpoint**: Foundation ready — schemas admit the new fields, the rule pack loads,
flow completeness is truthful.

---

## Phase 3: User Story 1 - Middleware-borne controls are real in the graph (Priority: P1) 🎯 MVP

**Goal**: Route/module wiring registrations produce traversable graph edges;
header/cookie channels count as attacker-controlled sources; driver convenience
methods count as data access; the reference header-identity fixture traces entry
point → guard → datastore.

**Independent Test**: `pytest -q tests/integration/test_header_identity_fixture.py`
— the persisted graph contains endpoint→guard `handler` edges for
`router.use(authenticateUser)` and `router.get('/me', authenticateUser, …)`, and flow
tracing connects an endpoint to a datastore through the middleware.

### Tests for User Story 1 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T008 [P] [US1] Unit tests for channel/driver/auth recognition in tests/unit/test_enrichers.py: `req.headers['x']`/`req.cookies.x`/`request.headers`/`@RequestHeader`/`.getHeader(`/`c.GetHeader(` mark `user_controlled_input`; `db.get(...)`/`conn.run(...)`/`cursor.all(...)` produce `execute` data-access facts while `session.get(` does NOT; `authenticateUser(`/`verifyJwtToken(`/`passport.authenticate` match the auth context hint
- [X] T009 [P] [US1] Unit tests for wiring-fact extraction in tests/unit/test_enrichers.py: `router.use(authenticateUser)` and route-arg middleware produce identifiers; `(req,res)=>…` handlers, `mw.bind(x)`, `mod.auth`, and plain call shapes produce none (research R1 matcher rules)
- [X] T010 [P] [US1] Unit tests for edge resolution in tests/unit/test_build_code_graph.py: wiring facts become `calls` (file→guard) + scoped `handler` (endpoint→guard) edges; cross-repo and unresolved names produce no edge; name resolution is same-repo only
- [X] T011 [P] [US1] Unit test for `annotate_unattached_guards` in tests/unit/test_build_code_graph.py: a guard-catalogue function with only a test-file referrer gets `unattached_security_guard`; a wired one does not; test-path filtering per contracts/graph-wiring-contract.md §3
- [X] T012 [US1] Integration test in tests/integration/test_header_identity_fixture.py: build stages 1–3 over the T002 fixture; assert graph edges endpoint→guard, `user_controlled_input` on the middleware, data-access facts on its `db.get/db.run`, and ≥1 traced flow endpoint→middleware→datastore

### Implementation for User Story 1

- [X] T013 [US1] Extend `src/pipeline/extract/enrichers.py` recognizers per research R2: header/cookie channels in `_USER_INPUT_HINTS`; receiver-scoped convenience methods in `_SQL_EXECUTE` (detail from the convenience group); identifier-prefix auth hints in `_AUTH_HINTS` (prefix families, passport/jwt/bcrypt verifiers) — all pattern-tuple extensions to the existing mechanism
- [X] T014 [US1] Add `Wiring` dataclass to `src/pipeline/extract/__init__.py` and extraction in `src/pipeline/extract/enrichers.py` per contracts/graph-wiring-contract.md §1 (use-arg + route-arg recognizers, whole-identifier matcher, sorted deterministic facts, additive `to_dict`)
- [X] T015 [US1] Add `GraphBuilder.resolve_wiring()` and endpoint bookkeeping in `src/pipeline/build_code_graph.py` per contracts §2 (second pass after `resolve_calls`, `by_symbol` same-repo resolution, `handler`/`calls` edges, unresolved names produce none); call it from `run()` between `resolve_calls` and `resolve_template_bindings`
- [X] T016 [US1] Implement FR-006 `annotate_unattached_guards()` in `src/pipeline/build_code_graph.py` per contracts §3 using `load_guard_names()` from T006; call it after `resolve_wiring` in `run()`; wire the annotation into `partition_repo.DOMAIN_BY_ANNOTATION` (authentication, authorization) and `triage.CONTROL_ANNOTATIONS`

**Checkpoint**: US1 independently verifiable — T012 green; reference fixture graph
truthful.

---

## Phase 4: User Story 2 - Incomplete substrate is declared, never silent (Priority: P1)

**Goal**: A repository with endpoints and data access but zero traced flows declares
a named reachability gap; verdicts distinguish traced from presence; certainty
demotes while the gap is active; the summary never overstates.

**Independent Test**: `pytest -q tests/integration/test_reachability_gap.py` over the
T003 fixture — coverage note present, summary split correct, CWE-306 demoted,
no complete-path claim for presence findings.

### Tests for User Story 2 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T017 [P] [US2] Unit tests in tests/unit/test_verify.py: `basis == "presence"` set on the no-flow presence shortcut; `basis == "traced"` on complete paths; under the reachability flag a presence-confirmed CWE-306 becomes `plausible` with the gap reason while CWE-798/522/352 stay `verified` — per contracts/traceability-contract.md §1.3
- [X] T018 [P] [US2] Unit test for the gap trigger (lives in tests/unit/test_reachability_report.py): trigger exactly when endpoints>0 ∧ data-access facts>0 ∧ flows==0; no fire for static-site graphs (contracts §3)
- [X] T019 [P] [US2] Unit tests for the summary split in tests/unit/test_generate_report.py: counts separated by basis; complete-path wording only quantifies traced findings; the P>0 qualifier sentence appears (contracts §2)
- [X] T020 [US2] Integration test in tests/integration/test_reachability_gap.py over the T003 fixture per quickstart Scenario 2, including resume-repetition determinism (gap declared identically from persisted artifacts)

### Implementation for User Story 2

- [X] T021 [US2] Extend `src/pipeline/verify.py`: `Verdict` gains `basis`; presence shortcut and traced-verified set it; `Verifier`/`apply_verification` accept `reachability_unconfirmed` and apply the FR-009 demotion
- [X] T022 [US2] Add the FR-007 gap computation via a shared helper in `src/pipeline/run.py` immediately after `trace_flows`: counts from graph nodes/facts, fixed message template from data-model.md, emitted via the existing `_warn` channel. `correlate_findings.finalize()` MUST derive the `reachability_unconfirmed` flag internally from its `graph` + `flows` inputs using that same helper, so the pipeline path, resume path, and the standalone `correlate_findings` CLI agree by construction (no flag parameter threading)
- [X] T023 [US2] Update the executive-summary lead in `src/pipeline/generate_report.py` per contracts §2 (basis-split counts, wording honesty)

**Checkpoint**: US2 independently verifiable — degraded substrate is declared and
never reads as clean or complete.

---

## Phase 5: User Story 3 - Subdivided segments keep reachability context (Priority: P2)

**Goal**: Every subdivision part receives the module's route enumeration; production
files order ahead of test files; packets carry per-file role digests and
guard-attachment lines.

**Independent Test**: `pytest -q tests/unit/test_partition_repo.py -k entrypoints`
plus a packet-content assertion over a subdivided fixture (tests-first alphabetical
poisoning covered by the T002 fixture's `__tests__`).

### Tests for User Story 3 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T024 [P] [US3] Unit tests in tests/unit/test_partition_repo.py: subdivided parts all carry the module `entrypoints`; production files precede `__tests__`/`*.test.*` in part assignment; test-only endpoints attributed test-scoped
- [X] T025 [P] [US3] Unit tests in tests/unit/test_build_context.py: per-file inbound-reference digest lines and `guards:` lines appear in `call_graph_summary`; `guards: none recorded` emitted only for route-bearing files when sibling route files attach guards (FR-016 evidence-only per clarify Q4)
- [X] T043 [P] [US3] Unit tests for the unresolved-wiring record in tests/unit/test_build_code_graph.py: a wiring fact whose target matches no in-repo symbol lands in the graph artifact's `unresolved_wiring` array with `{file, line, name, reason}`, sorted deterministically; resolved targets never appear; the key is present-but-empty when nothing is unresolved (contracts/graph-wiring-contract.md §6) — remediates analysis finding U2
- [X] T044 [P] [US3] Unit tests for the system-review Guard attachment section in tests/unit/test_run_review.py (or nearest review-narrative test module): narrative lists per-module guard attachment and names route modules with `guards: none` when siblings attach the shared guard, using the T002 fixture's guard-consistent group as the negative case — remediates analysis finding U1

### Implementation for User Story 3

- [X] T026 [US3] Update `src/pipeline/partition_repo.py`: `_part()` keeps the entrypoint enumeration on every part (FR-011) — bounded at `_MAX_PART_ENTRYPOINTS` (40) with an explicit "+N more (full enumeration in segments/<id>.json)" remainder marker, because the scale fixture's 734 routes would otherwise blow the packet budget (FR-011's "compact" is the contract, not the full list); subdivision iteration orders production files before test files (FR-012); endpoints enumerated with a test-scope marker when the defining file is test-classed
- [X] T027 [US3] Extend `src/pipeline/build_context.py` `_call_summary` with the deterministic digest line families per contracts/graph-wiring-contract.md §5 (research R6)
- [X] T045 [US3] Record unresolved wiring in `GraphBuilder.resolve_wiring()` (src/pipeline/build_code_graph.py): names with no in-repo symbol append `{file, line, name, reason: "no in-repo symbol with this name"}` to a `builder.unresolved_wiring` list, emitted sorted as the graph document's `unresolved_wiring` array per contracts §6
- [X] T046 [US3] Feed the guard-attachment matrix into the system review in `src/pipeline/run.py`: `_system_review_narrative` accepts the graph additionally to findings/workspace and appends a deterministic "Guard attachment" section computed from wiring edges + `unresolved_wiring` per contracts/graph-wiring-contract.md §5 (feature-015 `flow_coverage` precedent); resume path recomputes identically (narrative is derived, not persisted state)

**Checkpoint**: US3 independently verifiable — subdivision never silently starves a
part of reachability context.

---

## Phase 6: User Story 4 - Client-asserted-identity is a first-class detectable weakness (Priority: P2)

**Goal**: The versioned rule pack deterministically detects the archetype; reasoning
guidance names it in all three reasoning stages; guard inconsistency surfaces as
evidence; triage can never refute via the implicated perimeter.

**Independent Test**: `pytest -q tests/integration/test_header_identity_fixture.py -k finding`
— the archetype finding lands at the trust function as a format detection, verified/
presence-basis, and survives triage (refuted disallowed; perimeter citations rejected).

### Tests for User Story 4 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T028 [P] [US4] Unit tests for archetype matching in tests/unit/test_identity_rules.py: function-scope `identity_read` present + all `requires_absent` absent + `dispatch` present fires; presence of any `requires_absent` pattern suppresses; non-matching function bodies (the JWT-guard safe pattern) do not fire
- [X] T029 [P] [US4] Unit tests for pipeline finding shape in tests/unit/test_identity_findings.py: `detection: "format"`, CWE dataset validation, normalized location resolution against the code model, per-segment append parity with secret findings
- [X] T030 [P] [US4] Unit tests for the triage gates in tests/unit/test_triage.py + tests/unit/test_triage_apply.py: `refuted` rejected for findings whose CWE is in the pack's set (format-detections family); `refuted`/`downgraded` rejected when any citation resolves into the implicated perimeter (FR-020 triage half); independent-control citations still accepted
- [X] T031 [US4] Integration test completing the story per spec US4 acceptance in tests/integration/test_header_identity_fixture.py: end-to-end the agent-mediated (or oracle) scan of the T002 fixture produces the CWE-290 anchor finding and zero safe-pattern findings

### Implementation for User Story 4

- [X] T032 [US4] Write the v1 rule pack content in `src/skill_core/data/identity_archetype_rules.json`: the Express/header rule per data-model.md (stacks, globs, scope, read/absent/dispatch patterns, CWE-290, severity, value-free title/description/recommendation); bump `version` to "1"
- [X] T033 [US4] Implement the function-scoped evaluator in `src/pipeline/identity_rules.py` (reuse `misconfig.py` evaluation loop shape: glob selection, per-symbol body slices via FileFacts symbols, sorted emission); findings appended per segment in `src/pipeline/run.py` through the existing normalizer path used for deterministic secret findings, `tool_ref` = `identity-archetype@<version>:<rule-id>`
- [X] T034 [US4] Triage gating in `src/pipeline/triage.py` + `src/pipeline/triage_apply.py`: replace the hardcoded credential frozenset approach with pack-aware refutation-disallowed membership; add the FR-020 perimeter rejection to verdict application (shared implicated-location helper imported from verify.py)
- [X] T035 [P] [US4] Prompt guidance (FR-015): authentication-domain sentence in `src/skill_core/prompts/segment_scan.md`; candidate-control implicated-guard and format-no-refute notes in `src/skill_core/prompts/triage_finding.md`; guard-inconsistency evidence sentence in `src/skill_core/prompts/final_review.md`

**Checkpoint**: US4 independently verifiable — archetype detection deterministic,
reasoning sealed against self-refutation.

---

## Phase 7: User Story 5 - Regression net against this failure class (Priority: P3)

**Goal**: The accuracy benchmark asserts the new defect class per class; two-run
byte-identity holds with all additions active.

**Independent Test**: `pytest -q -m benchmark` passes with the new class; a revert of
any recognition task fails the class.

### Tests for User Story 5 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T036 [US5] Add the "guard-hidden trust boundary" defect class as a new case file tests/benchmark/cases/guard_hidden_trust_boundary.json plus a `test_defect_class_guard_hidden_trust_boundary` in tests/benchmark/test_accuracy_benchmark.py (ground truth from the T002 fixture manifest; deliberate safe-pattern non-reports asserted), matching the existing per-class pattern so a regression fails the build per constitution
- [X] T037 [US5] Extend the determinism two-run integration test in tests/integration/test_determinism.py (or nearest equivalent) to cover the T002 and T003 fixtures: byte-identical artifacts on repeat runs, including the reachability-gap declaration and archetype findings

### Implementation for User Story 5

- [X] T038 [US5] Wire the new defect class into the benchmark's per-class aggregation in tests/benchmark/test_accuracy_benchmark.py (`test_every_defect_class_has_an_expectation` covers it once T036 lands) so SC-004/SC-005 are visible in benchmark output

**Checkpoint**: US5 verifiable — the failure class cannot regress silently.

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Documentation currency and quality gates across all stories.

- [X] T039 [P] Update `README.md` surfaces per the constitution's honest-documentation gate (Status/Roadmap/feature lists and any command references affected by the new detection family and reachability-gap coverage note)
- [X] T040 [P] Update `docs/` pages describing verification verdicts, coverage gaps, and deterministic detection data formats; `AGENTS.md` notes only if agent guidance changed
- [X] T041 Run the full quickstart validation in specs/016-flow-graph-completeness/quickstart.md scenarios 1–5 and record outcomes
- [X] T042 Final gates: `pytest -q` (full suite), `pytest -q -m slow` (large-repository scale scan), `ruff check src tests` — all green on a clean checkout

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: no dependencies
- **Phase 2 (Foundational)**: depends on Phase 1 — **BLOCKS all user stories** (schemas must admit new fields; rule pack must load; flow completeness must be truthful before any verdict or digest can rely on it)
- **Phase 3 (US1, P1)**: depends on Phase 2 — MVP
- **Phase 4 (US2, P1)**: depends on Phase 2; T022's ordering benefits from US1's wiring edges existing (more graphs have honest zero-flow vs true-clean distinction) but is independently testable on the T003 fixture
- **Phase 5 (US3, P2)**: depends on Phase 2 + US1's wiring facts (digest lines project wiring edges)
- **Phase 6 (US4, P2)**: depends on Phase 2 + US1 (guard visibility) — T031's anchor finding asserts the flow US1 creates
- **Phase 7 (US5, P3)**: depends on all active stories
- **Phase 8 (Polish)**: depends on Phase 3–7

### Within Each User Story

- Tests MUST be written and FAIL before implementation (constitution)
- Schema/data changes before consumers
- Core implementation before pipeline wiring
- Story complete before moving to next priority

### Parallel Opportunities

- T001–T003 (Phase 1) all parallel; T004–T006 (Phase 2) parallel except T024/T020 fixture couplings
- Within US1: T008–T011 parallel; within US2: T017–T019 parallel; within US4: T028–T030 parallel, T035 parallel to T032–T034
- US2 and US3 can proceed in parallel once US1 lands

---

## Parallel Example: User Story 1

```bash
# Tests first, all parallel:
Task: "T008 unit tests channels/drivers/auth prefixes in tests/unit/test_enrichers.py"
Task: "T009 unit tests wiring-fact extraction in tests/unit/test_enrichers.py"
Task: "T010 unit tests edge resolution in tests/unit/test_build_code_graph.py"
Task: "T011 unit tests unattached-guard annotation in tests/unit/test_build_code_graph.py"
# Then implementation, sequential on shared files:
Task: "T013 enrichers recognizers"  →  Task: "T014 wiring facts"  →  Task: "T015 resolve_wiring"  →  Task: "T016 annotate_unattached_guards"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 + Phase 2
2. Complete Phase 3 (US1): the reference miss becomes visible to the pipeline —
   the graph/flow substrate alone restores what reasoning needs
3. **STOP and VALIDATE**: T012 integration green
4. Ship as the minimal release increment if time-constrained

### Incremental Delivery

1. Setup + Foundational → foundation ready
2. US1 → MVP (middleware truthfulness)
3. US2 → degraded-coverage honesty (report no longer overstates)
4. US3 → subdivision robustness · US4 → deterministic archetype net
5. US5 → benchmark regression net; Polish gates → release

## Coverage Trace

| Spec item | Tasks |
|---|---|
| FR-001/FR-002 (wiring edges) | T009, T010, T014, T015, T012 |
| FR-003 (header/cookie sources) | T008, T013 |
| FR-004 (driver conventions) | T008, T013 |
| FR-005 (auth-name prefixes) | T008, T013 |
| FR-006 (unattached guard) | T011, T016 |
| FR-007 (reachability gap) | T018, T020, T022 |
| FR-008 (traced vs presence) | T004, T017, T019, T021, T023 |
| FR-009 (demotion under gap) | T017, T021, T022 |
| FR-010 (undetermined wiring) | T005 (schema), T043, T045 |
| FR-011/FR-012 (partition) | T024, T026 |
| FR-013 (role digest) | T025, T027 |
| FR-014 (archetype rules) | T001, T006, T028, T029, T032, T033, T031 |
| FR-015 (prompt guidance) | T035 |
| FR-016 (evidence-only inconsistency) | T025, T027, T044, T046 |
| FR-017 (versioned data) | T001, T006, T032 |
| FR-018 (benchmark) | T036–T038 |
| FR-019 (determinism/safety) | T037, T042 |
| FR-020 (implicated guard, both stages) | verify half landed pre-spec; triage half T030, T034 |
| FR-021 (recall off per-scan path) | T036 (benchmark-owned recall); no sweep task by decision |
| US1 | T008–T016 |
| US2 | T017–T023 |
| US3 | T024–T027, T043–T046 |
| US4 | T028–T035 |
| US5 | T036–T038 |
