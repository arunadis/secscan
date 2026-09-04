# Tasks: Finding Triage Reasoning Round

**Input**: Design documents from `/specs/013-finding-triage/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: included — the constitution mandates test-first (tests are written before
implementation and MUST fail first; fixtures declare ground truth).

**Organization**: tasks grouped by user story; US1 is the MVP.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Different files, no dependency on an incomplete task
- **[Story]**: US1 = refutation, US2 = downgrades, US3 = flagging + user declarations, US4 = benchmark gate

## Path Conventions

Single project: `src/pipeline/`, `src/skill_core/`, `src/config/`, `src/profiles/`,
`tests/` at repository root (per plan.md Structure Decision).

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: payload artifacts and configuration surface every story builds on

- [x] T001 [P] Create the triage verdict payload schema `src/skill_core/schemas/triage_answer.json` per `contracts/triage-round.md` §4: closed `verdict` enum (`confirmed|downgraded|refuted|flagged`), conditional requirements (citations non-empty iff verdict is `refuted`/`downgraded`; `user_question` plus optional `settling_evidence_hint` iff `flagged`), citation object shape (`repo`, `file`, `line_start`, `line_end`, optional `symbol`, `pattern`)
- [x] T002 [P] Create the payload prompt `src/skill_core/prompts/triage_finding.md`: closed verdict vocabulary, mandatory citations with exact `pattern` text for any refute/downgrade claim, `flagged` answers carry a concrete `user_question` and (where known) a `settling_evidence_hint`, explicit statement that credential findings can never be refuted, instruction that agent-mediated reasoners may consult only files listed in `consultable_files`
- [x] T003 [P] Add the `triage` config section to `src/config/loader.py` (keys `enabled` [auto|on|off], `min_severity_band`, `include_unverified`; strict unknown-key rejection; `SECSCAN_TRIAGE_*` env overrides via existing `ENV_PREFIX` mechanism) and register profile key `analysis_depth.finding_triage` parsing in the profile schema
- [x] T004 Set per-profile triage defaults in `src/profiles/builtin.yaml` per `contracts/triage-round.md` §2 (quick: `finding_triage: false`; full: `finding_triage: true`; audit: `finding_triage: true`) and downstream defaults `min_severity_band` full=Medium / audit=Low, `include_unverified: true`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: the triage round plumbing — stage, packets, runner, verdict parsing,
evidence re-verification, decision log — that every user story builds on

**⚠️ CRITICAL**: no user story work can begin until this phase is complete

- [x] T005 Register stage `finding_triage` in `STAGES` (between `correlate_findings` and `system_review`) in `src/pipeline/state.py`, and add it to `_ANALYSIS_STAGES` in `src/pipeline/run.py` so depth changes invalidate it
- [x] T006 [P] Implement candidate selection in `src/pipeline/triage.py` (`select_candidates(findings, profile, config)`): exclude findings with a `dependency` block, apply profile/config threshold per `contracts/triage-round.md` §2 (severity band ≥ configured minimum OR `detection == "heuristic"`; `include_unverified` toggle), deterministic ordering by finding id
- [x] T007 Implement the triage packet builder in `src/pipeline/triage.py`: per finding — verbatim finalized finding, redactor-processed excerpt (blocked windows noted, never passed unredacted), `candidate_controls` from the deterministic collector (control-annotated files from graph annotations + framework-control catalogue entries from `controls` data + architecture-profile integration points from member manifests + the finding's verification path; budget-limited by shedding whole entries with a warning), and `consultable_files` (agent-mediated mode only: per-file zero-redaction-hit set derived from the redactor's hit record; key omitted in endpoint modes)
- [x] T008 Implement `TriageRunner` in `src/pipeline/triage.py` mirroring the `EscalationRunner` contract (build `AnalysisRequest` with `request_id = "triage-" + finding_id`, budget-fit against the actual serialized request, record packets through the existing context-packet writer, run through the injected `AnalysisClient`, record usage via `UsageTracker`, reuse/put answers through `AnswerStore`); no escalation ladder (one level)
- [x] T009 [P] Implement the verdict parser in `src/pipeline/triage.py` per `contracts/triage-round.md` §4 rules 1–6: strict JSON, finding-id match, closed enum, conditional citation/question requirements, credential-class (CWE-798/CWE-522) `refuted` rejection before evidence checking, redaction sweep of answer content before any persistence; failure = whole-answer rejection returning a `rejected-malformed` outcome
- [x] T010 [P] Implement the deterministic evidence re-verifier in `src/pipeline/triage_evidence.py` per `contracts/triage-round.md` §5: repo-membership check, file existence under the cited member, line-range bounds, verbatim `pattern` within cited lines, optional symbol resolution against the code model; per-citation pass/fail results; verdict applies only when all citations verify, else `degraded-flagged` with failure reason
- [x] T011 Wire the `finding_triage` stage into `src/pipeline/run.py` between `correlate_findings` and `system_review`: load and match user declarations at stage start (calls into `src/pipeline/triage_declarations.py` — stub OK until US3), select candidates, run the round (interactive-loop and `pending` accumulation like segment analysis; batch mode dispatched by `TriageRunner` reusing the batch ledger/poll helpers — `BatchRoundRunner` stays segment-shaped and is NOT generalized), raise `AgentHandoff` on pending triage requests with exit-3 resume, on completion apply verdicts (calls into `src/pipeline/triage_apply.py` — stub returns findings unchanged until US1), write `triage/decisions.json`, and render the triage coverage line in the report coverage section whenever eligible candidates went unanswered (`triage ran but N of M candidates were not adjudicated`, FR-009 — this gap declaration is Foundational, not a later presentation task)
- [x] T012 Write the decision log in `src/pipeline/triage_apply.py` (`write_decisions(...)` → `triage/decisions.json`): one entry per candidate per `data-model.md` "Triage Decision" (finding_id, verdict_attempted, outcome, applied_effect, per-citation verification results, reason), sorted by finding id, canonical JSON — this function is complete in this phase even though effects are stubbed
- [x] T013 Update the artifact redaction sweep (wherever the existing Safety-Invariant sweep enumerates artifact paths) to cover triage outputs: `handoff/responses/triage-*` answer files, `triage/decisions.json`, and citation patterns persisted in suppressions — so reasoner output can never carry a credential value into an artifact

**Checkpoint**: a scan runs the stage end to end with a stub apply layer — requests are issued, answers persisted/reused byte-identically, verdicts parsed and re-verified, decisions logged, unanswered rounds declared in the report; findings pass through unchanged

---

## Phase 3: User Story 1 - Refuting disprovable findings (Priority: P1) 🎯 MVP

**Goal**: a finding provably neutralized by a control located elsewhere in the
repository is refuted with cited evidence that the pipeline re-verifies
deterministically, and lands in the auditable suppression list — headline bands no
longer include it

**Independent Test**: fixture with (a) endpoint group authorized only via a
framework security-config registration and (b) a genuinely unprotected endpoint
group; scan refutes (a) into the suppressions section with verified citations and
leaves (b) in the findings stream unchanged

### Tests for User Story 1 ⚠️ (write first; all MUST fail before implementation)

- [x] T014 [P] [US1] Unit tests for suppression application in `tests/unit/test_triage_apply.py`: verified `refuted` verdict excludes the finding from the stream and appends a `triage-control-present` suppression with per-citation evidence; failed verification degrades to flagged; credential-class refute never reaches application (defense in depth across the parsed/applied boundary per `data-model.md` state transitions)
- [x] T015 [P] [US1] Contract test in `tests/contract/test_triage_answer.py`: `triage_answer.json` conformance across all four verdicts and every invalid combination from `contracts/triage-round.md` §4
- [x] T016 [P] [US1] Integration test in `tests/integration/test_finding_triage.py`: fixture workspace with the two endpoint groups above; agent-mediated run answers the triage handoff via fixture responder, report shows (a) in suppressions with ground `triage-control-present` and (b) unaffected; rerun with persisted answers produces byte-identical artifacts (SC-005)

### Implementation for User Story 1

- [x] T017 [US1] Add the triage fixture workspace as `tests/fixtures/triage_targets.py` (module-based fixture builder + scripted responder — shared by integration and benchmark tests; as landed) serving every later phase's integration tests: security-config-authorized controller + unprotected controller, wildcard-CORS config, localhost-only dev token, test-file credential fixture — mirroring the baseline report's stacks; consumed by T016, T022, T026 and the Phase-6 corpus
- [x] T018 [US1] Implement `refuted` application in `src/pipeline/triage_apply.py`: after T010 verification passes, exclude the finding from the correlated stream, append the suppression record to `tooling/suppressions.json` per `contracts/report-and-decisions.md` §1 (fields `tool_id: "triage"`, ground, evidence lines naming each verified citation), and record decision outcome `applied`/`suppression-added`
- [x] T019 [US1] Implement the `degraded-flagged` path in `src/pipeline/triage_apply.py`: a refute/downgrade whose citations fail re-verification leaves the finding in the stream and calls the shared `attach_flag()` helper (the same helper T027 uses for `flagged` — one attach path, never two) with the reasoner's rationale as question context plus the verification-failure reason (recorded in decisions), per FR-007 and the data-model state transitions
- [x] T020 [US1] Create the application seams in `src/pipeline/triage_apply.py`: named entry points for `flagged`/`confirmed`/`downgraded` application returning the finding set, so US2/US3 fill bodies without restructuring (stub behavior: `confirmed` = no-op; `flagged` = `attach_flag()`; `downgraded` = no-op until US2)

**Checkpoint**: US1 independently testable — refutations applied, audited, suppressed from bands; T014–T016 green

---

## Phase 4: User Story 2 - Calibrating true findings that are over-graded (Priority: P2)

**Goal**: a real finding whose impact is limited by verified repository facts is
downgraded with recorded rationale — staying in the report — so severity ordering
reflects what was established

**Independent Test**: fixture wildcard-CORS config without credential forwarding;
scan reports the finding with the reduced, cited severity and the downgrade
rationale on its record

### Tests for User Story 2 ⚠️

- [x] T021 [P] [US2] Unit tests in `tests/unit/test_triage_apply.py`: verified downgrade adjusts severity/confidence, records `{verdict, rationale, citations, previous_severity, previous_confidence}` on the finding's `triage` block, and preserves calibration invariants (no unproven finding outranks a proven one) when `calibrate` ordering is re-checked after adjustment
- [x] T022 [P] [US2] Integration test in `tests/integration/test_finding_triage.py`: wildcard-CORS fixture downgraded with visible rationale; finding remains in its (reduced) band in both JSON and Markdown report

### Implementation for User Story 2

- [x] T023 [US2] Implement `downgraded` application in `src/pipeline/triage_apply.py` (fills the T020 seam): compute adjusted severity/confidence from the rationale's claimed limiting facts (bounded: never raise scores; verified citations required, else degrade to flag per T019), attach the `triage` annotation block per `data-model.md` "Finding annotations", and re-run the calibration ordering invariant over the post-triage set in `src/pipeline/run.py` stage wiring
- [x] T024 [US2] Render triage outcomes in `src/pipeline/generate_report.py` and `src/pipeline/render_html.py`: downgrade rationale with adjusted + previous grading (no reduced visibility, FR-011), and the methodology note stating the triage mode and consultation boundary in effect (packet-only vs. hybrid with the zero-hit consult set) per FR-006 and `contracts/report-and-decisions.md` §2 rule 4

**Checkpoint**: US1 and US2 both green and independently demonstrable

---

## Phase 5: User Story 3 - Flagging context-dependent findings for the user (Priority: P2)

**Goal**: findings whose risk depends on out-of-repo facts render in an
awaiting-verification report section with a concrete question, and the user's
recorded answers resolve flags on the next scan as auditable, reversible
user-declared evidence

**Independent Test**: fixture credential used only against a localhost dev server;
scan flags it with a question; recording a declaration resolves the flag on re-scan
with `user-declared` provenance; deleting the declaration restores the flag

### Tests for User Story 3 ⚠️

- [x] T025 [P] [US3] Unit tests for the declarations lifecycle in `tests/unit/test_triage_declarations.py` per `contracts/report-and-decisions.md` §4: identity + question matching (line drift tolerated), application with provenance, lapse on CWE/file/question change, `refute` on credential-class rejected, reversibility (remove → flag returns), answer cap/sweep rejection
- [x] T026 [P] [US3] Integration tests in `tests/integration/test_finding_triage.py`: flagged finding renders in `awaiting_verification` (JSON + Markdown) while staying graded in the stream; declaration round-trip applies → resolves with provenance → removal re-flags (quickstart scenario 4)

### Implementation for User Story 3

- [x] T027 [US3] Implement `flagged` application in `src/pipeline/triage_apply.py` (fills the T020 seam): `attach_flag()` stores `awaiting_verification` = `{question, settling_evidence_hint}` taken from the verdict fields; grading untouched (FR-012)
- [x] T028 [US3] Implement `src/pipeline/triage_declarations.py`: load `.secscan/triage/declarations.json` (schema_version 1, strict validation), match by `finding_ref` identity + question, apply resolution at stage start (downgrade path reuses T023; refute path reuses T018; provenance block `triage.user_declaration`), lapse handling with decision-log records, credential-refute rejection per contract rule 3
- [x] T029 [US3] Render the awaiting-verification section in `src/pipeline/generate_report.py` (optional top-level `awaiting_verification` key, sorted by finding id) plus Markdown/HTML writers per `contracts/report-and-decisions.md` §2 — the `triage_unresolved` coverage line itself already landed in T011

**Checkpoint**: flags, questions, and the declaration loop work end to end

---

## Phase 6: User Story 4 - Triage quality is asserted, not eyeballed (Priority: P3)

**Goal**: triage correctness becomes a release-blocking benchmark defect class over
maintained ground-truth corpora

**Independent Test**: benchmark run over the triage corpus — every `expect-refuted`
case refuted with verified citations, every `expect-flagged` flagged with a
question, every `must-survive` case graded intact; a suppression of a genuine seed
fails the build

### Tests for User Story 4 ⚠️

- [x] T030 [P] [US4] Add triage ground-truth cases to `tests/benchmark/cases/`: control-elsewhere fixtures (security-config filter registration, checksum verification helper, URL allowlist validator — the baseline audit's Class C patterns) annotated `expect-refuted`; dev-local credential fixtures annotated `expect-flagged`; genuine-finding seeds annotated `must-survive`
- [x] T031 [US4] Add the `triage_correctness` defect class to `tests/benchmark/test_accuracy_benchmark.py`: assertions per annotation class with release-blocking failure semantics matching the existing per-class gate (FR-016); recall assertion that triage never alters what the detector/segment analysis detect (FR-017, compare pre/post stage artifacts)

### Implementation for User Story 4

- [x] T032 [US4] Wire corpus annotations through the benchmark harness: stable annotation keys in case manifests, verdict extraction from scan artifacts (`triage/decisions.json` + suppressions + awaiting_verification), per-class result reporting

**Checkpoint**: `pytest -q tests/benchmark -k triage` green; a deliberately wrong
verdict fixture proves the gate fails

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: docs currency (constitution gate), skill surface, final validation

- [x] T033 [P] Update `src/skill_core/SKILL.md` with a triage section per `contracts/triage-round.md` §6 (triage request files `triage-SEC-*`, consult `consultable_files` only, answer per `schemas/triage_answer.json`, re-run to resume) — mirror the existing step-6 segment section
- [x] T034 [P] Documentation updates per the constitution's documentation-currency gate: `README.md` (triage round + awaiting-verification + declarations), affected `docs/` pages, `AGENTS.md` layout row for the new `triage*` modules if the layout table changes
- [x] T035 Run the full verification suite `pytest -q` then `pytest -q -m slow`, and `ruff check src tests`; fix any failures introduced by this feature
- [x] T036 Execute every `quickstart.md` scenario (1–5 covered by the test suites; scenario 6, the baseline prism-bi spot-check with a live model, is an operator follow-up)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: no dependencies
- **Phase 2 (Foundational)**: depends on T001–T004; BLOCKS all stories — T005 must precede T011 wiring; T007/T008 must precede T011; T009/T010 precede all application work
- **Phase 3 (US1)**: depends on Phase 2 — T017 (fixtures) precedes T016's green run and feeds US2/US3/US4 test fixtures
- **Phase 4 (US2)**: depends on T020 (application seams) — grading semantics only, no packet changes
- **Phase 5 (US3)**: depends on T020; declarations additionally need T027's flag shape
- **Phase 6 (US4)**: can start once Phase 3 behaviors exist to assert; corpus work (T030) is independent of US2/US3
- **Phase 7 (Polish)**: after the stories in scope are complete

### User Story Dependencies

- **US1 (P1)**: independent after Foundational
- **US2 (P2)**: independent of US1's behavior; shares the apply seam (T020), so sequence after it
- **US3 (P2)**: independent of US1/US2 verdict effects; shares apply + report writers
- **US4 (P3)**: asserts the behaviors of US1–US3; corpus authoring (T030) can begin in parallel with any story

### Parallel Opportunities

- Phase 1: T001, T002, T003 in parallel
- Phase 2: T006, T009, T010 in parallel (different modules); T007→T008 sequential (same file)
- US1 tests T014–T016 in parallel; later stories' tests (T021/T022, T025/T026, T030) each parallel within their phase
- T033, T034 in parallel in Polish

### Parallel Example: User Story 1

```bash
# Tests first (all fail before implementation):
Task: "Unit tests for suppression application in tests/unit/test_triage_apply.py"
Task: "Contract test in tests/contract/test_triage_answer.py"
Task: "Integration test in tests/integration/test_finding_triage.py"

# Then implementation in order:
Task: "Fixture workspace under tests/integration/fixtures/triage-workspace/"
Task: "Refuted application in src/pipeline/triage_apply.py"
Task: "Degraded-flagged path in src/pipeline/triage_apply.py"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Phase 1 + Phase 2 → triage round runs end to end with stub application, gaps declared
2. Phase 3 (US1) → refutations with re-verified evidence land in the auditable
   suppression list; headline bands stop counting them
3. **STOP and VALIDATE** against quickstart scenarios 1–3

### Incremental Delivery

1. + US2 → cited downgrades with calibration invariants intact
2. + US3 → awaiting-verification section + user declaration loop
3. + US4 → benchmark gate becomes release-blocking
4. Polish → docs, skill surface, full suite

### Notes

- All decisions trace to [research.md](research.md) (R1–R11); contracts in
  [contracts/](contracts/) are binding for the contract tests
- Never print from the stage — all terminal/log output flows through the reporter
  (AGENTS.md non-negotiable)
- Batch parity: triage packets are built once and reused for either policy; the
  same-content guarantee applies (feature 012 precedent)
