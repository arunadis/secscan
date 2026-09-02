---

description: "Task list for feature 003 implementation"
---

# Tasks: Reduce Hard-Coded-Credential False Positives

**Input**: Design documents from `/specs/003-reduce-secret-false-positives/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/detection-contracts.md, quickstart.md

**Tests**: INCLUDED — the constitution mandates test-first ("Tests are written before
implementation and MUST fail first"); every test task must be verified failing before its
implementation task begins.

**Organization**: Tasks are grouped by user story (US1 P1 → US2 P2 → US3 P3) so each is
independently implementable and testable. Every task cites the requirement/contract it
discharges.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3)
- Requirement citations use spec FR numbers and contract IDs (C1–C6 from
  `contracts/detection-contracts.md`); research decisions cited as R1–R6 from `research.md`

## Path Conventions

- Single project: `src/pipeline/`, `tests/` at repository root
- Existing files referenced: `src/pipeline/redact.py`, `src/pipeline/secret_findings.py`,
  `src/pipeline/verify.py`, `src/pipeline/stacks.py`, `src/pipeline/correlate_findings.py`,
  `src/pipeline/generate_report.py`, `src/pipeline/build_context.py`

---

## Phase 1: Setup

**Purpose**: Establish a verified-green starting point — accuracy work against a red baseline is meaningless.

- [X] T001 Run the full existing suite (`pytest -q && ruff check src tests`) from the repository root and confirm it is green before any change; record the credential-detection recall baseline asserted by the existing redaction tests (constitution gate; these tests must remain green unmodified-in-expectation per contract C3)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The Detection Decision record extension that US1's suppression audit trail (FR-004) and US3's corpus assertions both depend on.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T002 Extend the redactor's decision records in `src/pipeline/redact.py` per `data-model.md` "Detection Decision": add `rule` (the matched redactor rule/label, or `entropy-candidate` for exempted entropy matches — FR-004 requires the matched rule), `classification` (`identifier` | `message-string` | `credential-format` | `ambiguous-literal`), and `reason` to the exemption record, and add `exempt-message` to the decision vocabulary alongside the existing `exempt-identifier` (FR-004; data-model validation rules). Surface the extended records in the context-packet redaction section via `src/pipeline/build_context.py` so suppressions are inspectable in artifacts, mirroring the existing `exempted` plumbing

**Checkpoint**: Decision records can carry classification + reason; user story implementation can now begin

---

## Phase 3: User Story 1 - Identifiers are not reported as credentials (Priority: P1) 🎯 MVP

**Goal**: A camelCase identifier containing a credential word (`openaiModelInputTokenCostGpt51ChatLatest`) or a UI message constant (`INVALID_PASSWORD`) no longer produces a CWE-798 finding, while every genuine credential is still detected.

**Independent Test**: `pytest -q tests/unit/test_redact.py` — credential-word identifier and message-string fixtures produce zero hits with recorded exemption decisions; the seeded credential corpus retains 100% recall (contracts C1, C2, C3; SC-001, SC-002).

### Tests for User Story 1 ⚠️ WRITE FIRST, VERIFY THEY FAIL

- [X] T003 [P] [US1] Create `tests/fixtures/credential_corpus.py` with seeded credentials: format-matched keys (AWS-style, GitHub-token-style), a high-entropy value assigned to a credential-named key, a readable multi-word passphrase assigned to `password`, and one identifier-shaped-but-real credential that must still be blocked — each entry with `expected_recall: true` per `data-model.md` Corpus Entry (FR-005, FR-006, C3)
- [X] T004 [P] [US1] Extend `tests/fixtures/identifier_corpus.py` with the evidenced false positives: camelCase/PascalCase identifiers embedding credential words (`openaiModelInputTokenCostGpt51ChatLatest` class — SEC-0085), UI message constants (`INVALID_PASSWORD` class — SEC-0093), and login-page identifier cases (SEC-0091/0092), each with `expected_findings: 0` and a `rationale` citing the original finding id (FR-011 corpus data, C2)
- [X] T005 [US1] Add failing unit tests in `tests/unit/test_redact.py` asserting contract C1 (credential context evaluated with the candidate span masked: identifier-internal `Token` creates no context; `apiKey = "<value>"` still fires), C2 (exemption conjunction incl. the new message-string arm, every exemption recorded with classification + reason), and C3 (100% recall over `credential_corpus.py`, credential-named assignment beats readability, all pre-existing redaction expectations unchanged) (FR-001, FR-002, FR-003, FR-004, FR-005, FR-006, FR-007)

### Implementation for User Story 1

- [X] T006 [US1] Implement mask-then-match credential-context evaluation in `src/pipeline/redact.py`: in the entropy path, replace `_SECRET_CONTEXT.search(line)` with a search against the line text with the candidate span masked by a fixed placeholder, so context can only come from tokens outside the match (R1; FR-003; C1)
- [X] T007 [US1] Implement message-string classification in `src/pipeline/redact.py`: a quoted literal reading as natural language (contains spaces + multiple words, or sentence punctuation) classifies as `message-string`; extend the exemption gate to the full C2 conjunction — shape in {identifier, message-string} AND no masked-line credential context AND not assigned to a credential-named key AND no rule-pack format match — recording each exemption via the T002 decision record (R2, R3; FR-001, FR-002, FR-004; C2)
- [X] T008 [US1] Verify via `pytest -q tests/unit/test_redact.py` that the T005 tests now pass and the pre-existing redaction suite (including 002's identifier-exemption and recall-regression guards in `tests/unit/test_redact.py`) is green unmodified; if any recall test fails, the implementation is wrong — recall precedence is absolute (FR-005; constitution Principle III)

**Checkpoint**: User Story 1 complete — the SEC-0085 class is eliminated with recall intact; independently testable via `tests/unit/test_redact.py`

---

## Phase 4: User Story 2 - Heuristic detections carry honest confidence (Priority: P2)

**Goal**: Findings from entropy heuristics publish with strictly lower confidence than format-matched credentials and can never be `verified`; test-code credentials are reported at reduced severity/confidence with the context named — never suppressed.

**Independent Test**: `pytest -q tests/unit/test_secret_findings.py tests/unit/test_verify.py` — format vs heuristic vs test-code grading asserted (contract C4; SC-006).

### Tests for User Story 2 ⚠️ WRITE FIRST, VERIFY THEY FAIL

- [X] T009 [P] [US2] Add failing unit tests in `tests/unit/test_secret_findings.py` asserting: emitted findings carry `detection` (`format` | `heuristic`, heuristic iff label is `high-entropy-secret`) and `code_context` (`production` | `test`); confidence ordering format-prod > heuristic-prod > *-test; severity ordering likewise (test-code findings land in a strictly lower severity score/band than the same detection class in production code); test-code findings are still emitted with the context named in the description (FR-008, FR-009, FR-010; C4)
- [X] T010 [P] [US2] Add failing unit tests in `tests/unit/test_verify.py` asserting the CWE-798/259/256/522/532 auto-verify shortcut applies only when `detection == "format"`; heuristic findings take the standard trace path and come out `plausible` when no flow exists (R4; FR-008; C4)
- [X] T011 [P] [US2] Add a failing contract test in `tests/contract/test_finding_schema.py` asserting the `finding` artifact's new optional fields `detection` and `code_context` are additive (no existing field changed, `schema_version` unchanged) and that `detection == "heuristic"` ⇒ `verification.status != "verified"` holds for any emitted finding (FR-008; C5)

### Implementation for User Story 2

- [X] T012 [US2] Add test-path conventions as versioned data (per stack: `src/test/**`, `tests/**`, `**/*.test.*`, `**/*_test.go`, `conftest.py`, …) to the stack descriptors consumed by `src/pipeline/stacks.py`, plus a deterministic path classifier resolving against code-model file records (R5; FR-010; data-model "Test-Path Convention")
- [X] T013 [US2] Implement detection provenance and per-label grading in `src/pipeline/secret_findings.py`: set `detection` from the originating label, `code_context` from the T012 classifier, and confidence per class (format ≈ 0.95 unchanged; heuristic ≈ 0.6; test context reduced further); for `code_context == "test"` also reduce the severity score/band relative to the same detection class in production code (FR-010 requires both severity and confidence reduction); heuristic descriptions state the heuristic basis ("possible credential — review required") instead of asserting exposure (R4; FR-008, FR-009, FR-010)
- [X] T014 [US2] Narrow the auto-verify shortcut in `src/pipeline/verify.py` (currently lines 130–136) to findings with `detection == "format"`, and propagate `detection`/`code_context` unchanged through `src/pipeline/correlate_findings.py` normalization/dedup and into the rendered report in `src/pipeline/generate_report.py` (R4; FR-008; C4)

**Checkpoint**: User Story 2 complete — SEC-0085-class heuristic hits can no longer publish as verified 0.95 exposures; independently testable via the T009–T011 suites

---

## Phase 5: User Story 3 - False-positive regression guard (Priority: P3)

**Goal**: A maintained false-positive corpus and a ground-truth-audited baseline gate the build: any future change that re-introduces an identifier/message false positive or drops a real credential fails CI.

**Independent Test**: `pytest -q tests/benchmark/test_accuracy_benchmark.py -k credential` plus the corpus suite — both green, and both demonstrably fail when a suppression rule is deliberately broken (contract C6; SC-001–SC-005).

**Note**: The benchmark assertions encode the *fixed* behavior; while the suite is test-first per
task, its end-state assertions are only satisfiable after US1/US2 — run them red against current
behavior, keep them red while implementing, and require green here.

### Implementation for User Story 3

- [X] T015 [US3] Perform the one-time ground-truth audit: for each of the 23 CWE-798 findings in baseline scan `20260831T081536Z-438706` (artifacts under `/Users/aruna/Documents/skh/.security-scan/findings/`), open the cited source in `/Users/aruna/Documents/skh` and label the finding true-positive or false-positive with a one-line rationale (the SEC-0085/0091/0092/0093 identifier-message class vs the SEC-0076/0084 genuine-value class); record labels as `tests/benchmark/cases/audited_credential_baseline.json` per `data-model.md` Corpus Entry (`source_label` = original finding id + verdict) (SC-003 baseline; spec Assumptions "Ground-truth audit")
- [X] T016 [P] [US3] Add the false-positive corpus zero-findings suite in `tests/unit/test_false_positive_corpus.py`: every `identifier_corpus.py` entry with `expected_findings: 0` produces no credential finding end-to-end (redactor hit → `secret_findings` emission), and every suppression is recorded as an inspectable Detection Decision (FR-011; C6)
- [X] T017 [P] [US3] Add the credential-precision defect class to the accuracy benchmark in `tests/benchmark/test_accuracy_benchmark.py` with expectations in `tests/benchmark/cases/`: assert the audited baseline entry-by-entry (confirmed FPs no longer reported; confirmed TPs still reported), and wire the class into the per-class release-blocking gate so a precision regression fails the build alone (FR-012; C6)
- [X] T018 [US3] Add an integration scan over the reference fixture workspace in `tests/integration/` asserting the end-to-end outcome: only format-confirmed and genuinely ambiguous credential findings are published, suppression decisions appear in scan artifacts with file/line/rule/reason, and the artifact redaction sweep still passes over all artifacts containing the new fields (FR-004; SC-001, SC-002, SC-004, SC-005; C5)

**Checkpoint**: User Story 3 complete — precision and recall are both build-gated per defect class

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Full-gate verification across all stories

- [X] T019 Run `pytest -q && ruff check src tests` from the repository root; all green with zero recall reduction across every suite (constitution merge gate)
- [X] T020 [P] Run the two-run byte-identical artifact comparison on a fixture scan to confirm determinism is preserved after the redactor changes (constitution Safety Invariant; Principle I)
- [X] T021 [P] Review `README.md` status claims against the shipped behavior and update only if the detection-precision claims are now stale (constitution: honest documentation)
- [X] T022 Execute every scenario in `quickstart.md` end-to-end and confirm each expected outcome (SC-001 through SC-006)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately
- **Foundational (Phase 2)**: Depends on T001 — BLOCKS all user stories
- **US1 (Phase 3)**: Depends on Phase 2
- **US2 (Phase 4)**: Depends on Phase 2; touches different files than US1 (`secret_findings.py`, `verify.py`, `stacks.py` vs `redact.py`) and can run parallel with US1 if staffed
- **US3 (Phase 5)**: Depends on Phase 2; T015 (audit) is independent of all code tasks and can start immediately; T016–T018 assert the fixed behavior and are only satisfiable after US1/US2
- **Polish (Phase 6)**: Depends on all completed stories

### User Story Dependencies

- **US1 (P1)**: No story dependencies — MVP
- **US2 (P2)**: Independent of US1 (different pipeline stages); shares only the Phase 2 decision record
- **US3 (P3)**: Depends on US1's corpus fixtures (T004) and asserts US1+US2 end state; its audit task (T015) is fully independent

### Within Each User Story

- Tests written first and verified failing before implementation (constitution test-first gate)
- Fixtures before tests; tests before implementation
- If a precision change forces a recall failure, the implementation is wrong — recall wins (Principle III)

### Parallel Opportunities

- T003 ∥ T004 (different fixture files)
- T009 ∥ T010 ∥ T011 (different test files)
- US1 ∥ US2 as whole stories (disjoint implementation files)
- T015 ∥ everything (manual audit against the skh checkout)
- T016 ∥ T017 (different test files)
- T020 ∥ T021 in Polish

---

## Parallel Example: User Story 1

```bash
# Launch fixtures together:
Task: "Create tests/fixtures/credential_corpus.py ..."          # T003
Task: "Extend tests/fixtures/identifier_corpus.py ..."          # T004

# Then the failing test task (T005), then implementation T006 → T007 → T008
```

## Parallel Example: User Story 2

```bash
# Launch all failing-test tasks together:
Task: "... test_secret_findings.py provenance/confidence ..."   # T009
Task: "... test_verify.py narrowed auto-verify ..."             # T010
Task: "... contract/test_finding_schema.py additive fields ..." # T011

# Then T012 (data) → T013 (emission) → T014 (verification/propagation)
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 (T001) + Phase 2 (T002)
2. Complete Phase 3 (T003–T008)
3. **STOP and VALIDATE**: `pytest -q tests/unit/test_redact.py` green; the SEC-0085 fixture class silent, recall 100%
4. This alone removes the largest false-positive class — demoable as the MVP

### Incremental Delivery

1. Setup + Foundational → decision records ready
2. US1 → identifier/message FPs eliminated → validate → deliver (MVP)
3. US2 → honest confidence/verification grading → validate → deliver
4. US3 → permanent build gate with audited baseline → validate → deliver

---

## Notes

- [P] tasks = different files, no dependencies on incomplete tasks
- [USn] label maps each task to its spec user story for traceability
- Tests MUST fail before implementation; verify the failure is for the intended reason
- Recall is constitutionally non-negotiable: any conflict between a false positive and a false negative resolves toward reporting
- Commit after each task or logical group; stop at any checkpoint to validate the story independently
