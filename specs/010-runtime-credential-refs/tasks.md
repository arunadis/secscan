---

description: "Task list for feature 010 implementation"
---

# Tasks: Runtime Credential References Are Not Hard-Coded Credentials

**Input**: Design documents from `/specs/010-runtime-credential-refs/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/detection-contracts.md, quickstart.md

**Tests**: INCLUDED — the constitution mandates test-first ("Tests are written before
implementation and MUST fail first"); every test task must be verified failing before its
implementation task begins. Recall tests (contract R3) are the exception that must be green
*before and after*: they are the floor, not the feature.

**Organization**: Tasks are grouped by user story (US1 P1 → US2 P2 → US3 P3) so each is
independently implementable and testable. Every task cites the requirement/contract it
discharges.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3)
- Requirement citations use spec FR numbers, contract IDs R1–R6 from
  `contracts/detection-contracts.md`, and research decisions R1–R7 from `research.md`
  (prefixed `research` where ambiguous)

## Path Conventions

- Single project: `src/pipeline/`, `src/skill_core/schemas/`, `tests/` at repository root
- Existing files referenced: `src/pipeline/redact.py`, `src/pipeline/reproduce.py`,
  `src/skill_core/schemas/context_packet.json`, `tests/fixtures/credential_corpus.py`,
  `tests/fixtures/identifier_corpus.py`, `tests/unit/test_redact.py`,
  `tests/unit/test_false_positive_corpus.py`, `tests/unit/test_reproduce_honesty.py`,
  `tests/benchmark/test_accuracy_benchmark.py`, `tests/benchmark/cases/*.json`,
  `tests/integration/test_credential_precision.py`, `docs/security-model.md`

---

## Phase 1: Setup

**Purpose**: Establish a verified-green starting point and pin the recall floor before any detector change.

- [X] T001 Run `pytest -q && ruff check src tests` from the repository root and confirm green; run the quickstart §1 snippet from `specs/010-runtime-credential-refs/quickstart.md` and record that the first six lines currently yield `assigned-secret` hits and `"${SKILLHUNT_PORTAL_BACKEND_PROD_DB_PASSWORD_2024_v3}"` yields `high-entropy-secret` (baseline for SC-001; research "Baseline measurements")
- [X] T002 Run only the recall floor — `pytest -q tests/unit/test_redact.py tests/benchmark/test_accuracy_benchmark.py -k "credential or redact"` — and confirm every entry of `tests/fixtures/credential_corpus.py` is detected; this set MUST remain green unmodified-in-expectation through the feature (FR-006, contract R3)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Extend the recall corpus FIRST so the new exemption is developed against the tightened floor, and open the artifact schema for the new decision kind.

**⚠️ CRITICAL**: T003–T005 must land before any exemption code in Phase 3.

- [X] T003 Extend `CREDENTIALS` in `tests/fixtures/credential_corpus.py` with must-find reference-look-alike literals (FR-007, FR-013, contract R3): `password: "${DB_PASSWORD:-hunter2hunter2}"`, `password: "${DB_PASSWORD:=hunter2hunter2}"`, `password: "${DB_PASSWORD:+hunter2hunter2}"`, `password = "$PREFIX-hunter2hunter2"`, `password = "hunter2hunter2$SUFFIX"`, `password = "pa$$w0rd-really-long"`, `password = "${NAME"`, `password = "%NAME"`, `key: "${AKIAIOSFODNN7EXAMPLE}"` — each with an `origin` under a production path and a `why` naming the look-alike class; run T002 again and record that the `${…:-hunter2hunter2}`, `:=`, `:+` entries currently FAIL (the recall hole research R3 closes) while the others pass
- [X] T004 [P] Add `"exempt-reference"` to the `redaction.exempted_items[].decision` enum in `src/skill_core/schemas/context_packet.json`; do not touch `schema_version` (additive, contract R5, research R6)
- [X] T005 [P] Add a contract test in `tests/contract/` (alongside the existing context-packet schema test) asserting a packet whose `exempted_items` contains `decision: "exempt-reference"` validates and one containing `decision: "exempt-location"` is REJECTED (that decision never reaches an artifact per data-model.md); verify the first assertion fails before T004 and passes after (contract R5)

**Checkpoint**: recall corpus tightened (with three known-red entries awaiting Phase 3), schema open.

---

## Phase 3: User Story 1 — Runtime references are not reported as hard-coded credentials (Priority: P1) 🎯 MVP

**Goal**: A quoted value that is entirely runtime indirection (`"$VAR"`, `"${VAR}"`, `"%VAR%"`, `"{{ x }}"`, `"${{ secrets.X }}"`, `"$(…)"`, punctuation-joined compositions, `${X:?msg}`) is left visible, recorded as an `exempt-reference` decision, and never becomes a finding — on both the assignment and entropy paths — while every literal, malformed reference, or `:-`/`:=`/`:+` literal operand is still redacted and reported.

**Independent Test**: `pytest -q tests/unit/test_redact.py tests/unit/test_false_positive_corpus.py tests/unit/test_secret_findings.py tests/integration/test_credential_precision.py` green; quickstart §1 and §2 both print `OK`.

### Tests for User Story 1 (write first, verify failing)

- [X] T006 [P] [US1] Create `tests/fixtures/runtime_reference_corpus.py` exporting `REFERENCES: tuple[tuple[str, str, str], ...]` of `(origin, line, why)` (data-model "RuntimeReferenceCorpusEntry"; FR-012; research R7) containing: the three `skh` lines verbatim — `export AWS_SECRET_ACCESS_KEY="$AWS_DEVIN_PROD_SECRET_ACCESS_KEY"` at `skillhunt-portal-backend/migration/p0/verify-account.sh`, `AWS_ACCESS_KEY_ID="$OLD_AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$OLD_AWS_SECRET_ACCESS_KEY" aws route53 list-hosted-zones --query 'HostedZones[].{Id:Id,Name:Name}' || true` at `skillhunt-portal-backend/migration/p8/preflight-check.sh`, `AWS_ACCESS_KEY_ID="$NEW_AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$NEW_AWS_SECRET_ACCESS_KEY" query 985444478718 "$OUT_DIR/cost-new.json"` at `skillhunt-portal-backend/migration/p9/cost-compare.sh`; one entry per family — `secret = "${ENV_SECRET}"`, `password: "%DB_PASSWORD%"`, `secret: "{{ vault_secret }}"`, `token: "${{ secrets.GH_TOKEN }}"`, `api_key = "$(cat /run/secrets/key)"`; compositions `AUTH_TOKEN="$DB_USER:$DB_PASSWORD"`, `password: "${HOST}/${TOKEN}"`; operands `password: "${DB_PASSWORD:-}"`, `password: "${DB_PASSWORD:-$FALLBACK_PASSWORD}"`, `password: "${DB_PASSWORD:-changeme}"`, `password: "${DB_PASSWORD:?DB_PASSWORD is required}"`; entropy-path case `export DB_PASSWORD="${SKILLHUNT_PORTAL_BACKEND_PROD_DB_PASSWORD_2024_v3}"`; each `why` names the family (contract R1)
- [X] T007 [P] [US1] Add unit tests to `tests/unit/test_redact.py` for `classify_runtime_reference` (contract R1): parametrize the MUST-classify and MUST-NOT-classify lists from `contracts/detection-contracts.md` §R1 verbatim; assert returned `RuntimeReference.families` and `.names` for `$DB_USER:$DB_PASSWORD` (`("shell-bare","shell-bare")`, `("DB_USER","DB_PASSWORD")`) and `.operators == (":?",)` for `${DB_PASSWORD:?DB_PASSWORD is required}`; assert determinism (two calls, identical result) — verify failing (ImportError)
- [X] T008 [P] [US1] Add unit tests to `tests/unit/test_redact.py` for the redaction-layer exemption (contract R2, FR-005a): for each `REFERENCES` entry, `result.text == line`, `result.hits == []`, `result.blocked == 0`, exactly one `exempted` decision with `decision == "exempt-reference"`, `classification.startswith("runtime-reference:")`, `origin`/`line`/`reason` set; assert the entropy-path entry records `rule == "entropy-candidate"` and the others `rule == "assigned-secret"`; assert `reason` contains the referenced name for `$AWS_DEVIN_PROD_SECRET_ACCESS_KEY` — verify failing
- [X] T009 [P] [US1] Extend `tests/unit/test_false_positive_corpus.py` to iterate `REFERENCES` in both existing tests: zero findings from `findings_from_hits`, zero blocked, and every decision has `decision in ("exempt-identifier", "exempt-message", "exempt-reference")` (FR-005, FR-012) — verify failing
- [X] T010 [P] [US1] Add fixture files and assertions to `tests/integration/test_credential_precision.py` (FR-000 — path-agnostic; SC-001, SC-004): add `migration/p0/verify-account.sh` containing the SEC-0080 `use_prod`/`use_dev` functions verbatim from the spec, and `deploy/docker-compose.yml` with `DB_PASSWORD: "${DB_PASSWORD:?DB_PASSWORD is required}"` and `API_TOKEN: "%API_TOKEN%"`; assert no CWE-798 finding has `location.file` under `migration/` or `deploy/`; assert at least one context packet's `redaction.exempted_items` contains an `exempt-reference` decision whose `origin` ends with `verify-account.sh`; assert the existing `GOOGLE_KEY` finding is unchanged — verify failing

### Implementation for User Story 1

- [X] T011 [US1] Implement the reference grammar in `src/pipeline/redact.py` (research R1, R2, R3; data-model "RuntimeReference"): add `@dataclass(frozen=True) class RuntimeReference(families, names, operators)` and `classify_runtime_reference(value: str) -> RuntimeReference | None` performing a left-to-right scan that consumes one family at each position — `shell-bare` `\$[A-Za-z_]\w*`, `shell-braced` `\$\{` name `[:]?[-=+?]` operand `\}` with balanced braces, `shell-subst` `\$\(`…`\)` balanced or backtick pair, `batch` `%[A-Za-z_]\w*%`, `template` `\{\{`…`\}\}` balanced, `ci-expr` `\$\{\{`…`\}\}` (checked before `template`/`shell-braced`) — allows only non-alphanumeric characters between expressions, fails on any alphanumeric outside an expression or on unbalanced delimiters, evaluates `:-`/`-`/`:=`/`=`/`:+`/`+` operands recursively (pass if empty, `_is_placeholder`, or itself classifies) and discards `:?`/`?` operands; return `None` if no expression was consumed
- [X] T012 [US1] Narrow `_PLACEHOLDER` in `src/pipeline/redact.py` by removing the `\$\{[^}]*\}` alternative (research R1/R3 — it is the recall hole) so braced references are handled only by `classify_runtime_reference`; confirm `test_placeholders_are_not_redacted` in `tests/unit/test_redact.py` still passes for `secret = "${ENV_SECRET}"` once T013 lands (contract R3 last bullet)
- [X] T013 [US1] Wire the assignment-path exemption in `Redactor.redact` in `src/pipeline/redact.py` (research R4, FR-001, FR-005, FR-005a, FR-008): in the rules loop, after `_is_placeholder`, when `rule.label == "assigned-secret"` and `classify_runtime_reference(value)` returns a reference, append `ExemptionDecision(origin, line_no_for(text, start), rule="assigned-secret", value, classification="runtime-reference:" + ",".join(sorted(set(ref.families))), reason=f"every letter and digit lies inside a well-formed {family} reference to {names}; a reference exposes an environment-variable name, not a value", decision="exempt-reference")` and `continue`; format-rule labels MUST NOT consult the classifier
- [X] T014 [US1] Wire the entropy-path exemption in `Redactor.redact` in `src/pipeline/redact.py` (research R4, FR-001): before `_has_credential_context`, locate the enclosing quoted literal (or bare token) around the candidate span on its line and, if that enclosing value classifies via `classify_runtime_reference` and the candidate lies inside one of its expressions, record the same `exempt-reference` decision with `rule="entropy-candidate"` and `continue`; add a module docstring paragraph explaining why both paths need it (the `${SKILLHUNT_…_v3}` measurement)
- [X] T015 [US1] Update the `ExemptionDecision.classification` and `.decision` field comments in `src/pipeline/redact.py` to list `runtime-reference:<family>` / `exempt-reference` alongside the existing values (data-model "ExemptionDecision"); confirm `src/pipeline/build_context.py` serialises the new decision with no code change
- [X] T016 [US1] Run T002, T003 recall tests plus T007–T010 and confirm all green, including the three previously-red `${…:-/:=/:+ hunter2hunter2}` entries (FR-006, FR-007, contract R3); run `ruff check src tests`

**Checkpoint**: SEC-0080/0082/0084 lines produce no hit and an inspectable `exempt-reference` decision; recall corpus fully green with the tightened floor. MVP deliverable.

---

## Phase 4: User Story 2 — Report text never redacts its own file paths (Priority: P2)

**Goal**: The reproduction block names the finding's file and symbol verbatim even when the path is long and the line names a credential symbol; credential values in the same text are still redacted; format-rule matches are never protected.

**Independent Test**: `pytest -q tests/unit/test_reproduce_honesty.py tests/unit/test_redact.py -k "known_safe or location"` green; quickstart §3 prints the full path.

### Tests for User Story 2 (write first, verify failing)

- [X] T017 [P] [US2] Add unit tests to `tests/unit/test_redact.py` for `Redactor.redact(text, origin, known_safe=(...))` (contract R4, FR-009, FR-010): (a) `"Inspect skillhunt-portal-backend/migration/p0/verify-account.sh#AWS_SECRET_ACCESS_KEY in a local checkout"` with `known_safe=("skillhunt-portal-backend/migration/p0/verify-account.sh", "AWS_SECRET_ACCESS_KEY")` returns unchanged text and one decision `decision == "exempt-location"`, `classification == "location-token"`; (b) the same text with an appended `Xh8Kq2Lm9Rt4Wv7Zy1Bc3Df6Gj0Np5Sa` still redacts that value; (c) `known_safe=("AKIAIOSFODNN7EXAMPLE",)` on text containing that token still yields an `aws-access-key` redaction (format rules win); (d) `known_safe=()` output is byte-identical to a call without the argument; (e) a location token that today produces `[BLOCKED:unclassified-secret]` (a 24+ char path segment with a capital run and no identifier shape, e.g. `build/ABCDEFGHJKLMNPQRSTUVWXYZ2345/out.sh`, on a line with no credential context) is preserved verbatim with an `exempt-location` decision whose `reason` states the token is already published unredacted in the finding's structured location — verify failing (TypeError)
- [X] T018 [P] [US2] Add tests to `tests/unit/test_reproduce_honesty.py` (contract R4, FR-011): build a CWE-798 finding at `skillhunt-portal-backend/migration/p0/verify-account.sh#AWS_SECRET_ACCESS_KEY` with `verification.status == "verified"`; assert the path and symbol appear verbatim in `block["trigger"]` and `"[REDACTED" not in block["trigger"]`; assert a CWE-798 finding whose `location.symbol` is a 30-char high-entropy string still gets it preserved (it is a symbol from the code model) while a seeded credential value injected via a monkeypatched `_build_parts` is redacted — verify failing

### Implementation for User Story 2

- [X] T019 [US2] Add `known_safe: Sequence[str] = ()` to `Redactor.redact` in `src/pipeline/redact.py` (research R5; data-model "Protected span"): compute protected spans as every non-overlapping occurrence of each non-empty token (`str.find` loop, deterministic order); in the entropy loop, before context/shape checks, if the candidate span overlaps a protected span record `ExemptionDecision(rule="entropy-candidate", classification="location-token", reason=f"inside scanner-composed location token {token!r}; already published unredacted in the finding's location", decision="exempt-location")` and `continue`; rule-pack spans are never affected; thread the parameter through `redact_mapping` unchanged (default)
- [X] T020 [US2] In `build_reproduction` in `src/pipeline/reproduce.py`, build `known_safe = tuple(t for t in (location.get("repo"), location.get("file"), location.get("symbol"), where) if t)` and pass it to every `redactor.redact(...)` call in the backstop loop (FR-009, FR-011); update the "Backstop" comment to state that location tokens are protected from heuristic redaction only
- [X] T021 [US2] Add an assertion to `tests/integration/test_credential_precision.py` (and `tests/integration/test_report_artifacts.py` if it iterates findings) that for every CWE-798 finding, `location["file"]` occurs verbatim in `reproduction["trigger"]` or `reproduction["trigger_omitted_reason"]`, and that for every finding of any CWE, no reproduction field (`preconditions`, `trigger`, `expected_behavior`, `observed_behavior`, `outcome_to_check`, `trigger_omitted_reason`) contains `[REDACTED` or `[BLOCKED` immediately adjacent to a path separator or `#` (i.e. no location token was consumed) (contract R4 last bullet, FR-011, SC-005); run and confirm green
- [X] T022 [US2] Run `pytest -q tests/unit/test_reproduce_honesty.py tests/unit/test_redact.py tests/integration/test_credential_precision.py tests/integration/test_report_artifacts.py` and `ruff check src tests`; confirm green

**Checkpoint**: reproduction text is readable and consistent with structured location; values still redacted.

---

## Phase 5: User Story 3 — Regression guard for runtime-reference precision (Priority: P3)

**Goal**: The build fails if a runtime reference is ever reported, a look-alike literal is ever missed, or a location token is ever redacted from report prose; the `skh` baseline audit records the three findings as false positives.

**Independent Test**: `pytest -q tests/benchmark/test_accuracy_benchmark.py -k credential_precision` green, and deliberately re-adding `\$\{[^}]*\}` to `_PLACEHOLDER` or removing the T013 branch turns it red.

- [X] T023 [P] [US3] Record SEC-0080, SEC-0082, SEC-0084 in `tests/benchmark/cases/audited_credential_baseline.json` under a new top-level `follow_up_scans` block (`feature: "010-runtime-credential-refs"`, `audited`, `scan_id`, `entries`), each with `verdict: "false-positive"`, location `skillhunt-portal-backend/migration/p0/verify-account.sh:47` / `p8/preflight-check.sh:336` / `p9/cost-compare.sh:31`, and a `rationale` naming the shell-bare runtime reference. NOT appended to `entries`: the labels collide with the 2026-08-31 scan's own SEC-0080/0082/0084, which are different findings; `entries` stays at 23 (contract R6, FR-014)
- [X] T024 [P] [US3] Add a second expectation object to `tests/benchmark/cases/credential_precision.json` with `defect_class: "credential-precision"`, `assertion` naming runtime-reference assignments (`"$VAR"`, `"%VAR%"`, `"{{ }}"`, `"${{ }}"`, `"$( )"`) as must-not-find and reference-look-alike literals as must-find, and `baseline: "feature 010 review: SEC-0080/0082/0084 — env-var references published as verified CWE-798 at 0.95"` (FR-014)
- [X] T025 [US3] Update `test_defect_class_credential_precision` in `tests/benchmark/test_accuracy_benchmark.py` (contract R6, FR-012–FR-014): keep the 23-entry integrity assertion and add one for the `follow_up_scans` block (exactly one block, `feature == "010-runtime-credential-refs"`, labels `["SEC-0080", "SEC-0082", "SEC-0084"]`, all `false-positive`, rationale mentions "runtime reference"); on the FP side additionally iterate `tests.fixtures.runtime_reference_corpus.REFERENCES` asserting `result.hits == []` and `not findings_from_hits(...)`; on the TP side the existing loop over the extended `CREDENTIALS` now covers FR-013 — add an explicit assertion that the `${…:-hunter2hunter2}` entry is detected (the recall gain), and a report-text assertion that `build_reproduction` for a CWE-798 finding at a 60-char slash-joined path keeps the path verbatim (SC-005)
- [X] T026 [US3] Mutation check (FR-014, contract R6): temporarily re-add `\$\{[^}]*\}` to `_PLACEHOLDER` in `src/pipeline/redact.py` and confirm `pytest -q tests/benchmark/test_accuracy_benchmark.py -k credential_precision` fails (first on the `${ENV_SECRET}` corpus entry losing its exempt-reference decision; the `${…:-hunter2hunter2}` must-find is also lost); revert; temporarily comment out the T013 branch and confirm it fails on the `REFERENCES` must-not-find; revert; record both outcomes in the test's docstring

**Checkpoint**: the guard is proven to bite in both directions.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [X] T027 [P] Update `docs/security-model.md` (redaction section) with a paragraph on runtime references — the six families, the "every letter and digit inside a reference" rule, `:?` vs `:-`/`:=`/`:+` operand handling, and that references stay visible in context because they expose only environment-variable names; note the closed `${X:-literal}` gap (constitution "Documentation currency")
- [X] T028 [P] Update `docs/artifacts.md` (context-packet `redaction.exempted_items` description) to list `exempt-reference` with its `runtime-reference:<family>` classification, and note that reproduction-text location tokens are protected from heuristic redaction (constitution "Documentation currency")
- [X] T029 [P] Add one sentence to `README.md` under the credential-detection / "Secrets never reach a model" bullet stating that environment-variable references (`"$VAR"`, `"${VAR}"`, `"%VAR%"`, template/CI expressions) are recognised as runtime wiring and never reported as hard-coded credentials
- [X] T030 Run the one-off confirmation scan against the `skh` workspace per `specs/010-runtime-credential-refs/quickstart.md` §6; confirm SEC-0080/0082/0084 are absent and every other baseline CWE-798 finding is present; record scan id, date, and outcome under **Assumptions → Baseline** in `specs/010-runtime-credential-refs/spec.md` (SC-003, clarification Q4) — if the workspace is unavailable, record that explicitly rather than omitting the entry
- [X] T031 Run the full gate from the repository root: `pytest -q && pytest -q -m slow && ruff check src tests`; confirm byte-identical artifacts on a two-run comparison of the integration fixture scan (constitution Safety Invariants) and that `tests/integration/test_full_scan.py::test_no_unredacted_secret_reaches_a_context_packet` and `tests/integration/test_credential_precision.py::test_no_credential_value_reaches_any_artifact` remain green with `$VAR` now visible in packets
- [X] T032 Run quickstart §1–§5 from `specs/010-runtime-credential-refs/quickstart.md` end to end and confirm every expected output; set `**Status**: Implemented` in `specs/010-runtime-credential-refs/spec.md`

---

## Dependencies & Execution Order

### Phase dependencies

- **Phase 1 (Setup)**: no dependencies — start immediately
- **Phase 2 (Foundational)**: after Phase 1; T003 MUST precede all of Phase 3 (the floor is tightened before the exemption exists); T004 ↔ T005 are a red/green pair
- **Phase 3 (US1)**: after Phase 2 — the MVP; T006–T010 (tests) before T011–T015 (implementation); T011 → T012 → T013 → T014 → T015 → T016 sequential (same file)
- **Phase 4 (US2)**: after Phase 2; independent of US1 in behaviour, but T019 edits `redact.py` so schedule after T016 to avoid merge friction; T017–T018 before T019–T020
- **Phase 5 (US3)**: after US1 and US2 (it guards both); T023 ∥ T024 then T025 → T026
- **Phase 6 (Polish)**: after all stories; T027–T029 parallel; T030 needs the `skh` workspace; T031 → T032 last

### User story dependency graph

```text
Setup ─▶ Foundational ─▶ US1 (P1, MVP) ─▶ US2 (P2) ─▶ US3 (P3) ─▶ Polish
                              │              │           ▲
                              └──────────────┴───────────┘  (US3 asserts both)
```

### Within each story

Tests written and verified failing → implementation → story-local test run → checkpoint.

---

## Parallel Execution Examples

**Phase 2**: T004 (schema) ∥ T005 (contract test) — different files.

**US1 tests**: T006 (new fixture) ∥ T007 ∥ T008 (both `test_redact.py` — write in one editing pass if the same agent; otherwise sequential) ∥ T009 (`test_false_positive_corpus.py`) ∥ T010 (`test_credential_precision.py`).

**US2 tests**: T017 (`test_redact.py`) ∥ T018 (`test_reproduce_honesty.py`).

**US3**: T023 (`audited_credential_baseline.json`) ∥ T024 (`credential_precision.json`).

**Polish**: T027 (`docs/security-model.md`) ∥ T028 (`docs/artifacts.md`) ∥ T029 (`README.md`).

---

## Implementation Strategy

**MVP = Phases 1–3 (T001–T016).** This alone removes SEC-0080/0082/0084 from every scan, closes the `${X:-literal}` recall hole, and records every exemption. It is shippable on its own.

**Increment 2 = Phase 4 (T017–T022).** Makes reproduction steps for the *remaining, genuine* credential findings readable. Small, isolated, and independently testable.

**Increment 3 = Phase 5 (T023–T026).** Locks both behaviours into the release-blocking benchmark class and proves the guard bites via mutation.

**Finish = Phase 6.** Documentation currency (a constitution gate — stale docs block merge), the one-off `skh` confirmation, and the full determinism/redaction sweep.

Recall discipline throughout: T002/T003 recall tests are run after **every** implementation task in Phases 3–4; any red there halts the feature (constitution Principle III).
