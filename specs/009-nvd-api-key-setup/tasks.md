---

description: "Task list for feature implementation"
---

# Tasks: NVD API Key Setup During Initialization

**Input**: Design documents from `/specs/009-nvd-api-key-setup/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: INCLUDED — the constitution mandates test-first ("Tests are written before implementation and MUST fail first"). Contract tests guard the additive registry/artifact schema changes.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- Single project: `src/`, `tests/` at repository root
- Code: `src/pipeline/init_cmd.py`, `src/pipeline/tooling/` per plan.md
- Registry data: `src/skill_core/data/tools.json` per research.md R3
- Tests reuse feature-008 shims/fixtures (`tests/fixtures/tooling_workspace/`, `tests/helpers/tool_shims.py`) — the `multi_eco/` and `project_provided/` workspaces make `owasp-dependency-check` applicable

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Declarative data and the non-interactive opt-in flag plumbing that every story consumes

- [X] T001 Add the optional `credential` block to the `owasp-dependency-check` entry in `src/skill_core/data/tools.json`: `env_var: "NVD_API_KEY"`, `obtain_url: "https://nvd.nist.gov/developers/request-an-api-key"`, and `absence_impact` carrying the FR-004 implication text (rate-limited, much slower first NVD sync, intermittent sync failures) — data only per research.md R3/data-model.md §1; no other entries gain a block
- [X] T002 Extend the init CLI in `src/pipeline/init_cmd.py` with the `--allow-keyless-nvd` argparse flag and thread `allow_keyless_nvd: bool = False` through `main()` into `run_init()` per contracts/init-nvd-credential.md §1 — signature/plumbing only, no behavior change yet

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The registry `credential` block parsing/validation and the pure credential-decision module — every user story consumes both

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T003 [P] Extend contract tests in `tests/contract/test_tool_registry.py` for the `credential` block per contracts/init-nvd-credential.md §3: block optional; when present all of `env_var`/`obtain_url`/`absence_impact` required; `env_var` matches uppercase env-name shape; `obtain_url` is `https://`; malformed blocks aggregate problems like existing `RegistryError` style; the shipped `tools.json` block on `owasp-dependency-check` validates — MUST FAIL (registry ignores the block today)
- [X] T004 [P] Write unit tests in `tests/unit/test_tooling_credentials.py` for the pure module per research.md R6/R7: `key_present(spec, environ)` (unset, empty, whitespace-only ⇒ absent; non-empty ⇒ present); `warning_text(spec)` includes the registry `absence_impact` and `obtain_url`; `guidance_text(spec)` instructs setting the variable by name and NEVER solicits a value — MUST FAIL (module does not exist)
- [X] T005 Implement credential-block parsing + strict validation in `src/pipeline/tooling/registry.py`: frozen `CredentialSpec` dataclass on `ToolEntry` (`credential: CredentialSpec | None`), validation rules from data-model.md §1 aggregated through `RegistryError`, deterministic as today — T003 passes
- [X] T006 Implement `src/pipeline/tooling/credentials.py`: pure, injected-`environ` helpers `key_present()`, `warning_text()`, `guidance_text()` and the closed `CredentialState` string constants (`available` / `awaiting-key` / `degraded-no-key` / `skipped-no-key`) per data-model.md §2 — T004 passes

**Checkpoint**: Foundation ready — registry knows which tools are NVD-backed and the credential decision logic is unit-proven; user story implementation can now begin

---

## Phase 3: User Story 1 - Provide an NVD API key during initialization (Priority: P1) 🎯 MVP

**Goal**: When `NVD_API_KEY` is present, init detects it by name and reports the NVD-backed tool as available with no prompt; when the user chooses "provide a key" mid-init, init installs/configures the tool wired by variable name, reports `awaiting-key`, and a later re-run upgrades to `available`.

**Independent Test**: quickstart.md Scenario 1 and the "provide" sub-case of Scenario 2 pass; no credential prompt appears when the key is set.

### Tests for User Story 1 (write FIRST, confirm FAIL)

- [X] T007 [P] [US1] Integration test in `tests/integration/test_tooling_init.py`: with `NVD_API_KEY` set in the injected environ against a maven fixture, init emits NO credential prompt, the report carries the `available` line (including the presence-not-validity note, FR-003), and `.security-scan/tooling/availability.json` annotates exactly the `owasp-dependency-check` record with `credential: {"variable": "NVD_API_KEY", "state": "available"}` — MUST FAIL
- [X] T008 [US1] Integration test in `tests/integration/test_tooling_init.py` for the install-and-wire path (research R5/R7): keyless interactive run whose prompt stub answers "provide" — guidance references `obtain_url` and instructs setting `NVD_API_KEY` without ever asking for a value, the tool installs via shims, record shows `credential.state: "awaiting-key"`; a re-run with the key then set upgrades the state to `available` without reinstalling — MUST FAIL

### Implementation for User Story 1

- [X] T009 [US1] Implement presence detection + record annotation in `src/pipeline/init_cmd.py` `_tooling_flow`: for each applicable entry carrying a `credential` block (including already-installed tools per FR-001), compute the state via `tooling/credentials.py` and attach `credential: {variable, state}` to the availability record before `write_availability` (records for other tools never gain the object); render the informational check lines from data-model.md §4 (all `required=False` — readiness never flips) covering FR-001, FR-002, FR-003, FR-007, FR-011 — T007 passes
- [X] T010 [US1] Implement the interactive "provide a key" branch in `src/pipeline/init_cmd.py`: on that choice echo `guidance_text()` and proceed with installation/configuration wired by name only, recording `awaiting-key` (state re-derived each run, never persisted as sticky — research R5; nothing about the key value is read, echoed, or written, FR-005c/FR-011) — T008 passes

**Checkpoint**: User Story 1 fully functional and independently testable — key-present and provide-key flows report honest states with zero secret handling

---

## Phase 4: User Story 2 - Initialize without an NVD API key, informed choice (Priority: P2)

**Goal**: Keyless interactive init warns with the registry-declared implication BEFORE any install of the NVD-backed tool and offers skip / proceed-degraded / provide; skip never counts as failure and re-running later with a key installs normally.

**Independent Test**: quickstart.md Scenario 2 skip and proceed sub-cases pass; the warning provably precedes any install invocation.

### Tests for User Story 2 (write FIRST, confirm FAIL)

- [X] T011 [P] [US2] Integration test in `tests/integration/test_tooling_init.py`: keyless interactive run whose prompt stub answers "skip" — no install of the tool is attempted (shim harness asserts), record shows `decision: "skipped-no-key"` + `credential.state: "skipped-no-key"`, `InitReport.ready` is still true in the zero-config case, and the report names the tool as skipped WITH the how-to-add-later note (FR-006, FR-008) — MUST FAIL
- [X] T012 [US2] Integration test in `tests/integration/test_tooling_init.py`: keyless interactive run answering "proceed" — the `absence_impact` warning is captured by the echo stub BEFORE the shim records any install invocation; tool installs; record carries `credential.state: "degraded-no-key"`. Same test also covers the pre-existing-installation edge case (spec Edge Cases): with `dependency-check.sh` already shimmable on PATH and no key set, the presence check still runs, NO install-side prompt is issued, and the report renders the informational `degraded-no-key` line — MUST FAIL

### Implementation for User Story 2

- [X] T013 [US2] Implement the warning + three-choice protocol in `src/pipeline/init_cmd.py` `_tooling_flow` per contracts/init-nvd-credential.md §2: when an NVD-backed tool is keyless and init is interactive, echo `warning_text()` (absence impact + obtain_url) before that tool's installation begins, then accept skip / proceed / provide per tool (FR-004, FR-005a/b) — T012 passes
- [X] T014 [US2] Implement skip semantics in `src/pipeline/init_cmd.py`: "skip" excludes the tool from the install selection (works alongside the existing `--install`/`resolve_selection` machinery interactively), writes the new closed decision value `skipped-no-key` on the missing record plus mirrored `credential.state`, leaves readiness untouched, and a later run with the key set installs the tool normally (FR-006, FR-008) — T011 passes

**Checkpoint**: User Stories 1 AND 2 both work independently — every keyless interactive path is warned, chosen, and honestly recorded

---

## Phase 5: User Story 3 - Non-interactive initialization behaves deterministically (Priority: P3)

**Goal**: Headless init never waits for a credential answer; keyless NVD-backed tools default to `skipped-no-key` with declared reason in every non-prompting context, and only the explicit `--allow-keyless-nvd` flag permits a degraded keyless install.

**Independent Test**: quickstart.md Scenarios 3 and 5 pass with zero prompts issued.

### Tests for User Story 3 (write FIRST, confirm FAIL)

- [X] T015 [P] [US3] Integration test in `tests/integration/test_tooling_init.py`: keyless runs with `--no-input` and with a non-TTY stdin (no prompt callable) never invoke the credential prompt, record `skipped-no-key` with the declared reason, and exit success (FR-009) — MUST FAIL
- [X] T016 [US3] Integration test in `tests/integration/test_tooling_init.py`: blanket consent keyless — `--yes` and `--install=all` WITHOUT the flag filter the NVD-backed tool out of the selection (`skipped-no-key`); WITH `allow_keyless_nvd=True` the tool installs and records `degraded-no-key`; the flag NEVER widens the tool selection itself (FR-010, quickstart Scenario 6) — MUST FAIL

### Implementation for User Story 3

- [X] T017 [US3] Implement non-interactive keyless handling in `src/pipeline/init_cmd.py` `_tooling_flow`: in every non-prompting context (`--no-input`, non-TTY guard, `--yes`, `--install` driven selections) remove keyless NVD-backed tools from the selection and record `skipped-no-key` unless `allow_keyless_nvd` (from T002) is set, in which case install and record `degraded-no-key` (FR-009, FR-010) — T015, T016 pass

**Checkpoint**: All user stories independently functional — interactive and headless flows both honor the four honest credential states

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Constitutional invariants and documentation that span stories

- [X] T018 [P] Extend `tests/contract/test_tooling_artifacts.py` for the additive availability field per contracts/init-nvd-credential.md §4: records with and without `credential` validate; `credential.state` is the closed four-value enum; `decision` vocabulary gains exactly `skipped-no-key`
- [X] T019 [P] Write the secret-hygiene sweep in `tests/integration/test_nvd_key_redaction.py`: run init (shims, `--yes`, key set to a distinctive sentinel) and assert the sentinel appears in NO file under `.security-scan/` and NOT in the rendered report/stdout (SC-004, Principle III)
- [X] T020 [P] Extend `tests/integration/test_tooling_determinism.py`: two init runs with identical injected environment (both key-set and keyless variants) produce byte-identical `tooling/availability.json` (Principle I byte-identity invariant)
- [X] T021 [P] Update `README.md` init documentation: NVD_API_KEY behavior (set the variable; init detects by name; presence-only check), the four credential states, and `--allow-keyless-nvd` — honest documentation gate
- [X] T022 Run the full verification gates: `pytest` green, `ruff check src tests` clean, contract suite green; then walk quickstart.md Scenarios 1–6 end-to-end

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup (T001 data feeds registry validation tests) - BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Foundational phase completion
  - US2 and US3 share the `_tooling_flow` edit surface with US1 — sequential per story is the safe order (P1 → P2 → P3); parallel staffing must serialize on `src/pipeline/init_cmd.py`
- **Polish (Final Phase)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 2 (P2)**: Can start after Foundational (Phase 2) - integrates into the same prompt flow built in US1 (T010), should still be independently testable via its own stubbed prompt answers
- **User Story 3 (P3)**: Can start after Foundational (Phase 2) - reuses the states/annotation from US1 and the flag from Setup (T002), independently testable headless

### Within Each User Story

- Tests MUST be written and FAIL before implementation
- Pure module/registry changes (Foundational) before init-flow changes
- Story complete before moving to next priority

### Parallel Opportunities

- T003 and T004 (contract + unit tests, different files) run in parallel
- T007 || T008 would conflict on the same test file — keep sequential within the file (as ordered)
- US2's T011/T012 and US3's T015/T016 likewise share `test_tooling_init.py` — sequential within each story as ordered
- All Polish tasks T018–T021 run in parallel (four different files)

---

## Parallel Example: Foundational Phase

```bash
# Write both failing test suites together (different files):
Task: "Extend contract tests in tests/contract/test_tool_registry.py for the credential block"
Task: "Write unit tests in tests/unit/test_tooling_credentials.py for the pure credentials module"
```

## Parallel Example: Polish Phase

```bash
# Four independent files, launch together:
Task: "Contract-test the additive availability credential field in tests/contract/test_tooling_artifacts.py"
Task: "Write sentinel redaction sweep in tests/integration/test_nvd_key_redaction.py"
Task: "Extend byte-identity init tests in tests/integration/test_tooling_determinism.py"
Task: "Document NVD key behavior in README.md"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (data block + flag plumbing)
2. Complete Phase 2: Foundational (registry parse/validate + pure credentials module) — CRITICAL, blocks all stories
3. Complete Phase 3: User Story 1 (key-present + provide-key paths)
4. **STOP and VALIDATE**: quickstart Scenarios 1 and 2(provide) pass independently
5. A keyless user still gets a safe outcome at this point (existing init flow unchanged for them until US2/US3 land — degraded behavior is today's status quo, declared in the report)

### Incremental Delivery

1. Setup + Foundational → registry knows NVD-backed tools; credential logic unit-proven
2. Add US1 → happy path + awaiting-key → validate → MVP
3. Add US2 → informed keyless choice (the spec's headline ask) → validate
4. Add US3 → headless determinism and blanket-consent filtering → validate
5. Polish → invariants (redaction sweep, byte-identity, contracts) + docs

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- The NVD_API_KEY VALUE never enters any code path: tests use sentinels only to prove absence (T019)
- `skipped-no-key` is the ONLY new decision value; all credential nuance lives in `credential.state` (research.md R4 precedence note)
- Verify each story's new tests fail before its implementation tasks
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Avoid: editing `provision.py` (selection filtering happens in `_tooling_flow` BEFORE it), embedding key-format validation (forbidden by FR-003), sticky skip state (spec edge case: re-run must install normally)
