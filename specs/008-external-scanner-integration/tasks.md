---

description: "Task list for feature implementation"
---

# Tasks: External Scanner Tooling Integration

**Input**: Design documents from `/specs/008-external-scanner-integration/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: INCLUDED — the constitution mandates test-first ("Tests are written before implementation and MUST fail first") and FR-013 requires fixture ground truth under the release-blocking benchmark rule.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- Single project: `src/`, `tests/` at repository root
- New code: `src/pipeline/tooling/`, `src/pipeline/adapters/` per plan.md
- Registry data: `src/skill_core/data/tools.json` per contracts/data-contracts.md
- Fixtures: `tests/fixtures/tooling_workspace/` per quickstart.md

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Fixture scaffolding and configuration keys everything else builds on

- [X] T001 [P] Create fixture workspaces under `tests/fixtures/tooling_workspace/` per contracts in quickstart.md: `multi_eco/` (package.json + pom.xml), `project_provided/` (pom.xml declaring `org.owasp:dependency-check-maven` plugin + `mvnw` wrapper), `vuln_dep/` (package-lock.json with a seeded vulnerability beyond the bundled snapshot), `crosscheck/` (project plus recorded external report containing absent-package, version-mismatch, unresolvable-location, and true findings), `crash_tool/` (fixture where a tool shim exits 137) — each with a README noting declared ground truth
- [X] T002 [P] Create the PATH-shim harness in `tests/fixtures/tooling_workspace/shims/` and `tests/helpers/tool_shims.py`: fake executables that emit recorded tool output from `tests/fixtures/tooling_workspace/recorded/*.json` (npm audit JSON, dependency-check JSON, semgrep JSON, gitleaks JSON, osv-scanner JSON, trivy JSON), respond to version probes, and never touch the network; a helper prepends the shim dir to PATH for tests
- [X] T003 Add additive config keys in `src/config/loader.py` (and `default_config_yaml`): `tooling.install` (enum `never|ask|all`, default `ask`), `tooling.timeout_s` (default 120); strict validation rejects unknown keys and bad values, matching existing loader style

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Tool registry data + loader + ecosystem detection — every story consumes these

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T004 Write contract test `tests/contract/test_tool_registry.py` asserting the registry schema from `contracts/data-contracts.md`: `registry_version` present; unique `id`s; required fields per entry; `kind: dependency-audit` implies nonempty `covers_ecosystems`; `invoke.requires_lockfile` names a known lockfile; closed enums for `kind`, `network`, `project_local[].mechanism` — MUST FAIL (module does not exist yet)
- [X] T005 Author `src/skill_core/data/tools.json` with entries for semgrep, gitleaks, osv-scanner, trivy, npm-audit, pip-audit, govulncheck, and owasp-dependency-check, following the entry shape in contracts/data-contracts.md and the per-tool read-only invocations pinned in research.md R2 (including Dependency-Check's project-provided vs. standalone modes and out-of-project `--data`/`--out` dirs)
- [X] T006 Implement the registry loader and validator in `src/pipeline/tooling/registry.py` (load, validate against contract rules, expose entries by id/kind/ecosystem) so T004 passes; deterministic ordering of entries
- [X] T007 [P] Write unit tests in `tests/unit/test_ecosystem_detection.py` for detection over the multi_eco, project_provided, and single-ecosystem fixtures: ecosystems with evidence paths, monorepo members, and a no-manifest project returning empty — MUST FAIL
- [X] T008 Implement ecosystem detection in `src/pipeline/tooling/ecosystem.py` producing EcosystemDetection records (evidence paths, member attribution), reusing manifest enumeration from `src/pipeline/audits/offline.py` and adding Gradle (`build.gradle[.kts]`) and Maven build-file detection — T007 passes

**Checkpoint**: Foundation ready — registry loads, ecosystems detect deterministically; user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Provisioning applicable scanning tools during init (Priority: P1) 🎯 MVP

**Goal**: Init detects ecosystems, maps applicable tools via the registry, discovers project-provided instances for direct use, and installs genuinely-missing tools only after presenting the exact list for selective confirmation — without ever touching the scanned project.

**Independent Test**: quickstart.md Scenarios 1–3 (multi_eco, project_provided, consent flows) pass; project files byte-identical before/after every init run.

### Tests for User Story 1 (write FIRST, confirm FAIL)

- [X] T009 [P] [US1] Integration test for applicability output in `tests/integration/test_tooling_init.py`: multi_eco project offers npm/maven-applicable entries only, none for absent ecosystems; per-tool source + network declared (FR-001, FR-002, SC-001)
- [X] T010 [P] [US1] Integration test for project-provided discovery in `tests/integration/test_tooling_init.py`: project_provided fixture reports `project-provided` with wrapper invocation, excluded from the install list; precedence over system-installed duplicate (FR-003a, SC-007)
- [X] T011 [P] [US1] Integration test for consent flows in `tests/integration/test_tooling_init.py`: interactive list is presented before any install; selective deselection installs only the confirmed subset; `--install=all`, `--install=name,...`, `--yes`, `--no-input` semantics per contracts/cli.md; declined/skipped tools declared as limitations (FR-003)
- [X] T012 [P] [US1] Unit tests for project-local discovery rules in `tests/unit/test_tool_discovery.py`: manifest-dep, manifest-plugin, bin-path, wrapper mechanisms from research R3; undetermined compatibility is declared, not assumed (FR-003a)

### Implementation for User Story 1

- [X] T013 [US1] Implement project-local + system discovery in `src/pipeline/tooling/discover.py` returning ToolAvailabilityRecord per registry entry (source: project-provided / system-installed / missing / not-applicable; version or undetermined; precedence rule) — T012 passes (FR-002, FR-003a)
- [X] T014 [US1] Implement the consent-gated, selective provisioner in `src/pipeline/tooling/provision.py`: channel selection from `provision_channels`, installation into the canonical target — the scanner's own user-level tooling directory (outside both the scanned project and, where they differ, the payload) per research.md R4 — post-install verification via `version_probe`, honest failure reporting without blocking (FR-003, FR-004)
- [X] T038 [US1] Contract test for `.security-scan/tooling/availability.json` in `tests/contract/test_tooling_artifacts.py` asserting the schema in contracts/data-contracts.md §2 (fields, enums, tolerance of missing optional `version`/`invocation`) — MUST FAIL before T016 writes the artifact (FR-014, constitution contract-test gate)
- [X] T015 [US1] Rewrite init's scanner-tooling section in `src/pipeline/init_cmd.py`: replace the fixed `SCANNER_EXECUTABLES` probe with registry-driven applicability + discovery, add `--install`, `--yes`, `--no-input` CLI flags per contracts/cli.md, render the exact install list and per-tool source/network lines (FR-001, FR-002, FR-003)
- [X] T016 [US1] Persist `.security-scan/tooling/availability.json` from init per data-model.md (fields incl. `decision`), byte-deterministic serialization (FR-014)
- [X] T017 [US1] Add the read-only guarantee test in `tests/integration/test_tooling_readonly.py`: hash all fixture manifests/lockfiles/sources before and after every init mode (interactive-declined, `--no-input`, `--install=all` with shims) and assert byte-identity (FR-004, SC-002)

**Checkpoint**: User Story 1 fully functional and independently testable — init provisions (or honestly declines) with zero mutation of the scanned project

---

## Phase 4: User Story 2 - Running installed tools as part of the analysis (Priority: P2)

**Goal**: Every applicable available tool runs read-only during analysis; output is normalized, deduplicated, provenance-tracked, and merged; unavailability is declared as a coverage limitation, never silence.

**Independent Test**: quickstart.md Scenarios 4 and 6 pass — seeded advisory surfaced exactly once with provenance; crash-tool and zero-tool runs complete with declared limitations.

### Tests for User Story 2 (write FIRST, confirm FAIL)

- [X] T018 [P] [US2] Integration test for run→normalize→merge in `tests/integration/test_tooling_run.py`: vuln_dep fixture with shims; seeded beyond-snapshot advisory appears exactly once with multi-contributor `sources`; `runs.json` shows `ran` + `read_only_guard: passed` (FR-005, FR-006, SC-003)
- [X] T019 [P] [US2] Integration test for resilience in `tests/integration/test_tooling_run.py`: crash_tool shim (exit 137, garbage output) degrades to `failed` + reason with zero partial merges; a recorded valid-JSON-but-wrong-schema-version report (format drift per spec Edge Cases) is rejected as `failed` with zero merges; zero-tool run (bare PATH) reproduces today's findings with every external contribution declared as a limitation (FR-009, FR-010, SC-005, SC-006)

### Implementation for User Story 2

- [X] T020 [US2] Implement the read-only, timeout-bounded, never-raises tool runner in `src/pipeline/tooling/runner.py`: registry `invoke` argv, fingerprint guard reused from `src/pipeline/audits/base.py`, output discarded when the guard trips, timeout → `failed` with stable reason string (no stderr embedding) (FR-004, FR-005)
- [X] T039 [P] [US2] Contract test for `.security-scan/tooling/runs.json` in `tests/contract/test_tooling_artifacts.py` asserting the schema in contracts/data-contracts.md §3 (`status=failed` ⇒ non-empty `reason`; `read_only_guard=tripped` ⇒ `status=failed`) — MUST FAIL before T021 writes the artifact (FR-005, constitution contract-test gate)
- [X] T021 [P] [US2] Implement ToolRunRecord persistence to `.security-scan/tooling/runs.json` in `src/pipeline/tooling/runner.py` (or a small `records.py`): tool/db versions, invocation without secrets, status/reason (data-model.md)
- [X] T022 [P] [US2] Implement dependency-audit adapters in `src/pipeline/adapters/npm_audit.py`, `src/pipeline/adapters/pip_audit.py`, `src/pipeline/adapters/govulncheck.py`: parse tool JSON into the NormalizedExternalFinding shape, dropping run-varying fields (FR-005)
- [X] T023 [P] [US2] Implement the OWASP Dependency-Check adapter in `src/pipeline/adapters/dependency_check.py` parsing its JSON report into NormalizedExternalFinding, covering both invocation modes from research R2 (FR-005)
- [X] T024 [P] [US2] Implement the semgrep, gitleaks, osv-scanner, and trivy adapters in `src/pipeline/adapters/{semgrep,gitleaks,osv,trivy}.py`, completing 001 US3's deferred T049–T051 set, all emitting NormalizedExternalFinding with `tool_ref` preserved (FR-005)
- [X] T025 [US2] Extend `src/pipeline/ingest_findings.py`: derive covered-domain mapping from the registry (`covers_ecosystems`) instead of hard-coded `DEPENDENCY_SCANNERS`; implement advisory-identity dedupe (ecosystem/package/affected_range + shared advisory ids) merging contributors into one finding's `sources` list; preserve the documented trap — skip a native domain only on actual external findings (FR-006, research R5)
- [X] T026 [US2] Wire the external-tool stage into the scan pipeline in `src/pipeline/run.py`/`src/pipeline/scan_cli.py`: cheap availability re-probe at scan time (research R8), run applicable available tools through the runner, ingest through the extended seam, additive config wiring for `tooling.*` (FR-005)
- [X] T027 [US2] Emit CoverageLimitationDeclarations for every applicable tool not run into the report summary artifact in `src/pipeline/generate_report.py`; absence of external results must render as limitation, never clean (FR-009)
- [X] T028 [US2] Route all external tool output through the existing redaction layer (`src/pipeline/redact.py`) before artifact write or any model-facing use; add a unit test with a shim whose recorded output embeds a credential pattern and assert the value never appears in any artifact (FR-011)

**Checkpoint**: User Stories 1 AND 2 both work independently — scans merge external findings comprehensively and honestly

---

## Phase 5: User Story 3 - Cross-checking tool findings against the codebase (Priority: P3)

**Goal**: Every external finding is cross-checked; only deterministic structural disproof suppresses (package-absent, version-outside-range, location-unresolvable, component-absent), every suppression is auditable, and reachability doubts retain findings as undetermined.

**Independent Test**: quickstart.md Scenario 5 passes — suppression corpus behaves per declared ground truth; suppression section renders count + reasons without a re-scan.

### Tests for User Story 3 (write FIRST, confirm FAIL)

- [X] T029 [P] [US3] Integration test for the suppression corpus in `tests/integration/test_tooling_crosscheck.py`: crosscheck fixture's four seeded false/disprovable findings land only in `suppressions.json` with correct grounds + evidence; the true finding and the reachability-doubt finding are retained (the latter `verification: undetermined` with reason); zero true findings suppressed (FR-007, FR-008, SC-004)

### Implementation for User Story 3

- [X] T030 [US3] Implement `src/pipeline/crosscheck.py`: evaluation of each ingested finding against resolved pins from `src/pipeline/audits/offline.py` `extract_components` + version comparators, tiered location resolution from feature 002, and code-model component presence; closed `disproof_ground` enum per contracts/data-contracts.md; reachability/usage inputs may inform `undetermined` but never suppression (FR-007, FR-008)
- [X] T040 [US3] Contract test for `.security-scan/tooling/suppressions.json` in `tests/contract/test_tooling_artifacts.py` asserting the schema in contracts/data-contracts.md §5, including the closed `disproof_ground` enum and non-empty `evidence` — MUST FAIL before T031 writes the artifact (FR-007, constitution contract-test gate)
- [X] T031 [US3] Persist SuppressionRecords to `.security-scan/tooling/suppressions.json` and FindingDisposition wiring in report assembly; a suppression without evidence fails the report gate (data-model.md validation rules)
- [X] T032 [US3] Add the **External tooling** and **Suppressed findings** report sections in `src/pipeline/generate_report.py` and `src/pipeline/render_html.py` per contracts/data-contracts.md §6, including the zero-tool limitation rendering (FR-014, FR-009)
- [X] T033 [US3] Assign verification states to retained findings (`verified`/`plausible`/`undetermined` + reason) using the existing tri-state model in `src/pipeline/verify.py`, integrated into the merged finding stream (FR-008)

**Checkpoint**: All user stories independently functional — merged findings are cross-checked, suppressions auditable, unknowns declared

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Ground truth, invariants, and documentation across stories

- [X] T034 [P] Extend benchmark ground truth with tooling cases in `tests/benchmark/cases/` (seeded true findings, deliberate false positives that must be suppressed, undetermined cases that must be retained) and wire them into the accuracy benchmark so any regression fails the build (FR-013)
- [X] T035 Add the two-run byte-identity invariant test in `tests/integration/test_tooling_determinism.py`: two scans over the crosscheck fixture with fixed shims produce byte-identical artifacts including `availability.json`, `runs.json`, `suppressions.json`, and reports (Principle I, SC criteria)
- [X] T041 Extend the scanner-ignores-itself invariant: add assertions to `tests/unit/test_source_walk.py` (alongside `test_is_skipped_dir_predicate`) that `.security-scan/tooling/` artifacts and the provision target directory are excluded from source/manifest enumeration, and extend the integration coverage so tool caches/DBs created under the scan dir never appear in findings or the code model (FR-012, constitution Safety Invariants)
- [X] T036 [P] Update `README.md` with honest status for external tooling (what is built vs. planned) and document the new `tooling.*` config keys and init flags in the configuration reference (constitution: honest documentation)
- [X] T037 Run every quickstart.md scenario end-to-end, then the full gate suite: `pytest` green, `ruff check src tests` clean, contract tests passing, no credential-detection recall reduction (constitution quality gates)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Phase 1 fixtures (T001/T002) — BLOCKS all user stories
- **User Stories (Phases 3–5)**: All depend on Foundational completion
  - US1 (Phase 3) is independent; US2 (Phase 4) consumes adapter/registry from Foundational but not US1's init flows; US3 (Phase 5) consumes US2's merged finding stream (cross-check operates on ingested findings) — testable independently with recorded ingestion fixtures
- **Polish (Phase 6)**: Depends on all targeted stories

### User Story Dependencies

- **US1 (P1)**: Foundational only — no dependency on US2/US3
- **US2 (P2)**: Foundational only — works with pre-installed/shimmed tools even if US1's init provisioning is absent
- **US3 (P3)**: Consumes US2's normalized findings in production, but its fixtures record ingestion output directly, so it remains independently testable

### Within Each User Story

- Tests written and confirmed FAILING before any implementation task
- Discovery/runner primitives before pipeline wiring
- Story checkpoint passes before moving to the next priority

### Parallel Opportunities

- Phase 1: T001, T002, T003 in parallel (different trees)
- Phase 2: T004 (contract test) parallel with T005 (data) — then T006; T007/T008 sequential pair
- US1: T009–T012 tests in parallel; T013 before T014/T015/T016
- US2: T018/T019 parallel; T022, T023, T024 adapters fully parallel; T025 and T026 sequential after runner
- US3: T030 before T031–T033; T032/T033 parallel
- Foundational complete → US1 and US2 can start in parallel across two workers

---

## Parallel Example: User Story 2

```bash
# Launch all US2 tests together after runner exists:
Task: "Integration test for run→normalize→merge in tests/integration/test_tooling_run.py"
Task: "Integration test for resilience in tests/integration/test_tooling_run.py"

# Launch all adapters together:
Task: "Implement dependency-audit adapters (npm_audit.py, pip_audit.py, govulncheck.py)"
Task: "Implement OWASP Dependency-Check adapter in dependency_check.py"
Task: "Implement semgrep/gitleaks/osv/trivy adapters"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup + Phase 2: Foundational → registry and detection ready
2. Complete Phase 3: US1 → **STOP and VALIDATE** via quickstart Scenarios 1–3
3. At this point init alone tells users exactly what external coverage they have — a deliverable increment

### Incremental Delivery

1. Setup + Foundational → registry, detection, fixtures
2. US1 → provisioning with consent gates (MVP)
3. US2 → tool execution, normalization, dedupe, honest limitations
4. US3 → cross-check suppression with audit trail
5. Polish → benchmark ground truth, determinism invariant, docs, gates

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to user story for traceability
- Tests MUST fail before implementation (constitution: test-first)
- Every task cites its requirement ids; new artifacts are additive-only (contracts/data-contracts.md stability rules)
- Commit after each task or logical group; stop at any checkpoint to validate a story independently
- T038–T041 were appended after `/speckit-analyze` remediation (artifact contract tests + self-exclusion invariant); they slot into their story phases ahead of the writer tasks they gate (T038→T016, T039→T021, T040→T031) and can parallel with each phase's other tests
