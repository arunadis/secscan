# Tasks: Hierarchical LLM-Efficient Security Scanning for Large Codebases

**Input**: Design documents from `/specs/001-hierarchical-security-scan/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Included — the spec's success criteria (SC-003, SC-007, SC-009, SC-010, SC-011) mandate seeded fixture repositories and measurable validation, so contract/integration test tasks are part of each story.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1–US5)
- All file paths follow plan.md structure (`src/`, `tests/` at repository root)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

- [X] T001 Create project structure per plan.md: `src/{installer,skill_core,pipeline,profiles,config}/`, `tests/{contract,integration,fixtures,unit}/`
- [X] T002 Initialize Python 3.11+ project (`pyproject.toml`) with dependencies from research.md R2: `tree-sitter>=0.26`, `tree-sitter-python`, `tree-sitter-java`, `tree-sitter-javascript`, `tree-sitter-typescript`, `tree-sitter-go`, `pyyaml`, `jsonschema`, `click`; dev deps `pytest`, `ruff`
- [X] T003 [P] Configure linting/formatting (`ruff`) and pytest settings in `pyproject.toml`
- [X] T004 [P] Create fixture-repo scaffolding conventions doc + base helper `tests/fixtures/build_fixture.py` for generating seeded-vulnerability repos used across stories

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T005 [P] Write JSON Schemas for all artifacts (workspace, repository manifest, code graph, segment, context packet, report) in `src/skill_core/schemas/` per `contracts/artifact-schemas.md`
- [X] T006 [P] Write finding JSON Schema `src/skill_core/schemas/finding.json` per `contracts/finding-schema.md` (incl. verification + reproduction blocks)
- [X] T007 Implement artifact store and checkpoint manager in `src/pipeline/state.py`: envelope fields, content hashing, resume keys, stage status, per-file hashes (FR-016, FR-016a)
- [X] T008 [P] Implement config loader with strict schema validation and env-var overrides in `src/config/loader.py` per `contracts/config-schema.md` (FR-023, FR-026)
- [X] T009 [P] Implement deterministic redaction engine (rule packs + entropy + custom patterns, block-and-warn on uncertainty) in `src/pipeline/redact.py` (FR-006a, research.md R5)
- [X] T010 [P] Ship versioned CWE→OWASP→compliance mapping dataset + CWE ID validator in `src/skill_core/cwe_map.json` and `src/pipeline/cwe.py` (FR-012, research.md R6)
- [X] T011 [P] Implement token accounting and budget enforcement primitives in `src/pipeline/budget.py` (FR-007)
- [X] T012 [P] Implement usage/cost tracker (tokens per stage/tier, batch share, fallbacks, savings estimate) in `src/pipeline/usage.py` (FR-019)
- [X] T013 Implement built-in scan profiles (`quick`, `full`, `audit`) as data + profile resolution with per-scan overrides in `src/profiles/builtin.yaml` and `src/config/profiles.py` (FR-028)
- [X] T014 Implement external endpoint client (Anthropic/OpenAI-compatible) with provider batch abstraction `submit_batch`/`poll`, interactive fallback, and mode-aware feature gating in `src/pipeline/llm_client.py` (FR-007a, FR-016b, FR-027, research.md R4)
- [X] T015 Implement execution-mode resolver (agent-mediated default vs external endpoint; credentials via env var; precedence rules) in `src/config/mode.py` (FR-025, FR-027)
- [X] T016 [P] Contract tests: every schema in `src/skill_core/schemas/` validates golden valid/invalid samples in `tests/contract/test_schemas.py`
- [X] T017 [P] Unit tests for redaction engine (known credential formats, entropy strings, custom patterns, block-on-uncertain) in `tests/unit/test_redact.py`

**Checkpoint**: Foundation ready — user story implementation can now begin in parallel

---

## Phase 3: User Story 1 — Scan a Large Repository End-to-End (Priority: P1) 🎯 MVP

**Goal**: Full hierarchical scan of a workspace producing a unified, evidence-backed, verification-aware security report without loading the whole repo into one context

**Independent Test**: `security-scan run --full --profile full` on `tests/fixtures/single-repo-shop` in agent-mediated mode (no API key) yields a report where every finding has CWE/CVSS/confidence/evidence + reproduction block, seeded true positives are found, and no analysis invocation exceeded budget (quickstart Scenarios 1, 7)

### Tests for User Story 1

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T018 [P] [US1] Build single-repo fixture `tests/fixtures/single-repo-shop/` (multi-module app with seeded SQLi, missing authz, hardcoded secret, one cross-component flow vuln) per SC-009, plus a synthetic-scale generator `tests/fixtures/generate_large_repo.py` that produces a repository at least 10x larger than the smallest configured context window for SC-001 validation
- [X] T019 [P] [US1] Integration test for end-to-end agent-mediated scan in `tests/integration/test_full_scan.py` (quickstart Scenario 1 assertions: finding completeness, budget compliance, usage summary; runs against the SC-001 synthetic-scale repo from T018 asserting no invocation exceeded its budget)
- [X] T020 [P] [US1] Integration test for verification/reproduction output in `tests/integration/test_verification.py` (quickstart Scenario 7: verified/plausible statuses, repro blocks, disproven findings absent)

### Implementation for User Story 1

- [X] T021 [US1] Implement workspace assembly + repository manifest discovery in `src/pipeline/discover_repo.py` (FR-001, FR-001a, FR-001c: manifest file optional, auto-discovery fallback)
- [X] T022 [US1] Implement tree-sitter extraction layer (per-language queries for files/classes/functions/imports/call sites) in `src/pipeline/extract/` with deterministic sorted output (research.md R2)
- [X] T023 [P] [US1] Implement framework enrichers (HTTP entry points, DB access, trust annotations for Flask/FastAPI/Django/Express/Spring/Gin) in `src/pipeline/extract/enrichers.py` (FR-003)
- [X] T024 [US1] Implement code graph builder merging per-file facts into `code-graph.json` with stable IDs in `src/pipeline/build_code_graph.py` (FR-002; depends on T022, T023)
- [X] T025 [US1] Implement security-boundary partitioning in `src/pipeline/partition_repo.py` (FR-004; subdivision when over budget)
- [X] T026 [US1] Implement context packet builder with redaction, token budgets, and escalation levels 1–4 in `src/pipeline/build_context.py` (FR-005, FR-006, FR-006a; depends on T009, T011, T025)
- [X] T027 [US1] Write orchestrator instructions `src/skill_core/SKILL.md` (workflow, rules: bounded context, evidence mandatory, no free-form findings, no whole-repo loading)
- [X] T028 [P] [US1] Write prompt templates `src/skill_core/prompts/segment_scan.md` (local + segment analysis, FR-008, domain guidance selection per FR-011)
- [X] T029 [P] [US1] Write prompt templates `src/skill_core/prompts/final_review.md` (system-level review) and `src/skill_core/prompts/partition.md` / `discover.md`
- [X] T030 [US1] Implement findings normalization: schema enforcement, CWE validation, band derivation, free-form rejection + retry/escalate in `src/pipeline/normalize_findings.py` (FR-012, FR-013; depends on T006, T010)
- [X] T031 [US1] Implement static verification (source-to-sink trace, verified/plausible/disproven + gap documentation) in `src/pipeline/verify.py` (FR-029)
- [X] T032 [US1] Implement reproduction block generation (preconditions, benign-canary trigger, expected vs observed, local/test scope) in `src/pipeline/reproduce.py` (FR-030)
- [X] T033 [US1] Implement data-flow tracing (source→transform→validate→sink representations) in `src/pipeline/dataflow.py` (FR-010; feeds T031)
- [X] T034 [US1] Implement unified report generator (severity-grouped, verification-aware ranking, repro subsections inline, exec summary, attack paths, coverage statement, usage/cost summary, execution mode + profile recorded) in `src/pipeline/generate_report.py` (FR-018, FR-019; MD + JSON)
- [X] T035 [US1] Evidence escalation loop: escalation levels + threshold-driven context expansion in `src/pipeline/escalate.py` (FR-006; 80/15/4/1 tiering target per SC-004; depends on T011, T026)
- [X] T036 [US1] Wire pipeline driver `src/pipeline/run.py`: stage sequencing, resume via state store, agent-mediated vs endpoint execution switch (depends on T007, T014, T015, T021–T035)

**Checkpoint**: US1 fully functional — zero-config full scan of a fixture repo produces a complete verified report

---

## Phase 4: User Story 2 — Install the Scanner into a Coding Agent (Priority: P2)

**Goal**: One-command, per-project, agent-portable installation with init, config generation, environment checks, and in-place upgrades

**Independent Test**: Run installer in a fresh project for each supported agent; verify skill files + registered command, `init` output readiness table, gitignored `.security-scan/`, and upgrade preservation (quickstart Scenario 0)

### Tests for User Story 2

- [X] T037 [P] [US2] Integration test matrix over agent adapters in `tests/integration/test_install_matrix.py` (install → files exist + frontmatter valid per agent → command invocable; quickstart Scenario 0)

### Implementation for User Story 2

- [X] T038 [US2] Implement installer CLI (`init`, `version`, `--ai`, `--force`, idempotency) in `src/installer/cli.py` (FR-020, contracts/cli-contracts.md)
- [X] T039 [P] [US2] Implement Claude Code adapter in `src/installer/agents/claude.py` (`.claude/skills/security-scan/SKILL.md` mapping, research.md R1)
- [X] T040 [P] [US2] Implement Copilot adapter in `src/installer/agents/copilot.py` (`.github/skills/`)
- [X] T041 [P] [US2] Implement Cursor adapter in `src/installer/agents/cursor.py` (`.cursor/skills/`)
- [X] T042 [P] [US2] Implement Windsurf adapter in `src/installer/agents/windsurf.py` (`.windsurf/skills/`)
- [X] T043 [P] [US2] Implement Devin + cross-vendor adapters in `src/installer/agents/devin.py` and `src/installer/agents/agents.py` (`.devin/skills/`, `.agents/skills/`)
- [X] T044 [P] [US2] Implement Gemini adapter (YAML frontmatter + Markdown → TOML translation, `$ARGUMENTS`→`{{args}}`) in `src/installer/agents/gemini.py`
- [X] T045 [US2] Implement init command: default config generation + environment checks (endpoint connectivity, credential presence, scanner tool detection, workspace manifest detection) in `src/pipeline/init_cmd.py` (FR-024)
- [X] T046 [US2] Implement in-place upgrade (replace skill files, preserve config + artifacts, flag schema changes, `--force` downgrade guard) in `src/installer/upgrade.py` (FR-020)
- [X] T047 [US2] Implement `.gitignore` handling for `.security-scan/` (default ignore + opt-in commit flag) in `src/installer/cli.py`
- [X] T047a [US2] Implement the `security-scan` scan CLI (`init`/`run`/`status`/`report` with `--profile`/`--policy`/`--set`/`--segment`/`--full`) in `src/pipeline/scan_cli.py`, plus derived per-repository report views in `src/pipeline/report_view.py` (FR-018, FR-022, contracts/cli-contracts.md)
- [X] T047b [US2] Filter segment-analysis prompt guidance to each segment's domains in `src/pipeline/prompts.py` (FR-011)

**Checkpoint**: US1 AND US2 both work independently

---

## Phase 5: User Story 3 — Triage Traditional Scanner Findings (Priority: P2)

**Goal**: Ingest SAST/secrets/dependency/IaC scanner output and have bounded-context analysis verdict exploitability with evidence

**Independent Test**: Fixture scanner outputs with known TP/FP findings; triage verdicts reference concrete code context; seeded FP (parameterized upstream) marked not-exploitable with mitigating code cited (quickstart Scenario 2)

### Tests for User Story 3

- [ ] T048 [P] [US3] Integration test for ingestion + triage in `tests/integration/test_ingest_triage.py` with recorded scanner JSON fixtures (quickstart Scenario 2)

### Implementation for User Story 3

- [ ] T049 [P] [US3] Implement Semgrep adapter in `src/pipeline/adapters/semgrep.py` (JSON → normalized findings, tool_ref preserved)
- [ ] T050 [P] [US3] Implement Gitleaks adapter in `src/pipeline/adapters/gitleaks.py`
- [ ] T051 [P] [US3] Implement OSV-Scanner adapter in `src/pipeline/adapters/osv.py`
- [ ] T052 [P] [US3] Implement Trivy (IaC) adapter in `src/pipeline/adapters/trivy.py`
- [ ] T053 [US3] **Seam exists**: `pipeline/ingest_findings.py` owns de-duplication against native audits (002 FR-030c); adapters register here. Implement ingestion driver (detect available tools, run when present, normalize via adapter registry) in `src/pipeline/ingest_findings.py` (FR-009; depends on T049–T052)
- [ ] T054 [P] [US3] Write triage prompt template `src/skill_core/prompts/triage.md` (exploitability verdict with mitigating-code citation)
- [ ] T055 [US3] Wire triage step into `src/pipeline/run.py` (bounded context around each ingested finding; verdict into finding record)

**Checkpoint**: US1–US3 all work independently

---

## Phase 6: User Story 4 — Correlate and Deduplicate Cross-Segment Findings (Priority: P2)

**Goal**: Cross-segment and cross-repo correlation so systemic issues are reported once with consolidated evidence, and cross-boundary vulnerabilities are detected

**Independent Test**: Multi-repo fixture `tests/fixtures/workspace-orders-payments/` — systemic weakness reported once with multi-segment evidence; cross-repo identity-trust vulnerability found with evidence from both repos (quickstart Scenario 3)

### Tests for User Story 4

- [ ] T056 [P] [US4] Build multi-repo workspace fixture `tests/fixtures/workspace-orders-payments/` (two repos, declared + undeclared integrations, seeded cross-repo vuln) per SC-010
- [ ] T057 [P] [US4] Integration test for correlation + cross-repo detection in `tests/integration/test_correlation.py` (quickstart Scenario 3, incl. auto-discovery path without manifest)

### Implementation for User Story 4

- [ ] T058 [US4] Implement cross-repo integration discovery/typing (sync-api, async-messaging, shared-datastore, identity-propagation) in `src/pipeline/integrations.py` (FR-001b, FR-001c)
- [ ] T059 [US4] Extend code graph builder for cross-repo edges in `src/pipeline/build_code_graph.py` (depends on T058)
- [ ] T060 [US4] **Partially built by feature 002** — `correlate_findings.correlate()` implements `duplicate` and `same`; `related`/`dependent`/`independent` and conflict reconciliation remain. Implement correlation engine (same/related/dependent/duplicate/independent classification, canonical grouping, conflict reconciliation with recorded reasoning) in `src/pipeline/correlate_findings.py` (FR-014)
- [ ] T061 [P] [US4] Write correlation prompt template `src/skill_core/prompts/correlation.md`
- [ ] T062 [US4] Implement system-level cross-boundary review (identity/trust propagation across segments and repos) in `src/pipeline/system_review.py` using `prompts/final_review.md` (FR-008, FR-015)
- [ ] T063 [US4] Extend report generator for unified workspace report (per-repo attribution, cross-system evidence citation, per-repo derived views) in `src/pipeline/generate_report.py` (FR-018)
- [ ] T064 [US4] Implement mid-scan integration discovery handling (incorporate + re-evaluate conclusions) in `src/pipeline/integrations.py` (edge case)

**Checkpoint**: US1–US4 all work independently

---

## Phase 7: User Story 5 — Incrementally Rescan After a Code Change (Priority: P3)

**Goal**: File-level changes trigger re-analysis of only affected segments, findings, and conclusions — including cross-repo dependents

**Independent Test**: Full scan → single-file change → rescan re-analyzes only affected segments at <20% of full cost; interrupted scans auto-resume without re-executing completed stages (quickstart Scenario 4)

### Tests for User Story 5

- [ ] T065 [P] [US5] Integration test for incremental rescan in `tests/integration/test_incremental.py` (change file → affected-only re-analysis, cost <20%; cross-repo dependent invalidation)
- [ ] T066 [P] [US5] Integration test for interruption/auto-resume in `tests/integration/test_resume.py` (kill mid-scan, verify no completed stage re-executes, SC-008)

### Implementation for User Story 5

- [ ] T067 [US5] Implement change detection (per-file content hashes → affected segments) in `src/pipeline/state.py` (FR-017)
- [ ] T068 [US5] Implement dependent-invalidation across repos (integration graph → dependent segments in other repos) in `src/pipeline/integrations.py` (FR-017)
- [ ] T069 [US5] Implement invalidation cascade to findings/conclusions + selective re-run in `src/pipeline/run.py` (FR-017)
- [ ] T070 [US5] Implement profile-depth switching re-analysis (shallow→deep uses artifacts, never presents shallow as exhaustive) in `src/pipeline/run.py` (FR-028 edge case)
- [X] T071 [US5] Implement `--segment <id>` single-segment re-run in `src/pipeline/run.py` (SC-007) — delivered with T047a

**Checkpoint**: All user stories independently functional

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [ ] T072 [P] Batch/off-peak end-to-end: window scheduling, expiry detection, recorded interactive fallback in `src/pipeline/llm_client.py` + `src/pipeline/run.py` (FR-007a, FR-016b; quickstart Scenario 6)
- [ ] T073 [P] Missing-subsystem and undeclared-integration coverage-gap reporting in `src/pipeline/generate_report.py` (edge cases)
- [x] T074 [P] Determinism hardening: byte-identical artifact regression test in `tests/integration/test_determinism.py` (artifact-schemas.md invariant 1)
- [x] T075 [P] Artifact redaction sweep test (no unredacted secrets in any artifact) in `tests/contract/test_artifact_redaction.py` (invariant 4)
- [ ] T076 [P] Performance validation: ~1h/1M LOC interactive-mode benchmark + ≥5x token-savings report check in `tests/integration/test_perf.py` (SC-004, SC-006)
- [ ] T077 Documentation: user guide in `docs/` (install, init, config reference, profiles, modes) 
- [ ] T078 Run full quickstart.md validation across all 8 scenarios and fix gaps
- [ ] T079 [P] Unit test coverage pass for `src/pipeline/` stage scripts in `tests/unit/`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup — BLOCKS all user stories
- **User Stories (Phase 3–7)**: All depend on Foundational completion
  - US1 (P1) must complete first (core pipeline; other stories' artifacts build on it)
  - US2, US3 can proceed in parallel after Foundational
  - US4 depends on US1's findings pipeline (T030, T034)
  - US5 depends on US1 (T036, the pipeline driver) and US4 (T064) for cross-repo invalidation
- **Polish (Phase 8)**: Depends on all desired user stories being complete

### User Story Dependencies

- **US1 (P1)**: After Foundational — no story dependencies (MVP)
- **US2 (P2)**: After Foundational — independent of US1 (installer wraps pipeline CLIs)
- **US3 (P2)**: After Foundational — integrates into US1's run driver but independently testable with recorded scanner fixtures
- **US4 (P2)**: After US1 — needs findings pipeline + report generator to extend
- **US5 (P3)**: After US1 (and US4 for cross-repo invalidation)

### Within Each User Story

- Fixture/test tasks first (fail before implementation)
- Schemas/models before stage scripts
- Stage scripts before driver wiring
- Story checkpoint before next priority

### Parallel Opportunities

- T003/T004 (Setup); T005/T006/T008/T009/T010/T011/T012 + T016/T017 (Foundational)
- US1: T018/T019/T020 tests; T023/T028/T029 prompts/enrichers
- US2: T039–T044 all adapters in parallel
- US3: T049–T052 all scanner adapters in parallel
- US4: T056/T057 fixtures/tests; T061 prompt
- Polish: T072–T076, T079 in parallel

---

## Parallel Example: User Story 2

```bash
# Launch all agent adapters together (independent files):
Task: "Implement Claude Code adapter in src/installer/agents/claude.py"
Task: "Implement Copilot adapter in src/installer/agents/copilot.py"
Task: "Implement Cursor adapter in src/installer/agents/cursor.py"
Task: "Implement Windsurf adapter in src/installer/agents/windsurf.py"
Task: "Implement Devin + cross-vendor adapters in src/installer/agents/devin.py and agents.py"
Task: "Implement Gemini adapter in src/installer/agents/gemini.py"
```

## Parallel Example: User Story 3

```bash
# Launch all scanner adapters together (independent files):
Task: "Implement Semgrep adapter in src/pipeline/adapters/semgrep.py"
Task: "Implement Gitleaks adapter in src/pipeline/adapters/gitleaks.py"
Task: "Implement OSV-Scanner adapter in src/pipeline/adapters/osv.py"
Task: "Implement Trivy (IaC) adapter in src/pipeline/adapters/trivy.py"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL — blocks all stories)
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: quickstart Scenarios 1 + 7 pass on the seeded fixture
5. Demo: zero-config agent-mediated scan producing a verified report

### Incremental Delivery

1. Setup + Foundational → foundation ready
2. US1 → validate (MVP) → demo
3. US2 → validate install matrix → demo (now distributable)
4. US3 → validate triage → demo
5. US4 → validate multi-repo correlation → demo (enterprise story)
6. US5 → validate incremental/resume → full feature set
7. Polish → perf/determinism hardening

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to spec.md user stories for traceability
- Fixture repos under `tests/fixtures/` are shared infra: build once, reuse across stories
- Verify tests fail before implementing
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
