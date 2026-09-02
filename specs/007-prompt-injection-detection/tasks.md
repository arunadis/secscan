# Tasks: Prompt Injection Detection

**Input**: Design documents from `/specs/007-prompt-injection-detection/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/ (data-contracts.md), quickstart.md

**Tests**: Included — the constitution mandates test-first (`pytest` green, `ruff check src tests` clean, contract tests per schema, per-defect-class accuracy assertions). Tests are written before implementation and must fail first.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., [US1], [US2], [US3], [US4])
- Single-project layout: `src/`, `tests/` at repository root

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Data-file skeletons and fixture scaffolding that every later phase references

- [X] T001 Create `src/skill_core/data/llm_integrations.json` v1 skeleton per contracts §2.1 (version, dataset_date, sources, empty `sdk_modules`/`http_endpoints`/`local_endpoints`/`candidate_hints` arrays)
- [X] T002 [P] Create `src/skill_core/data/supply_chain_rules.json` v1 skeleton per contracts §2.2 (empty `rules` array)
- [X] T003 [P] Create `src/skill_core/data/agent_config_rules.json` v1 skeleton per contracts §2.3 (empty `rules` array)
- [X] T004 [P] Create `tests/fixtures/llm_workspace/` fixture root with README noting seeded ground truth lives in benchmark cases

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Taxonomy, file classes, schema enums, and recognition that ALL stories depend on

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T005 [P] Add failing contract test for the three new versioned data files (load-time validation, unique ids, compilable patterns, `validate_cwe`) in `tests/contract/test_data_files.py`
- [X] T006 [P] Add failing contract test for additive schema extensions (code_graph.json `file_class` and `annotations` enums; finding.json optional `mitigation`) in `tests/contract/test_schemas.py`
- [X] T007 Extend `src/skill_core/cwe_map.json` to version 2: add CWE-1427, CWE-250, CWE-829, CWE-494 entries and the `llm_top10_2025` mapping block per research.md R6 (additive only; verify ids against cwe.mitre.org)
- [X] T008 Add `ai-agent-config`, `ai-mcp-config`, `prompt-artifact` file classes with exact-filename lists to `src/skill_core/data/stacks.json` (bump version) per research.md R4 — no glob matching at v1 (classifier matches bare filenames)
- [X] T009 Add the three new file classes and five new annotations (`llm_invocation`, `llm_prompt_sink`, `tool_declaration`, `external_content_source`, `ai_config`) to `src/skill_core/schemas/code_graph.json` enums (additive)
- [X] T010 Add optional additive `mitigation` object (`control` / `state` / `reason` required-when-undetermined) to `src/skill_core/schemas/finding.json` per contracts §3
- [X] T011 Extend `src/pipeline/extract/config_files.py` so the three new AI file classes annotate `ai_config` per research.md R4
- [X] T012 Populate `src/skill_core/data/llm_integrations.json` with v1 recognition data: hosted SDK modules (python + javascript at minimum), model-API host suffixes, local endpoint hosts/ports, and undetermined-posture candidate hints per research.md R3
- [X] T013 Implement `src/pipeline/extract/llm_integration.py`: deterministic pattern-driven recognition over redacted text emitting graph annotation facts (`llm_invocation`, `llm_prompt_sink`, `tool_declaration`, `external_content_source`) plus undetermined-posture candidates with evidence offsets per research.md R1/R3
- [X] T014 Wire the extractor into `src/pipeline/build_code_graph.py`: annotate nodes, register prompt-sink nodes, link tool declarations to their segment
- [X] T015 Extend `src/pipeline/dataflow.py`: `is_sink` recognizes `llm_prompt_sink`; `sources()` includes `external_content_source` nodes per research.md R2
- [X] T016 Add `llm-security` domain to `src/pipeline/partition_repo.py` DOMAIN_BY_ANNOTATION / DOMAIN_BY_FILE_CLASS / DOMAIN_BY_NAME maps and the `_ALWAYS`-independent assignment so only LLM-evidenced segments receive it per research.md R5
- [X] T017 [P] Add the `- **llm-security**` guidance bullet (direct vs indirect categories, sensitive-data-in-context and insecure-output-handling classes per FR-008a, flow-as-evidence, capability reach, mitigation tri-state) between the DOMAIN-GUIDANCE markers in `src/skill_core/prompts/segment_scan.md`
- [X] T018 Extend `src/pipeline/verify.py` sink-kind awareness so LLM flows adjudicate with existing verified/plausible/disproven machinery and mitigation/honest-uncertainty reasons per research.md R2

**Checkpoint**: Foundation ready — per-file-class coverage includes AI artifacts, taxonomy serves new CWE ids, LLM recognition + tracing operate; user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Detect direct prompt injection attack surfaces (Priority: P1) 🎯 MVP

**Goal**: Scanning a repo where untrusted user input reaches instruction-bearing model context produces a CWE-1427 finding citing source, assembly, and invocation, with mitigation state honestly recorded

**Independent Test**: Scan the US1 fixture workspace; seeded vulnerable surfaces are reported with resolving locations, safe structured-usage fixtures produce zero findings (quickstart.md Scenarios 1–2)

- [X] T019 [US1] Write failing unit tests for the LLM extractor: SDK/HTTP/local pattern hits, candidate heuristics → undetermined posture, redacted-text input in `tests/unit/test_llm_integration_extract.py`
- [X] T020 [US1] Write failing unit tests for prompt-sink tracing in `tests/unit/test_dataflow_llm.py`: user_controlled_input → llm_prompt_sink flow construction (direct injection), sensitive_data → llm_prompt_sink (CWE-200 sensitive data in context, FR-008a), llm_invocation → security_sink (CWE-116/20 insecure output handling, FR-008a), validation recognition, non-LLM repos produce no traces
- [X] T021 [P] [US1] Create `tests/fixtures/llm_workspace/us1_direct/` seeded fixtures: vulnerable prompt assembly (SDK + raw HTTP + local endpoint variants) and safe structured-separation counterparts with declared ground truth
- [X] T022 [US1] Implement finding emission in `src/pipeline/llm_findings.py` for all LLM classes per contracts §4: direct injection (`cwe: CWE-1427`, evidence source/assembly/invocation) plus sensitive-data-in-context (`CWE-200`) and insecure-output-handling (`CWE-116`/`CWE-20`) from their respective flows (FR-008a); `mitigation` tri-state on every finding; validate against finding.json before admission
- [X] T023 [US1] Wire direct-injection findings into `src/pipeline/run.py` after dataflow/verify stages: normalize → verify (disproven rejected) → artifact under existing findings envelope with deterministic ordering
- [X] T024 [US1] Add `llm-detection` defect class to `tests/benchmark/__init__.py` and create `tests/benchmark/cases/llm_scan.json` case(s) — following the existing case schema declared in `tests/benchmark/__init__.py` — asserting seed-hit recall for direct injection, sensitive-context, and insecure-output classes plus must-not-report false positives per research.md R9
- [X] T025 [US1] Make T019/T020 unit tests and the US1 benchmark assertions pass; run `pytest tests/unit/test_llm_integration_extract.py tests/unit/test_dataflow_llm.py -q` and `pytest tests/benchmark -q`

**Checkpoint**: Direct prompt injection detection verified end-to-end (US1 standalone MVP)

---

## Phase 4: User Story 2 - Detect indirect prompt injection exposure (Priority: P2)

**Goal**: Third-party content ingestion into model context is reported with source and capability reach; demonstrated boundaries lower confidence or suppress findings

**Independent Test**: Scan the US2 fixture workspace; unbounded ingestion yields indirect-category CWE-1427 findings citing ingestion point + reachable capability; bounded fixture yields none or `mitigation.state: demonstrated` (quickstart.md Scenario 3)

- [X] T026 [US2] Extend `tests/unit/test_llm_integration_extract.py` with failing tests for `external_content_source` recognition (fetch results, inbound messages, tool results, record loaders → context insertion)
- [X] T027 [US2] Extend `tests/unit/test_dataflow_llm.py` with failing tests: external_content_source → llm_prompt_sink flows, capability reach evidence (function-call/tool access reachable from the invocation segment), boundary-label validation recognition
- [X] T028 [P] [US2] Create `tests/fixtures/llm_workspace/us2_indirect/` seeded fixtures: unbounded external-content ingestion and boundary-labeled counterpart with ground truth
- [X] T029 [US2] Extend `src/pipeline/llm_findings.py`: indirect category findings consume external-content flows; evidence names ingestion point and reachable tools/actions/data; `mitigation` reflects demonstrated boundary labeling per data-model.md (Prompt Injection Surface)
- [X] T030 [US2] Extend `tests/benchmark/cases/llm_scan.json` with indirect-exposure cases (bounded vs unbounded; must-not-report for boundary-labeled fixtures)
- [X] T031 [US2] Make new unit tests and benchmark assertions pass in `tests/unit/test_llm_integration_extract.py`, `tests/unit/test_dataflow_llm.py`, and `tests/benchmark/cases/llm_scan.json`; no regression in US1 assertions

**Checkpoint**: Indirect exposure detection verified; direct + indirect categories both live

---

## Phase 5: User Story 3 - Flag over-privileged agent and tool configurations (Priority: P3)

**Goal**: Shipped AI config artifacts with excessive grants (no demonstrated approval gate) and sensitive values embedded in prompt artifacts produce findings without exposing values

**Independent Test**: Scan the US3 fixture workspace; over-privileged MCP/agent configs yield CWE-250 findings citing artifact + capability; scoped counterparts yield none; embedded credential reported via secret findings, value absent from all artifacts (quickstart.md Scenario 4)

- [X] T032 [US3] Write failing unit tests for agent-config evaluation: structural (MCP JSON) and anchored-pattern (markdown rule files) forms, approval-gate evidence, redacted-text evaluation in `tests/unit/test_agent_config.py`
- [X] T033 [P] [US3] Populate `src/skill_core/data/agent_config_rules.json` v1 rules (grant capabilities × forms, CWE-250) per contracts §2.3 and research.md R8
- [X] T034 [P] [US3] Create `tests/fixtures/llm_workspace/us3_agent_config/` seeded fixtures: over-privileged vs scoped MCP configs and agent rule files, plus a prompt artifact embedding a credential
- [X] T035 [US3] Implement `src/pipeline/agent_config.py` (`run(roots) -> findings`) with misconfig-style load-time rule validation (fail build, not scan), value-free findings, evaluation over redacted text per contracts §4
- [X] T036 [US3] Wire agent-config review into `src/pipeline/run.py`: normalize → `findings/agent_config.json` artifact; verify the new file classes pass through the redactor and the redaction sweep covers the new artifact (FR-009)
- [X] T037 [US3] Add agent-config cases to `tests/benchmark/cases/llm_scan.json` (grants flagged, scoped must-not-report, embedded-secret reporting)
- [X] T038 [US3] Make T032 tests and benchmark assertions pass in `tests/unit/test_agent_config.py` and `tests/benchmark/cases/llm_scan.json`; run the redaction sweep test over `tests/fixtures/llm_workspace/us3_agent_config/` embedded-credential fixtures

**Checkpoint**: Agent/tool configuration review verified; artifacts feed capability reach for US2 evidence

---

## Phase 6: User Story 4 - Detect supply-chain and dependency-confusion exposure (Priority: P4)

**Goal**: Dependency declarations vulnerable to confusion/typosquatting/substitution produce findings with tri-state guard evidence; hardened manifests produce none (all offline, deterministic)

**Independent Test**: Scan the US4 fixture workspace; unprotected internal-namespace + mutable references yield CWE-829/CWE-494 findings with manifest citations; pinned/registry-scoped manifests yield none (quickstart.md Scenario 5)

- [X] T039 [US4] Write failing unit tests for supply-chain evaluation: rule kinds (`internal-namespace-unprotected`, `mutable-reference`, `suspicious-package`), guard tri-state (lockfile / registry-config / undetermined), ecosystem parsing in `tests/unit/test_supply_chain.py`
- [X] T040 [P] [US4] Populate `src/skill_core/data/supply_chain_rules.json` v1 rules (npm + pypi ecosystems; offline suspicious-name dataset) per contracts §2.2 and research.md R7
- [X] T041 [P] [US4] Create `tests/fixtures/llm_workspace/us4_supply_chain/` seeded fixtures: confusion-vulnerable manifests (no lockfile/registry guard), mutable references, hardened counterparts (lockfile + private-registry pinning), FP fixtures
- [X] T042 [US4] Implement `src/pipeline/supply_chain.py` (`run(roots) -> findings`): structural manifest/lockfile parsing, guard-evidence detection, `undetermined` guard state when resolution config is external to the repo per research.md R7
- [X] T043 [US4] Wire supply-chain evaluation into `src/pipeline/run.py`: normalize → `findings/supply_chain.json` artifact with deterministic ordering
- [X] T044 [US4] Add `supply-chain-detection` defect class to `tests/benchmark/__init__.py` and cases to a new `tests/benchmark/cases/supply_chain.json` asserting 100% seeded exposure recall and hardened-manifest silence per SC-008
- [X] T045 [US4] Make T039 tests and supply-chain benchmark assertions pass in `tests/unit/test_supply_chain.py` and `tests/benchmark/cases/supply_chain.json`

**Checkpoint**: Supply-chain detection verified; all stories complete

---

## Final Phase: Polish & Cross-Cutting Concerns

**Purpose**: Category-wide invariants and release gates

- [X] T046 Add two-run byte-identity integration test covering the new artifacts and findings (`tests/integration/test_report_artifacts.py` extension per SC-005)
- [X] T047 Verify coverage statement lists `ai-agent-config`, `ai-mcp-config`, `prompt-artifact` classes and that undetermined integration postures are declared in reports; extend `tests/integration/` to assert no silent exclusion (FR-011, quickstart.md Scenario 6)
- [X] T048 Run and green the full gate (`pytest` over `tests/`, `ruff check src tests`, schema contract tests in `tests/contract/`) per quickstart.md Scenario 8
- [X] T049 Update capability/status statements in `README.md` to match shipped behavior (constitution: honest documentation)
- [X] T050 Demonstrate SC-007's worked data-only class addition: append one synthetic rule/class entry to a versioned data file (e.g., `src/skill_core/data/agent_config_rules.json`) with no pipeline-code change, add a matching seeded fixture in `tests/fixtures/llm_workspace/`, and assert in `tests/benchmark/cases/llm_scan.json` that the fixture finding flows through unchanged pipeline stages

---

## Dependencies

- Setup (Phase 1) → Foundational (Phase 2) blocks everything
- US1 (Phase 3) depends on Foundational only — independently deliverable MVP
- US2 (Phase 4) depends on US1's finding plumbing (`llm_findings.py`, benchmark case file) — extends it
- US3 (Phase 5) depends on Foundational (file classes, schema, redaction) — parallel with US2 if sequenced after its fixture conventions
- US4 (Phase 6) depends on Foundational only — fully parallel with US1–US3 (different module, data file, fixtures, benchmark case file)
- Polish (Final) depends on all four stories

## Parallel Execution Examples

- **Phase 1 & 2 (data/schema)**: T001/T002/T003/T004 in parallel; T005/T006 in parallel; T012/T017 parallel
- **US2**: T026 and T027 (different test files) in parallel with fixture task T028
- **US3**: T033 (data) and T034 (fixtures) in parallel before T035
- **US4**: T040 (data) and T041 (fixtures) in parallel before T042; whole story parallel to US2/US3
- **Cross-story**: after Phase 2, US1 and US4 runs fully in parallel; US3 largely parallel; US2 waits on US1's plumbing

## Implementation Strategy

1. **MVP first**: Phases 1–3 deliver standalone direct prompt-injection detection gated by its benchmark class
2. **Incremental**: merge US4 anytime (no story dependencies); land US2 after US1 plumbing; land US3 when config-artifact fixtures exist
3. **Gate discipline**: every phase ends with failing-first tests made green; the benchmark's release-blocking per-class assertions guard each increment
