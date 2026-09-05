# Tasks: Business-Flow (Functional) Vulnerability Analysis

**Input**: Design documents from `/specs/015-business-flow-analysis/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: INCLUDED — the constitution mandates test-first (tests MUST be written and
fail before implementation) and fixture-declared ground truth, including deliberate
safe flows that MUST NOT be flagged. Accuracy-benchmark regressions are
release-blocking.

**Organization**: Tasks are grouped by user story (US1–US4 from spec.md) so each story
ships as an independently testable increment.

**Remediation note (2026-09-05, /speckit-analyze)**: addresses findings F1 (regimes.json
resume-key ordering ⇒ stub dataset in Setup, T005), C1 (multi-repo workspace fixture +
stitching test, T006 and T020), A1 (fixture paths resolved in quickstart.md), C2
(severity-neutrality assertion folded into T018).

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3, US4)
- All paths are repository-relative

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Skeletons every story builds on — new files, schema registration, fixture
directories. Existing project; no dependency installation needed.

- [X] T001 [P] Create new schema `business_flow.json` for the flows artifact in src/skill_core/schemas/business_flow.json (envelope payload shape per contracts/business-flow-artifact.md §2: flows[], coverage{}, invariants: node_ids resolve, partial ⇒ non-empty gap_reasons)
- [X] T002 [P] Create new schema `flow_answer.json` for the reasoning-round answer in src/skill_core/schemas/flow_answer.json (flow_id, assessment enum clean|gap|violation|undetermined, undetermined_reasons[], findings[] per contracts §3)
- [X] T003 [P] Create the round prompt skeleton in src/skill_core/prompts/business_flow.md (step-walk instruction: "at every step, who is allowed to be here, and is that enforced?"; explicit undetermined declaration requirement; answer format pointer to flow_answer.json)
- [X] T004 [P] Create new test fixture directory tests/fixtures/flow-app/ with a small sample application declaring ground truth in the fixture manifest format used by existing fixtures (seeded two-step privilege-escalation flow + at least two deliberately safe flows)
- [X] T005 [P] Create stub versioned dataset src/skill_core/data/regimes.json with top-level {version: "0", dataset_date: "2026-09-05", regimes: []} so foundational resume keys (T011) can reference it before US3 fills in v1 content (remediates analysis finding F1)
- [X] T006 [P] Create multi-repo workspace test fixture tests/fixtures/flow-workspace/ with two members connected by one declared sync-api integration in workspace declaration and one undeclared cross-repo hop, ground truth declared per fixture format (remediates analysis finding C1; quickstart Scenario 3)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Config/schema/pipeline wiring that MUST land before any story; guarantees
the disabled path is byte-identical (SC-001 is guarded here, tested in US2).

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T007 Extend finding schema additively in src/skill_core/schemas/finding.json: optional `flow_category` (enum flow-gap|regulatory-violation), `flow_ref` (string), `flow_narrative` ({name, steps[], missing_check, compromise}), `regulatory_refs[]` ({regime, obligation, basis?}) per data-model.md; keep additionalProperties closed and schema_version "1"
- [X] T008 Add all-or-nothing + category-consistency validation for the new finding fields in src/pipeline/normalize_findings.py (flow_category ⇔ flow_ref ⇔ flow_narrative present together; regulatory-violation ⇒ non-empty regulatory_refs; flow_ref resolvable against business-flows.json once available; unresolvable ⇒ rejected with reason, mirroring tiered location resolution)
- [X] T009 Add `business_flow` config section in src/config/loader.py: extend _ALLOWED, DEFAULT_CONFIG (omit `enabled` so absent = unset), validate_config rules (enabled bool; applicability_mode ∈ hybrid|declared-only|inferred-only, default hybrid; declared_regimes list of strings), SECSCAN_BUSINESS_FLOW_* env overrides in apply_env_overrides, and a Config.business_flow property
- [X] T010 Add `business_flow: bool` to AnalysisDepth in src/config/profiles.py, include it in depth_key, and ship `business_flow: false` on quick/full/audit in src/profiles/builtin.yaml (FR-001); implement effective-enablement precedence --set > profile > config.business_flow.enabled > false
- [X] T011 Register stages `business_flow_model` (after build_code_graph) and `business_flow_analysis` (before correlate_findings finalize) in src/pipeline/state.py STAGES and src/pipeline/run.py _ANALYSIS_STAGES, with resume keys covering code-graph hash + workspace hash + business_flow config + regimes.json version (stub from T005 until US3 fills v1); both stages no-op when disabled
- [X] T012 Create deterministic flow reconstruction in src/pipeline/business_flow.py: BusinessFlow/FlowStep builders over code-graph endpoints/handler/calls/reads/writes edges and security annotations; stable flow ids (sha12 over entry node + ordered step node ids); actor determination declared|inferred|undetermined; cross-repo stitching ONLY via declared typed integrations from workspace.json (sync-api, async-messaging, shared-datastore, identity-propagation) with per-step repo attribution; partial=true + gap_reasons for undeclared/undetermined boundaries; write .secscan/business-flows.json via store.write with schema "business_flow"
- [X] T013 Implement business_flow_analysis round runner in src/pipeline/business_flow.py: per-flow AnalysisRequest(stage="business_flow_analysis", level="system"), context packet = flow + redacted step excerpts (+ consultable_files in agent mode), prompt from prompts/business_flow.md, escalation capped by profile max_escalation_level, budget enforced via estimated_tokens against the serialized request, AgentHandoff on pending answers (exit 3), answer cache via answers.py, usage recorded under stage "business_flow_analysis", parse via flow_answer.json and emit raw findings with flow_category="flow-gap" + flow_ref
- [X] T014 Wire both stages into src/pipeline/run.py: run business_flow_model after build_code_graph; collect flow findings into raw_findings BEFORE correlate_findings.finalize so they inherit normalize/applicability/verify/correlate/triage; emit progress only via progress.py (stage_started/segment_started/segment_done/stage_done, mirroring the finding_triage pattern)
- [X] T015 Extend src/pipeline/verify.py with the flow-aware verdict branch (FR-017): for findings with flow_ref, verified = concrete traversable step path reaches the privileged operation with no intervening check annotation and all locations resolve; plausible = path exists but reachability/control state undetermined; disproven = every modeled path passes the check (existing rejected/unpublish handling applies); verification fully static; step sequences never rendered as source→sink traces

**Checkpoint**: Foundation ready — disabled scans are byte-identical; flows artifact
exists when enabled; analysis round emits normalized findings through the standard
pipeline.

---

## Phase 3: User Story 1 - Scan reports business-flow gaps with the compromised flow (Priority: P1) 🎯 MVP

**Goal**: With flow analysis enabled, the report contains flow-gap findings that name
the flow, show the steps, state the missing/violated check, and explain the compromise
— verified, correlated, triaged, and ranked like any other finding.

**Independent Test**: Scan tests/fixtures/flow-app/ with flow analysis enabled; the
seeded privilege-escalation flow yields exactly one flow-gap finding with inline flow
narrative, safe flows yield none, and a code-level scan of the same fixture reports
nothing for it. The workspace fixture (T006) additionally proves cross-repo stitching
and partial-flow declaration.

### Tests for User Story 1 ⚠️ WRITE FIRST, MUST FAIL

- [X] T016 [P] [US1] Contract tests for business_flow.json and flow_answer.json in tests/contract/test_business_flow_schemas.py (golden flow artifact + answer; invalid mutations rejected; additive finding-field conformance)
- [X] T017 [P] [US1] Unit tests for flow reconstruction in tests/unit/test_business_flow_model.py (stable ids across re-runs; actor determination incl. undetermined; annotation propagation onto steps)
- [X] T018 [P] [US1] Unit tests for the flow-aware verification branch in tests/unit/test_verify_flow.py (verified/plausible/disproven per FR-017 on fixture graphs; disproven ⇒ status rejected + recorded in correlated.disproven; **and** a finding with undetermined reachability never outranks a proven one — severity/confidence reflect what was proven per FR-010, remediating analysis finding C2)
- [X] T019 [P] [US1] Unit tests for the flow↔code "related" linker in tests/unit/test_correlate_flow_links.py (same-cwe/location pairs linked both ways; unrelated pairs untouched; no double-counting)
- [X] T020 [US1] Integration test for multi-repo stitching on tests/fixtures/flow-workspace/ in tests/integration/test_business_flow_workspace.py (steps across the declared sync-api integration stitch into one flow with per-step repo attribution — FR-015; the undeclared hop produces partial=true with gap_reasons=["integration-undeclared"] declared in flow coverage — FR-016; no inference — remediation of analysis finding C1)
- [X] T021 [US1] Integration test for the full scan on tests/fixtures/flow-app/ with flow analysis on in tests/integration/test_business_flow_scan.py (finding content contract per SC-003; safe flows unflagged; flow_coverage section present; usage itemized under business_flow_analysis)

### Implementation for User Story 1

- [X] T022 [US1] Implement the flow↔code linker in src/pipeline/correlate_findings.py: after _link_systemic, pair flow findings with code findings sharing (cwe, repo, file) and record relationships {type: "related", reason} both ways (FR-011)
- [X] T023 [US1] Extend triage candidate controls in src/pipeline/triage.py collect_candidate_controls: include flow-step evidence locations and (when present) obligation text so flow findings are triaged with the same citation re-verification gates (triage_evidence.verify_citations)
- [X] T024 [US1] Render the flow narrative inline in src/pipeline/generate_report.py _render_finding (conditional on flow_category: flow name, ordered steps with repo attribution, missing/violated check, compromise path) and add the additive flow_coverage report section (reconstructed/analyzed/partial/unanalyzed with reasons) passing through resolve_narrative_references unchanged (dangling refs quarantine, exit 4)
- [X] T025 [US1] Mirror T024 rendering in src/pipeline/render_html.py _render_finding + flow coverage section in HTML
- [X] T026 [US1] Add additive flow_coverage to src/skill_core/schemas/report.json (version unchanged) and extend contract tests accordingly
- [X] T027 [US1] Extend the accuracy benchmark with a new defect class for seeded flow gaps in tests/benchmark/ (fixture ground truth includes the seeded escalation flow AND deliberately safe flows; assert ≥80% detection, 0 safe-flow flags; single-class regression fails the build per constitution)

**Checkpoint**: US1 complete — flow-gap findings detected, verified, linked, triaged,
rendered, ranked; fixture proves code-level scan finds nothing for the seeded gap;
workspace fixture proves FR-015/FR-016 stitching and partial declaration.

---

## Phase 4: User Story 2 - User controls whether flow analysis runs (Priority: P2)

**Goal**: Default off everywhere; enable via profile/config/--set; skill asks
interactively only when preference unset and offers opt-in "remember"; non-interactive
never blocks.

**Independent Test**: Three runs of tests/fixtures/flow-app/ — (a) default, (b) profile
with business_flow enabled, (c) skill-driven run with interactive "yes" — (a) is
byte-identical to a pre-feature scan while (b) and (c) include the round.

### Tests for User Story 2 ⚠️ WRITE FIRST, MUST FAIL

- [X] T028 [P] [US2] Unit tests for config validation + precedence in tests/unit/test_config_business_flow.py (unknown keys rejected; absent enabled = unset distinct from explicit false; precedence --set > profile > config > false; env overrides SECSCAN_BUSINESS_FLOW_*)
- [X] T029 [P] [US2] Byte-identical parity test in tests/integration/test_business_flow_off_parity.py (feature disabled ⇒ two in-place full reruns produce identical artifacts modulo scan id and state bookkeeping, and no flow artifacts exist; SC-001)
- [X] T030 [US2] Skill ask/remember integration test in tests/integration/test_skill_flow_ask.py installed-payload matrix style: unset config ⇒ skill prompt directs the ask; remembered assent writes business_flow.enabled into .secscan/config.yaml and suppresses future asks; decline ⇒ nothing written, asked again; direct `secscan run` never prompts and treats unset as disabled (FR-004)

### Implementation for User Story 2

- [X] T031 [US2] Add the business-flow section to src/skill_core/SKILL.md: pre-run ask preconditions (no business_flow.enabled key, no profile enablement), per-scan --set pass-through for the answer, explicit "remember this choice" offer → write enabled into config on assent only, and the business-flow handoff instructions for handoff/responses of stage business_flow_analysis (mirroring the segment-scan and triage sections)
- [X] T032 [US2] Ensure per-scan override plumbing in src/pipeline/scan_cli.py accepts analysis_depth.business_flow via --set (existing _parse_set/profiles._merge path) and document the key; no new CLI surface beyond this

**Checkpoint**: US2 complete — every enable/disable path behaves per FR-001–FR-005;
new users are never charged tokens by default; answers persist only on explicit
opt-in.

---

## Phase 5: User Story 3 - Scan flags flows breaching declared regulatory obligations (Priority: P3)

**Goal**: Reconstructed flows are evaluated against applicable regulatory regimes
(hybrid/declared-only/inferred-only); breaches become regulatory-violation findings
naming regime + obligation; candidates in hybrid mode are declared but never evaluated
until confirmed.

**Independent Test**: Fixture with a consent-less personal-data signup flow declared
gdpr ⇒ one regulatory-violation finding naming regime + obligation + failing step(s);
same fixture with no declared/inferred regime ⇒ zero findings and an explicit declared
undeclared-state record.

### Tests for User Story 3 ⚠️ WRITE FIRST, MUST FAIL

- [X] T033 [P] [US3] Unit tests for regimes dataset loading in tests/unit/test_regimes_data.py (version/dataset_date validation, malformed data fails load — build-time not scan-time; v1 contains gdpr, ccpa, hipaa with obligations + data-category signals)
- [X] T034 [P] [US3] Unit tests for regulated-data category detection + applicability modes in tests/unit/test_regime_applicability.py (deterministic detection over graph annotations/names via dataset rules; hybrid ⇒ candidates recorded not evaluated; declared-only ⇒ no inference; inferred-only ⇒ candidates evaluated with basis; multi-regime breach ⇒ single finding carrying all refs)
- [X] T035 [US3] Integration tests for the three modes in tests/integration/test_business_flow_regimes.py (declared-only finding content per FR-019/SC-007; hybrid candidate declaration with zero findings until declared; inferred-only findings with regulatory_refs[].basis; unknown regime id ⇒ config error)

### Implementation for User Story 3

- [X] T036 [US3] Fill the v1 dataset src/skill_core/data/regimes.json on top of the T005 stub: bump to version "1"; regimes gdpr/ccpa/hipaa each with obligations[] ({id, title, summary, flow_patterns[]}: consent-before-collection, data-subject access/deletion paths, regulated-data safeguards on external share) and regulated_data_categories[] (personal-data, health-data, financial-data with deterministic signal rules)
- [X] T037 [US3] Load the dataset via resources.data_path with functools.cache in src/pipeline/business_flow.py (load-time validation raises on bad data; expose version() helper per the stack_currency.py pattern)
- [X] T038 [US3] Enrich flow reconstruction in src/pipeline/business_flow.py: per-step data_categories from dataset signal rules (sensitive_data annotations + shipped lexicons); candidate regime detection for hybrid mode written into coverage.candidate_regimes as suggested-not-evaluated; applicability section {mode, evaluated_regimes, skipped_reason} in business-flows.json
- [X] T039 [US3] Extend the round in src/pipeline/business_flow.py: packet includes obligations of evaluated regimes; prompt section in src/skill_core/prompts/business_flow.md instructs obligation evaluation per flow (potential-compliance-risk wording, never legal determination — FR-021); answers emit flow_category="regulatory-violation" findings with regulatory_refs [{regime, obligation, basis?}] and dedupe regimes onto one finding per breach (FR-019)
- [X] T040 [US3] Extend benchmark with a regulatory defect class in tests/benchmark/ (seeded consent-less collection + missing deletion path + safeguard-less external share cases; deliberately compliant flows unflagged; ≥80% per SC-006; regime/obligation names asserted per SC-007)

**Checkpoint**: US3 complete — all three applicability modes behave per contract
config-skill §3 and the data-model applicability matrix; unassessable obligations are
declared, never read clean.

---

## Phase 6: User Story 4 - Flow-analysis cost is visible and bounded (Priority: P4)

**Goal**: Enabled scans itemize business_flow_analysis tokens separately; capped
profiles degrade flows to declared coverage gaps instead of over-running.

**Independent Test**: Same fixture with flow analysis off vs on: usage summary shows
the round's incremental cost itemized; under a depth-capped profile, flows needing more
depth appear as coverage gaps with reasons; no request exceeds its serialized budget.

### Tests for User Story 4 ⚠️ WRITE FIRST, MUST FAIL

- [X] T041 [P] [US4] Unit tests for usage attribution in tests/unit/test_usage_flow_stage.py, asserting the recording T013 already performs (UsageTracker by_stage entry business_flow_analysis; cached answers never counted in run usage; batch ledger entries keyed by level:model) — test-only over existing implementation per analysis finding D1
- [X] T042 [US4] Depth- and budget-ceiling degradation tests in tests/integration/test_business_flow_budget.py (still-undetermined at the profile escalation ceiling ⇒ declared with the ceiling named as reason; oversized minimal packet ⇒ declared budget-ceiling without the request ever being sent — asserted against the serialized request; FR-012)

### Implementation for User Story 4

- [X] T043 [US4] Implement ceiling-gated flow subdivision/declaration in src/pipeline/business_flow.py (flows exceeding profile escalation ceiling ⇒ coverage.unanalyzed with reason budget-ceiling; subdivision along security boundaries where possible per FR-012)

**Checkpoint**: US4 complete — opt-in cost is visible and predictable; capped profiles
declare rather than silently under-analyze.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Documentation currency (constitution gate), final validation.

- [X] T044 [P] Update README.md per honest-documentation gate: Status header, Roadmap (mark feature built, remove/move planned items), feature list, config reference (business_flow keys + env overrides), artifact layout (.secscan/business-flows.json, findings/flows.json), profile table row meaning
- [X] T045 [P] Update docs/ (getting-started.md configuration section + any flow/profile pages) and AGENTS.md if agent guidance changed (new stages, new prompt file, skill ask behavior)
- [X] T046 [P] Update specs/015 contract drift notes if implementation moved requirements (spec record per documentation-currency gate)
- [X] T047 Run full verification: pytest -q && pytest -q -m slow && ruff check src tests all green; then execute quickstart.md scenarios 1–6 end-to-end and confirm expected outcomes

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately
- **Foundational (Phase 2)**: Depends on Phase 1 — BLOCKS all user stories
- **US1 (Phase 3)**: Depends on Phase 2 — MVP path
- **US2 (Phase 4)**: Depends on Phase 2 (T009/T010 config+profile); independent of US1 detection logic but shares fixtures
- **US3 (Phase 5)**: Depends on Phase 2 (reconstruction + round, T012/T013) and Setup stub T005; adds regime data to the same module
- **US4 (Phase 6)**: Depends on US1 (usage attribution exists via T013) for full value
- **Polish (Phase 7)**: Depends on all desired stories complete

### User Story Dependencies

- **US1 (P1)**: Standalone after Foundational — no other story needed
- **US2 (P2)**: Standalone config/skill surface; tests reuse flow-app fixture from T004
- **US3 (P3)**: Builds on US1's round/prompt/packet machinery (same files) but its
  acceptance is independently demonstrable
- **US4 (P4)**: Builds on US1's usage recording; independently testable

### Within Each User Story

- Tests MUST be written first and fail before implementation (constitution)
- Schema/data before consumers; model before runner; runner before report rendering
- Story checkpoint green before advancing priority

### Parallel Opportunities

- T001–T006 all parallel (six disjoint files/dirs)
- T016–T019 parallel (four disjoint test files); T020/T021 after T012–T015 land
- T024/T025 parallel (markdown vs html renderers) after T022/T023
- T028/T029 parallel; T033/T034 parallel
- T044/T045/T046 parallel (different docs)

---

## Parallel Example: User Story 1

```bash
# Launch US1 failing tests together:
Task: "Contract tests for business_flow.json and flow_answer.json in tests/contract/test_schemas.py"
Task: "Unit tests for flow reconstruction in tests/unit/test_business_flow_model.py"
Task: "Unit tests for the flow-aware verification branch in tests/unit/test_verify_flow.py"
Task: "Unit tests for the flow↔code linker in tests/unit/test_correlate_flow_links.py"

# Then renderers together after pipeline seams land:
Task: "Flow narrative rendering in src/pipeline/generate_report.py"
Task: "Flow narrative rendering in src/pipeline/render_html.py"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Phase 1 Setup (T001–T006)
2. Phase 2 Foundational (T007–T015) — disabled byte-identity guaranteed
3. Phase 3 US1 (T016–T027) — **STOP and VALIDATE** against the independent test
4. Demoable: flow-gap findings with narratives in all report formats

### Incremental Delivery

1. Foundation → US1 (detection) → ship/demo
2. + US2 (opt-in controls, ask/remember) → ship/demo
3. + US3 (regulatory obligations) → ship/demo
4. + US4 (cost visibility) → polish (docs) → release gates: benchmark green per
  defect class, no README claims left stale
