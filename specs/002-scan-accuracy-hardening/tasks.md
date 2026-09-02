# Tasks: Scan Result Accuracy Hardening

**Input**: Design documents from `/specs/002-scan-accuracy-hardening/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Included — and here they are not optional. FR-043/FR-043a/FR-043b *require* a regression
benchmark asserting per accuracy defect class, and every success criterion (SC-001…SC-013) is stated
as a measurement against a fixture with declared ground truth. Test tasks are therefore requirements
work, not discretionary.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of
each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1–US6)
- All file paths follow plan.md structure (`src/`, `tests/` at repository root)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Dependencies, data-file plumbing, and the fixture/benchmark scaffolding every story needs

- [X] T001 Add `tree-sitter-html>=0.23.2` to `[project.dependencies]` in `pyproject.toml` (research.md A1 — the only new grammar; do not add `tree-sitter-language-pack` or `tree-sitter-jinja-dialects`, both rejected in A1)
- [X] T002 [P] Create `src/skill_core/data/` and extend `src/pipeline/resources.py` with a `data_path(name)` resolver that works in both the source layout and the installed skill payload (mirrors the existing `cwe_map_path()`)
- [X] T003 [P] Add an accuracy-fixture helper `tests/fixtures/accuracy.py` on top of the existing `build_fixture.py`, able to declare ground truth for symbol line ranges, reachable/unreachable sinks, and expected resolution tier
- [X] T004 [P] Create the benchmark harness skeleton `tests/benchmark/__init__.py` + `tests/benchmark/cases/` with the Accuracy Benchmark Case format from data-model.md (`case_id`, `kind`, `target`, `expectations[]` with `defect_class`/`assertion`/`baseline`)
- [X] T005 [P] Record the pre-feature baseline for SC-013 in `tests/benchmark/cases/baseline_usage.json` (from the reviewed scan: 7.58x savings, 39,575 input tokens, 25 invocations, escalation spread L1:10/L2:9/L3:6)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Schema deltas, the four shipped knowledge bases, and file-granularity graph nodes — every user story depends on these

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T006 [P] Apply the `finding.json` delta in `src/skill_core/schemas/finding.json` per `contracts/schema-deltas.md`: `location.tier`/`symbol_confirmed`/`alternatives_existed`/`chosen_by`, `reclassification`, `applicability`, `framework_control`, `calibration`, `dependency`, `reproduction.mode`/`outcome_to_check`/`trigger_omitted_reason`/`traced_trail`, and `source` enum value `dependency-audit` (all additive; `schema_version` stays `1`)
- [X] T007 [P] Apply the `code_graph.json` delta in `src/skill_core/schemas/code_graph.json`: node types `template`/`config`, annotations `template_sink`/`framework_control`/`control_bypass`, node fields `parsed`/`format`, edge type `renders`
- [X] T008 [P] Apply the `report.json` delta in `src/skill_core/schemas/report.json`: `coverage.file_classes`, `coverage.audit_outcomes`, `coverage.resolution_tiers`, `coverage.blocking_gaps`
- [X] T009 [P] Add the new schema `src/skill_core/schemas/architecture_profile.json` and embed it in the repository-manifest and segment schemas per `contracts/schema-deltas.md`
- [X] T010 [P] Extend `tests/contract/test_schemas.py` with valid/invalid samples for every added field **and** a backward-compatibility case asserting that a pre-feature finding artifact still validates (schema-deltas.md "assert both directions")
- [X] T011 [P] Ship `src/skill_core/data/applicability.json` (versioned, sorted) with the first entry from research.md A5 — CWE-918 requires `server-request-issuer`; defensible alternatives CWE-20/CWE-116 — plus a loader in `src/pipeline/applicability.py` that validates ids against the shipped CWE dataset
- [X] T012 [P] Ship `src/skill_core/data/framework_controls.json` from the research.md A1 catalogue (Angular, React, Vue, Jinja2, Django, Thymeleaf, JSP, Go `html/template`) recording per framework: default controls, weakness classes mitigated, sink syntaxes, bypass syntaxes, and **whether it escapes by default** (Jinja2 and JSP do not)
- [X] T013 [P] Ship `src/skill_core/data/stacks.json` mapping each parsed language to its template forms, file suffixes, primary package ecosystem, and audit adapter id (FR-025a, FR-030d)
- [X] T014 [P] Ship `src/skill_core/data/eol.json` as a pinned MIT `endoflife-date/release-data` snapshot with `dataset_version`/`dataset_date` and the manifest-identifier → product-id mapping, plus a loader with a staleness threshold (default 90 days) in `src/pipeline/stack_currency.py` (research.md A3)
- [X] T015 Broaden enumerated source suffixes in `src/pipeline/state.py` (`_SOURCE_SUFFIXES`) and emit **file-granularity nodes with `parsed: false`** for files whose language has no grammar, in `src/pipeline/build_code_graph.py` (FR-003c — this is what gives FR-003's file tier something to resolve against; without it a Ruby/PHP/C# repo produces no nodes at all)
- [X] T016 Add per-file-class classification (`source`/`template`/`dependency-manifest`/`deploy-config`/`datastore-rules`/`client-cache-config`) driven by `stacks.json`, in `src/pipeline/discover_repo.py`, so the Coverage Statement is derivable from the graph rather than recomputed (FR-029)
- [X] T017 [P] Unit tests for the four data loaders (schema validity, determinism of load order, staleness reporting, "adding a stack is a data-only change") in `tests/unit/test_data_files.py`
- [X] T018 Add the new deterministic stages to the `STAGES` tuple in `src/pipeline/state.py` and sequence them in `src/pipeline/run.py` per research.md A8: resolution inside normalize → applicability → correlate → verify → calibrate → reproduce → consistency gate → report

**Checkpoint**: Foundation ready — user story implementation can now begin in parallel

---

## Phase 3: User Story 1 — Trust every factual claim in a finding (Priority: P1) 🎯 MVP

**Goal**: Every location, evidence trail, and reproduction step is either established fact or explicitly labelled as untested hypothesis

**Independent Test**: `security-scan run --full` on `tests/fixtures/single-repo-shop` and `tests/fixtures/unparsed-language` — every reported location matches declared ground truth exactly, every evidence-trail entry is a traced edge, every reproduction block is achievable or labelled a hypothesis, and unparsed-language findings are reported at file tier rather than dropped (quickstart Scenarios 1–3)

### Tests for User Story 1

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T019 [P] [US1] Build fixture `tests/fixtures/unparsed_language.py` — a member in a language the code model does not parse (Ruby or C#), with seeded findings and declared ground truth, for SC-001a
- [X] T020 [P] [US1] Extend `tests/fixtures/single_repo_shop.py` with declared symbol line ranges and a sink whose value is interpolated **after a fixed prefix**, so probe infeasibility (FR-009) is exercisable
- [X] T021 [P] [US1] Unit tests for tiered resolution in `tests/unit/test_locate.py`: symbol tier, file tier, ambiguous-symbol tie-break determinism, rejection when the file is unverifiable, rejection when the file was shed to satisfy the budget
- [X] T022 [P] [US1] Integration test for exact locations in `tests/integration/test_locations.py` (quickstart Scenario 1: SC-001, SC-002 — zero drift, `location.tier` present on every reported finding, no finding claiming its location was unmatched)
- [X] T023 [P] [US1] Integration test for unparsed languages in `tests/integration/test_locations.py` (quickstart Scenario 2: SC-001a — seeded findings reported at `tier: file` with `symbol_confirmed: false`, `resolution_tiers.rejected == 0`)
- [X] T024 [P] [US1] Integration test for reproduction honesty in `tests/unit/test_reproduce_honesty.py` + `tests/integration/test_verification.py` (quickstart Scenario 3: SC-003, SC-004 — `mode: observed` only when `verified`, `traced_trail` ⊆ `verification.path`, no infeasible trigger, `trigger_omitted_reason` when omitted)
- [X] T025 [P] [US1] Benchmark expectations for the `evidence-integrity` defect class in `tests/benchmark/cases/reviewed_real.json`: baselines "2 of 2 locations wrong by 1–2 lines", "1 of 2 unresolved but published", "3 of 8 trail entries off-path", "2 of 2 repro blocks unachievable"

### Implementation for User Story 1

- [X] T026 [US1] Implement tiered location resolution in `src/pipeline/locate.py` per `contracts/accuracy-contracts.md` §1: symbol tier overwrites the model's line range from the graph node so the code model is the sole authority (FR-001); file tier verifies file existence and line bounds; rejection only when the file is unverifiable; deterministic tie-break (own repo → same file → smallest node id) recorded in `chosen_by` with `alternatives_existed` set (FR-004)
- [X] T027 [US1] Wire `locate` into `src/pipeline/normalize_findings.py` so resolution runs **before** `dedupe_by_location`, and make dedupe key off the resolved range so findings differing only in guessed lines collapse (FR-007)
- [X] T028 [US1] Remove the unresolved-but-published path in `src/pipeline/verify.py`: delete the `"the reported location could not be matched to the code graph"` verdict and consume the resolved location instead (FR-003b)
- [X] T029 [US1] Emit line-numbered source (`<line>|` prefix) at **every** escalation level in `src/pipeline/build_context.py`, including `_slice_symbols`, keeping the token budget authoritative so numbering-induced overflow sheds files and reports them as today (FR-002, research.md A6)
- [X] T030 [US1] Update `src/skill_core/prompts/segment_scan.md` to stop asking the model to supply line numbers as authoritative, and to state that source is line-numbered and locations are resolved against the code model
- [X] T031 [US1] Extract sink value-construction shape (is the untrusted value interpolated after a fixed prefix?) in `src/pipeline/extract/enrichers.py`, exposed on `FileFacts` for probe feasibility
- [X] T032 [US1] Split traced path from supporting evidence in `src/pipeline/reproduce.py`: populate `traced_trail` from `verification.path` only, omit it when no path was traced, and stop concatenating evidence items and the finding's own location into it (FR-005, FR-006)
- [X] T033 [US1] Add hypothesis mode to `src/pipeline/reproduce.py`: `mode: observed` only when `verification.status == "verified"`, otherwise `mode: hypothesis` with `outcome_to_check` and an explicit statement that the scanner did not observe it (FR-008), leaving the benign-proof safety constraints — non-destructive canaries, no real credentials, `local/test` scope, no attack execution — in force unchanged (FR-012)
- [X] T034 [US1] Implement probe feasibility in `src/pipeline/reproduce.py` using T031's sink shape: reject a probe whose success criterion requires controlling a fixed prefix, and omit the trigger with `trigger_omitted_reason` when no feasible probe exists (FR-009, FR-010) — this is what kills the benchmark's `http://127.0.0.1:9/...` probe against a fixed-host URL
- [X] T035 [US1] Render the tier distinction and hypothesis mode in `src/pipeline/generate_report.py` so a reader can tell a symbol-level from a file-level guarantee, and a hypothesis from an observation (FR-003a)

**Checkpoint**: US1 fully functional and independently testable — findings are location-exact and reproduction-honest, with no dependency on any other story

---

## Phase 4: User Story 2 — Get the weakness class and severity right (Priority: P1)

**Goal**: Architecture-aware weakness classification and verification-aware severity, so nothing is misrouted or over-alarmed

**Independent Test**: `security-scan run --full` across `tests/fixtures/architectures` (four shapes, same seeded smell) and `tests/fixtures/multi-member-workspace` — no finding carries a class structurally impossible for its reachable architectures, the multi-member case *retains* what the single browser-only member suppresses, and no unproven finding outranks a proven one (quickstart Scenarios 4–6)

### Tests for User Story 2

- [X] T036 [P] [US2] Build fixture `tests/fixtures/architectures.py` — four members (browser-client, server-request-issuer, cli, library) each seeded with the same unencoded-interpolation smell, plus one member with an undeterminable architecture
- [X] T037 [P] [US2] Build fixture `tests/fixtures/multi_member_workspace.py` — browser client + sibling server reachable via a declared sync-API integration, a shared-datastore coupling, a reverse-direction coupling, a hard-coded host pointing at a sibling, and one genuinely unowned host (FR-043a)
- [X] T038 [P] [US2] Unit tests for architecture classification in `tests/unit/test_architecture.py`: each shape from positive evidence, `undetermined` with reason, segment scope overriding member scope, and the assertion that `undetermined` is never replaced by an assumed value (FR-013b)
- [X] T039 [P] [US2] Unit tests for the applicability relation in `tests/unit/test_applicability_eval.py`: suppression only on positive structural disproof; retention on `applicable: true`, on `undetermined` reachability, on `undetermined` architecture, and on operator override; direction respected; all four integration classes counted as reachability
- [X] T040 [P] [US2] Unit tests for framework controls in `tests/unit/test_controls_calibrate.py`: `credited` / `bypassed` / `absent` / `unassessed` state matrix, bypass must be on the traced path, `credited` requires full parse coverage of the path, Jinja2 and JSP not treated as escape-by-default
- [X] T041 [P] [US2] Unit tests for calibration in `tests/unit/test_controls_calibrate.py`, including the post-condition `max(severity of plausible-unconfirmed) < min(severity of verified)` within a scan
- [X] T042 [P] [US2] Unit tests for host ownership in `tests/unit/test_controls_calibrate.py`: `internal` for a member or declared integration far side, `external` otherwise, `undetermined` reported as external with ownership stated (FR-024a, FR-024b)
- [X] T043 [P] [US2] Integration test for architecture-aware classification in `tests/integration/test_classification.py` (quickstart Scenario 4: SC-005 — remap recorded with original class, new class, reason; remaps below threshold still in artifacts)
- [X] T044 [P] [US2] Integration test for cross-member retention in `tests/integration/test_cross_member.py` (quickstart Scenario 5: SC-005a — the class suppressed on the lone browser-only member is retained here with `enabling_member` naming the sibling; host ownership assertions)
- [X] T045 [P] [US2] Integration test for control crediting and calibration in `tests/integration/test_classification.py` (quickstart Scenario 6: SC-006 — reduced severity when credited, capped confidence when unassessed, severity untouched by an off-path bypass)
- [X] T046 [P] [US2] Benchmark expectations for the `classification` and `calibration` defect classes in `tests/benchmark/cases/reviewed_real.json`: baselines "1 of 2 misclassified (CWE-918 on a browser-only target)" and "2 of 2 severities overstated"

### Implementation for User Story 2

- [X] T047 [US2] Implement deterministic architecture classification in `src/pipeline/architecture.py`: shapes from manifest/config evidence, `undetermined` with reason, member and segment scope, no assumed substitution (FR-013–FR-013c, FR-014)
- [X] T048 [US2] Attach Architecture Profiles to `repository/<repo>.manifest.json` and, when they differ, to `segments/<id>.json` in `src/pipeline/discover_repo.py` and `src/pipeline/partition_repo.py`
- [X] T049 [US2] Implement cross-member reachability in `src/pipeline/applicability.py` from the graph's `cross_repo` edges plus all four typed integration classes, directed, deterministic, with no analysis context involved (FR-015a, FR-015b, research.md A7)
- [X] T050 [US2] Implement the applicability evaluation and remap gate in `src/pipeline/applicability.py` per `contracts/accuracy-contracts.md` §2: suppression only on `applicable: false`; record `Applicability Conclusion` and `Reclassification Record`; honour operator override (FR-015c, FR-016, FR-017, FR-019)
- [X] T051 [US2] Move correlation after remapping in `src/pipeline/run.py` and confirm `src/pipeline/correlate_findings.py` deduplicates findings that became identical through a remap (FR-018)
- [X] T052 [US2] Implement framework-control evaluation in `src/pipeline/controls.py` per `contracts/accuracy-contracts.md` §3, including the `unassessed` posture for an unrecognized framework or any unparsed file on the path (FR-022c), and the off-path bypass leaving this finding's severity untouched while being reported as its own hygiene finding (FR-022b) — FR-021, FR-022, FR-022a, FR-022d
- [X] T053 [US2] Implement severity/confidence calibration in `src/pipeline/calibrate.py` per §4: caps for `plausible` with unconfirmed reachability, control-credited severity reduction, `unassessed` confidence cap with no severity inflation, and a `Calibration Record` for each (FR-020)
- [X] T054 [US2] Reframe description, attack scenario, and impact to the residual risk a credited control permits, in `src/pipeline/calibrate.py`, so no narrative describes an impact the control prevents (FR-023)
- [X] T055 [US2] Implement host ownership in `src/pipeline/hosts.py` per §7 and mint the third-party-trust finding for `external` hosts only, exempting workspace-internal hosts with no new operator configuration (FR-024–FR-024b)

**Checkpoint**: US1 AND US2 both work independently. Note the deliberate interaction with US3: until templates are parsed, findings whose path touches a template resolve to `unassessed` rather than `credited` — correct by FR-022c, and upgraded automatically once US3 lands

---

## Phase 5: User Story 3 — See findings in the files where they actually live (Priority: P2)

**Goal**: Templates, manifests, deployment config, datastore rules, and client-cache config are all in the code model, with template bindings as sinks

**Independent Test**: `security-scan run --full` on `tests/fixtures/per-language-stacks` — all five file classes represented and segment-assigned, template bindings discovered as sinks with zero manual steps, unparseable dialects declared with their format named (quickstart Scenario 7)

### Tests for User Story 3

- [X] T056 [P] [US3] Build fixture `tests/fixtures/per_language_stacks.py` — one member per parsed language (JS/TS, Python, Java, Go), each with a template carrying an unsafe binding, a dependency manifest, deployment config, datastore rules, and client-cache config, for SC-007a
- [X] T057 [P] [US3] Add a `.tsx` member with `dangerouslySetInnerHTML` to T056's fixture, which fails today because `.tsx` is parsed with the non-JSX grammar (research.md A1)
- [X] T058 [P] [US3] Unit tests for template extraction in `tests/unit/test_templates.py` covering every sink in the research.md A1 catalogue: Angular `[innerHTML]`/`ng-bind-html`, React `dangerouslySetInnerHTML`, Vue `v-html`, Jinja2/Django `|safe`, Thymeleaf `th:utext`, JSP `<%= %>`/`escapeXml="false"`, Go `template.HTML`
- [X] T059 [P] [US3] Integration test for file-class coverage in `tests/integration/test_coverage.py` (quickstart Scenario 7: SC-007, SC-007a — five classes represented, `renders` edges linking template sinks to the code supplying the value, unparseable dialects named not skipped)
- [X] T060 [P] [US3] Benchmark expectations for the `coverage` defect class in `tests/benchmark/cases/reviewed_real.json`: baseline "0 of 5 file classes represented; four `[innerHTML]` sinks found only by a manual step"

### Implementation for User Story 3

- [X] T061 [US3] Fix the TSX grammar mapping: add a `tsx` language keyed to `language_tsx()` in `src/pipeline/extract/__init__.py` `_GRAMMARS`, and map `.tsx` to it in `src/pipeline/discover_repo.py` `LANGUAGE_BY_SUFFIX` (research.md A1)
- [X] T062 [US3] Register `tree-sitter-html` in `src/pipeline/extract/__init__.py` `_GRAMMARS` and add template suffixes to `LANGUAGE_BY_SUFFIX` and `_SOURCE_SUFFIXES` from `stacks.json`
- [X] T063 [US3] Implement template extraction in `src/pipeline/extract/templates.py`: parse markup with `tree-sitter-html`, detect unsafe bindings as attributes, and add a deterministic delimiter pass for Jinja/Django `|safe` and Go `template.HTML` (research.md A1 — no per-dialect grammars)
- [X] T064 [US3] Emit `template` nodes annotated `template_sink` and `renders` edges back to the code supplying the bound value, in `src/pipeline/build_code_graph.py` (FR-025)
- [X] T065 [US3] Implement configuration-file representation in `src/pipeline/extract/config_files.py` for dependency manifests and lockfiles, deployment/hosting config, datastore rules, and service-worker/client-cache config, emitting `config` nodes at file granularity (FR-026)
- [X] T066 [US3] Ensure partitioning assigns every template and config file to a segment in `src/pipeline/partition_repo.py`, so no security-relevant file is left out of every segment as `package.json` and `firebase.json` were (FR-026)
- [X] T067 [US3] Derive vulnerability domains from code facts present in a segment rather than module naming, in `src/pipeline/partition_repo.py`, so a segment containing a third-party egress call is assessed for personal-data exposure regardless of its name (FR-028)
- [X] T068 [US3] Emit the per-file-class Coverage Statement — `represented`, `unparsed` with format and reason, `not_attempted`, remediation command — in `src/pipeline/generate_report.py`, with silent exclusion treated as a contract violation (FR-027, FR-029)

**Checkpoint**: All of US1–US3 independently functional; findings whose paths touch templates now upgrade from `unassessed` to `credited`/`bypassed` in US2's control evaluation

---

## Phase 6: User Story 4 — Learn about known-vulnerable dependencies (Priority: P2)

**Goal**: Dependency exposure is reported per member and per advisory, or declared as a loud blocking gap — never silently absent

**Independent Test**: `security-scan run --full` on `tests/fixtures/multi-member-workspace` with known-vulnerable manifests and a hoisted lockfile — runtime advisories ranked above dev, one finding per advisory attributing every affected member, per-member gaps where a toolchain is missing, `could-not-check` never rendered as clean, and manifest/lockfile hashes unchanged (quickstart Scenario 8)

### Tests for User Story 4

- [X] T069 [P] [US4] Extend `tests/fixtures/multi_member_workspace.py` with known-vulnerable manifests across two ecosystems (npm + PyPI). The hoisted-lockfile, manifest-without-lockfile, and hidden-toolchain cases are covered synthetically in `tests/contract/test_audit_adapters.py` rather than in the fixture — cheaper and more precise, since each needs a different tree shape
- [X] T070 [P] [US4] Contract tests for the audit adapter guarantees in `tests/contract/test_audit_adapters.py` per `contracts/audit-adapter-contract.md`: read-only (manifest and lockfile hashes unchanged), never raises, `clean` only when audited and clean, deterministic normalized output, bounded by timeout, tool output redacted
- [X] T071 [P] [US4] Unit tests for advisory grouping and attribution in `tests/contract/test_audit_adapters.py`: grouping by `(ecosystem, package, affected_range)`, the ordered attribution fallback, and the prohibition on guessing or broadening to every member (FR-030b, FR-030e, FR-030f)
- [X] T072 [P] [US4] Unit tests for stack currency in `tests/unit/test_stack_currency.py`: past-support-window findings, dataset staleness reporting, manifest-identifier → product-id mapping
- [X] T073 [P] [US4] Integration test for dependency reporting in `tests/integration/test_dependency_audit.py` (quickstart Scenario 8: SC-008, SC-008a — per-ecosystem audit, runtime ranked above dev, one finding per advisory, hoisted-lockfile attribution, per-member gaps, network-failure tri-state)
- [X] T074 [P] [US4] Benchmark expectations for the `dependency-coverage` defect class in `tests/benchmark/cases/reviewed_real.json`: baseline "domain entirely unassessed; 23 runtime advisories (15 high) invisible"

### Implementation for User Story 4

- [X] T075 [US4] Implement the adapter protocol and shared guarantees in `src/pipeline/audits/base.py`: `detect`/`available`/`audit`, the tri-state `AuditOutcome`, mandatory per-member timeout, never-raises contract, read-only enforcement, and redaction of tool output before write (FR-031, FR-033)
- [X] T076 [P] [US4] Implement the Node adapter in `src/pipeline/audits/node.py` for npm/pnpm/yarn per the commands in `contracts/audit-adapter-contract.md`, normalizing onto stable fields only and discarding `via`/`effects`/`fixAvailable` volatility, and handling yarn Berry's NDJSON (research.md A2)
- [X] T077 [P] [US4] Implement the Python adapter in `src/pipeline/audits/python.py` using `pip-audit --format json`
- [ ] T077a [US4] (FR-030d) Add `poetry export`/`uv export` upstream to `src/pipeline/audits/python.py` where those managers are detected — without it a Poetry/uv project with no `requirements.txt` audits its environment rather than its lockfile
- [X] T078 [P] [US4] Implement the Go adapter in `src/pipeline/audits/go.py` using `govulncheck -json ./...`
- [ ] T078a [US4] (FR-030d) Support a local advisory DB via `-db file://…` in `src/pipeline/audits/go.py` — air-gapped runs are exactly where this matters, and today they degrade to `could-not-check`
- [X] T079 [P] [US4] Implement the Java adapter in `src/pipeline/audits/java.py` using the `coordinates-plus-offline-match` capability — `mvn -o -q dependency:list` / `gradle -q dependencies` matched against a bundled OSV Maven export — because no read-only native audit exists and resolving a plugin would violate FR-031 (research.md A2). **Maven only**; Gradle is T079a
- [ ] T079a [US4] (FR-030d) Add Gradle coordinate enumeration (`gradle -q dependencies`) to `src/pipeline/audits/java.py`; a Gradle project currently reports `could-not-check`
- [X] T080 [US4] Implement monorepo attribution in `src/pipeline/audits/attribution.py` with the ordered fallback: native per-member (`npm audit --workspace=`), then declaring-manifest mapping, then `workspace-not-derivable` stated explicitly (FR-030e, FR-030f)
- [X] T081 [US4] Register the audit adapters in `src/pipeline/ingest_findings.py` (created; `run.py` calls through it so FR-030c de-duplication has one owner), running them per member against that member's own ecosystem, only where a dedicated external scanner has not already covered the domain, and merging on advisory identity so nothing is double-reported (FR-030a, FR-030c, FR-032)
- [X] T082 [US4] Implement end-of-support findings in `src/pipeline/stack_currency.py` for declared language, runtime, and framework versions, independent of any individual advisory, mapped to CWE-1104/CWE-1035 (FR-034)
- [X] T083 [US4] Render `coverage.audit_outcomes` and promote unassessed dependency domains to `coverage.blocking_gaps` at the top of the report with the exact command to run, clearly distinguished from a clean result, in `src/pipeline/generate_report.py` (FR-033, FR-035)

**Checkpoint**: US1–US4 independently functional; the benchmark's largest real exposure is now reported.
Three adapter capabilities are deliberately deferred (T077a, T078a, T079a — all FR-030d): Poetry/uv
lockfile export, govulncheck's local advisory DB, and Gradle coordinate enumeration. Each degrades to
`could-not-check` with a runnable command rather than to a silent gap, so the story's guarantees hold;
the coverage is narrower than FR-030d's ideal, not weaker than its floor.

---

## Phase 7: User Story 5 — Stop redaction from manufacturing coverage gaps (Priority: P3)

**Goal**: Coverage gaps represent real uncertainty, with no loss of secret-detection recall

**Independent Test**: the identifier corpus produces zero coverage gaps while every seeded credential is still detected (quickstart Scenario 9)

### Tests for User Story 5

- [X] T084 [P] [US5] Build `tests/fixtures/identifier_corpus.py` from real-project identifiers, import specifiers, and module paths, including the four benchmark false positives (`unSubscribeToSystemPrefferedColorScheme`, `platform-browser-dynamic`, `BrowserDynamicTestingModule`, `platformBrowserDynamicTesting`) with their measured entropies 4.025–4.208
- [X] T085 [P] [US5] Extend `tests/unit/test_redact.py` with the identifier-exemption cases **and** a recall-regression guard asserting every seeded credential in the existing fixtures is still detected (FR-037 — recall may never regress), plus an identifier-shaped credential that must still be blocked; assert SC-009's pair of numbers directly (zero identifier-caused gaps, 100% credential recall)
- [X] T086 [P] [US5] Benchmark expectations for the `redaction-precision` defect class in `tests/benchmark/cases/reviewed_real.json`: baseline "4 of 12 coverage notes were identifier false positives"

### Implementation for User Story 5

- [X] T087 [US5] Implement the identifier-shape gate in `src/pipeline/redact.py`: exempt a high-entropy candidate only when it decomposes into `camelCase`/`PascalCase`/`snake_case`/`kebab-case`/`module-path`/`filesystem-path` segments **and** the line carries no credential context (declaration, comment, or structured-data `key: value` line). Path shapes are checked **per segment**: base64 and AWS keys also contain `/`, so a whole-string test would read a secret as a two-level path; leave `_ENTROPY_THRESHOLD` unchanged (FR-036, research.md A4 — raising the threshold would drop real base64 secrets)
- [X] T088 [US5] Extend `SecretHit` with `decision` and `identifier_shape`, and make blocked-value coverage gaps name file, line, and why the value could not be classified, in `src/pipeline/redact.py` and `src/pipeline/build_context.py` (FR-038, FR-039)

**Checkpoint**: US1–US5 independently functional

---

## Phase 8: User Story 6 — Read a report that does not contradict itself (Priority: P3)

**Goal**: No dangling references, no self-contradiction, and none of the existing honesty markers lost

**Independent Test**: reports rendered from fixtures spanning every severity band contain zero unresolvable internal references and zero narratives contradicting their own verdict; a contradiction blocks the write (quickstart Scenario 10)

### Tests for User Story 6

- [X] T089 [P] [US6] Build fixture `tests/fixtures/all_bands.py` producing findings in every severity band, including a Medium finding whose weakness class has a High default severity — the exact shape that produced "see the High section"
- [X] T090 [P] [US6] Unit tests for the consistency gate in `tests/unit/test_consistency.py`: dangling section reference, narrative contradicting a credited control, reproduction depending on an absent precondition, `mode: observed` without `verified`, and missing read-guidance when nothing was verified
- [X] T091 [P] [US6] Integration test in `tests/integration/test_verification.py` (quickstart Scenario 10: SC-010) asserting a contradiction **blocks** the write, plus an FR-044 preservation check that verdict badges, verification gaps, the verified count, and declared coverage gaps all survive

### Implementation for User Story 6

- [X] T092 [US6] Fix the severity-section pointer in `src/pipeline/generate_report.py` `_recommendations` to use the finding's own published `severity_band` instead of `cwe.band_for(cwe.default_severity(...))` (FR-040 — the "see the High section" defect)
- [X] T093 [US6] Add read-guidance to the executive summary when no finding was verified end to end, in `src/pipeline/generate_report.py` (FR-041)
- [X] T094 [US6] Implement the pre-write consistency gate in `src/pipeline/consistency.py` per `contracts/accuracy-contracts.md` §6 and call it from `src/pipeline/generate_report.py` before any artifact is written, withholding or regenerating the contradicting part (FR-042), including the check that no reproduction block depends on a precondition the finding's own impact text says is absent (FR-011)

**Checkpoint**: All six user stories independently functional

---

## Phase 9: Polish & Cross-Cutting Concerns

**Purpose**: The full benchmark gate, determinism and cost verification, and documentation

- [X] T095 Implement the benchmark runner in `tests/benchmark/test_accuracy_benchmark.py` asserting **per defect class**, so a regression in one class fails without being masked by another class improving (FR-043b)
- [X] T096 Add the seeded multi-member benchmark case `tests/benchmark/cases/seeded_workspace.json` with declared ground truth for cross-member applicability, host ownership, mixed ecosystems, and path-scoped bypass detection (FR-043a)
- [X] T097 Complete the reviewed-real benchmark case `tests/benchmark/cases/reviewed_real.json` end to end (quickstart Scenario 11: SC-011, SC-012 — no request-forgery finding, injection at Low/informational with the sanitizer credited, dependency finding or blocking gap, zero identifier gaps, no dangling reference, and ranked recommendations reproducing the reviewer's order with dependencies first)
- [X] T098 [P] Determinism verification in `tests/integration/test_determinism.py`: two consecutive runs produce byte-identical artifacts including normalized audit output, covering the known `npm audit --json` instability (SC-013, research.md A2)
- [X] T099 [P] Token-cost measurement in `tests/integration/test_determinism.py` asserting the savings ratio has not fallen more than 15% below `baseline_usage.json` after line numbering (SC-013, research.md A6)
- [X] T100 [P] Re-run the existing artifact redaction sweep in `tests/contract/` against every new artifact and finding field, confirming no credential reaches any output (SC-013)
- [X] T101 [P] Update `README.md`: the accuracy properties as a first-class section, the new data files, the `dependency-audit` finding source, tiered locations, and hypothesis-mode reproduction; refresh the test count and roadmap
- [X] T102 [P] Document the four shipped knowledge bases and how to extend them without touching pipeline code in `docs/extending-data.md` (FR-013c, FR-022d, FR-025b)
- [X] T103 [P] Add an `eol.json` refresh command to `src/pipeline/scan_cli.py` (explicit opt-in only, never an implicit network fetch) and document the staleness threshold (research.md A3)
- [X] T104 Run every scenario in `specs/002-scan-accuracy-hardening/quickstart.md` (Scenarios 1–12) against the fixtures and record results; confirm every SC-001…SC-013 assertion is exercised by at least one automated test under `tests/`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies — start immediately
- **Foundational (Phase 2)**: depends on Setup — **BLOCKS all user stories**
- **User Stories (Phases 3–8)**: all depend on Foundational
  - US1, US2, US4, US5, US6 are mutually independent and can proceed in parallel
  - US3 is independent but *enhances* US2 (see below)
- **Polish (Phase 9)**: depends on all desired stories; T097 requires all six

### User Story Dependencies

- **US1 (P1)**: after Phase 2. No dependency on any other story.
- **US2 (P1)**: after Phase 2. Independent. Reads `verification.path`, which exists today.
- **US3 (P2)**: after Phase 2. Independent.
- **US4 (P2)**: after Phase 2. Fully independent — touches no shared module except the report renderer.
- **US5 (P3)**: after Phase 2. Independent; confined to the redactor.
- **US6 (P3)**: after Phase 2. Independent, but its value grows as other stories add fields to check.

**The one soft coupling, by design**: US2's FR-022a requires the bypass search to cover every file
class the code model represents. Before US3, a path touching a template yields `unassessed` — which is
*correct* under FR-022c, not a bug — and upgrades to `credited`/`bypassed` automatically once US3
lands. US2 is therefore independently shippable and correct; US3 raises its precision. Tests must
assert the `unassessed` behaviour so the property holds in both orders.

### Within Each User Story

- Tests are written first and must fail before implementation
- Data files and schemas (Phase 2) before any consumer
- Extraction before graph emission before partitioning before reporting
- Stage order inside the pipeline is fixed by research.md A8 and must not be reordered

### Parallel Opportunities

- Phase 1: T002–T005 in parallel
- Phase 2: T006–T014 and T017 in parallel (T015, T016 and T018 run alone — T015/T018 touch shared files, and T016 consumes the `stacks.json` that T013 creates)
- Every story's test tasks are `[P]` within that story
- Phase 6: T076–T079 are one adapter per file, fully parallel
- Phase 9: T098–T103 in parallel

---

## Parallel Example: Phase 2 Foundational

```bash
# Schemas and data files are independent files:
Task: "Apply finding.json delta in src/skill_core/schemas/finding.json"
Task: "Apply code_graph.json delta in src/skill_core/schemas/code_graph.json"
Task: "Apply report.json delta in src/skill_core/schemas/report.json"
Task: "Add src/skill_core/schemas/architecture_profile.json"
Task: "Ship src/skill_core/data/applicability.json + loader"
Task: "Ship src/skill_core/data/framework_controls.json"
Task: "Ship src/skill_core/data/stacks.json"
Task: "Ship src/skill_core/data/eol.json + staleness loader"
```

## Parallel Example: User Story 4 adapters

```bash
# One ecosystem per file, no shared state:
Task: "Implement Node adapter in src/pipeline/audits/node.py"
Task: "Implement Python adapter in src/pipeline/audits/python.py"
Task: "Implement Go adapter in src/pipeline/audits/go.py"
Task: "Implement Java adapter in src/pipeline/audits/java.py"
```

---

## Implementation Strategy

### MVP First (US1 + US2)

The recommended MVP is **both P1 stories**, not just US1:

1. Phase 1: Setup
2. Phase 2: Foundational (CRITICAL — blocks everything)
3. Phase 3: US1 — locations exact, reproduction honest
4. Phase 4: US2 — right weakness class, calibrated severity
5. **STOP and VALIDATE**: quickstart Scenarios 1–6; benchmark `evidence-integrity`, `classification`, and `calibration` classes pass
6. Demo: re-scan the benchmark target and show that the two findings the reviewer disputed are now correctly classified and scored

Rationale: US1 and US2 together fix everything the reviewer called damaging, need no new grammar and
no subprocess work, and touch only deterministic post-processing. US3 and US4 are the larger builds
(new extractors, new adapters, new fixtures per language and ecosystem).

### Incremental Delivery

1. Setup + Foundational → foundation ready
2. US1 → validate → demo (locations and reproduction trustworthy)
3. US2 → validate → demo (**MVP** — classification and severity correct)
4. US3 → validate → demo (nothing security-relevant invisible; US2 precision rises)
5. US4 → validate → demo (the largest real exposure now reported)
6. US5 + US6 → validate → demo (clean coverage section, self-consistent report)
7. Polish → full benchmark gate, determinism, cost, docs

### Parallel Team Strategy

After Phase 2, with four developers: A on US1, B on US2, C on US3+US4 (both coverage-shaped), D on
US5+US6 (both small and confined). D finishes early and picks up Phase 9 test infrastructure.

---

## Notes

- `[P]` tasks = different files, no dependencies
- `[Story]` label maps each task to a spec.md user story for traceability
- Every task cites the FR/SC it discharges, or the research decision it implements
- Verify tests fail before implementing
- Commit after each task or logical group
- Stop at any checkpoint to validate a story independently
- **Never guess in either direction; declare the unknown.** FR-013a, FR-015c and FR-022c all restate
  this rule. If a task's implementation forces a choice between a false positive and a false negative,
  the answer is a third state that records the uncertainty — not a coin flip
- Additive schemas only: a pre-feature artifact must still validate after every task in Phase 2
