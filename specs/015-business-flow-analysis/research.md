# Research: Business-Flow (Functional) Vulnerability Analysis

**Date**: 2026-09-05 | **Spec**: [spec.md](spec.md)

All findings below come from direct inspection of the codebase (pipeline, config,
schemas, skill payload). No NEEDS CLARIFICATION items remain open; every design
unknown raised during planning is resolved here with a decision.

## Decision 1: Two-stage split — deterministic flow model, then a bounded reasoning round

**Decision**: Split the feature into a deterministic stage `business_flow_model`
(reconstruct business flows from `code-graph.json` + `workspace.json`, write
`.secscan/business-flows.json`) and a bounded-LLM round `business_flow_analysis`
(reason over flow packets, emit raw flow findings).

**Rationale**: Constitution Principle I requires discovery and evidence collection to
be deterministic with model reasoning only over prepared evidence. The code graph
already carries every flow ingredient — `endpoint` nodes with `handler` edges, `calls`
edges, `datastore` nodes with `reads`/`writes`, and `authentication_required` /
`authorization_required` / `sensitive_data` / `trust_boundary` annotations
(`src/pipeline/build_code_graph.py:190-218`, `src/pipeline/extract/enrichers.py:138-184`,
`src/pipeline/dataflow.py:30-169`). Reconstruction is therefore a new derivation over
existing artifacts, not a new repository crawl.

**Alternatives considered**: Pure-LLM flow discovery (rejected — violates Principle I,
non-deterministic); extending `dataflow.trace_flows` directly as "the flows" (rejected —
source→sink data paths are not business journeys; flows need actor/step/transition
grouping above data paths, though they reuse the same `FlowGraph` adjacency).

## Decision 2: Where the round plugs into the pipeline

**Decision**: `business_flow_model` runs immediately after `build_code_graph`.
`business_flow_analysis` runs after the deterministic finding passes
(`misconfig`/`compound`/`llm_findings`/…) and **before** `correlate_findings.finalize`
(`src/pipeline/run.py:598-613`), so its findings join `raw_findings` and receive
normalization, applicability, verification, correlation, and finding-triage for free.

**Rationale**: FR-011 requires flow findings to flow through every existing pass.
Running before `finalize` reuses `FindingNormalizer` (`normalize_findings.py:91-211`),
`applicability.apply_applicability`, `verify.apply_verification`
(`verify.py:175-195`), `correlate` (`correlate_findings.py:39-90`), and triage
(`triage.py`, `triage_apply.py`) with zero special-casing. Triage (FR-011, spec
assumption) then operates on flow findings like any other correlated finding.

**Alternatives considered**: Post-correlation round modeled on `finding_triage`
(rejected — findings would land after verify/correlate; normalize/verify would need a
second pass and correlation could never relate flow findings to code-level findings);
a new narrative-only stage modeled on the current deterministic `system_review`
(`run.py:686-697`) (rejected — the feature's output is schema-conforming findings,
not prose).

## Decision 3: Configuration surface and precedence

**Decision**: Add a `business_flow` config section (validated in
`src/config/loader.py`) plus an `AnalysisDepth.business_flow: bool` profile flag:

```yaml
business_flow:
  enabled: true | false            # ABSENT key = preference unset (see Decision 4)
  applicability_mode: hybrid       # hybrid | declared-only | inferred-only (default hybrid)
  declared_regimes: []             # e.g. ["gdpr", "ccpa", "hipaa"]
```

Effective enablement resolves: `--set` profile override > profile
`analysis_depth.business_flow` > config `business_flow.enabled` > default `false`.
All built-in profiles ship `business_flow: false` (FR-001). Config registration follows
the existing pattern: `_ALLOWED`, `DEFAULT_CONFIG` (defaults omit `enabled` so
"unset" is distinguishable from explicit `false`), `apply_env_overrides` sections
(`SECSCAN_BUSINESS_FLOW_*`), `validate_config`, and a `Config.business_flow` property.

**Rationale**: Mirrors how `finding_triage` and `system_review` are toggled today
(`AnalysisDepth` booleans, `profiles.py:35-43`) while keeping regime policy
(profile-independent, project-level) in config — matching the spec's "no new storage
mechanism" assumption.

**Alternatives considered**: Config-only toggle (rejected — per-profile depth variance,
e.g. enabling flow analysis only in `audit`, would be impossible); profile-only
(rejected — the interactive "remember" preference and regime declarations are
project-scoped, not profile-scoped).

## Decision 4: Interactive ask mechanics and "remember" persistence

**Decision**: The *skill* (not the CLI) asks. `SKILL.md` directs the agent: before
`secscan run`, if `.secscan/config.yaml` lacks an explicit `business_flow.enabled`
key, ask the user whether to run business-flow analysis, offer "remember this choice",
and on explicit assent write `enabled: true|false` into `business_flow:` (a plain
non-secret key). Re-asking happens only while the key stays unset. The ask is a
skill-layer interaction; `secscan run` itself never prompts (FR-004).

**Rationale**: FR-003 + clarified persistence semantics; agent-mediated mode is exactly
where a scan spans multiple sessions, so the remembered key removes repeat friction
with explicit consent only. Writing `.secscan/config.yaml` is scanner-owned state, so
the "never mutate the scanned project" invariant is untouched. Absent-vs-explicit-false
is detectable because `DEFAULT_CONFIG` intentionally omits `enabled`.

**Alternatives considered**: CLI `--ask`/`--remember` flags (rejected — adds CLI surface
for an agent-side interaction the spec scopes to the skill); always-persist (rejected —
silently persists a cost/security-relevant choice from a chat answer).

## Decision 5: Regulatory regimes as versioned data + deterministic applicability

**Decision**: New dataset `src/skill_core/data/regimes.json` (`version` +
`dataset_date`, loaded via `resources.data_path` with `functools.cache`, like
`stack_currency.py:25-49`). v1 ships three regimes — `gdpr`, `ccpa`, `hipaa` — each
with its obligations (consent-before-collection, data-subject access/deletion,
regulated-data safeguards) and a deterministic `regulated_data_categories` mapping.
Applicability per FR-022/FR-023:

- *declared-only*: only `business_flow.declared_regimes` are evaluated.
- *inferred-only*: regimes raised from regulated-data categories detected in the code
  graph (e.g. `sensitive_data` fields, datastore/field names matched by dataset rules);
  all candidates evaluated, findings state the detection basis.
- *hybrid* (default): declared regimes evaluated; detected-but-undeclared categories
  raise **candidate regimes** recorded in the flows artifact as
  `suggested-not-evaluated`; no findings until the user declares the regime.

Inference is rule-over-graph, never model output (Principle I).

**Alternatives considered**: LLM-judged applicability (rejected — constitution forbids
model-derived applicability); shipping no v1 regimes and requiring full user-defined
regimes (rejected — the spec names privacy/healthcare examples and SC-006 fixtures need
seeded regimes).

## Decision 6: Finding representation (schema stays additive, version 1)

**Decision**: Flow findings are ordinary findings plus additive optional fields in
`src/skill_core/schemas/finding.json`:

- `flow_category`: enum `flow-gap` | `regulatory-violation`
- `flow_ref`: stable flow identifier into `business-flows.json`
- `flow_narrative`: `{name, steps[] (ordered, each repo-attributable), missing_check, compromise}`
- `regulatory_refs`: `[{regime, obligation, basis?}]` (required iff category is
  `regulatory-violation`; `basis` states detection basis in inferred-only mode)

Consistency rule (enforced in normalization + contract tests, since JSON Schema
`if/then` would complicate the existing schema): the trio `flow_category` / `flow_ref` /
`flow_narrative` is all-or-nothing. Additive change — no `schema_version` bump
(`schemas.py:20` stays `"1"`).

**Alternatives considered**: A separate flow-finding artifact/report section (rejected —
spec Q&A: merged ranked list, one ranking, no double-counting); new `source` enum value
(rejected — `source: "analysis"` already covers reasoning-produced findings).

## Decision 7: Flow identity and cross-run stability

**Decision**: A flow's stable id is derived from its entry node and ordered step node
ids: `flow = sha256(entry_node_id + "\n" + "\n".join(step_node_ids))[:12]`, prefixed
`flow:<workspace>:`. Step node ids reuse the existing stable `<repo>:<path>#<symbol>`
identifiers. Partial flows (undeclared/undetermined cross-repo boundary, FR-016) carry
`"partial": true` plus a `gap_reason`, computed from the same inputs, so identity stays
stable across runs and dedupe/matching works on re-scan.

**Rationale**: Constitution Principle I (stable identifiers) + SC-001
determinism; regressions and benchmark fixtures need to assert on stable flow ids.

## Decision 8: Path-based verification for flow findings

**Decision**: Extend `verify.py` with a flow-aware branch: for findings carrying
`flow_ref`, verification walks the reconstructed flow's step graph (built over the
same `FlowGraph` adjacency, `dataflow.py:54-76`) — `verified` when a concrete
traversable step path reaches the privileged operation with no intervening check
annotation and all locations resolve; `plausible` when a path exists but reachability
or control state is undetermined; `disproven` when every modeled path passes the check
(existing behavior applies: `status="rejected"`, unpublished, id recorded in
`correlated.disproven`). Verification stays fully static (Principle VI) and the step
sequence renders as ordered steps, never as a source→sink trace (FR-009/FR-017).

**Rationale**: FR-017 verbatim; reuses the existing verdict vocabulary so profile
thresholds, ranking (`generate_report.py:24-42`), and triage gates behave identically.

## Decision 9: Flow ↔ code-finding relationship

**Decision**: After `correlate`, a deterministic linker pairs flow findings with
code-level findings sharing `(cwe, repo, file)` (same seam as `_link_systemic`,
`correlate_findings.py:75-90`) and records a `relationships` entry of type `"related"`
both ways (schema already supports it, `finding.json:723-730`). No dedupe — both
findings remain; FR-011's "related, never double-counted" is satisfied by the link and
by root-cause keys not colliding (flow findings key on their flow evidence location).

## Decision 10: Triage, budgets, batching, usage, progress reuse

**Decision**: Flow findings are triage candidates like any other;
`collect_candidate_controls` (`triage.py:97`) additionally seeds flow-step evidence and
the applicable regime/obligation text into `candidate_controls`. The reasoning round
uses `AnalysisRequest(stage="business_flow_analysis", level="system")` (so model tier
maps to `model_map.system`, `config/mode.py:80-84`), reuses `AgentMediatedClient`
handoff files, `EndpointClient` answer caching (`answers.py`), `BatchLedger` batching
(`batch_runner.py`), escalation capped by the profile's `max_escalation_level`, and
budgets enforced via `AnalysisRequest.estimated_tokens()` against the serialized
request. Usage is recorded as stage `business_flow_analysis` in `UsageTracker`
(FR-013). Progress uses `reporter.stage_started/segment_started/segment_done/
stage_done` following the `finding_triage` pattern (`run.py:827-972`); both new stages
join `state.STAGES` (`state.py:51-68`) and `_ANALYSIS_STAGES` (`run.py:759-773`) with
resume keys covering graph hash + `business_flow` config + `regimes.json` version.

## Decision 11: Report rendering and flow coverage declaration

**Decision**: `generate_report.py:_render_finding` and `render_html.py:_render_finding`
extend conditionally on `flow_category` to render the flow narrative inline (name,
ordered steps with repo attribution, missing/violated check, compromise path, regulatory
refs). The report gains an additive `flow_coverage` section (report.json additive,
version unchanged) listing flows reconstructed / analyzed / partial (with reasons) /
unanalyzed, plus candidate regimes and declared-but-unassessable regimes (SC-004,
SC-007, FR-010). Flow narratives name flow ids and finding ids, so they pass through
`resolve_narrative_references` (`generate_report.py:74-168`) like any other section —
dangling references quarantine with exit code 4, unchanged.

## Decision 12: Test strategy anchors

**Decision**: Contract-test the new schemas and the additive finding fields
(`tests/contract/`); unit-test flow reconstruction, applicability modes, verification
branch, linker, and config validation; extend accuracy-benchmark fixtures with seeded
flow gaps and seeded regulatory cases per defect class (release-blocking per
constitution), including deliberately safe flows that MUST NOT be flagged (SC-002,
SC-006); determinism two-run test with the feature both disabled (byte-identical to
pre-feature, SC-001) and enabled (byte-identical across reruns); integration test
covering multi-repo stitching over declared `sync-api` / `identity-propagation`
integrations and partial-flow declaration for undeclared ones.
