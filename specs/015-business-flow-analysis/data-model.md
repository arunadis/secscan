# Data Model: Business-Flow (Functional) Vulnerability Analysis

**Date**: 2026-09-05 | **Spec**: [spec.md](spec.md) | **Research**: [research.md](research.md)

All persistence is artifact JSON under `.secscan/` plus the existing layered
configuration. No new storage mechanism. Existing entities (`finding`, envelope, state)
are extended **additively** — `SCHEMA_VERSION` remains `"1"`.

## Entity: BusinessFlow (new artifact `business-flows.json`)

Produced deterministically by stage `business_flow_model` from `code-graph.json` +
`workspace.json`. Identical graph + workspace + `regimes.json` version ⇒ byte-identical
artifact.

| Field | Type | Notes / validation |
|---|---|---|
| `id` | string | Stable: `flow:<workspace>:<sha12>` over entry node id + ordered step node ids (neighbours `<repo>:<path>#<symbol>`) |
| `name` | string | Human-readable; derived from entry point (route path / CLI command) |
| `actor` | object | `{kind: anonymous\|authenticated\|role, role?: string, determination: declared\|inferred\|undetermined}` |
| `steps` | FlowStep[] | Ordered; never empty |
| `related_data_flows` | string[] | Flow ids from `dataflow.trace_flows` that thread through the steps (supporting evidence — **not** rendered as the business path) |
| `partial` | bool | `true` when a cross-repo boundary is undeclared/undetermined or the flow could not be closed |
| `gap_reasons` | string[] | Present iff `partial`; machine-readable reasons (`integration-undeclared`, `integration-type-undetermined`, `actor-undetermined`, `budget-unreconstructable`) |

### FlowStep

| Field | Type | Notes |
|---|---|---|
| `node_id` | string | `<repo>:<path>#<symbol>` — repo attribution is free (FR-015) |
| `operation` | enum | `entry \| transition \| mutation \| external-call \| terminal` |
| `annotations` | string[] | Subset of code-graph annotations present here (`authentication_required`, `authorization_required`, `sensitive_data`, `trust_boundary`, …) |
| `data_categories` | string[] | Deterministically detected regulated-data categories (`personal-data`, `health-data`, `financial-data`) from `regimes.json` signal rules — evaluated over file *text* during extraction (file-node fact), merged onto steps; node-identity matching is an additional, weaker signal |
| `integration_leg` | object? | `{type: sync-api\|async-messaging\|shared-datastore\|identity-propagation, target_repo}` when the step crosses repos via a declared integration |

## Entity: FlowCoverage (section of `business-flows.json`)

| Field | Type | Notes |
|---|---|---|
| `reconstructed` | string[] | Flow ids |
| `analyzed` | string[] | Flow ids that received a completed reasoning request |
| `partial` | object[] | `{flow_id, gap_reasons}` |
| `unanalyzed` | object[] | `{flow_id, reason}` (e.g. handoff abandoned, budget ceiling under capped profile) |
| `undetermined` | object[] | `{flow_id, reasons[]}` — answered but undetermined flows, with the reasons (added during implementation; plan deviation 3) |
| `candidate_regimes` | object[] | `{regime, detected_categories[], step_refs[]}` — hybrid mode only; **suggested-not-evaluated** |
| `applicability` | object | `{mode: hybrid\|declared-only\|inferred-only, evaluated_regimes[], skipped_reason?}` |

Undetermined states have explicit `reason` fields; nothing reads as clean by omission
(FR-010, SC-004, SC-007).

## Entity: RegulatoryRegime (versioned dataset `src/skill_core/data/regimes.json`)

Top level: `{version, dataset_date, regimes[]}`. v1 regimes: `gdpr`, `ccpa`, `hipaa`.

| Field | Type | Notes |
|---|---|---|
| `id` / `name` | string | e.g. `gdpr` / "EU General Data Protection Regulation" |
| `obligations[]` | object | `{id, title, summary, flow_patterns[]}` — patterns describe the flow shape the obligation demands (e.g. `consent-before-collection`, `data-subject-deletion-path`, `regulated-data-safeguard-on-external-share`), as evidence rules for reasoning and verification |
| `regulated_data_categories[]` | object | `{category, signals[]}` — deterministic signals over node names/annotations that raise the category (e.g. `health-data`: field/symbol names matching shipped term lists, or `sensitive_data` annotation + health lexicon) |

Adding a regime or obligation = data edit + `version`/`dataset_date` bump (FR-020).
Wording is potential-compliance-risk style, never legal determination (FR-021).

## Extensions to Code Graph (`code_graph.json`, additive, version unchanged)

Feature 015 adds two file-node facts (implementation deviation 1 in plan.md):

| Field | Type | Notes |
|---|---|---|
| `outbound_hosts` | string[] | Sorted, deduplicated outbound URL hostnames referenced by the file (excludes localhost/loopback). Cross-repo flow hops are pinned per-file from these hosts; a host matching a workspace member name (exact or dotted-prefix) is a hop candidate, anything else a third party. |
| `data_categories` | string[] | Regulated-data categories detected in the file's text via the regime dataset's shipped signal rules; merged onto flow steps. |

## Extensions to Finding (`finding.json`, additive, version unchanged)

| Field | Type | Rule |
|---|---|---|
| `flow_category` | enum `flow-gap` \| `regulatory-violation` | Present iff `flow_ref`/`flow_narrative` present (all-or-nothing) |
| `flow_ref` | string | MUST resolve to a flow id in `business-flows.json` (SC-003 — unresolvable refs are rejected in normalization, mirroring tiered location resolution) |
| `flow_narrative` | object | `{name, steps[], missing_check, compromise}` — `steps[]` = `{node_id, detail}`; `missing_check` names the absent/violated control; `compromise` = who gains what |
| `regulatory_refs[]` | object | `{regime, obligation, basis?}` — REQUIRED iff `flow_category = regulatory-violation` (FR-019, SC-007); `basis` = detection basis, required in `inferred-only` mode (FR-023) |

Inherited behavior: `verification.status` uses the existing
`verified / plausible / disproven` vocabulary via the flow-aware verification branch
(FR-017); `relationships[].type = "related"` links to code-level findings (FR-011);
`triage` block unchanged; `compliance_refs` (CWE-derived annotations) continue
unchanged and are distinct from `regulatory_refs`.

## Extensions to Report (`report.json`, additive)

| Field | Type | Notes |
|---|---|---|
| `flow_coverage` | object | Mirror of FlowCoverage; rendered as a declared-coverage section |
| (within each finding) | — | conditional inline rendering of `flow_narrative` + `regulatory_refs` in all three formats (FR-014) |

## Extensions to Config (`config.yaml` + profiles)

```yaml
business_flow:
  enabled: true|false        # absent key ⇒ preference unset (skill asks)
  applicability_mode: hybrid # hybrid|declared-only|inferred-only, default hybrid
  declared_regimes: []       # strings; MUST exist in regimes.json
```

Profiles: additive `analysis_depth.business_flow: bool` (all built-ins `false`).
Precedence: `--set` > profile > config > default `false`.
Env overrides: `SECSCAN_BUSINESS_FLOW_ENABLED`, `SECSCAN_BUSINESS_FLOW_APPLICABILITY_MODE`,
`SECSCAN_BUSINESS_FLOW_DECLARED_REGIMES`.
Strict validation rejects unknown keys (existing `_check_unknown_keys`).

## State transitions

### BusinessFlow (within a scan)

```
reconstructed ── enabled? ──no──► (coverage: unanalyzed[reason=disabled])
      │yes
      ▼
awaiting reasoning ── answer received ──► analyzed (findings may or may not result)
      │handoff pending / abandoned               │ anyway coverage.analyzed
      ▼                                          ▼
unanalyzed[reason=handoff-abandoned]      verification → triage → report
```

`partial` is a property at reconstruction, orthogonal to analysis status — a partial
flow is still analyzed (within what is known) and its gaps declared.

### Candidate regime (hybrid mode)

```
detected (category signal) ──► suggested-not-evaluated (declared in coverage)
      │ user confirms by adding to declared_regimes
      ▼
evaluated (obligations assessed on next scan; stage resume keyed on config change)
```

### Applicability mode — per-regime evaluation matrix

| Mode | Declared in config | Raised by detection | Result |
|---|---|---|---|
| hybrid | yes | — | evaluated |
| hybrid | no | yes | candidate: recorded, not evaluated |
| declared-only | yes | — | evaluated |
| declared-only | no | yes | ignored (no inference) |
| inferred-only | — | yes | evaluated; findings carry `basis` |
| inferred-only | — | no | not applicable |
