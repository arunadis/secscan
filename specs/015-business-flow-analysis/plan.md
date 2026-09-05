# Implementation Plan: Business-Flow (Functional) Vulnerability Analysis

**Branch**: `015-business-flow-analysis` | **Date**: 2026-09-05 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/015-business-flow-analysis/spec.md`

**Note**: Filled by the `/speckit-plan` command per the plan template workflow.

## Summary

secscan today finds defects *inside* code units; this feature finds defects *of the
business flow itself* — missing enforcement between steps, skippable enforced steps,
cross-role/tenant transitions — plus regulatory-obligation breaches (consent,
data-subject rights, regulated-data safeguards). A new deterministic stage
`business_flow_model` reconstructs business flows from the existing code graph and
workspace integrations (stitching steps across repos **only** through declared, typed
integration points; partial flows declared otherwise). A new bounded-LLM round
`business_flow_analysis` then walks each flow per the clarified semantics and emits
schema-conforming findings that join `raw_findings` **before** `correlate_findings.finalize` —
inheriting normalization, applicability, path-based verification (`verified` /
`plausible` / `disproven`, FR-017), correlation links to code-level findings, triage,
and the merged ranked report inline (FR-008/FR-011/FR-014). Everything is opt-in
(default off everywhere: FR-001, FR-005 byte-identical disabled), governed by a
`business_flow` config section + profile flag + a skill-level ask-with-opt-in-remember
(FR-002–FR-004), with regime applicability modes `hybrid|declared-only|inferred-only`
(FR-022/FR-023) and regimes shipped as versioned data (FR-020). Token cost obeys the
existing serialized-request budgets and is itemized per stage (FR-012/FR-013).

## Technical Context

**Language/Version**: Python 3.11+

**Primary Dependencies**: none new — tree-sitter (pinned wheels), PyYAML, stdlib json;
payload ships as `src/pipeline/` + `src/skill_core/`

**Storage**: artifacts under `.secscan/` (canonical sorted JSON, trailing newline);
`.secscan/config.yaml`; versioned data in `src/skill_core/data/regimes.json` (new)

**Testing**: pytest (~800 tests + `-m slow` scale scan), ruff (`E/F/I/UP/B`, line 100);
contract tests under `tests/contract/`; accuracy benchmark per defect class
(release-blocking)

**Target Platform**: CLI / installed agent skill (`python -m pipeline.scan_cli`),
macOS/Linux

**Project Type**: offline security-scanner CLI + skill payload

**Performance Goals**: flow analysis fully opt-in; budgets enforced against the
serialized request (`AnalysisRequest.estimated_tokens`); `business_flow_analysis`
usage itemized separately in the usage summary

**Constraints**: no network in default path; never mutate the scanned project; secrets
never reach a model (packets built over redacted excerpts like triage packets);
identical input + tool version ⇒ byte-identical artifacts; endpoints only via
`src/pipeline/providers.py`; progress only via `src/pipeline/progress.py`

**Scale/Scope**: multi-repo workspaces (typed integrations: sync-api, async-messaging,
shared-datastore, identity-propagation); `quick/full/audit` profiles with escalation
ceiling ≤ 4; agent-mediated handoff across sessions (exit 3 resume)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Evaluation (pre-Phase-0 and post-Phase-1 — identical) | Verdict |
|---|---|---|
| I. Determinism Before Intelligence | Flow reconstruction is a deterministic derivation over `code-graph.json`/`workspace.json` (stable ids per Decision 7); regime applicability is rule-over-graph + declared config, never model output (Decision 5); all artifacts canonical JSON; resume keys include graph/config/data versions. | PASS |
| II. Context Is a Managed Resource | One bounded request per flow (`level="system"` tier), escalation begins small and is capped by the profile ceiling — flows exceeding the ceiling are declared coverage gaps (spec assumption), enforced against the serialized request (Decision 10). | PASS |
| III. Secrets Never Reach a Model | Flow packets are built over redacted excerpts via the same packet/excerpt machinery as triage (`triage.py:209-237`); agent-mode direct file consults remain limited to zero-redaction-hit files. | PASS |
| IV. Evidence Over Assertion | Findings enforce `finding.json` (+ additive fields); `flow_ref` resolves against `business-flows.json` or is rejected (SC-003); step sequences render as steps-with-evidence, never as source→sink traces (FR-009). | PASS |
| V. Honest Uncertainty | Undetermined actor/reachability/regimes/partial flows are recorded with reasons (FlowCoverage) and can never suppress, read as clean, or inflate severity (FR-010, SC-004/SC-007). | PASS |
| VI. Observe, Never Attack | Verification stays static path-walking (Decision 8); no flow execution; scanner writes only `.secscan/`; the config "remember" write is an explicit agent action on scanner-owned state (contract config-skill §2). | PASS |

No exceptions required; Complexity Tracking empty by design.

## Project Structure

### Documentation (this feature)

```text
specs/015-business-flow-analysis/
├── plan.md              # This file
├── research.md          # Phase 0 output — 12 design decisions
├── data-model.md        # Phase 1 output
├── contracts/
│   ├── business-flow-artifact.md   # stages, business-flows.json schema, round exchange
│   └── config-skill.md             # config keys, precedence, skill ask/remember
├── quickstart.md        # Phase 1 output — 6 validation scenarios
├── checklists/requirements.md
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created here)
```

### Source Code (repository root)

```text
src/
├── pipeline/
│   ├── business_flow.py        # NEW: flow reconstruction + analysis round runner
│   │                           #      (model + packet builder + answer parser)
│   ├── run.py                  # wire stages; raw_findings seam before finalize
│   ├── state.py                # STAGES += business_flow_model, business_flow_analysis
│   ├── verify.py               # flow-aware verdict branch (path semantics, FR-017)
│   ├── correlate_findings.py   # flow↔code "related" linker
│   ├── triage.py               # candidate_controls: flow steps + obligation text
│   ├── generate_report.py      # inline flow narrative; flow_coverage section
│   ├── render_html.py          # same, HTML
│   └── schemas.py              # auto-discovers two new schemas below
├── config/
│   ├── loader.py               # business_flow section: _ALLOWED/defaults/env/validate
│   └── profiles.py             # AnalysisDepth.business_flow + depth_key
├── profiles/builtin.yaml       # business_flow: false on quick/full/audit
└── skill_core/
    ├── SKILL.md                # ask/remember behavior + business-flow handoff section
    ├── prompts/business_flow.md        # NEW round prompt (step-walk + obligations)
    ├── schemas/business_flow.json      # NEW flows artifact schema
    ├── schemas/flow_answer.json        # NEW round answer schema
    ├── schemas/finding.json            # additive: flow_category/flow_ref/flow_narrative/regulatory_refs
    ├── schemas/report.json             # additive: flow_coverage
    └── data/regimes.json               # NEW versioned dataset (v1: gdpr, ccpa, hipaa)

tests/
├── contract/                   # new + updated schema conformance (additive deltas)
├── unit/                       # reconstruction, applicability modes, verify branch,
│                               # linker, config validation, answer parsing
├── integration/                # end-to-end scans on/off, multi-repo stitching,
│                               # partial flows, skill ask/remember, installed payload
├── benchmark/                  # seeded flow-gap + regulatory classes, safe-flow guards
└── fixtures/                   # flow-app + multi-repo workspace fixtures w/ ground truth
```

**Structure Decision**: single project; the feature extends the existing pipeline and
payload in place (no new packages). Deterministic model + LLM round live in one new
module `business_flow.py`, following the runner conventions of `triage.py` and
`escalate.py`; everything else is seam-level extension (see research.md Decisions
2–10).

## Complexity Tracking

> No constitution violations; no complexity exceptions required.

## Implementation deviations (recorded 2026-09-05, per the documentation-currency gate)

1. **Cross-repo stitching pin**: plans/contracts said legs follow `calls` edges +
   declared integrations. Implementation additionally ships `outbound_hosts` on
   file nodes (extraction chain: `enrichers.py` → `FileFacts` → graph), because
   manifest `external_services` only names known SaaS tokens, not arbitrary member
   hosts. Additive to `code_graph.json` (schema version unchanged). Hops are pinned
   per-file from those hosts; `calls` edges never cross repos for flows.
2. **`AnalysisDepth.business_flow` is tri-state** (`None` = profile silent) and
   built-ins omit the key, so `business_flow.enabled` in config works with the
   default `full` profile while explicit profile flags still take precedence.
   `depth_key` gains the flow suffix only when the flag is explicit, so upgrading
   the tool never forces re-analysis of previously scanned projects.
3. **Flow coverage gained an `undetermined` collection** (additive to
   `business_flow.json` + report rendering) so undetermined-at-ceiling states are
   declared in the report itself, not only as warning lines (SC-004).
4. **Usage attribution (T041)** is test-only over the recording the round performs
   (analysis finding D1).
5. **Undetermined-at-ceiling reason**: reaching the profile escalation cap still
   undetermined names the ceiling (`depth-ceiling`) — the spec's "profile ceiling
   ⇒ declared gap" assumption made concrete.
