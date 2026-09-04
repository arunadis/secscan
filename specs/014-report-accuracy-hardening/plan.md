# Implementation Plan: Report Accuracy Hardening

**Branch**: `014-report-accuracy-hardening` | **Date**: 2026-09-04 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/014-report-accuracy-hardening/spec.md`

## Summary

Eliminate the four false-positive / report-integrity classes observed in the
manual cross-check of report `20260904T085653Z-7ab7bd.md`:

1. **Usage evidence for dependency findings** (FR-001–003): persist per-file
   imports in the code graph (already extracted, currently dropped), then a
   deterministic pass attaches a three-state `usage` block (found / none-found /
   undetermined) to every dependency and currency finding. None-found caps
   confidence and reframes the narrative; it never suppresses and never adjusts
   severity (clarification Q1).
2. **Integration evidence for all misconfig findings** (FR-004): shipped
   `integration_markers` per misconfig rule class produce an integrated /
   no-integration-found / undetermined state; no-integration-found shifts
   remediation toward removal and is declared, never suppressed.
3. **Template-aware framework controls** (FR-005–007, hybrid per Q2): sinks in
   `type:"template"` nodes are matched against shipped control sink lists —
   unmatched sinks are simply not applicable (`absent`). For matched sinks,
   deterministic credit requires zero member-wide bypass annotations plus full
   parse coverage; bypass-present or incomplete-coverage cases become triage
   candidates under the existing citation gates.
4. **Currency merge + reference quarantine** (FR-008–010): currency findings roll
   up per `(member, product, cycle)` — the key SC-001 needs — before ID assignment; dangling finding- id
   references in narrative sections are quarantined (section omitted, defect
   declared in the report, exit code 4) instead of blocking publication (Q5).

Approach: extend deterministic passes and versioned data only; the single model
touchpoint is the existing triage candidate mechanism. All schema additions are
optional fields (additive; no `schema_version` bump).

## Technical Context

**Language/Version**: Python 3.11 (constitution requirement), tree-sitter grammars pinned

**Primary Dependencies**: No new runtime dependencies. Existing: tree-sitter
extractor (`src/pipeline/extract/`), artifact store with canonical JSON
(`store.canonical_json`), shipped data under `src/skill_core/data/`.

**Storage**: Files only — `.secscan/` artifacts (code graph JSON, findings,
reports). No database.

**Testing**: pytest (~800 tests) + `pytest -q -m slow` for scale scan; ruff
(line-length 100, py311, rules E/F/I/UP/B). Test-first per constitution; new
benchmark cases in `tests/benchmark/cases/` + fixtures in `tests/fixtures/`.

**Target Platform**: Offline CLI (`secscan` console script / installed skill
payload). No network in the default path.

**Project Type**: library/cli (installable skill)

**Performance Goals**: Usage/integration passes are O(files × markers) over the
persisted code graph — must not slow the scale scan beyond its existing
completing budget; no wall-clock SLO beyond `pytest -m slow` staying green.

**Constraints**:
- Byte-identical artifacts for identical input + tool version (canonical JSON,
  sorted collections, stable IDs assigned after merge).
- The three stdout summary lines in `scan_cli.cmd_run` are a frozen interface —
  quarantine signaling must use exit code + report content + `scan.log`, never a
  new stdout line.
- Progress only via `src/pipeline/progress.py`; stages never print.
- Import strings in graph nodes are redactor-swept like any persisted content
  (import statements cannot contain secret values; the sweep is retained as the
  enforcement layer).
- Read-only against the scanned project; no new tool invocations.

**Scale/Scope**: Must hold on `-m slow` large-repository scale scan; multi-member
workspaces (merge keys and bypass scans are member-scoped).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle / Gate | Verdict | Assessment |
|---|---|---|
| I. Determinism Before Intelligence | PASS | All new evidence (imports, config refs, dynamic forms, integration markers, bypass scan) is computed by deterministic passes from shipped data and the code graph. The only model involvement is the existing triage candidate path for hedged controls, gated by citation re-verification. IDs assigned after merging, sorted collections — byte-identical output preserved. |
| II. Context Is a Managed Resource | PASS | No new context packets. Template controls reach the triage round as `candidate_controls` through the existing bounded packet builder. |
| III. Secrets Never Reach a Model | PASS | Import statements/config keys are structural references, not values; persisted graph additions pass the existing redactor sweep over artifacts. No content flows to a model that did not already (triage packets unchanged in shape). |
| IV. Evidence Over Assertion | PASS (strengthened) | Usage locations, integration markers, and bypass sites are citations against the graph/model. FR-010 closes the dangling-reference hole by quarantine + a residual strict check. |
| V. Honest Uncertainty | PASS (central driver) | Both new evidence types are three-state with undetermined never collapsing to a directional answer; none-found never suppresses; undetermined never inflates; severity never adjusted by usage (Q1); unproven findings still capped by the existing severity ceiling. |
| VI. Observe, Never Attack | PASS | Fully static; no new external tool invocations; read-only invariant unchanged. |
| Gate: Additive schemas | PASS | New fields (`imports` on file nodes, `usage` on dependency findings, `integration` on misconfig findings, `dependency` block on currency findings, `quarantined_sections` on report) are all optional and additive. No `schema_version` bump. |
| Gate: Extensibility as data | PASS | New versioned data: `usage_patterns.json` (config reference rules, dynamic forms, module↔package mapping); `integration_markers` added to `misconfig_rules.json`; bypass/sink data unchanged. Adding a rule class or ecosystem extends data, not stages. |
| Gate: Accuracy regressions release-blocking | PASS | FR-012 adds the four observed failures as benchmark ground truth; existing corpora must stay green. |
| Gate: Honest documentation | PASS | tasks.md must include README/docs updates for the new exit code, new report field, and new data file in the same change set. |
| Frozen interface: stdout summary lines | PASS (design constraint) | Exit code 4 added; stdout untouched. Recorded in Technical Context/Constraints so tasks cannot regress it. |

No violations; Complexity Tracking table intentionally empty.

**Post-design re-check (after Phase 1)**: All gates still PASS. Specifics
confirmed by the design artifacts:

- Principle I — research R1/R7 keep ID assignment after merging and require
  sorted collections; every new evidence path is a deterministic pass or shipped
  data (contracts assert byte-identical output in Scenario "Determinism gate").
- Principle V — data-model.md §2/§3 encode three-state usage/integration with
  `undetermined` never collapsing to a directional answer; contract invariants
  forbid suppression-by-usage and inflation-by-undetermined.
- Principle IV — contracts/report-quarantine.md keeps a residual strict
  consistency check after quarantine, so the "references must resolve" invariant
  still holds for everything that ships.
- Frozen-interface constraint — research R8 routes defect signaling through exit
  code 4, report body, and `scan.log`; the three stdout lines are untouched.
- Extensibility-as-data — all per-ecosystem / per-rule-class knowledge lives in
  `usage_patterns.json` (new) and `misconfig_rules.json` markers; adding a
  stack/rule/control extends data only.

## Project Structure

### Documentation (this feature)

```text
specs/014-report-accuracy-hardening/
├── plan.md              # This file (/speckit-plan command output)
├── research.md          # Phase 0 output (/speckit-plan command)
├── data-model.md        # Phase 1 output (/speckit-plan command)
├── quickstart.md        # Phase 1 output (/speckit-plan command)
├── contracts/           # Phase 1 output (/speckit-plan command)
│   ├── usage-evidence.md
│   ├── integration-evidence.md
│   ├── template-controls.md
│   └── report-quarantine.md
└── tasks.md             # Phase 2 output (/speckit-tasks command - NOT created by /speckit-plan)
```

### Source Code (repository root)

```text
src/
├── pipeline/
│   ├── extract/__init__.py        # dynamic-import capture per usage_patterns.json (R3)
│   ├── build_code_graph.py        # persist FileFacts.imports onto file nodes (R1)
│   ├── usage_evidence.py          # NEW: usage pass — imports/config/dynamic (R2–R4)
│   ├── misconfig.py               # attach integration state from marker data (R5)
│   ├── controls.py                # template sink matching + member-wide bypass scan (R6)
│   ├── correlate_findings.py      # finalize(): wire usage pass before calibration
│   ├── audits/__init__.py         # currency findings: dependency block + merge (R7)
│   ├── generate_report.py         # resolve_narrative_references + quarantine (R8)
│   ├── consistency.py             # residual dangling-reference rule family (R8)
│   └── scan_cli.py                # EXIT_REPORT_DEFECT = 4 wiring (R8)
├── skill_core/
│   ├── data/
│   │   ├── usage_patterns.json        # NEW versioned data (R2/R3, name mapping)
│   │   └── misconfig_rules.json       # + integration_markers per entry (R5)
│   └── schemas/
│       └── code_graph.json        # additive: optional imports on file nodes
tests/
├── benchmark/cases/               # usage_none_found, template_sink_escaping,
│                                  # currency_merge, dangling_reference (R9)
├── fixtures/                      # builders for the four new cases
├── contract/                      # schema conformance for new optional fields
├── integration/                   # exit-code-4 path; end-to-end re-scan assertions
└── unit/                          # usage_evidence, controls template path,
                                   # currency merge, reference resolver
```

**Structure Decision**: Single-project layout unchanged; all work lands in the
existing `src/pipeline/` stage modules plus one new module
(`usage_evidence.py`) and one new data file. Template binding extraction extends
the existing template extraction from feature 002; no new stage is added —
`usage_evidence` runs inside `correlate_findings.finalize()` (R4).

## Complexity Tracking

No constitution violations to justify.
