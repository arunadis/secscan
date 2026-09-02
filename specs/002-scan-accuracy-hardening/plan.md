# Implementation Plan: Scan Result Accuracy Hardening

**Branch**: `002-scan-accuracy-hardening` | **Date**: 2026-08-30 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/002-scan-accuracy-hardening/spec.md`

## Summary

Make the pipeline's published claims match its evidence. An independent review of a real scan found
the reporting honest about its gaps but overstated in every exploitability narrative: line numbers
wrong by 1–2, an "evidence trail" that was a concatenation rather than a path, an "Observed" step
asserting behaviour nothing had observed, reproduction steps whose success criterion was
unachievable, a weakness class structurally impossible for the target, and the repository's largest
real exposure (272 dependency advisories) never assessed because the file classes carrying it were
absent from the code model.

The technical approach is deliberately weighted toward **deterministic post-processing over new model
reasoning**. Most defects exist because the pipeline already holds the authoritative answer and does
not consult it before publishing, so the bulk of the work is five new deterministic stages inserted
between analysis and reporting — tiered location resolution, architecture-aware applicability,
framework-control evaluation, severity calibration, and report self-consistency checking — plus two
coverage expansions (template and configuration extraction into the code graph; native per-ecosystem
dependency audits) and one precision fix in the redactor. No new LLM invocation is added, so token
cost is essentially unchanged and the measured savings ratio is preserved.

Four knowledge bases ship as versioned data next to the existing `cwe_map.json`, all required to be
extensible without touching pipeline stages: weakness-class applicability per architecture, framework
default controls and their bypass sites, template/ecosystem support descriptors, and
end-of-support dates.

## Technical Context

Inherited unchanged from `001-hierarchical-security-scan` except where noted.

**Language/Version**: Python 3.11+

**Primary Dependencies**: existing — py-tree-sitter v0.26+ with grammar wheels, jsonschema, PyYAML,
click, argparse. **Added**: exactly one new grammar, `tree-sitter-html` (0.23.2, MIT, pre-built
wheel); dialects without a maintained wheel (Angular, Vue, JSP, Thymeleaf, Go templates,
Jinja/Django) are covered by a deterministic attribute and delimiter pass over the parsed HTML tree
rather than by new grammars (research.md A1). Native audit tools (`npm`/`pnpm`/`yarn`, `pip-audit`,
`govulncheck`, Maven/Gradle) are invoked as read-only subprocesses only when already present — never
installed (A2). Three new versioned data files ship in the payload; no new runtime dependency (A3, A5).

**Defect found during research**: `.tsx` is mapped to the non-JSX TypeScript grammar, so React
`dangerouslySetInnerHTML` in `.tsx` files is currently invisible. Fixing the `language_tsx()` mapping
is in scope here as part of FR-025a/FR-029 (A1).

**Storage**: unchanged — local filesystem artifacts under `.security-scan/`.

**Testing**: pytest. **Added**: an accuracy-benchmark harness asserting per defect class (FR-043b);
a seeded multi-member workspace fixture (FR-043a); a fixture in a language the code model does not
parse, to prove file-tier resolution (SC-001a); one member per parsed language to prove minimum
template/ecosystem support (SC-007a); an identifier corpus for redaction precision (SC-009).

**Target Platform**: unchanged — macOS/Linux/Windows CLI inside supported agents or standalone.

**Project Type**: unchanged — CLI tool + agent skill package.

**Performance Goals**: no new model invocations, so per-scan token cost is unchanged apart from
line-numbered source in context packets. Budget: the measured savings ratio versus the
maximal-context baseline must not fall by more than 15% (SC-013). Native audits add subprocess time
bounded by a per-member timeout, and are skipped when a dedicated scanner already covered the domain.

**Constraints**: all new decision logic is deterministic and offline — no model reasoning decides
applicability, architecture, or control state (FR-013, FR-015b). Native audits are strictly read-only:
no install, no upgrade, no manifest or lockfile mutation (FR-031). Existing safety properties hold
unchanged: no attack execution, secrets never reach a model, budgets enforced against the serialized
request, byte-identical artifacts for identical input.

**Scale/Scope**: unchanged workspace scale. New per-scan work is O(findings) for the resolution,
applicability, control and calibration stages, and O(members) for audits — negligible against
existing graph construction.

**Unknowns resolved in Phase 0**: template grammar availability and unsafe-binding syntax per stack
(A1); native audit commands, JSON shapes, and runtime-vs-dev discrimination (A2); offline
end-of-support data and its licensing (A3).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

*Re-evaluated 2026-08-31, after the constitution was ratified at v1.0.0.* When this plan was written
the constitution was an unfilled template, so both gates recorded "PASS (no gates defined)". That is
no longer true and the section is restated rather than left stale.

**Pre-Phase-0 status**: PASS. The design adds no new model invocation, no new network dependency in
the default path, and no relaxation of an existing safety property. It moves decisions from model
output to deterministic shipped data, which strengthens Principle I (Determinism Before Intelligence).

**Post-Phase-1 status**: PASS against all six principles.

| Principle | How this feature stands |
|---|---|
| I. Determinism Before Intelligence | Applicability, architecture, controls and calibration are decided from shipped data, never model output. Adapter output is normalized because `npm audit --json` is not stable. |
| II. Context Is a Managed Resource | Line numbering is accounted for against the budget; template and config files enter the model so segments are bounded over a complete view. |
| III. Secrets Never Reach a Model | The identifier gate improves precision only; recall is asserted unchanged (FR-037). |
| IV. Evidence Over Assertion | The code model becomes the sole authority for locations; unresolvable locations are rejected rather than published with a caveat. |
| V. Honest Uncertainty | This feature is the principle's origin. FR-013a, FR-015c, FR-022c and FR-024b each give an unknown its own third state. |
| VI. Observe, Never Attack | Verification stays static; audits are read-only and asserted so by hashing manifests before and after. |

**Resolved by ratification**: this plan previously recommended codifying *never guess in either
direction* because three separate requirements had to restate it in the absence of a constitution.
That is now Principle V, and the duplication is a known cost rather than an open question.

## Project Structure

### Documentation (this feature)

```text
specs/002-scan-accuracy-hardening/
├── plan.md              # This file (/speckit-plan command output)
├── research.md          # Phase 0 output (/speckit-plan command)
├── data-model.md        # Phase 1 output (/speckit-plan command)
├── quickstart.md        # Phase 1 output (/speckit-plan command)
├── contracts/           # Phase 1 output (/speckit-plan command)
│   ├── accuracy-contracts.md      # tiered resolution, applicability, controls, calibration
│   ├── audit-adapter-contract.md  # native ecosystem audit adapter interface
│   └── schema-deltas.md           # additive changes to finding/code_graph/report schemas
└── tasks.md             # Phase 2 output (/speckit-tasks command - NOT created by /speckit-plan)
```

### Source Code (repository root)

Additions and modifications only; the layout established in feature 001 is otherwise unchanged.

```text
src/
├── pipeline/
│   ├── locate.py                  # NEW  tiered location resolution (FR-001..FR-004, FR-007)
│   ├── architecture.py            # NEW  architecture profiles, `undetermined` state (FR-013*)
│   ├── applicability.py           # NEW  weakness-class × architecture relation, remap (FR-015*, FR-016*)
│   ├── controls.py                # NEW  framework default controls + path-scoped bypass (FR-021, FR-022*)
│   ├── calibrate.py               # NEW  verification-aware severity/confidence caps (FR-020)
│   ├── consistency.py             # NEW  pre-write report contradiction checks (FR-040..FR-042)
│   ├── stack_currency.py          # NEW  end-of-support findings (FR-034)
│   ├── hosts.py                   # NEW  host ownership vs workspace membership (FR-024*)
│   ├── audits/                    # NEW  native ecosystem audit adapters (FR-030*)
│   │   ├── base.py                #      adapter protocol, read-only guarantees, timeouts
│   │   ├── node.py  python.py  java.py  go.py
│   │   └── attribution.py         #      hoisted-lockfile member attribution (FR-030e/f)
│   ├── extract/
│   │   ├── templates.py           # NEW  template bindings as sinks (FR-025*)
│   │   └── config_files.py        # NEW  manifests/deploy/datastore/cache config (FR-026)
│   ├── build_code_graph.py        # MOD  file-tier nodes for unparsed languages (FR-003c)
│   ├── build_context.py           # MOD  line-numbered source at every level (FR-002)
│   ├── partition_repo.py          # MOD  domains from code facts, not module names (FR-028)
│   ├── normalize_findings.py      # MOD  resolve locations before dedupe (FR-007)
│   ├── verify.py                  # MOD  consume resolved locations; no unresolved publish
│   ├── reproduce.py               # MOD  hypothesis vs observation; probe feasibility (FR-008..FR-011)
│   ├── redact.py                  # MOD  identifier-shape exclusion before blocking (FR-036..FR-038)
│   ├── correlate_findings.py      # MOD  run after remapping (FR-018)
│   ├── generate_report.py         # MOD  band from the finding; tier + coverage rendering (FR-029, FR-040)
│   ├── discover_repo.py           # MOD  classify architecture; template/config suffixes
│   ├── state.py                   # MOD  extend enumerated source suffixes
│   └── run.py                     # MOD  sequence the new deterministic stages
└── skill_core/
    ├── data/                      # NEW  versioned, extensible knowledge bases
    │   ├── applicability.json     #      weakness class × architecture (FR-015)
    │   ├── framework_controls.json#      default controls + bypass sites (FR-022d)
    │   ├── stacks.json            #      template forms + package ecosystems per language (FR-025a/FR-030d)
    │   └── eol.json               #      end-of-support dates, with dataset version (FR-034)
    ├── schemas/                   # MOD  additive fields only (contracts/schema-deltas.md)
    └── prompts/segment_scan.md    # MOD  stop asking the model for line numbers it cannot know

tests/
├── fixtures/
│   ├── multi_member_workspace.py  # NEW  cross-member applicability, host ownership,
│   │                              #      mixed ecosystems, hoisted lockfile (FR-043a)
│   ├── unparsed_language.py       # NEW  file-tier resolution proof (SC-001a)
│   ├── per_language_stacks.py     # NEW  one member per parsed language (SC-007a)
│   └── identifier_corpus.py       # NEW  redaction precision corpus (SC-009)
├── benchmark/                     # NEW  accuracy benchmark harness, asserts per defect class
│   └── cases/                     #      expected outcomes incl. the reviewed real target
├── unit/                          # NEW  test module per new pipeline module
├── integration/                   # MOD  end-to-end accuracy assertions
└── contract/                      # MOD  schema conformance for the added fields
```

**Structure Decision**: Extend the existing single Python project. Two new packages only —
`pipeline/audits/` (one adapter per ecosystem, mirroring the established `pipeline/adapters/`
scanner-adapter pattern) and `skill_core/data/` (versioned knowledge bases, mirroring the existing
`cwe_map.json` placement so they ship with the installed payload and stay offline). Every other
addition is a single-purpose module in `pipeline/`, matching the existing one-concern-per-stage
convention, and every modification is confined to a stage that already owns that concern.

The new deterministic stages are inserted into the existing pipeline sequence between analysis and
reporting, so `run.py` gains sequencing but no stage is restructured:

```text
segment_analysis
   ↓
normalize_findings   ← locate.py (tiered resolution) runs before dedupe
   ↓
applicability        ← architecture.py + applicability.py (remap, record)
   ↓
correlate_findings   ← now strictly after remapping
   ↓
verify_findings
   ↓
calibrate            ← controls.py + calibrate.py (caps, control credit)
   ↓
reproduce            ← hypothesis-aware, probe feasibility
   ↓
generate_report      ← consistency.py gate before write
```

`ingest_findings` gains the native audit adapters alongside the existing external-scanner adapters,
merging on advisory identity so a domain covered by an installed scanner is not double-reported.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

No violations — the constitution defines no gates.

One complexity note recorded deliberately, not as a violation: this feature adds eight new pipeline
modules and four data files. The alternative considered was folding the logic into the existing
`normalize_findings.py` and `verify.py`, which would have kept the module count flat. It was rejected
because each new concern has a distinct failure mode the spec requires to be independently
observable — a reader must be able to tell a resolution failure from an applicability suppression
from a calibration cap — and the benchmark harness asserts per defect class (FR-043b), which is only
practical if each class has its own seam.
