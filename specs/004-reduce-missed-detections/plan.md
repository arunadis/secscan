# Implementation Plan: Reduce Missed Detections (False Negatives)

**Branch**: `004-reduce-missed-detections` | **Date**: 2026-08-31 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/004-reduce-missed-detections/spec.md`

## Summary

A comparative review found four verified miss classes: dangerous security-configuration states
(CSRF disabled, wildcard CORS) that no deterministic check covers; compound cross-file weaknesses
(public GraphQL endpoint + cyclic schema + absent depth limits; seed-data shared password + public
login) that segment-local analysis cannot assemble; known-vulnerable dependencies surfaced only as
asides inside other findings; and coverage gaps (blocked values, budget-dropped files) recorded
without any security-impact assessment. The fix is four deterministic, data-driven capabilities:
a control-check rule pack over security-config files (US1), a compound-finding rule engine that
evaluates evidence legs against whole-repository deterministic structures after segment analysis
completes (US2), first-class dependency findings from bundled advisory data across all four
ecosystems (US3), and coverage gaps that carry cause + security-impact assessment, ranked with
security-critical files first (US4). All rules ship as versioned data; no new LLM invocation is
added; absence-of-control claims cite the deterministic search that established them.

## Technical Context

**Language/Version**: Python 3.11+ (constitution technology constraint)

**Primary Dependencies**: pinned tree-sitter grammar wheels, PyYAML, jsonschema, click (all existing); no new runtime dependencies

**Storage**: N/A — JSON artifacts under `.security-scan/`; rules and advisory data ship as versioned in-repo data under `src/skill_core/data/`

**Testing**: pytest (unit / contract / integration / benchmark), ruff; fixture corpora in `tests/fixtures/`; per-defect-class accuracy benchmark

**Target Platform**: CLI tool (`secscan`), local or CI, macOS/Linux

**Project Type**: CLI security scanner (offline deterministic pipeline + bounded LLM analysis)

**Performance Goals**: no regression in scan wall-time; rule evaluation is linear in graph size

**Constraints**: fully offline default path (advisory data bundled, versioned); byte-identical artifacts for identical input; no credential value in any artifact; recall precedence (constitution Principles I, III, V)

**Scale/Scope**: workspaces ~10⁵ LOC, JVM/Node/Python/Go; reference scans: `20260831T071644Z-c3b48b` (uc-framework repo) and `20260831T081536Z-438706` (skh workspace)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Evaluation | Result |
|-----------|-----------|--------|
| I. Determinism Before Intelligence | All four capabilities are deterministic rule/data evaluation over prepared structures (code graph, manifests, config files); no model output decides detection; advisory data ships versioned inside the payload; no network added | PASS |
| II. Context Is a Managed Resource | No new LLM invocation; the compound stage runs after segment analysis over deterministic whole-repo structures, never over raw segment source in bulk | PASS |
| III. Secrets Never Reach a Model | Seed-data credential detection reports the *pattern* without the value (same mechanism as existing hard-coded-secret findings); redaction precedence unchanged | PASS |
| IV. Evidence Over Assertion | Every compound-finding leg carries a resolvable location; absence-of-control claims cite the searched configuration space; schema-conforming findings only | PASS |
| V. Honest Uncertainty | `undetermined` control state and `could-not-check` audit outcomes are first-class; an undetermined leg downgrades the finding to plausible with the gap named, never suppresses it; no absence claim without a completed search | PASS |
| VI. Observe, Never Attack | No verification/reproduction behavior change; tooling remains read-only | PASS |

No violations anticipated. Complexity Tracking will record any justified exceptions.

**Post-design re-check (2026-08-31)**: Phase 0/1 artifacts confirm the gates. R1/R6 read raw
source for structural patterns only — matched values never enter findings or artifacts, and the
redaction sweep still passes (Principle III, contracts D1/D2). R2 adds no LLM invocation and
reads whole-repo *structures* (graph, manifests), not bulk source (Principle II). R3 avoids a
new grammar dependency (constitution technology constraints). R4 restores the offline guarantee
the audit stage was designed for but never had data for; staleness degrades to could-not-check,
never clean (Principle V, contract D3). Schema changes are additive (`gap_details`, advisory
snapshots) — no version bump (R5). One nuance recorded openly: `.sql`/`.graphql` content is
read by deterministic evaluators without entering the code model interior — they remain
file-tier nodes, and their findings resolve at file tier, which FR-003b location resolution
already supports.

## Project Structure

### Documentation (this feature)

```text
specs/004-reduce-missed-detections/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created here)
```

### Source Code (repository root)

```text
src/pipeline/
├── misconfig.py             # NEW  control-check rule evaluation over config/security files (US1)
├── compound.py              # NEW  compound-finding rule engine over whole-repo structures (US2)
├── audits/                  # MOD  advisory matching for all four ecosystems from bundled data (US3)
├── generate_report.py       # MOD  coverage gaps gain cause + impact + ranking (US4)
├── build_context.py         # MOD  gap records carry cause (blocked value | budget-dropped) (US4)
└── correlate_findings.py    # MOD  ingest misconfig/compound findings into correlation

src/skill_core/data/
├── misconfig_rules.json     # NEW  versioned control-check rules (stacks, patterns, severity, CWE)
├── compound_rules.json      # NEW  versioned compound weakness patterns (evidence legs)
└── advisories/              # NEW  versioned per-ecosystem advisory snapshots

tests/
├── fixtures/                # NEW  misconfig/compound/advisory fixture workspaces + must-find corpus
├── unit/                    # NEW  test_misconfig.py, test_compound.py, test_coverage_gaps.py
├── contract/                # MOD  rule-data schema + finding contract tests
├── benchmark/cases/         # MOD  must-find corpus for the two reference scans (FR-011)
└── integration/             # NEW  end-to-end scan asserting all four miss classes are caught
```

**Structure Decision**: single Python project; new capabilities are new pipeline modules fed by
versioned data, consistent with the constitution's extensibility-as-data principle and the
existing `controls.py` / `audits/` patterns. No new top-level packages, no new external services.

## Complexity Tracking

> To be filled if the Constitution Check identifies justified exceptions.
