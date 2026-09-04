# Implementation Plan: Finding Triage Reasoning Round

**Branch**: `013-finding-triage` | **Date**: 2026-09-04 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/013-finding-triage/spec.md`

## Summary

Add a single post-correlation reasoning round — `finding_triage` — between the
`correlate_findings` and `system_review` stages. The round hands each eligible
finalized finding to the reasoning layer (agent handoff, interactive endpoint, or
provider batch — the same client surface feature 012 normalized) together with the
finding, its redacted excerpt, and deterministically collected candidate-control
locations. The reasoner answers from a closed verdict vocabulary
(`confirmed` / `downgraded` / `refuted` / `flagged`); any verdict that would
suppress or downgrade must cite evidence, and a deterministic re-verifier checks
every citation against the code model before the verdict applies. Verified
refutations join the existing auditable suppression list under a new triage ground;
downgrades flow through the existing calibration bookkeeping; flags render in a new
awaiting-verification report section carrying concrete user questions, which users
resolve by recording durable declarations that apply on the next scan. Value-level
credential precision stays with feature 003's deterministic work and is out of
scope.

## Technical Context

**Language/Version**: Python 3.11+ (pinned tree-sitter grammar wheels; no new runtime deps)

**Primary Dependencies**: existing pipeline seams only — `pipeline.llm_client`
(`AnalysisClient`, `AgentHandoff`), `pipeline.answers` (AnswerStore),
`pipeline.batch_runner` (round dispatch), `pipeline.redact` (SecretHit set),
`pipeline.crosscheck` (suppression records), `pipeline.calibrate` (grading
bookkeeping), `pipeline.generate_report` (report sections)

**Storage**: `.secscan/` artifacts — new: `triage/requests/*.json` packets recorded
via the existing context-packet writer, verdicts persisted through the existing
`analysis/answers/` AnswerStore, `triage/decisions.json` decision log,
`triage/declarations.json` (user-declared answers), suppressions extended in
`tooling/suppressions.json`

**Testing**: pytest (`tests/unit`, `tests/contract`, `tests/integration`),
`tests/benchmark` accuracy corpus; ruff (line-length 100, py311)

**Target Platform**: macOS/Linux CLI; installable skill payload (`src/skill_core`)

**Project Type**: CLI + installable agent skill

**Performance Goals**: triage adds one reasoning item per candidate finding; total
round tokens stay within the profile budget mechanism (Principle II, budgets checked
against the serialized request, identical to segment analysis)

**Constraints**: offline default; no network in deterministic stages; read-only
against scanned projects; secret values never enter packets, verdicts, or artifacts
(artifact redaction sweep); suppressed/downgraded verdicts only on
deterministically re-verified citations

**Scale/Scope**: baseline is the labelled 45-finding scan
(`20260903T042832Z-c63749`); reference scale-scan fixtures; ~25 candidate findings
per large-repo scan at `full` profile defaults

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Evaluation | Status |
|---|---|---|
| **I. Determinism Before Intelligence** | Triage verdicts are reasoning output, but their *application* is deterministic: citations re-verified against the code model, decisions persisted content-addressed (`answers.py` precedent, FR-015), so identical input + cached answers → byte-identical artifacts. Candidate selection, packet construction, and evidence gates are deterministic stages. Matches the treatment segment analysis already receives. | PASS |
| **II. Context Is a Managed Resource** | Triage requests are bounded packets built and budgeted through the same machinery as analysis requests (`EscalationRunner._fit` discipline: measure the serialized request, shed whole items, warn). One request per candidate finding; no escalation ladder inside triage. | PASS |
| **III. Secrets Never Reach a Model** | Hard gate of the design. Triage packets contain only redacted excerpts (FR-003). The hybrid raw-file consultation in agent-mediated mode (FR-006) is restricted to files the redactor classified with zero hits — a set known deterministically at build time and written into the request. All reasoner output (verdicts, citation patterns) is redaction-swept before persistence, extending the existing artifact sweep invariant; a citation whose pattern sweeps as credential-like is rejected, so verdicts can never carry secret values into artifacts. Credential findings can never be refuted (FR-008). | PASS |
| **IV. Evidence Over Assertion** | The whole feature is this principle enforced on reasoning output: no verdict changes a finding without citations, and citations are judged by the deterministic layer, not trusted. Malformed or unverifiable output is rejected, and the finding proceeds as untriaged. Rejected verdicts are recorded (FR-014). | PASS |
| **V. Honest Uncertainty** | Unanswered rounds declare a coverage gap rather than assuming outcomes (FR-009). Unverifiable refutations degrade to `flagged`, never suppress. Flagged findings stay in the stream normally graded (FR-012). User declarations carry explicit provenance and lapse on location/weakness mismatch (FR-019/020). | PASS |
| **VI. Observe, Never Attack** | Triage reads code; it executes and mutates nothing. The scanned tree stays untouched; user declarations live under `.secscan/` (scanner-owned), not the project. | PASS |

**Gate result: PASS — no violations, no Complexity Tracking entries.**

*Post-design re-check (Phase 1 complete): PASS.* The design kept every gate:
evidence re-verification is fully deterministic (R6), the consultation boundary is
enforced by artifact-level redaction sweep and a machine-derived consultable set
(R7), credential-class refutation is structurally invalid in both reasoning output
and user declarations (contracts §4/§5, declarations rule 3), and every
undetermined state degrades to a declared gap or a flag — never to silence
(FR-009/012, data-model state transitions).

## Project Structure

### Documentation (this feature)

```text
specs/013-finding-triage/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/
│   ├── triage-round.md          # request packet + verdict answer contract
│   └── report-and-decisions.md  # suppressions extension, awaiting-verification
│                              #   section, user declarations
└── tasks.md             # Phase 2 (/speckit-tasks — not this command)
```

### Source Code (repository root)

```text
src/
├── pipeline/
│   ├── triage.py              # NEW: candidate selection, packet build, round driver
│   ├── triage_evidence.py     # NEW: citation schema + deterministic re-verification
│   ├── triage_apply.py        # NEW: verdict application (suppress/downgrade/flag),
│   │                          #      decision log, suppression-record extension
│   ├── triage_declarations.py # NEW: user-declared answer load/match/lapse
│   ├── run.py                 # stage wiring: finding_triage after correlate_findings
│   ├── state.py               # STAGES += finding_triage; resume keys
│   ├── prompts.py             # render triage prompt from payload templates
│   └── generate_report.py     # suppressions already rendered; add
│                              # awaiting_verification section + triage coverage note
├── skill_core/
│   ├── prompts/triage_finding.md   # NEW payload prompt
│   └── schemas/triage_answer.json  # NEW verdict schema
├── config/
│   ├── loader.py              # new `triage` section keys (SECSCAN_TRIAGE_*)
│   └── profiles schema        # analysis_depth.finding_triage per profile
└── profiles/builtin.yaml      # quick: off / full: on (High+ + heuristic) / audit: all

tests/
├── unit/test_triage*.py       # selection, verdict parse, evidence re-verify, apply
├── contract/                  # triage_answer.json conformance
├── integration/               # full-scan triage round over fixtures incl. handoff/batch
└── benchmark/cases            # triage ground-truth corpus (refute/flag/must-survive)
```

**Structure Decision**: Single pipeline module cluster under `src/pipeline/`
(`triage*` modules) — the feature is one pipeline stage plus payload additions, and
splitting evidence-checking from verdict-application mirrors the existing
`crosscheck`/`calibrate` discipline. No new top-level packages.

## Complexity Tracking

> No constitution violations to justify.
