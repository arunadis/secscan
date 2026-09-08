# Implementation Plan: Flow & Graph Completeness

**Branch**: `016-flow-graph-completeness` | **Date**: 2026-09-07 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/016-flow-graph-completeness/spec.md`

## Summary

Make the deterministic substrate truthful about how code is wired, and honest when
it cannot be: (1) extract registration-style attachments (`router.use(auth)`,
middleware arguments, `before_request`, `Use(…)`) as graph edges so guards sit on
traced paths; (2) recognize header/cookie channels as attacker-controlled sources
and driver convenience methods (`db.get|run|all`) as data access, so flows actually
exist; (3) fix flow-completeness accounting (label-vs-id comparison silently
downgraded every endpoint-anchored flow); (4) declare a named reachability coverage
gap when endpoints and data access exist but no flow connects them, with verdict
honesty (`basis: traced|presence`) and reduced certainty while the gap is active;
(5) ship a versioned rule pack detecting the client-asserted-identity archetype
(CWE-290 family) as format detections; (6) record unattached security guards as an
annotation that feeds domains, triage seeding, and digests; (7) close the
self-refutation loop at both the deterministic verify gate (landed) and reasoning
triage (citation perimeter rejection). Everything reuses existing seams; only one
new data file (`identity_archetype_rules.json`) and two additive schema fields
(`finding.verification.basis`, `code_graph` annotation enum value) are created.

## Technical Context

**Language/Version**: Python 3.11+ (per constitution)

**Primary Dependencies**: tree-sitter grammars (pinned wheels), pytest, ruff —
no new runtime dependencies

**Storage**: JSON artifacts under `.secscan/` (existing canonical-json store);
versioned data files under `src/skill_core/data/`

**Testing**: pytest (unit/contract/integration/benchmark), ruff (E/F/I/UP/B, 100 cols)

**Target Platform**: local CLI scanning, offline default path

**Project Type**: library/CLI (single project)

**Performance Goals**: no new reasoning rounds in default scan paths (clarify Q5);
extraction additions are pattern-level (negligible cost); determinism preserved

**Constraints**: offline; read-only against scanned projects; additive schemas only;
no model participation in structural decisions (Principle I)

**Scale/Scope**: repositories large enough to force segment subdivision; small
single-service apps (the reference miss was ~25 source files)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Verdict | Evidence |
|---|---|---|
| I. Determinism Before Intelligence | ✅ Pass | All recognition is pattern/rule-pack data and local structure; the model is never asked for wiring/edges. Deferred: runtime LLM-proposed edges (research.md, last item) — not in scope. |
| II. Context Is a Managed Resource | ✅ Pass | Packet changes (digest lines, route enumeration on every part) are bounded additions to an existing field (`call_graph_summary`), enforced against serialized budgets exactly as today. |
| III. Secrets Never Reach a Model | ✅ Pass | New patterns match code *shape*; identity values and matched text never enter artifacts (value-free findings precedent from feature 004). |
| IV. Evidence Over Assertion | ✅ Pass | Findings still conform to `finding.json`; locations resolve against the code model; `basis` makes the traced/inferred distinction explicit in the artifact instead of prose (FR-008 strengthens this principle). |
| V. Honest Uncertainty | ✅ Pass — this feature's core | FR-007 declares a named, actionable gap for unconnectable repos; FR-009 demotes certainty while active; FR-010 keeps unresolved wiring `undetermined`; unknown wiring is never guessed (R1 matcher rules). |
| VI. Observe, Never Attack | ✅ Pass | All changes are static/lexical; no probing of scanned projects. |

Post-Phase 1 re-check: contracts keep both gates green — schema changes additive,
data versioning recorded (`tool_ref` carries `identity-archetype@<version>`), no
schema_version bump anywhere.

## Project Structure

### Documentation (this feature)

```text
specs/016-flow-graph-completeness/
├── plan.md              # this file
├── research.md          # Phase 0 — decisions R1–R10
├── data-model.md        # Phase 1 — entities & state
├── contracts/
│   ├── traceability-contract.md        # verification.basis, FR-007 gap, summary wording
│   ├── graph-wiring-contract.md        # wiring facts → edges, annotations, digests
│   └── identity-archetype-rules.md     # rule pack shape, matching, finding semantics
├── quickstart.md        # validation scenarios
├── checklists/requirements.md
└── tasks.md             # /speckit-tasks (not created here)
```

### Source Code (repository root) — touch points (reuse-first)

```text
src/pipeline/
├── extract/
│   ├── enrichers.py          # header/cookie channels, db.get|run|all, auth-name
│   │                         # prefixes, Wiring fact extraction (R1, R2)
│   └── __init__.py           # Wiring dataclass + FileFacts/to_dict (additive)
├── build_code_graph.py       # resolve_wiring(), annotate_unattached_guards() (R8)
├── dataflow.py               # Flow.complete construction-truth fix (R3)
├── partition_repo.py         # route enumeration on every part; prod-first order;
│   │                         # DOMAIN_BY_ANNOTATION + unattached_security_guard
├── build_context.py          # role digest + guard-attachment lines (R6)
├── verify.py                 # basis field; reachability demotion (R4); implicated
│   │                         # gate — already landed (T008A)
├── run.py                    # reachability-gap declaration computation (R5)
├── generate_report.py        # summary split by basis (R4)
├── triage.py + triage_apply.py  # citation-perimeter rejection (R9); pack-aware
│   │                         # no-refute set
├── misconfig.py (precedent)  # extended rule-pack evaluation reused for
│   │                         # identity archetypes (R7)
└── redact.py (untouched)     # no redaction change needed — patterns are shape-only

src/skill_core/
├── data/identity_archetype_rules.json   # NEW — FR-014 + guard_names catalogue
├── schemas/finding.json      # additive verification.basis
├── schemas/code_graph.json   # additive annotation enum value
└── prompts/segment_scan.md, triage_finding.md, final_review.md  # FR-015 additions

tests/
├── unit/ (enrichers, wiring resolution, partition ordering, digest, verify basis,
│   triage perimeter, archetype rules data + evaluation)
├── contract/ (finding.json + code_graph.json conformance incl. new fields)
├── integration/ (header-identity fixture end-to-end; reachability-gap fixture;
│   determinism two-run)
├── fixtures/workspaces/header-identity-app/     # NEW — ground truth per AGENTS.md
└── benchmark/ (new defect class assertions)
```

## Complexity Tracking

> No violations requiring justification. Two scope-limiting tradeoffs, recorded for
> reviewers (not constitution exceptions):

| Limitation | Accepted because |
|---|---|
| Route-mount (`app.use("/api", router)`) cross-module guard inheritance not resolved | Import-graph resolution is the documented "later deep-analysis tier"; the missed issue class (same-module wiring) is covered. |
| Hints remain code-level patterns rather than a versioned stack-knowledge base | Lifting hint sets into data is a larger contract change; per-release additions stay additive and test-covered (research R2). |
