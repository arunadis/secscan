# Implementation Plan: Outcome-Quality Hardening

**Branch**: `017-outcome-quality-hardening` | **Date**: 2026-09-07 | **Spec**: [spec.md](spec.md)

## Summary

Post-016 hardening: presence-grade contract closes the verdict bug for the
identity-archetype family (CWE-290), resume keys become tool/recognizer-version
aware, deterministic-pack provenance is guaranteed end-to-end, root-cause families
present once with anchor/dependent links, presence-proven findings render with
explicit exposure framing, coverage notes dedupe across escalation levels, tool
limitations describe exclusion accurately, and triage questions batch by text. All
governed by fixture-driven regression (upgrade simulation; pack+model coexistence).

## Technical Context

**Language/Version**: Python 3.11+
**Primary Dependencies**: existing (tree-sitter, pytest, ruff)
**Storage**: JSON artifacts under `.secscan/`
**Testing**: pytest (unit/contract/integration/benchmark), ruff
**Constraints**: offline default; read-only; additive schemas; deterministic.

## Constitution Check

Re-checked from spec.md and research.md (per process): **all six pass**. The only
invariant touched is determinism-resume: caches gain precision, artifact bytes are
unaffected for a fixed tool build (version inputs are constants).

## Project Structure

```text
specs/017-outcome-quality-hardening/
├── plan.md · research.md · data-model.md · quickstart.md
├── checklists/requirements.md
└── contracts/
    ├── verification-grades.md        # FR-001/FR-005 catalogue + rendering
    ├── resume-keys.md                # FR-002 key composition
    ├── provenance-and-families.md    # FR-003/FR-004
    └── presentation-batch.md         # FR-006/FR-007/FR-008
```

Touch points: `src/pipeline/verify.py`, `state.py`, `normalize_findings.py`,
`correlate_findings.py`, `generate_report.py`, `triage_declarations.py`,
`build_context.py`, `tooling/` limitation source; new data only if contracts prove
versioning useful. Tests under `tests/unit|integration|benchmark` + fixture reuse
of 016's workspaces.

## Complexity Tracking

No constitution exceptions. Documented limitation: family detection keys on
identity-bearing channels only (guard-annotation or pack-provenance), which may
miss same-scheme-different-family presentations; recall upgrades belong to a later
structural-family pass.
