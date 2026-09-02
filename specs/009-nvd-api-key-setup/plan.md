# Implementation Plan: NVD API Key Setup During Initialization

**Branch**: `009-nvd-api-key-setup` | **Date**: 2026-09-02 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/009-nvd-api-key-setup/spec.md`

## Summary

Extend the existing `secscan init` tooling flow so that tools requiring NVD
(National Vulnerability Database) API access — currently only
`owasp-dependency-check` (feature 008 registry) — receive an honest, consent-based
credential decision at initialization. NVD-backing is declared **as data** in the
shipped tool registry (`credential` block, additive to the entry shape), a pure
presence check (`credentials.py`) reads the injected environment by variable name
only, and `init`'s tooling flow gains a four-state credential outcome
(`available` / `awaiting-key` / `degraded-no-key` / `skipped-no-key`) recorded in
the existing `tooling/availability.json` artifact. No secret value is ever
prompted for, echoed, or persisted; the key reaches the tool at scan time purely
via environment inheritance (Dependency-Check ≥ 9.0.4 reads `NVD_API_KEY` from the
environment — research.md R1).

## Technical Context

**Language/Version**: Python 3.11+ (constitution technology constraint)

**Primary Dependencies**: stdlib only for this feature (`json`, `shutil`,
`subprocess`, `argparse`); existing modules `pipeline.tooling.{registry,discover,
provision,state}`, `pipeline.init_cmd`, `pipeline.state.canonical_json`

**Storage**: files in the `.security-scan/` store — `tooling/availability.json`
(canonical JSON via `pipeline.state.canonical_json`, byte-identical invariant)

**Testing**: `pytest` (unit + integration + contract); gates per constitution:
`pytest` green, `ruff check src tests` clean, contract tests for every schema

**Target Platform**: macOS / Linux developer machines and CI (CLI tool)

**Project Type**: cli

**Performance Goals**: prompt/choice adds < 2 min to interactive init (SC-002);
non-interactive init terminates with zero prompts (SC-003); presence check is
O(1) dict lookup — no measurable cost

**Constraints**: no network access in the default path (key validation by
presence only, never against the NVD service); credentials referenced by
environment-variable *name* only, never stored or echoed (constitution);
initialization never hangs in non-interactive contexts (existing
`sys.stdin.isatty()` guard pattern)

**Scale/Scope**: one registry tool today (`owasp-dependency-check`) should trigger
the flow (maven ecosystem only); the credential mechanism is declared per tool so
future NVD-backed tools inherit it without pipeline changes
(extensibility-as-data gate)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Assessment | Result |
|---|---|---|
| I. Determinism Before Intelligence | Presence check is a pure function of the injected `environ` dict (same pattern as `run_init`'s existing `environ` parameter). Credential outcomes are fixed strings; records go through `canonical_json`. No LLM involvement anywhere in this feature. | PASS |
| II. Context Is a Managed Resource | Not touched — no analysis-context behavior changes. | N/A |
| III. Secrets Never Reach a Model / credential handling | The design never accepts the key value: no value prompt, no value persistence, no value in config/log/artifact. Only the variable name `NVD_API_KEY` and a presence state are recorded. Scan-time delivery is OS environment inheritance to the child tool process; the value never transits scanner artifacts. Test sentinel asserts the value appears in no artifact (SC-004). | PASS |
| IV. Evidence Over Assertion | Init-report credential states render only what the availability records say; no new report claims are asserted without a recorded decision. | PASS |
| V. Honest Uncertainty | Core of the feature: four distinct credential states, no conflation; a skipped or keyless tool can never read as configured; "presence, not validity" is stated when reporting `available` (FR-003). A keyless-disabled tool remains a declared coverage gap at scan time through the existing feature-008 machinery (source `missing` + decision). | PASS |
| VI. Observe, Never Attack | Init writes only into the `.security-scan/` store (existing behavior); no mutation of scanned projects. Provisioning remains consent-gated exactly as in feature 008; this feature only narrows what may install keyless. | PASS |
| Safety invariant: byte-identical for identical input | New artifact field is deterministic (fixed strings, sorted keys via `canonical_json`). Environment-dependent behavior risks nondeterminism ONLY across differing environments, which the invariant already scopes (identical input = identical environment). Presence is re-checked per run rather than persisted-and-trusted. | PASS |
| Safety invariant: secrets never reach a model | See Principle III row; SC-004 sweep test. | PASS |
| Extensibility as data | NVD-backing is a declared `credential` block on registry entries; adding a future NVD-backed tool is a data edit plus contract fixtures, zero pipeline code. | PASS |
| Spec-first / test-first | This plan precedes `tasks.md`; tasks will write failing tests before implementation (existing project pattern). | PASS |

No violations; Complexity Tracking intentionally left empty.

**Post-design re-check (after Phase 1)**: research.md R1–R7, data-model.md, and
contracts/init-nvd-credential.md confirm the assessments above — the credential
block keeps extensibility-as-data (R3), the closed `credential.state` enum
implements Honest Uncertainty without inflated or silent outcomes, scan-time
delivery is inheritance-only so the secret never transits argv, logs, or
artifacts (R1/contract §5), and the byte-identity invariant holds because all
new field values are fixed strings derived from the injected environment. No
principle conflict identified; no waiver required.

## Project Structure

### Documentation (this feature)

```text
specs/009-nvd-api-key-setup/
├── plan.md              # This file (/speckit-plan command output)
├── research.md          # Phase 0 output (/speckit-plan command)
├── data-model.md        # Phase 1 output (/speckit-plan command)
├── quickstart.md        # Phase 1 output (/speckit-plan command)
├── contracts/           # Phase 1 output (/speckit-plan command)
│   └── init-nvd-credential.md
└── tasks.md             # Phase 2 output (/speckit-tasks command - NOT created by /speckit-plan)
```

### Source Code (repository root)

```text
src/
├── pipeline/
│   ├── init_cmd.py                  # EXTEND: keyless warning/choice, selection
│   │                                # filtering, credential reporting (FR-004..FR-011)
│   └── tooling/
│       ├── credentials.py           # NEW: pure presence check, impact text,
│       │                            # credential-state computation (FR-001..FR-005)
│       ├── registry.py              # EXTEND: parse/validate optional `credential`
│       │                            # block on ToolEntry (FR-001)
│       ├── discover.py              # UNCHANGED (Availability.to_dict gains no
│       │                            # field here; init annotates the record dict)
│       ├── provision.py             # UNCHANGED (init filters selection before call)
│       └── state.py                 # UNCHANGED (canonical writer already generic)
└── skill_core/
    └── data/
        └── tools.json               # EXTEND: credential block on
                                     # owasp-dependency-check entry (data, not code)

tests/
├── unit/
│   └── test_tooling_credentials.py  # NEW: presence check, state computation,
│                                    # warning text content
├── integration/
│   ├── test_tooling_init.py         # EXTEND: keyless interactive + non-interactive
│   │                                # flows end-to-end through run_init
│   └── test_nvd_key_redaction.py    # NEW: sentinel-value sweep — key value never
│                                    # appears in any written artifact (SC-004)
└── contract/
    ├── test_tool_registry.py        # EXTEND: credential-block validation cases
    └── test_tooling_artifacts.py    # EXTEND: additive `credential` field shape +
                                     # closed state enum asserted
```

**Structure Decision**: Single-project layout, extending feature 008's tooling
package. The only all-new module is `src/pipeline/tooling/credentials.py`, kept
pure (dict-in/dict-out, no I/O beyond the injected environment) so every
requirement is unit-testable without a process or filesystem. All user-facing
decisions stay in `init_cmd.py`, which already owns the consent flow
(`_tooling_flow`) and the report render.

## Complexity Tracking

> No constitution violations to justify. Section intentionally empty.
