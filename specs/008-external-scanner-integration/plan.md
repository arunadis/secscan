# Implementation Plan: External Scanner Tooling Integration

**Branch**: `008-external-scanner-integration` | **Date**: 2026-09-02 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/008-external-scanner-integration/spec.md`

## Summary

Make `secscan` analyses comprehensive by provisioning, running, and trusting-but-verifying external security tools. During `init`, the scanner detects project ecosystems from manifests/build files, maps them to applicable tools via a shipped versioned **tool registry** (extending today's four fixed probes: semgrep, gitleaks, osv-scanner, trivy — plus package-manager audits and OWASP dependency-check), discovers tools the **project itself already provides** (project-local dependencies, declared build plugins, wrapper toolchains) and uses those directly, and installs only genuinely missing tools — after presenting the exact install list for **selective user confirmation**. During analysis, every applicable available tool runs **read-only** under timeout, its output is normalized and ingested through the existing `pipeline/ingest_findings.py` seam (finally building the `pipeline/adapters/` scanners that feature 001's US3 deferred), and every external finding is **cross-checked against the code model and resolved dependencies**: suppression is allowed only on deterministic structural disproof, recorded in an auditable suppression list; reachability doubts retain the finding as undetermined. Tool unavailability is always declared as a coverage limitation, never read as clean.

## Technical Context

**Language/Version**: Python 3.11+ (constitution constraint; matches existing codebase)

**Primary Dependencies**: Standard library only for the new pipeline code (`subprocess`, `shutil`, `json`). External tools themselves are *provisioned, not depended upon* — the scanner functions fully without them (FR-010).

**Storage**: File artifacts in the `.security-scan/` store (JSON, appended additively); versioned registry data in `src/skill_core/data/` (pattern: `stacks.json`, `advisories/*.json`)

**Testing**: pytest with fixture workspaces declaring ground truth; benchmark regression gates per the accuracy benchmark's release-blocking rule

**Target Platform**: Cross-platform CLI (macOS/Linux; tools provisioned per-platform via registry data)

**Project Type**: CLI tool / analysis pipeline

**Performance Goals**: Tool execution bounded by per-tool timeout (registry-declared, default 120s matching `audits/base.py`); external tool stage adds wall-clock only when tools are available and applicable

**Constraints**: Read-only against scanned projects (manifest/lockfile fingerprint before/after, reused from `audits/base.py`); no network in the default path — network only inside user-consented provisioning and declared tool executions; deterministic normalized projection of all tool output; additive schemas only

**Scale/Scope**: Registry targets the existing ecosystems (npm, pypi, maven, go) plus code-scanning tools (semgrep, gitleaks, trivy) and OWASP Dependency-Check (JVM via Maven/Gradle); monorepos per existing workspace-member partitioning

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Assessment | Result |
|-----------|------------|--------|
| I. Determinism Before Intelligence | Tool applicability, discovery, install-list, and suppression decisions are all derived from registry data and the code model — never model output. Tool output is normalized into the stable projection before artifact write (existing `audits/base.py` pattern extended). Network is confined to consented provisioning/declared tool runs; the default path stays offline. | PASS |
| II. Context Is a Managed Resource | External findings enter as structured findings through the existing ingestion seam; no new context expansion. | PASS |
| III. Secrets Never Reach a Model | FR-011: external tool output passes through the existing redactor before any artifact or model-facing use (gitleaks-style findings especially). | PASS |
| IV. Evidence Over Assertion | Suppression requires deterministic structural disproof with cited evidence; every suppression is an auditable record; finding locations must resolve against the code model (existing tiered location resolution gates unresolvable ones into suppression). | PASS |
| V. Honest Uncertainty (NON-NEGOTIABLE) | Tri-state tool outcomes (`ran`/`skipped`/`failed` with reason) mirror the existing `could-not-check` discipline; reachability doubts retain findings as undetermined; absence of external results is declared as a coverage limitation, never clean. | PASS |
| VI. Observe, Never Attack | Reuses `audits/base.py`'s fingerprint-verified read-only execution; installs land outside the scanned project; scanner payload/tool caches excluded from enumeration. A tool that cannot run read-only is declared inapplicable rather than run destructively. | PASS |
| Quality gates (extensibility-as-data, additive schemas, benchmark regression) | New tools are registry data, not pipeline changes; `findings/external/*.json` seam already exists and new artifacts (tool runs, suppressions) are additive; all detectors get fixture ground truth. | PASS |

**Evaluation**: No violations. One deliberate expansion of Principle I's default — user-consented provisioning and advisory fetching involve network — is an *opt-in extension beside* the unchanged offline default, not a weakening of it. Recorded in Complexity Tracking per the governance rule.

### Post-design re-check (after Phase 1)

Re-evaluated after generating research.md, data-model.md, contracts/, quickstart.md:

- **I. Determinism** — research R7 pins byte-identity to "identical input + identical tool/db versions" (the constitution's own wording); fixtures use recorded tool output so tests never touch network. Closed-enum `disproof_ground` keeps suppression derivation fully data-driven. **PASS**
- **III. Secrets** — data-contracts rule: `invocation` records carry env-var *names* only; gitleaks findings flow through the same redaction gate (FR-011). **PASS**
- **V. Honest uncertainty** — the contract closes the last loophole: `suppressions.json` `disproof_ground` is a closed enum whose extension requires governance review, so a future contributor cannot quietly add "looks unreachable" as a ground. **PASS**
- **VI. Read-only** — `read_only_guard=tripped` contractually forces `status: failed` and discards output (fingerprint pattern from `audits/base.py`); all report/cache/data dirs live outside the scanned project (research R2). **PASS**

**Result**: post-design Constitution Check passes with no new violations; Complexity Tracking entry unchanged.

## Project Structure

### Documentation (this feature)

```text
specs/008-external-scanner-integration/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
└── tasks.md             # Phase 2 output (/speckit-tasks)
```

### Source Code (repository root)

```text
src/
├── skill_core/data/
│   └── tools.json                      # NEW: versioned external-tool registry (FR-001)
├── pipeline/
│   ├── init_cmd.py                     # EXTEND: registry-driven detection/discovery/confirm/install
│   ├── tooling/                        # NEW package
│   │   ├── __init__.py
│   │   ├── registry.py                 # Tool registry load/validate (versioned data)
│   │   ├── ecosystem.py                # Ecosystem detection from manifests/build files
│   │   ├── discover.py                 # Project-local + system tool discovery (FR-003a)
│   │   ├── provision.py                # Selective, consent-gated installation (FR-003)
│   │   ├── runner.py                   # Read-only, timeout-bounded, never-raises execution (FR-004/005)
│   │   ├── state.py                    # Canonical writers for tooling/*.json artifacts
│   │   └── execute.py                  # Scan-stage orchestration + limitations (FR-005/009)
│   ├── adapters/                       # EXISTING (empty pkg — 001 US3 seam): fill per-tool normalizers
│   │   ├── semgrep.py gitleaks.py osv.py trivy.py   # NEW (completes 001 US3)
│   │   ├── npm_audit.py pip_audit.py govulncheck.py # NEW: package-manager audit adapters
│   │   └── dependency_check.py         # NEW: OWASP DC report normalizer
│   ├── ingest_findings.py              # EXTEND: merge + dedupe + provenance (FR-006)
│   ├── crosscheck.py                   # NEW: structural disproof + suppression list (FR-007/008)
│   ├── audits/                         # UNCHANGED behavior; stays as built-in fallback
│   └── generate_report.py              # EXTEND: tool-status + suppression sections (FR-009/014)
└── config/loader.py                    # EXTEND: additive config keys (install flag, timeouts)
tests/
├── fixtures/tooling_workspace/         # NEW: fixtures per availability state, per tool kind
├── integration/test_tooling_*.py       # NEW
├── benchmark/cases/*.json              # EXTEND: seeded TP/FP/undetermined ground truth (FR-013)
└── contract/                           # EXTEND: registry + artifact schema contracts
```

**Structure Decision**: Single Python project, extending the existing `src/pipeline/` layers. New code lands in a `pipeline/tooling/` package (provisioning + execution) and the pre-reserved `pipeline/adapters/` package (normalization), keeping the existing audits layer untouched as the offline baseline. All tool knowledge ships as versioned data in `src/skill_core/data/tools.json` per extensibility-as-data.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| Opt-in network/machine-changing path (consented tool installation, declared advisory fetching) extends Principle I's no-network default | The spec's core user value — comprehensive coverage beyond the bundled offline snapshot — requires external tools whose operation implicates network; the default offline path is unchanged and this path exists only on explicit confirmation (FR-003) | Offline-only alternative = status quo; the bundled snapshot is necessarily stale/incomplete and the feature's headline requirement cannot be met without the consented path |
