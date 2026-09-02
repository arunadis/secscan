# Implementation Plan: Hierarchical LLM-Efficient Security Scanning for Large Codebases

**Branch**: `001-hierarchical-security-scan` | **Date**: 2026-08-30 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/001-hierarchical-security-scan/spec.md`

## Summary

Deliver an installable, agent-portable security-scanning skill that performs hierarchical, context-bounded security analysis over workspaces of one or more repositories. Deterministic Python tooling (discovery, multi-language code graph, partitioning, redaction, artifact management, scanner-finding ingestion, report assembly) does all splitting and evidence collection; the executing coding agent's own model (default, zero-config) or an operator-configured external endpoint performs bounded reasoning over per-segment context packets using specialized prompt templates; structured findings (CWE/OWASP-labeled, CVSS-style severity, numeric confidence) are correlated across segments and repositories and aggregated into a unified report. Every stage emits durable JSON artifacts under a per-project `.security-scan/` directory, enabling auto-resume, incremental scans, and per-stage re-runs. A Spec Kit-style installer scaffolds an agent-agnostic core skill plus per-agent adapters, and a single config file plus named scan profiles (`quick`/`full`/`audit`, custom profiles allowed) control execution policy, model tiers, token budgets, and thresholds.

## Technical Context

**Language/Version**: Python 3.11+ (deterministic tooling, installer, and validation scripts)

**Primary Dependencies**: tree-sitter (multi-language AST/call extraction; see research.md R2), jsonschema (artifact/finding validation), PyYAML (config), click (installer CLI `secscan`), argparse (scan CLI `security-scan` and stage scripts — keeps the installed payload dependency-light). Optional external scanner adapters: Semgrep (SAST), Gitleaks (secrets), OSV-Scanner (dependencies), Trivy/Checkov (IaC) — invoked only when present.

**Storage**: Local filesystem only — JSON/Markdown artifacts in the scanned project's `.security-scan/` dot-directory (gitignored by default); no database, no remote storage.

**Testing**: pytest; fixture repositories with seeded ground-truth vulnerabilities (single-repo and multi-repo workspaces); schema-conformance contract tests for every artifact; golden-file report tests.

**Target Platform**: macOS/Linux/Windows CLI, executed inside supported coding agents (agent-agnostic core + per-agent adapters; see research.md R1) and standalone from a terminal.

**Project Type**: CLI tool + agent skill package (installer + skill templates + deterministic pipeline scripts).

**Performance Goals**: External-endpoint interactive mode: ~1 hour per 1M LOC full scan; incremental single-file rescan < 20% of full-scan cost; ≥5x token savings vs maximal-context baseline. Agent-mediated mode: no wall-clock target; resumable across agent sessions.

**Constraints**: No single analysis invocation exceeds its configured context budget; mandatory deterministic secret/credential redaction before any model call (both modes); strict config validation before scan start; schema-conforming findings only (free-form output rejected).

**Scale/Scope**: Workspaces of multiple repositories totaling 1M+ LOC; repositories at least 10x larger than one analysis context window; four integration classes across repos (sync APIs, async messaging, shared data stores, identity/trust propagation).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

*Re-evaluated 2026-08-31.* The constitution was an unfilled template when this plan was written, so both gates originally recorded "PASS (no gates defined)". It has since been ratified at v1.0.0 with six principles, and this section is restated against them rather than left stale.

**Pre-Phase-0 status**: PASS (retrospectively). This feature *established* Principles I (Determinism Before Intelligence), II (Context Is a Managed Resource), III (Secrets Never Reach a Model) and VI (Observe, Never Attack) — the constitution largely codifies what this plan designed.

**Post-Phase-1 status**: PASS with two gaps, both now closed by `002-scan-accuracy-hardening`:

- **Principle IV (Evidence Over Assertion)** — this design took a finding's location from model output rather than resolving it against the code model, and its report could contain internal references that do not resolve.
- **Principle V (Honest Uncertainty)** — this design had no third state for an undetermined architecture, reachability, or control, so unknowns resolved to a guess in one direction or the other.

Both were found by external review rather than by a gate, which is the reason the constitution now exists. No new violation is introduced by the remaining unbuilt phases of this feature (external-scanner triage, multi-repo correlation, incremental rescan), but each MUST be re-evaluated against all six principles when it is planned.

## Project Structure

### Documentation (this feature)

```text
specs/001-hierarchical-security-scan/
├── plan.md              # This file (/speckit-plan command output)
├── research.md          # Phase 0 output (/speckit-plan command)
├── data-model.md        # Phase 1 output (/speckit-plan command)
├── quickstart.md        # Phase 1 output (/speckit-plan command)
├── contracts/           # Phase 1 output (/speckit-plan command)
└── tasks.md             # Phase 2 output (/speckit-tasks command - NOT created by /speckit-plan)
```

### Source Code (repository root)

```text
src/
├── installer/                # `secscan` installer (per-agent scaffolding, upgrades)
│   ├── cli.py                # secscan init/agents/status/version, .gitignore handling
│   ├── core.py               # install orchestration, payload copy, install manifest
│   ├── upgrade.py            # upgrade planning, downgrade guard, stale-payload removal
│   └── agents/               # per-agent adapters (one module each)
│       ├── base.py           #   frontmatter split/join + default SKILL.md rendering
│       ├── claude.py  copilot.py  cursor.py  windsurf.py  devin.py
│       ├── agents.py         #   cross-vendor `.agents/skills/`
│       └── gemini.py         #   YAML+Markdown -> TOML translation
├── skill_core/               # agent-agnostic skill payload installed into projects
│   ├── SKILL.md              # orchestrator instructions template
│   ├── prompts/              # discover/partition/segment_scan/triage/correlation/final_review
│   ├── schemas/              # JSON Schemas: envelope, workspace, manifest, code_graph,
│   │                         #   segment, context_packet, finding, report, usage
│   └── cwe_map.json          # versioned CWE→OWASP→compliance dataset
├── pipeline/                 # deterministic stage scripts (runnable standalone & by agents)
│   ├── resources.py          # payload path resolution (source vs installed layout)
│   ├── schemas.py            # schema loading + validation façade
│   ├── discover_repo.py      # workspace assembly + repository manifest
│   ├── extract/              # tree-sitter per-language extraction + enrichers.py
│   ├── build_code_graph.py   # multi-language code graph, stable IDs, cross-repo edges
│   ├── partition_repo.py     # security-boundary segmentation
│   ├── build_context.py      # context packets + budgets
│   ├── prompts.py            # per-segment domain-guidance filtering (FR-011)
│   ├── redact.py             # deterministic secret redaction engine
│   ├── secret_findings.py    # hard-coded-credential findings from redaction hits
│   ├── budget.py             # token accounting/enforcement primitives
│   ├── usage.py              # usage/cost tracker
│   ├── escalate.py           # evidence-escalation loop (levels 1–4)
│   ├── dataflow.py           # source→sink data-flow tracing
│   ├── verify.py             # static verification (verified/plausible/disproven)
│   ├── reproduce.py          # reproduction block generation (benign canaries)
│   ├── adapters/             # scanner adapters: semgrep, gitleaks, osv, trivy
│   ├── ingest_findings.py    # ingestion driver + adapter registry
│   ├── normalize_findings.py # schema enforcement + CWE/OWASP mapping
│   ├── correlate_findings.py # dedup/relationship classification
│   ├── integrations.py       # cross-repo integration discovery/typing/invalidation
│   ├── system_review.py      # cross-boundary system-level review
│   ├── generate_report.py    # unified report + usage/cost summary (MD + JSON)
│   ├── report_view.py        # derived per-repository report projections
│   ├── llm_client.py         # endpoint client, batch abstraction, agent handoff io
│   ├── init_cmd.py           # init: default config + environment checks
│   ├── scan_cli.py           # `security-scan` init/run/status/report
│   ├── state.py              # artifact store, checkpoints, resume, change detection
│   └── run.py                # pipeline driver: sequencing, resume, mode switch
├── profiles/                 # built-in scan profiles (quick/full/audit) as data
│   └── builtin.yaml
└── config/                   # config schema, strict validation, env-var resolution
    ├── loader.py             # strict validation + env overrides
    ├── mode.py               # execution-mode resolver (agent-mediated vs endpoint)
    └── profiles.py           # profile resolution + per-scan overrides

tests/
├── contract/                 # JSON schema conformance + artifact redaction sweep
├── integration/              # end-to-end scans, install matrix, installed-payload
│                             #   subprocess checks, agent handoff, scan CLI
├── fixtures/                 # seeded-vulnerability repos + synthetic scale generator
└── unit/
```

**Console scripts**: `secscan` (installer, click) and `security-scan` (per-project
scan command, argparse). The installed payload can also be driven directly as
`python -m pipeline.scan_cli <subcommand>` with `scripts/` on `PYTHONPATH`, so a
project needs no global install.

**Structure Decision**: Single Python project (Option 1 variant). `pipeline/` stages are standalone CLI scripts so both execution modes work identically: an agent following `SKILL.md` invokes them, or the user runs them directly. `skill_core/` is the installable payload; `installer/agents/` holds the thin per-agent adapters selected at install time.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

No violations — constitution defines no gates.
