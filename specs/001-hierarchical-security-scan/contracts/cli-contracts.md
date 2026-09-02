# Contract: CLI Commands

The feature exposes two command surfaces, each a console script:

| Script | Surface | Implementation |
|--------|---------|----------------|
| `secscan` | Installer, run once per project from the scanner's distribution | `installer/cli.py` (click) |
| `security-scan` | Per-project scan command registered in the agent (FR-022) | `pipeline/scan_cli.py` (argparse) |

From an installed skill payload — with `<skill>/scripts` on `PYTHONPATH` — the scan
surface is also available as `python -m pipeline.scan_cli <subcommand>`, so a
project never needs a global install.

All commands exit non-zero on failure with actionable messages on stderr
(strict-validation spirit of FR-026). Exit codes: `0` success, `1` error,
`2` not ready (config invalid or missing), `3` agent handoff pending.

## Installer CLI

### `secscan init <project-dir> --ai <agent> [--force]`

Scaffolds the skill into the target agent's skills directory (FR-020).

- `--ai <agent>`: one of `claude | copilot | cursor | windsurf | devin | agents | gemini` (v1 adapter set, research.md R1).
- Writes the agent-agnostic core skill (SKILL.md + scripts + schemas + prompts) transformed by the selected agent's adapter.
- Re-running in an installed project performs an **in-place upgrade**: skill files replaced, project config and `.security-scan/` artifacts preserved, config schema changes flagged (FR-020).
- Idempotent; `--force` required to overwrite a newer pinned version.

### `secscan version`

Prints installer, artifact-schema, and config-schema versions (used by upgrade checks).

### `secscan agents`

Lists supported agents with their labels and skills directories.

### `secscan status <project-dir>`

Shows which agents the project has the skill installed for, plus scan state.

## Installed skill commands (inside the agent)

Registered by the installer as invocable commands/skills (FR-022). Names shown as canonical; each agent adapter maps to its invocation convention (e.g., `/security-scan`, `$security-scan`, `@security-scan`).

### `security-scan init`

Post-install initialization (FR-024): generates the default config file in `.security-scan/config.yaml`, then runs environment checks and reports a readiness table:

- model endpoint reachable / agent-mediated mode active (FR-027)
- credential env var present (without printing the value, FR-025) — or "not set → agent-mediated mode"
- optional scanner tools detected: semgrep / gitleaks / osv-scanner / trivy (per-tool: found/not found)
- workspace manifest found or auto-discovery will be used (FR-001c)

### `security-scan run [--profile <name>] [--policy interactive|batch-offpeak] [--set key=value ...] [--segment <id>] [--full]`

Executes the scan pipeline (US1–US5).

- Default: incremental scan (FR-017) under the configured/selected profile (FR-028) and execution policy (FR-007a).
- `--full`: force full scan. `--segment <id>`: re-run one segment from artifacts (SC-007).
- Auto-resume: if prior state exists with unfinished stages, resumes automatically (FR-016a); in agent-mediated mode, re-invoking continues the scan across sessions (FR-027).
- Pre-flight: strict config validation (FR-026); refuses to start on invalid config.
- Writes all artifacts to `.security-scan/` and the final report to `.security-scan/reports/<scan-id>.md` (+ `.json`).

### `security-scan status`

Shows pipeline state: stage statuses, last checkpoint, token/cost usage so far, batch jobs in flight (FR-019).

### `security-scan report [--repo <name>] [--format markdown|json]`

Re-renders the latest report from artifacts, optionally projected onto one repository (per-repo derived views, FR-018). A repository view retains cross-system findings that cite the repo as evidence, so shared issues stay visible to every subsystem they implicate.

## Pipeline stage CLIs (deterministic scripts, agent-invoked)

Every deterministic stage is a standalone script with the uniform contract
`python -m pipeline.<stage> --workdir <scan-root> [--flags]`, reading prior
artifacts and writing its own under `.security-scan/`. This lets an agent (or an
operator) re-run one stage without a full scan.

| Stage | Reads | Writes |
|-------|-------|--------|
| `discover_repo` | scan root, workspace manifest | `workspace.json`, `repository/*.manifest.json` |
| `build_code_graph` | manifests, source | `code-graph.json` |
| `partition_repo` | code graph | `segments/*.json` |
| `build_context` | segments, graph, source | `context-packets/*.json` |
| `ingest_findings` | external scanner output | `scanner-findings.json` |
| `normalize_findings` | `handoff/responses/*.json` | `findings/local/*.json` |
| `correlate_findings` | `findings/local/*`, code graph | `findings/correlated.json` |
| `generate_report` | correlated findings, workspace, usage | `reports/<scan-id>.{md,json}` |

The analysis step between `build_context` and `normalize_findings` is deliberately
*not* a deterministic script: it is the model's reasoning, exchanged through
`handoff/requests` and `handoff/responses` (agent-mediated) or performed against
the configured endpoint. Every other stage behaves identically in both execution
modes (FR-027).

`pipeline.run` chains the full sequence and is what `security-scan run` invokes.
It shares its finalization code with `correlate_findings`, so driving the stages
by hand produces the same findings as a full run (asserted by
`tests/integration/test_stage_cli.py`).

> `ingest_findings` is specified but not yet implemented (Phase 5).
