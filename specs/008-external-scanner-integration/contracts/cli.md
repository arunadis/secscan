# Contract: CLI Surface

Public command-line contract for feature 008. Stable identifiers and exit-code semantics are contractual; flag spelling may be adjusted during implementation but semantics must not change without a schema/contract bump.

## `secscan init`

```text
secscan init [--workdir PATH] [--install[=all|TOOL[,TOOL...]]] [--yes|--no-input]
```

| Flag | Semantics |
|---|---|
| *(default, interactive TTY)* | Detect ecosystems → resolve applicable tools from registry → present availability (project-provided / system-installed / missing) → enumerate exact install list → user confirms and may deselect individually → install confirmed subset |
| `--install=all` | Unattended consent for all genuinely-missing applicable tools |
| `--install=semgrep,osv-scanner` | Unattended consent for the named subset only |
| `--yes` | Assume confirmation of the full presented list (equivalent to `--install=all`); still prints the list before acting |
| `--no-input` | Never prompt; skip all installation with a declared note |

Guarantees:

1. Nothing is installed before the list is presented and confirmed (FR-003).
2. Project-provided tools never appear on the install list (FR-003a).
3. No file in the scanned project is created or modified (FR-004); exit code 0 means ready (built-in mode always OK), 1 means a *required* check failed — missing optional tools never fail init.
4. Output includes, per tool: applicability, source, version (or "undetermined"), network requirement, install channel used or skip reason.

## `secscan run` (scan)

```text
secscan run ... [--tool-timeout SECONDS]
```

| Behavior | Semantics |
|---|---|
| Tool stage | Every applicable available tool runs per its registry `invoke` contract, read-only-guarded, timeout-bounded, never-raises |
| Availability re-probe | Cheap re-probe at scan time; `availability.json` from init is informational (research R8) |
| Declared limitations | Every applicable tool not run appears in the report's coverage-limitation section; their absence never reads as clean (FR-009) |
| Exit code | Unchanged by tool failures — a crashing tool degrades to a declared limitation, never a failed scan (SC-006) |
