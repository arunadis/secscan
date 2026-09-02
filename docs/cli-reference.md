# CLI reference

One command, **`secscan`**, covers both setup and scanning. Global help:
`secscan --help` / `secscan <command> --help`.

Exit codes apply to `secscan run` and the payload CLI:

| Code | Meaning |
|------|---------|
| `0` | success |
| `1` | error |
| `2` | not ready (environment/config prerequisites unmet) |
| `3` | agent handoff pending — reasoning requests await answers in `.secscan/handoff/`; re-run to resume |

## `secscan init <dir>`

Set up secscan in a project: install the skill, generate config, check the
environment. Re-run to upgrade the installed skill in place.

```
secscan init [PROJECT] [OPTIONS]
```

| Option | Effect |
|--------|--------|
| `--ai <agent>` | Coding agent to install the skill into (`claude`, `copilot`, `cursor`, `windsurf`, `devin`, `agents`, `gemini`). Omit to generate config and check the environment without installing a skill. |
| `--force` | Allow downgrading a newer installed version. |
| `--commit-artifacts` | Do **not** gitignore `.secscan/` — scan artifacts will be committed. |
| `--no-init` | Install the skill without generating configuration or running environment checks. |
| `--install=<TOOLS>` | Install missing applicable external tools without prompting: `all`, or comma-separated ids (e.g. `--install=npm-audit,osv-scanner`). |
| `--yes` | Confirm the full presented install list (equivalent to `--install=all`). |
| `--no-input` | Never prompt; skip installation with a declared note. |

Behavioral notes:

- The exact install list is always presented and confirmed before anything installs.
- OWASP Dependency-Check is skipped keyless in non-interactive runs unless
  `--allow-keyless-nvd` is passed; `--yes`/`--install=all` never silently install it
  without `NVD_API_KEY` set.
- In-place upgrades preserve `.secscan/config.yaml` and existing artifacts, and
  report when the config schema changed.

## `secscan run`

Run a scan. Resumes from checkpoints automatically; `--full` forces a fresh scan.

```
secscan run [OPTIONS]
```

| Option | Effect |
|--------|--------|
| `--profile <name>` | `quick`, `full`, `audit`, or a custom profile name (default: `full`). See [Scan profiles](scan-profiles.md). |
| `--segment <id>` | Re-run analysis for one segment only. |
| `--full` | Force a full scan, ignoring checkpoints. |
| `--set KEY=VALUE` | Override a resolved profile setting for this scan (repeatable), e.g. `--set report_thresholds.min_confidence=0.8`. |
| `--policy <mode>` | Override the execution policy for this scan: `interactive` or `batch-offpeak`. |
| `--tool-timeout <seconds>` | Per-tool wall-clock ceiling for external tools (overrides `tooling.timeout_s`). |
| `--workdir <dir>` | Scan root (default: current directory). |

## `secscan report`

Re-render the latest report from artifacts — no LLM calls, no rescanning.

```
secscan report [OPTIONS]
```

| Option | Effect |
|--------|--------|
| `--repo <name>` | Filter to one repository's findings. |
| `--format <fmt>` | `markdown` (default), `json`, or `html`. |
| `--workdir <dir>` | Scan root (default: current directory). |

Reports are written to `.secscan/reports/`; the same data set renders to all three
formats.

## `secscan status <dir>`

Show installed skills (agent, pinned version, invocation), per-stage scan state,
agent-handoff progress (`answered/pending`), and the latest report path.

```
secscan status [PROJECT]        # default: current directory
```

## `secscan agents`

List the supported coding agents and where each expects skills to live. Use any
listed key as `--ai` for `init`.

## `secscan data`

Inspect the shipped knowledge bases (`applicability`, `framework_controls`,
`stacks`, `eol`), their versions, and their staleness.

| Option | Effect |
|--------|--------|
| `--refresh-eol` | Print instructions for refreshing the pinned end-of-support snapshot. Deliberately instructional — an implicit network fetch would break the offline guarantee and determinism. |

See [Extending the knowledge bases](extending-data.md).

## `secscan version`

Print the tool version and the artifact/config schema versions.

## The installed-payload CLI

From an installed skill payload — with no global `secscan` install — the same scan
surface is available by putting `<skill>/scripts` on `PYTHONPATH`:

```bash
PYTHONPATH=<skill>/scripts python -m pipeline.scan_cli <subcommand>
```

This is how the agent runs the deterministic stages from inside the scanned project.
