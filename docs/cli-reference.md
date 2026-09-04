# CLI reference

One command, **`secscan`**, covers both setup and scanning. Global help:
`secscan --help` / `secscan <command> --help`.

Exit codes apply to `secscan run` and the payload CLI:

| Code | Meaning |
|------|---------|
| `0` | success |
| `1` | error — including an analysis endpoint that kept refusing after all retries (one line on stderr, no traceback; segments already analysed are kept and the re-run resumes from the failed one) |
| `2` | not ready (environment/config prerequisites unmet) |
| `3` | agent handoff pending — reasoning requests await answers in `.secscan/handoff/`; re-run to resume |
| `4` | report published with quarantined narrative — a narrative section (system review, cross-system findings, attack paths, recommendations) referenced a finding id not admitted to the report and was omitted; the omission is declared in the report's *Report Integrity* section, and all findings still publish |
| `130` | interrupted by the operator (Ctrl-C); checkpoints are intact, re-run to resume. Under the batch policy the line also says how many provider batches are still processing — the re-run polls them instead of resubmitting |

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
| `--policy <mode>` | Execution policy for this scan: `auto` (batch when an endpoint is configured — the default), `interactive`, `batch`, or `batch-offpeak`. |
| `--tool-timeout <seconds>` | Per-tool wall-clock ceiling for external tools (overrides `tooling.timeout_s`). |
| `--output <level>` | Progress output on stderr: `quiet`, `default`, or `verbose` (overrides `output.level`; see [Configuration](configuration.md#output)). |
| `-q` / `-v` | Shorthand for `--output quiet` / `--output verbose`. Cannot be combined with each other or with `--output`. |
| `--workdir <dir>` | Scan root (default: current directory). |

### Progress output

A running scan reports what it is doing on **stderr**; the final summary
(`scan <id>: N finding(s) reported`, `report: <path>`, and an optional coverage-note
count) stays on **stdout**, so scripts and installed skills that parse the summary are
unaffected. At the `quiet` level stderr is silent and the terminal experience is
identical to earlier releases.

Each line carries the wall-clock time, the elapsed time since the scan started, a
tag, and the event:

```
14:02:11 +00:00 start scan 20260903T140211Z-1a2b3c (full profile, agent-mediated)
14:02:11 +00:00 start discover_repo
14:02:11 +00:00 done  discover_repo (0.4s)
14:02:12 +00:01 reuse build_code_graph (checkpoint)
14:02:12 +00:01 start segment_analysis segment 1/7 shop:orders
14:02:45 +00:34 wait  still running segment_analysis shop:orders (33s)
14:02:58 +00:47 done  segment_analysis segment 1/7 shop:orders (46s)
14:02:58 +00:47 warn  [segment_analysis/shop:orders] shop:orders: omitted 1 file(s) from the level-1 request to stay within the 12000-token budget
14:05:03 +02:52 skip  external_tooling tool 2/3 osv-scanner: 'OSV-Scanner' is not installed; run init to provision it
14:05:40 +03:29 pause 2 segment(s) awaiting agent reasoning in .secscan/handoff/ — re-run to resume
```

| Tag | Meaning |
|-----|---------|
| `start` / `done` | a stage, segment (`i/N`), or external tool began / finished, with elapsed time |
| `reuse` | the stage was satisfied from a checkpoint and not re-run |
| `skip` | not applicable (profile-disabled stage, tool not installed, lockfile absent) — the reason is printed |
| `warn` | a coverage note, rejected finding, tool limitation, or dependency-audit gap, printed with exactly the wording the report will use |
| `wait` | heartbeat: the current step has produced no event for 30 s and is still running; under the batch policy also `batch k/m processing c/N (waited …, next check in …)` on each status check |
| `info` | a provider batch was submitted: `batch k/m submitted: N items, model X, id …` |
| `fail` | a stage or the scan failed; the stage, elapsed time, and (redacted) error are named |
| `pause` | agent handoff (exit 3) — not a failure |
| `stop` | interrupted (exit 130) — re-run resumes from the checkpoint |

While a batch is outstanding the scan stays in the foreground; `batch k/m ended: …
(n fallback)` is printed when it resolves, followed by one `warn` line per item that
fell back to a live request (with the reason) and one per retry of a live request
(`rate limited (HTTP 429), attempt 2/5, waiting 7s`). The provider's cancel endpoint
is never called: an interrupted batch keeps running at the provider and is collected
by the next run.

On an interactive terminal the `start`/`wait` lines are shown on a single in-place
status line; completed stages, warnings, and failures stay in the scrollback. When
stderr is not a terminal (piped, redirected, CI, an agent), every event is a plain
line with no control sequences. `verbose` additionally shows the escalation level
and token count per segment, each external tool's version and invocation, and the
checkpoint key behind every `reuse`.

Regardless of level, every run writes the full trace at verbose detail to
`.secscan/scan.log` (overwritten per run). It is a diagnostic file, not a scan
artifact — see [Artifacts](artifacts.md).

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
