# Contract: Progress Output for `secscan run`

**Feature**: 011-scan-progress-output | **Date**: 2026-09-03

This contract binds the user-visible surfaces added by the feature. Anything not listed here
is unchanged from the current release.

## 1. Command-line surface

Applies identically to `secscan run` (click, `src/installer/cli.py`) and
`python -m pipeline.scan_cli run` (argparse, installed payload).

| Option | Values | Default | Notes |
|---|---|---|---|
| `--output LEVEL` | `quiet`, `default`, `verbose` | unset (resolve via env/config) | choice-validated |
| `-q` | — | — | alias for `--output quiet` |
| `-v` | — | — | alias for `--output verbose` |

`--output` with `-q`/`-v` together, or `-q` with `-v`, is a usage error (exit 2 from the
argument parser, as for any bad option).

### Resolution precedence

`--output`/`-q`/`-v` → `SECSCAN_OUTPUT_LEVEL` → `output.level` in `.secscan/config.yaml` →
`default`. The CLI value is injected as `SECSCAN_OUTPUT_LEVEL` into the environment passed to
the config loader (same mechanism as `--policy` and `--tool-timeout`).

### Config key

```yaml
output:
  level: default
```

Unknown keys under `output`, or a level outside the three values, are rejected by the strict
validator with the existing `ConfigError` wording style: `output.level must be one of: quiet,
default, verbose (got 'loud')`.

## 2. Stream contract

| Stream | Content | Change |
|---|---|---|
| stdout | final summary lines (`scan <id>: N finding(s) reported`, `report: <path>`, optional `(N coverage note(s) recorded in the report)`), or `handoff.instructions()` on exit 3, or nothing on error | **unchanged** at every level |
| stderr | progress and warning lines at `default`/`verbose`; nothing at `quiet`; existing error messages (`ConfigNotFound`, unknown segment) unchanged | new |
| `.secscan/scan.log` | all events at verbose detail, every level | new |

Exit codes are unchanged: `0` ok, `1` error, `2` not ready / usage, `3` agent handoff. New:
`130` when interrupted with Ctrl-C (previously an uncaught traceback with Python's default
exit status).

Ordering guarantee: all stderr progress lines for a run are written before the stdout summary
is printed; the reporter is closed (status line finalised, log flushed) before `print` of the
summary.

## 3. Line grammar (plain and file sinks)

```
<HH:MM:SS> <+MM:SS> <kind-tag> <text>
```

- `HH:MM:SS` — local wall-clock time of the event.
- `+MM:SS` — elapsed since `scan_started` (rolls to `+H:MM:SS` past an hour).
- `kind-tag` — fixed-width, one of:

| tag | kinds |
|---|---|
| `start` | `scan_started`, `stage_started`, `segment_started`, `tool_started` |
| `done ` | `stage_done`, `segment_done`, `tool_done` (status `ran`) |
| `reuse` | `stage_reused` |
| `skip ` | `stage_skipped`, `tool_done` (status `skipped`) |
| `fail ` | `stage_failed`, `tool_done` (status `failed`), `failed` |
| `warn ` | `warning` |
| `wait ` | `heartbeat` |
| `pause` | `paused` |
| `stop ` | `interrupted` |

- `text` forms (`{…}` are substituted; `[…]` appear at verbose only):

```
start  scan {scan_id} ({profile} profile, {mode})
start  {stage}
done   {stage} ({elapsed})
reuse  {stage} (checkpoint)[ resume_key={key}]
skip   {stage}: {reason}
fail   {stage} after {elapsed}: {message}
start  {stage} segment {i}/{N} {segment_id}
done   {stage} segment {i}/{N} {segment_id} ({elapsed})[ level={L} tokens={T}]
start  {stage} tool {i}/{N} {tool_id}
done   {stage} tool {i}/{N} {tool_id} ran ({elapsed})[ {tool_version}: {invocation}]
skip   {stage} tool {i}/{N} {tool_id}: {reason}
fail   {stage} tool {i}/{N} {tool_id}: {reason}
warn   [{stage}[/{subject}]] {message}
wait   still running {stage}[ {subject}] ({elapsed})
pause  {N} segment(s) awaiting agent reasoning in .secscan/handoff/ — re-run to resume
fail   scan failed in {stage}[ {subject}] after {elapsed}: {message}
stop   interrupted in {stage}[ {subject}] after {elapsed}; re-run to resume from checkpoint
```

`{elapsed}` renders as `1.2s`, `45s`, `3m12s`, `1h02m`. `{message}` for `warn` is the exact
string that appears in the report's coverage notes.

### Live (TTY) sink

Same text; permanent lines are printed exactly as above. Transient lines (`start`, `wait`)
are shown on a single status line prefixed with the `+MM:SS` column only and truncated to the
terminal width. On `close()` the current status line is promoted to a permanent line. No
colour codes are emitted in this feature.

## 4. `scan.log` format

```
secscan {TOOL_VERSION} scan {scan_id} started {ISO-8601 UTC}
<one line per event, grammar §3, verbose detail>
```

- Path: `<scan_root>/.secscan/scan.log`.
- Mode: overwrite per run; UTF-8; flushed per line.
- Present after any run whose configuration loaded successfully, including failed,
  interrupted and paused runs. When `.secscan/config.yaml` is missing or invalid the command
  fails exactly as today and **no** `scan.log` (and no `.secscan/` directory) is created.
- Not an artifact: no JSON envelope, not compared by determinism tests, not listed in any
  artifact manifest. Included in the credential redaction sweep.
- Contents obey FR-015: identifiers, paths, counts, durations, status words, report strings.

## 5. Library surface (internal, for the installed payload and tests)

```python
from pipeline import progress

reporter = progress.build_reporter(
    progress.OutputLevel.DEFAULT,
    stream=sys.stderr,
    log_path=store.dir / progress.LOG_FILE_NAME,
)
result = run_scan(root, progress=reporter, ...)
```

`run_scan(progress=None)` behaves exactly as today. `tooling.execute.run_external_scans`
gains the same optional `progress` keyword.

## 6. Backward-compatibility assertions (tests)

- `--output quiet`: stderr is empty; stdout equals the pre-feature lines byte for byte.
- No `--output`, non-TTY: stdout unchanged; stderr contains ≥1 `start` line before the
  first stage completes.
- Artifacts under `.secscan/**/*.json|*.md|*.html` are byte-identical between a `quiet` and a
  `verbose` run of the same input.
