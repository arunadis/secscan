# Quickstart: Validating Scan Progress Output

**Feature**: 011-scan-progress-output

Runnable checks that prove the feature end to end. Line formats are defined in
[contracts/progress-output.md](contracts/progress-output.md); entities in
[data-model.md](data-model.md).

## Prerequisites

```bash
uv venv --python 3.11 && uv pip install -e ".[dev]"
source .venv/bin/activate
```

A configured fixture is needed for manual runs; the `single_repo_shop` fixture used by the
integration suite works:

```bash
export SHOP=$(mktemp -d)/shop
python -c "from pathlib import Path; from tests.fixtures.single_repo_shop import build; build(Path('$SHOP'))"
secscan init "$SHOP" --yes
```

## 1. The scan is visibly alive (US1)

```bash
secscan run --full --workdir "$SHOP"
```

Expected on stderr, within one second: `… start  scan <id> (full profile, agent-mediated)`
then `start  discover_repo`, `done   discover_repo (0.3s)`, … `start  segment_analysis
segment 1/N <id>`. On an interactive terminal the `start` lines update in place and the
`done`/`warn` lines stay in scrollback. stdout still ends with the summary (or the handoff
instructions and exit 3 in agent-mediated mode).

Re-run without `--full`:

```bash
secscan run --workdir "$SHOP"
```

Expected: `reuse  discover_repo (checkpoint)`, `reuse  build_code_graph (checkpoint)`, … —
every stage still listed.

## 2. Problems surface while they happen (US2)

Handoff is the simplest mid-run condition in agent-mediated mode:

```bash
secscan run --full --workdir "$SHOP"; echo "exit=$?"
```

Expected: last stderr line `pause  N segment(s) awaiting agent reasoning in .secscan/handoff/ —
re-run to resume`; `exit=3`; `"$SHOP/.secscan/scan.log"` exists and its last line is the
same `pause` line.

Interrupt a run (press Ctrl-C during `segment_analysis`):

Expected: `stop   interrupted in segment_analysis <segment> after 12s; re-run to resume from
checkpoint`, exit 130, terminal left on a fresh line, `scan.log` ends with the `stop` line.

Force a failure (unknown segment is the cheap one):

```bash
secscan run --segment nope --workdir "$SHOP"; echo "exit=$?"
```

Expected: existing `unknown segment 'nope'…` message on stderr, exit 1, unchanged.

## 3. Output levels (US3)

```bash
secscan run --full --workdir "$SHOP" -q 2>err.txt >out.txt; wc -c err.txt   # expect 0
SECSCAN_OUTPUT_LEVEL=verbose secscan run --workdir "$SHOP" 2>&1 >/dev/null | grep -c 'level='
```

Expected: quiet writes nothing to stderr and `out.txt` holds only the summary lines; verbose
`done … segment` lines carry `level=` and `tokens=`. Piping (`2>&1 | cat`) always yields plain
lines with no `\r`/escape sequences:

```bash
secscan run --full --workdir "$SHOP" 2>&1 >/dev/null | cat -v | grep -c '\^\[' # expect 0
```

## 4. Heartbeat

Heartbeat needs a >30 s silent step. In tests this is exercised with an injected interval;
manually, use a slow external tool or endpoint. Expected: `wait   still running
segment_analysis <segment> (32s)` every 30 s until the next event; in a TTY it overwrites
the status line rather than adding lines.

## 5. Determinism and redaction gates

```bash
pytest -q tests/integration/test_determinism.py tests/contract/test_artifact_redaction.py \
       tests/integration/test_scan_progress.py tests/unit/test_progress.py
pytest -q                     # full suite must stay green
ruff check src tests
```

Expected: artifacts byte-identical between `quiet` and `verbose` runs; the redaction sweep
sees `scan.log` and finds nothing; no test that asserts on `cmd_run` stdout needed changing.

## 6. Documentation currency (constitution gate)

Confirm the change set touches: `docs/cli-reference.md` (`--output` row, stderr/stdout
split, exit 130), `docs/configuration.md` (`output.level`, `SECSCAN_OUTPUT_LEVEL`),
`docs/artifacts.md` (`scan.log`, "not an artifact"), `docs/getting-started.md` (what a
running scan looks like), `README.md`, `src/skill_core/SKILL.md`.
