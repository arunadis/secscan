# Quickstart: NVD API Key Setup During Initialization

Runnable validation scenarios proving the feature end-to-end. Field/enum names
are defined in [data-model.md](data-model.md); CLI and flow behavior in
[contracts/init-nvd-credential.md](contracts/init-nvd-credential.md). No
implementation code here — task-level detail belongs to `tasks.md`.

## Prerequisites

- Repo working tree; the project's venv active (`pytest`, `ruff` per
  constitution gates).
- A scratch directory as the init target (e.g. `$(mktemp -d)`), containing a
  Maven marker (`pom.xml`) so `owasp-dependency-check` is *applicable* —
  the credential flow only fires for registry tools applicable to detected
  ecosystems.
- No real NVD key is needed for any scenario here.

## Scenario 1 — Key present: no prompt, fully available (US1)

```bash
NVD_API_KEY=qs-test-value python -m pipeline.init_cmd --workdir "$SCRATCH" --no-input
```

Expected outcome:
- init completes with no credential prompt.
- Report shows the `owasp-dependency-check` credential line as `available`
  (with the "presence, not validity" note).
- `tooling/availability.json` in `$SCRATCH/.security-scan/` carries
  `credential: {"variable": "NVD_API_KEY", "state": "available"}` on that tool's
  record, and no other tool record carries a `credential` object.

## Scenario 2 — Interactive keyless: warning, then informed choice (US2)

```bash
env -u NVD_API_KEY python -m pipeline.init_cmd --workdir "$SCRATCH"
# (run in a TTY; answer the external-tools credential prompt per sub-case)
```

Expected outcomes per choice:

- **skip**: no install of the tool; record shows
  `decision: "skipped-no-key"` and `credential.state: "skipped-no-key"`;
  report names the tool as skipped and says how to add it later
  (set `NVD_API_KEY`, re-run init). init still reports ready (tool check is
  informational).
- **proceed**: tool installs per its registry channel; record shows
  `credential.state: "degraded-no-key"` with the rate-limited note.
- **provide**: tool installs; record shows `credential.state: "awaiting-key"`;
  report tells the user to set `NVD_API_KEY` and that it takes effect at scan
  time. Re-running init with the variable set upgrades the reported state to
  `available` without re-installing.
- In all sub-cases: the implication warning (rate-limited, much slower first
  sync, intermittent sync failures) appears BEFORE any installation of the
  tool.

## Scenario 3 — Non-interactive keyless: deterministic skip + opt-in (US3)

```bash
env -u NVD_API_KEY python -m pipeline.init_cmd --workdir "$SCRATCH" --no-input
env -u NVD_API_KEY python -m pipeline.init_cmd --workdir "$SCRATCH" --yes
env -u NVD_API_KEY python -m pipeline.init_cmd --workdir "$SCRATCH" --yes --allow-keyless-nvd
```

Expected outcomes:

- First two runs: zero prompts, tool record `skipped-no-key`, report declares
  the skip and reason, init completes "ready".
- Third run (`--allow-keyless-nvd`): tool installs, record
  `degraded-no-key` — the explicit opt-in is honored; without the flag, `--yes`
  alone never installs keyless.

## Scenario 4 — Secret hygiene sweep (SC-004 / Principle III)

With a distinctive sentinel value:

```bash
NVD_API_KEY=qs-sentinel-47f9 python -m pipeline.init_cmd --workdir "$SCRATCH" --yes
grep -r "qs-sentinel-47f9" "$SCRATCH/.security-scan/"   # expect: no matches
```

Expected outcome: the sentinel string appears in **no** file under
`.security-scan/`, and never in stdout/rendered report. (Automated:
`tests/integration/test_nvd_key_redaction.py`.)

## Scenario 5 — Blanket-consent filtering (FR-010)

```bash
env -u NVD_API_KEY python -m pipeline.init_cmd --workdir "$SCRATCH" --install=all --no-input
```

Expected outcome: registry tools without a credential block proceed per
feature-008 consent rules; the NVD-backed tool is excluded with
`skipped-no-key` and its absence from any attempted install is visible in the
install-list rendering/decision record.

## Scenario 6 — Edge cases (single automated pass)

Covered by integration tests rather than manual runs:

- `NVD_API_KEY=""` and `NVD_API_KEY="   "` behave as *not provided*.
- Tool already installed system-wide: presence check still runs; no
  install-side prompt; report shows `available` or `degraded-no-key` line.
- Re-run after `skipped-no-key` with the key set: tool installs normally
  (skip is not sticky).
- Blank `--install=` selections combined with `--allow-keyless-nvd` still
  require tool consent — the keyless flag never widens the *tool* selection.

## Regression gates (constitution)

- `pytest` green, `ruff check src tests` clean.
- `tests/contract/test_tooling_artifacts.py` extended: availability records
  with and without `credential` both validate; readers tolerate the additive
  field; `credential.state` enum closed.
- Byte-identity invariant: two identical init runs (same environment) produce
  byte-identical `availability.json`.
