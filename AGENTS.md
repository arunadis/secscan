# AGENTS.md

Guidance for coding agents working in this repository.

## What this is

**secscan** — hierarchical, context-bounded security scanning for large codebases,
installable as a skill into a coding agent. Deterministic tooling builds the repository
model and collects evidence; the LLM reasons only over small, redacted context packets.
See `README.md` for the full picture.

## Setup

```bash
uv venv --python 3.11
uv pip install -e ".[dev,plugin]" # editable install into ./.venv ([plugin] = MCP SDK)
source .venv/bin/activate         # ...or prefix commands with `uv run`
```

Note: `uv pip install -e .` does NOT put `secscan` on your PATH — use the venv or
`uv tool install --editable .`.

## Verification (run before finishing any change)

```bash
pytest -q                         # full suite (~900 tests); must be green
pytest -q -m slow                 # + large-repository scale scan
ruff check src tests              # line-length 100, py311, rules E/F/I/UP/B
secscan plugin check              # committed plugin files match their render (feature 018)
```

Integration tests exercise the install matrix and full scan lifecycle end to end, so
most behavioral changes are covered there. Test fixtures declare ground truth —
including deliberate false positives that must NOT be reported.

## Mutation testing (optional, not CI-gated)

mutmut is in the `dev` extra, configured in `[tool.mutmut]` (source `src/`, selection
`tests/unit` with `-x -q` — scoped to a single module the unit suite covers in
seconds; the full suite is far too slow per mutant):

```bash
mutmut run --max-children 4 "config.mode*"  # scoped wildcard; cap concurrency explicitly
mutmut run --max-children 4                 # resume the full campaign (incremental, cached)
mutmut results                # per-mutant verdicts (🎉 killed / 🙁 survived)
mutmut browse                 # TUI; write a survivor to disk with mutmut apply
```

Memory safety: mutmut 3.x runs pytest in-process inside forked children, and
`--max-children` defaults to `os.cpu_count()` — always pass it explicitly. A mutant
can also allocate unboundedly (e.g. a mutated loop bound); tests/conftest.py enforces
a per-child RAM cap under mutmut (`MUTMUT_MEM_CAP_GB`, default 4 GiB) via RLIMIT_AS
where the kernel honors it (Linux) and a ru_maxrss watchdog thread elsewhere (macOS
refuses to lower address-space limits), so a runaway child dies as a killed mutant
instead of OOM-ing the machine. Short timeouts
(`timeout_multiplier`/`timeout_constant` in `[tool.mutmut]`) bound CPU runaways;
`use_setproctitle = true` makes a runaway child identifiable as `mutmut: <name>` in
ps/top.

Results live in the gitignored `mutants/` work dir. For a deep campaign, temporarily
add `"tests/integration"` to `pytest_add_cli_args_test_selection` and, if those
edits matter, delete `mutants/` to invalidate cached verdicts.

## Naming conventions (single source of truth)

Everything is named **`secscan`** — do not reintroduce the old `security-scan` name:

| Surface | Value | Defined in |
|---|---|---|
| Skill name / agent command | `secscan` (`/secscan`, `@secscan`) | `SKILL_NAME` in `src/installer/core.py` |
| Artifacts directory | `.secscan/` | `SCAN_DIR_NAME` in `src/pipeline/state.py` |
| Console script | `secscan` (unified: installer + scan engine) | `[project.scripts]` in `pyproject.toml` |
| Env override prefix | `SECSCAN_<SECTION>_<KEY>` | `ENV_PREFIX` in `src/config/loader.py` |
| Payload-internal CLI | `python -m pipeline.scan_cli` | `src/pipeline/scan_cli.py` |
| MCP tool provider (plugin form) | `secscan mcp`; tools `secscan_<op>`; prompt `secscan`; resources `secscan://…` | `src/pipeline/mcp_server.py` (handlers), `src/pipeline/mcp_app.py` (serving) |
| Plugin package (repo root) | `plugin.json` + `mcp.json` (Agent Plugins 1.0.0), `.claude-plugin/` + `.mcp.json`, `gemini-extension.json` + `commands/`, `skills/secscan/SKILL.md` — all **generated** by `secscan plugin render` | `src/installer/plugin.py` |
| Optional extra | `secscan[plugin]` (`mcp>=2.1,<3`) — never required by the skill form | `[project.optional-dependencies]` |
| Run lock | `.secscan/run.lock` (not an artifact) | `RUN_LOCK_NAME` in `src/pipeline/state.py` |

Historical `specs/00X-*` documents still reference the old names — they are point-in-time
records; do NOT "fix" them.

## Layout

```
src/
├── installer/     secscan CLI (click group, unified command surface), per-agent
│                  adapters (claude/copilot/cursor/windsurf/devin/agents/gemini),
│                  in-place upgrade
├── skill_core/    installable payload: SKILL.md (core body with a `<!-- driver -->`
│                  marker), drivers/{shell,tools}.md (how the pipeline is invoked in the
│                  skill vs plugin form), prompts/, schemas/, data/, cwe_map.json
├── pipeline/      deterministic scan stages + payload CLI; tooling/ drives external
│                  scanners (provision, run, cross-check); triage* modules run the
│                  post-correlation finding-triage round (packets, verdict gates,
│                  citation re-verification, verdict application, user declarations);
│                  business_flow.py runs the opt-in flow reconstruction +
│                  analysis round (feature 015); identity_rules.py evaluates the
│                  versioned client-asserted-identity rule pack (feature 016)
├── config/        config loading, strict validation, profiles, execution mode
└── profiles/      built-in scan profiles as data
tests/
├── contract/      JSON-schema conformance
├── integration/   end-to-end scans, install matrix, installed-payload subprocess
├── contract/, benchmark/, fixtures/, helpers/, unit/
specs/             spec-first history (001–009), per-feature spec/plan/contracts/tasks
```

## Non-negotiables (enforce `.specify/memory/constitution.md`)

- **Determinism first**: identical input + tool version ⇒ byte-identical artifacts
  (sorted, canonical JSON with trailing newline via `store.canonical_json`).
- **Secrets NEVER reach a model**: the layered redactor runs before any context packet;
  unclassifiable content is blocked, not passed through. Never log or store credential
  values — only env-var NAMES.
- **No network, no mutation**: default path is offline; the scanner never installs,
  upgrades, or writes into the scanned project (hash-checked).
- **Honest uncertainty**: undetermined states are recorded explicitly and can never
  suppress a finding or read as clean.
- **Budgets enforced against the serialized request**, never estimates.
- **Agent handoff**: exit code 3 means reasoning files await answers in
  `.secscan/handoff/`; the scan resumes when re-run. The plugin form exposes the same
  handoff as tool states (`awaiting_reasoning`, `in_progress`, `locked`, …) and
  `secscan_submit_answer` writes exactly the response file an agent would.
- **Plugin form is additive**: `secscan init --ai <host> --plugin` registers the MCP
  tool provider at *user level* and writes nothing into the project; without
  `--plugin` the installer is byte-identical to before. When a project carries a
  skill install, the plugin delegates to that pinned payload (detected by the presence
  of `scripts/pipeline/mcp_server.py`, never by `TOOL_VERSION`) and never runs its own
  engine against it. `mcp_server.py` must not import `installer` or `mcp` (it is copied
  into the payload); the serving layer `mcp_app.py` is excluded from the payload.
- **Bounded `run` pauses only at checkpoints**: `run_scan(deadline=…)` raises
  `ScanPaused` before a checkpointed stage or at a batch-poll iteration, never between
  segments or deterministic passes (those re-drive on resume — pausing there livelocks),
  and only after the call completed one non-reused stage (guaranteed progress). The CLI
  never sets a deadline. Exit code 4 means the report
  published with narrative section(s) quarantined for a dangling finding
  reference — declared in the report's Report Integrity section, never stdout.
- **Progress is a side channel**: `src/pipeline/progress.py` is the only module that
  writes to the terminal during a scan (stderr) or to `.secscan/scan.log`. Never print
  from a stage; emit through the reporter. Timing/level never enters an artifact, and
  the three stdout summary lines in `scan_cli.cmd_run` are a frozen interface.
- **Endpoint calls only through `src/pipeline/providers.py` adapters**: never build a
  provider URL or request body anywhere else. Batch items reuse the interactive body
  builder so batching can never change what content reaches the provider.
- **Answer files hold exactly `{request_id, answer_key, content}`** (`.secscan/analysis/
  answers/`): nothing policy-dependent (source, tokens, timestamps) — those belong in
  `UsageTracker` or the batch ledger in `state.json`. A cached answer is never counted
  in the run's usage.
- Schemas are additive; breaking changes need a `schema_version` bump.
- Adding a stack/rule/control must extend versioned data, not pipeline stages.

## Spec-first workflow

Features are specified before implementation (GitHub Spec Kit; skills available as
`/speckit-specify`, `/speckit-plan`, `/speckit-tasks`, `/speckit-implement`, etc.).
Every feature evaluates against the constitution in the plan's Constitution Check.
Accuracy-benchmark regressions are release-blocking.
