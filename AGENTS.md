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
uv pip install -e ".[dev]"        # editable install into ./.venv
source .venv/bin/activate         # ...or prefix commands with `uv run`
```

Note: `uv pip install -e .` does NOT put `secscan` on your PATH — use the venv or
`uv tool install --editable .`.

## Verification (run before finishing any change)

```bash
pytest -q                         # full suite (~800 tests); must be green
pytest -q -m slow                 # + large-repository scale scan
ruff check src tests              # line-length 100, py311, rules E/F/I/UP/B
```

Integration tests exercise the install matrix and full scan lifecycle end to end, so
most behavioral changes are covered there. Test fixtures declare ground truth —
including deliberate false positives that must NOT be reported.

## Naming conventions (single source of truth)

Everything is named **`secscan`** — do not reintroduce the old `security-scan` name:

| Surface | Value | Defined in |
|---|---|---|
| Skill name / agent command | `secscan` (`/secscan`, `@secscan`) | `SKILL_NAME` in `src/installer/core.py` |
| Artifacts directory | `.secscan/` | `SCAN_DIR_NAME` in `src/pipeline/state.py` |
| Console script | `secscan` (unified: installer + scan engine) | `[project.scripts]` in `pyproject.toml` |
| Env override prefix | `SECSCAN_<SECTION>_<KEY>` | `ENV_PREFIX` in `src/config/loader.py` |
| Payload-internal CLI | `python -m pipeline.scan_cli` | `src/pipeline/scan_cli.py` |

Historical `specs/00X-*` documents still reference the old names — they are point-in-time
records; do NOT "fix" them.

## Layout

```
src/
├── installer/     secscan CLI (click group, unified command surface), per-agent
│                  adapters (claude/copilot/cursor/windsurf/devin/agents/gemini),
│                  in-place upgrade
├── skill_core/    installable payload: SKILL.md, prompts/, schemas/, data/, cwe_map.json
├── pipeline/      deterministic scan stages + payload CLI; tooling/ drives external
│                  scanners (provision, run, cross-check)
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
  `.secscan/handoff/`; the scan resumes when re-run.
- Schemas are additive; breaking changes need a `schema_version` bump.
- Adding a stack/rule/control must extend versioned data, not pipeline stages.

## Spec-first workflow

Features are specified before implementation (GitHub Spec Kit; skills available as
`/speckit-specify`, `/speckit-plan`, `/speckit-tasks`, `/speckit-implement`, etc.).
Every feature evaluates against the constitution in the plan's Constitution Check.
Accuracy-benchmark regressions are release-blocking.
