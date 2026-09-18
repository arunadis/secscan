# Quickstart: validating Plugin Install end to end

**Feature**: 018-plugin-install. Contracts: [mcp-tools.md](contracts/mcp-tools.md),
[plugin-manifests.md](contracts/plugin-manifests.md), [cli-plugin.md](contracts/cli-plugin.md).

## Prerequisites

```bash
uv venv --python 3.11
uv sync --extra dev --extra plugin       # base + tests + the MCP SDK
source .venv/bin/activate
```

## 1. Gates (automated)

```bash
pytest -q                                # full suite green, incl. the new unit/integration/contract tests
pytest -q -m slow                        # scale scan: SC-005 (bounded run, no lost work)
ruff check src tests
secscan plugin check                     # committed plugin files match their render (R8)
```

Expected: all green; `plugin check` prints nothing and exits 0.

## 2. Skill form is untouched (User Story 3, FR-001/FR-013/FR-023)

```bash
tmp=$(mktemp -d) && python -c "from pathlib import Path; from tests.fixtures.single_repo_shop import build; build(Path('$tmp/proj'))"
secscan init "$tmp/proj" --ai claude --no-init
find "$tmp/proj/.claude" -type f | sort                            # identical listing to main
uv venv "$tmp/venv" && uv pip install --python "$tmp/venv/bin/python" -e .   # base install only, no [plugin]
PYTHONPATH="$tmp/proj/.claude/skills/secscan/scripts" "$tmp/venv/bin/python" -m pipeline.scan_cli --help
```

Expected: the skill payload lists no `mcp` command and imports nothing from `mcp`;
`tests/integration/test_install_matrix.py` golden files show zero diff for every adapter.

## 3. Tool-driven lifecycle on any MCP host (User Story 2)

Automated equivalent: `tests/integration/test_mcp_lifecycle.py` (SDK stdio client ↔
`secscan mcp` subprocess). Manual walk-through with the MCP Inspector or any host:

1. Register the server: `{"command":"uv","args":["run","--project","<repo>","--extra","plugin","secscan","mcp"]}`.
2. `secscan_init {"workdir": "<proj>"}` → `state: ok` (or `not_ready` with the environment report).
3. `secscan_run {"workdir": "<proj>", "profile": "quick"}` →
   - progress arrives as `notifications/message` lines (stage names, `segment i/N`), **not** in the result;
   - result `state: awaiting_reasoning`, `pending: [...]`.
4. `secscan_list_requests` → ids; `secscan_get_request {"request_id": "<id>"}` → the request
   document; compare with `cat <proj>/.secscan/handoff/requests/<id>.json` — byte-equal.
5. `secscan_submit_answer` with `{"content": "not json"}` → `state: rejected`, `errors` listed,
   and `ls <proj>/.secscan/handoff/responses/` is unchanged.
6. `secscan_submit_answer` with a conforming findings document → `state: ok`, file present.
7. `secscan_run` again → `state: ok`, `summary` holds the three frozen lines,
   `report_path` exists. Exit-code parity: run the same project with the CLI and compare.
8. `secscan_report {"format": "json"}` → report content.

Expected: no stderr output from the server during any call; `.secscan/scan.log`
contains the same lines the host received.

## 4. Bounded run and lock (FR-007/FR-008)

```bash
# deadline: force a tiny bound on a large fixture
secscan_run {"workdir": "<large>", "time_budget_s": 5}
```

Expected: `state: in_progress`, `checkpoint.stage` named (a checkpointed stage — never a
segment id), `overran_bound` true only if one un-checkpointable stage exceeded the bound; **no** `secscan` process remains
(`pgrep -f pipeline.scan_cli` empty); `ls <large>/.secscan/run.lock` → absent. Repeat
`secscan_run` until `ok`; artifacts equal a single uninterrupted CLI run (parity test).

```bash
# lock: start a CLI scan, then call the tool while it runs
secscan run --workdir <large> &  sleep 1; secscan_run {"workdir": "<large>"}
```

Expected: `state: locked` with the CLI's pid and `driver: "cli"`; the CLI run
completes normally and the lock file is gone afterwards.

## 5. Plugin install per host (User Story 1) — manual, one line each

Automated part: `tests/integration/test_install_matrix.py::test_plugin_form` runs
`secscan init <proj> --ai <host> --plugin --no-init` for every host under a redirected
`HOME`/`APPDATA` and asserts (a) the expected user-level file gained `mcpServers.secscan`
(or the host CLI was invoked via a fake on `PATH`), (b) `git status --porcelain <proj>` is
empty, (c) the user install record has the host entry. What the tests cannot do is
prove each host *loads* the layout; check that by hand and note the result in the PR:

| Host | Install | Check |
|---|---|---|
| Cursor | Settings → Plugins → install from path `<repo>` (Agent Plugins) or `secscan init . --ai cursor --plugin` | `/secscan` skill visible; `secscan_*` tools listed |
| GitHub Copilot (VS Code / CLI) | install the plugin from `<repo>` | skill + tools listed |
| Devin | `devin plugins install --local <repo>` | `/secscan:secscan` available; `secscan_*` tools listed; only one `secscan` MCP server |
| Claude Code | `claude --plugin-dir <repo>` (guaranteed path; marketplace install needs a `.claude-plugin/marketplace.json`, deferred with publication — FR-003) | `/secscan:secscan`; MCP `secscan` prompt; one server |
| Gemini CLI | `gemini extensions install <repo>` | `/secscan` command; `secscan_*` tools |
| Windsurf | `secscan init . --ai windsurf --plugin` | tools listed in Cascade MCP panel (no skill — expected) |

Then open a project with **no** secscan files and run a `quick` scan through the host.
Expected: only `.secscan/` appears in the project (`git status` shows nothing else);
the report matches a skill-driven run of the same version.

## 6. Precedence: project skill install wins (FR-015)

```bash
secscan init <proj> --ai cursor --no-init         # project pinned to this checkout's version
# edit <proj>/.cursor/skills/secscan/.install-manifest.json tool_version to "0.0.9" to simulate an older pin
secscan_status {"workdir": "<proj>"}
```

Expected: `driver: {"form": "skill", "tool_version": "0.0.9", "plugin_version": "<current>", "delegated": true}`;
`secscan_run` result declares `bound: "unsupported by pinned payload v0.0.9"` and runs the
pinned payload. Remove `scripts/` from the skill dir → `state: error`,
`reason: corrupt skill install`, `repair` command shown; the plugin's engine never runs.

## 7. Single source (FR-018, SC-007)

```bash
sed -i.bak 's/## Objective/## Objective (edited)/' src/skill_core/SKILL.md
secscan plugin check                              # exit 1: stale: skills/secscan/SKILL.md, commands/secscan.toml
pytest -q tests/unit/test_plugin_render.py        # fails
mv src/skill_core/SKILL.md.bak src/skill_core/SKILL.md
```

## 8. Documentation reconciliation (constitution gate)

Confirm in the same change set: README Status header, install section ("skill or
plugin"), Roadmap, exit codes (unchanged) and `.secscan/` layout (`run.lock`);
`docs/agent-integration.md` per-host table (research R2); `docs/cli-reference.md`
(`mcp`, `plugin render|check`, `init --plugin`, lock message); `docs/configuration.md`
(`plugin.run_bound_s`); `docs/artifacts.md` (`run.lock` not an artifact);
`docs/getting-started.md`; `AGENTS.md` naming table (plugin surfaces, `[plugin]` extra,
`secscan plugin check` in the verification list).
