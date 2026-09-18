# Contract: CLI additions, run lock, deadline, user install record

**Feature**: 018-plugin-install

The three stdout summary lines printed by `scan_cli.cmd_run` and every existing exit
code are **unchanged** (FR-010). Everything below is additive.

## 1. `secscan mcp`

```
secscan mcp
```

Starts the stdio tool provider (`pipeline.mcp_server.main`). No options: the scan root
arrives per operation. Requires the `plugin` extra; when `mcp` cannot be imported the
command exits 1 with:

```
secscan mcp needs the plugin extra: install with  uv sync --extra plugin  (or  pip install "secscan[plugin]")
```

on stderr and nothing on stdout (stdout is the protocol channel). Exposed through the
click group in `installer/cli.py`; **not** through the payload's `python -m
pipeline.scan_cli` (a copied skill payload has no `mcp` dependency and must not
advertise the command — FR-023).

## 2. `secscan plugin render` / `secscan plugin check`

```
secscan plugin render [--root PATH]     # write the committed plugin files (default: repo root)
secscan plugin check  [--root PATH]     # exit 1 and list stale files; writes nothing
```

`render` writes exactly the files in contracts/plugin-manifests.md, canonical JSON
(sorted keys, 2-space indent, trailing newline) for `*.json`, and the existing adapter
renderers for `SKILL.md`/`secscan.toml`. `check` prints one line per stale file:
`stale: <relative path>` and a final hint `run: secscan plugin render`. Both are
deterministic and offline.

## 3. `secscan init … --plugin`

```
secscan init [PROJECT] --ai <host> --plugin [--plugin-root PATH] [--force] [--no-init] [--yes|--no-input]
```

| Behaviour | Rule |
|---|---|
| Without `--plugin` | byte-for-byte today's behaviour (skill form) — FR-013 |
| `--plugin` with `--ai agents` | usage error: "the cross-vendor target has no plugin form; add the mcp.json entry to your host by hand" |
| `--plugin` with `--ai windsurf` | registers MCP only and prints the note that guidance is tool/prompt-only |
| `--plugin-root` | plugin checkout to point the launch reference at; default: the checkout `secscan` itself runs from (`Path(__file__)` ancestors containing `plugin.json`); error if none |
| Pre-provisioning | runs `uv sync --extra plugin` in the plugin root so the host's first launch is offline; when `uv` is absent the step is skipped with a printed note naming the manual command (`pip install -e "<root>[plugin]"`) — the registration still proceeds |
| Registration | per host, research R2: JSON merge into the user-level MCP file or the host CLI command |
| Project writes | **none** (no skill dir, no `.gitignore` change) — FR-014; `PROJECT` is still accepted so the subsequent `init` (config + environment check) runs against it exactly as today unless `--no-init` |
| Record | user install record updated (data-model.md §3); downgrade refused unless `--force` (FR-016) |
| Failure | unwritable/unknown user-level location or missing host CLI → exit 1, message names the path or command tried; nothing is written anywhere |

Output (success):

```
Registered secscan v0.1.0 as a plugin for Cursor
  plugin root: /Users/x/src/secscan
  registered:  /Users/x/.cursor/mcp.json  (mcpServers.secscan)
  next: restart Cursor; the skill loads from the plugin, the tools from the MCP server
```

Followed by today's `init` report unless `--no-init`.

## 4. `secscan agents` and `secscan init --help`

`secscan agents` gains a fourth column, the install forms per host:

```
Supported agents (--ai):
  agents    Cross-vendor (.agents)   .agents/skills/           skill
  claude    Claude Code              .claude/skills/           skill, plugin
  copilot   GitHub Copilot           .github/skills/           skill, plugin
  cursor    Cursor                   .cursor/skills/           skill, plugin
  devin     Devin                    .devin/skills/            skill, plugin
  gemini    Gemini CLI               .gemini/commands/         skill, plugin
  windsurf  Windsurf (Cascade)       .windsurf/skills/         skill, plugin (MCP only)

Hosts without a listed plugin form can attach the tool provider from mcp.json to any MCP-capable agent.
```

(FR-017.)

## 5. Run lock (both forms)

| Surface | Behaviour |
|---|---|
| `run_scan` | acquires `.secscan/run.lock` on entry, releases in `finally`; stale (dead pid) locks are reclaimed |
| `secscan run` (CLI) | live lock → stderr `scan already running in <root> (pid N, started <time>, via cli|plugin); wait or remove .secscan/run.lock if that process is gone`, exit 1; stdout empty |
| `secscan status` (CLI) | adds a line `Running: pid N via <driver> since <time>` when a live lock exists |
| `secscan_run` (tool) | `state: locked` with the lock fields |
| Determinism tests | `run.lock` is excluded like `scan.log`; never present after a completed run |

## 6. Deadline (tool only)

`run_scan(..., deadline=clock()+bound)` — the CLI passes `None`. `ScanPaused` is raised
only at the boundaries enumerated in research R4 (checkpointed stage starts and
batch-poll iterations, after at least one non-reused stage completed in this call);
`store.save_state()` precedes it.
`cmd_run` does not catch `ScanPaused` (it can never be raised on the CLI path; a unit
test asserts the CLI never sets a deadline).

Config key `plugin.run_bound_s` (int, 5..3600, default 45; env
`SECSCAN_PLUGIN_RUN_BOUND_S`) — `docs/configuration.md`. Per-call `time_budget_s`
overrides it for one operation only.

## 7. Delegation subprocess (tool only, research R9)

When `installer.core.detect_installs(workdir)` is non-empty, `secscan_run`,
`secscan_status`, `secscan_report`, `secscan_init` delegate to the pinned payload by
subprocess, choosing the entry by **file presence** — `TOOL_VERSION` does not change
between commits, so a version comparison cannot tell a pre-feature payload from a
current one:

**`<skill_dir>/scripts/pipeline/mcp_server.py` present in the pinned payload**:

```
[sys.executable, "-m", "pipeline.mcp_server", "--oneshot", "<tool>", "<json args>"]
env: PYTHONPATH=<skill_dir>/scripts, plus the parent environment
```

`--oneshot` runs one tool handler in-process **without importing `mcp`** (the SDK is
imported only by the serving path, so a copied payload never needs the extra) and
prints the result envelope as one JSON document on stdout; progress lines go to its
stderr, which the parent forwards as `notifications/message`. The bound is honoured
because the handler is this feature's own `secscan_run`. The parent copies the
envelope through, setting `driver` (§1.1 of mcp-tools.md).

**`scripts/pipeline/mcp_server.py` absent (pinned payload predates this feature)**:

```
[sys.executable, "-m", "pipeline.scan_cli", <cmd>, "--workdir", <workdir>, "-q", <args…>]
env: PYTHONPATH=<skill_dir>/scripts, plus the parent environment
```

mapped: exit 0 → `ok`, 2 → `not_ready`, 3 → `awaiting_reasoning` (pending ids read from
`handoff/requests/` minus `handoff/responses/`), 4 → `report_defect`, 1 → `error` or
`endpoint_failed` (by the stderr `re-run to resume` marker). The `summary` field is the
subprocess's stdout lines; stderr is forwarded line-by-line as `notifications/message`.
The bound cannot be honoured, so the result declares
`bound: "unsupported by pinned payload v<X>"` and the call runs to completion.

In both cases the public `secscan run` CLI gains **no** new flag and no new exit code.

## 8. User install record

Path and shape: data-model.md §3. Written with `store.canonical_json`. Read by
`secscan status` (prints "Plugin installs (user level): cursor v0.1.0 → ~/.cursor/mcp.json")
and by `init --plugin` for the downgrade check.
