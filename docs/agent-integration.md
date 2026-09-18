# Agent integration

secscan's defining integration choice: in the default mode, **the scanner never
calls a model itself**. The coding agent you already use does the reasoning, with
its own model — no API key required, and no analysis content leaves your machine.
An external endpoint can be configured instead (see
[Configuration](configuration.md#execution-modes-who-does-the-reasoning)); this
page covers the default agent-mediated path and how agents are supported.

## The handoff protocol

When the pipeline needs reasoning (segment analysis, system review), it does not
call a model — it writes a request file and stops:

```
secscan run --full
→ 6 analysis request(s) await agent reasoning
  .secscan/handoff/requests/<request-id>.json   (prompt + bounded packet)
  answer into .secscan/handoff/responses/<request-id>.json, then re-run
```

- **Exit code 3** means "handoff pending". This is not an error; it is the normal
  pause point of an agent-mediated scan.
- Each request file carries the rendered prompt plus the bounded, redacted context
  packet — everything the reasoning needs, nothing else. Token budgets were already
  enforced against the serialized request before it was written.
- The answer is JSON conforming to the finding schema, written to the matching
  response file. Free-form output is rejected by the pipeline.
- Re-running `secscan run` picks up answered requests and continues. Because the
  exchange is **files**, one scan can span **multiple agent sessions** — answer
  what you can, re-run, repeat. Partial answers keep prior work.

In practice you don't read or write these files by hand: invoking the installed
`/secscan` skill in your agent drives the loop — the agent runs the pipeline,
reads the pending requests, answers them, re-runs. Progress is visible any time
with `secscan status .` (`Agent handoff: 4/6 request(s) answered`).

## The skill contract

The installed payload is `src/skill_core/SKILL.md` plus prompts, schemas, and the
knowledge bases. Its rules for the reasoning agent are non-negotiable:

1. Never load the repository into context; work only from the packets provided.
2. Prefer references (`file#symbol`) over pasting unrelated code.
3. Every finding must carry evidence — file, symbol, and why it matters.
4. Every finding must carry a CWE id **from the shipped dataset**, a CVSS-style
   severity score, and a numeric confidence.
5. Output **only** JSON conforming to the finding schema — no prose; the pipeline
   rejects free-form output.
6. No duplicate findings; no invented CWE ids.
7. Cross-segment claims must cite findings from more than one segment.
8. Never execute attacks; verification is static.
9. Reproduction steps use benign canary values, no real secrets, local/test scope
   only.

Model output is advice, not authority: locations are re-resolved against the code
model, CWE ids against the shipped dataset, and self-contradicting reports are
withheld entirely. See [Architecture — decision authority](architecture.md#decision-authority).

## Two install forms

secscan reaches an agent in one of two ways. Both drive the same engine and produce
byte-identical artifacts for the same input and answers; only *how the agent invokes
the pipeline* differs.

| | Skill form (default) | Plugin form |
|---|---|---|
| Install | `secscan init <project> --ai <host>` copies the payload into the project (`.claude/skills/secscan/`, …) | `secscan init <project> --ai <host> --plugin` registers an MCP tool provider in the host's **user-level** settings; or install the checkout as a plugin with the host's own command |
| Scope | per project — each project pins its own scanner version | per engineer — available in every workspace; version = the checked-out plugin content |
| Writes into the project | the skill directory, `.secscan/` at scan time, an optional `.gitignore` line | **nothing** except `.secscan/` at scan time |
| How the agent drives the scan | shell commands (`python -m pipeline.scan_cli …`), reads/writes `.secscan/handoff/` files | tool calls: `secscan_init`, `secscan_run`, `secscan_status`, `secscan_list_requests`, `secscan_get_request`, `secscan_submit_answer`, `secscan_report` |
| Guidance | `SKILL.md` (`/secscan`) | the same `SKILL.md` body as a plugin skill (`/secscan:secscan`) and as the MCP prompt `secscan` |
| Dependencies | none beyond the base install | the `plugin` extra (`mcp` SDK), never required by the skill form |

The skill form is unchanged and remains the default; the plugin form is additive.

### Plugin form: what a host loads

The repository root **is** the plugin. It ships the open [Agent Plugins 1.0.0](https://agent-plugins.org)
layout (`plugin.json`, `mcp.json`, `skills/secscan/SKILL.md`) plus the two vendor
layouts that do not read it. All of these files are generated from the single skill
source by `secscan plugin render`; `secscan plugin check` fails when they drift.

| Host | Layout it loads | Install the full plugin (skill + tools) | `init --plugin` registers the tool provider in |
|------|-----------------|------------------------------------------|-------------------------------------------------|
| Cursor | Agent Plugins root | Settings › Plugins › install from path `<checkout>` | `~/.cursor/mcp.json` |
| GitHub Copilot (VS Code, CLI, app) | Agent Plugins root | install the Agent Plugin from `<checkout>` | `~/.copilot/mcp-config.json` |
| Devin | `.claude-plugin/` (fallback) or Agent Plugins root | `devin plugins install --local <checkout>` | `~/.config/devin/mcp_config.json` (`%APPDATA%\devin\mcp_config.json` on Windows) |
| Claude Code | `.claude-plugin/plugin.json` + `.mcp.json` | `claude --plugin-dir <checkout>` (a marketplace listing needs a `marketplace.json`, deferred with publication) | `claude mcp add-json --scope user secscan …` (host CLI; `~/.claude.json` is host-owned and never edited directly) |
| Gemini CLI | `gemini-extension.json` + `commands/secscan.toml` | `gemini extensions install <checkout>` | the same command when `gemini` is on `PATH`, otherwise `~/.gemini/settings.json` |
| Windsurf | *none* — MCP registration only | — | `~/.codeium/windsurf/mcp_config.json` |
| `agents` (cross-vendor) | — | — | no plugin form: attach the `mcp.json` stdio entry to any MCP-capable host by hand |

**Windsurf** has no installable plugin format, so its plugin form is tools-only:
guidance reaches the model through tool descriptions and the MCP prompt, with no
skill surface. The skill form is the recommended Windsurf path.

The launch reference in every layout is the same: `uv run --project <plugin root>
--extra plugin secscan mcp`, so the version that runs is exactly the checked-out
plugin content. `secscan init --plugin` runs `uv sync --extra plugin` in the checkout
once so the host's first launch is offline; the `secscan mcp` process itself never
resolves or fetches anything. If `uv` is missing, provision by hand with
`pip install -e "<checkout>[plugin]"` — a missing launcher is a host-side launch
failure secscan cannot observe, so make sure `uv` is on the host's `PATH`.

### Plugin form: how a `run` behaves

- Every tool takes `workdir` (the scan root). The server holds no state between calls.
- `secscan_run` is **bounded**: it works for at most `plugin.run_bound_s` seconds
  (default 45; per call `time_budget_s`) and then stops at the next checkpoint with
  `state: in_progress`. Nothing keeps running in the background; call `secscan_run`
  again and it resumes from that checkpoint. Checkpoints are the pipeline's
  checkpointed stages and provider batch polls — a single un-checkpointable stage may
  run past the bound, and every call completes at least one new stage, so a scan can
  be slowed by the bound but never stalled.
- `awaiting_reasoning` is the tool-form equivalent of exit code 3: answer each
  `pending` id with `secscan_get_request` → `secscan_submit_answer` (validated against
  the request's schema before anything is written; a rejection writes nothing), then
  `secscan_run` again.
- `locked` means another scan — CLI or plugin — holds `.secscan/run.lock` for this root.
- Progress arrives as host notifications, never in the result, and is always in
  `.secscan/scan.log`.

### Precedence when a project also has a skill install

The **project skill install wins**. When `.secscan`'s project carries a skill install,
the tool provider detects its manifest and delegates the scan to that pinned payload
by subprocess — it never runs its own engine version against the project. Results say
so: `driver: {"form": "skill", "tool_version": <pinned>, "plugin_version": <plugin>,
"delegated": true}`. A pinned payload that predates the plugin form is driven through
its command line and cannot honour the bound; the result then declares
`bound: "unsupported by pinned payload v…"`. A corrupt install (missing entrypoint or
scripts) is reported with the repair command and is never silently bypassed.

## Supported agents

Seven agents are supported through thin adapters over one agent-agnostic core
(`src/installer/agents/`):

| Key | Notes | Install forms |
|-----|-------|---------------|
| `claude` | Claude Code | skill, plugin |
| `copilot` | GitHub Copilot | skill, plugin |
| `cursor` | Cursor | skill, plugin |
| `windsurf` | Windsurf | skill, plugin (MCP only) |
| `devin` | Devin | skill, plugin |
| `agents` | Cross-vendor `AGENTS.md` convention | skill |
| `gemini` | Gemini — its flat TOML command format is translated automatically | skill, plugin |

`secscan agents` lists them with the skill path each one expects and the forms available.

## Adding a new agent

An adapter implements three small surfaces (`src/installer/agents/base.py`):

- `skill_dir(project_root, skill_name)` — where the payload goes for this agent.
- `entrypoint(project_root, skill_name)` — the invocable command/skill file.
- `render_entrypoint(core_text, skill_name)` + `invocation_hint(skill_name)` — how
  the shared `SKILL.md` core becomes a native invocation for this agent.
- For the plugin form (optional): `plugin_layout`, `user_mcp_config` or
  `register_command`, `install_hint`, `root_placeholder` — where the host reads
  user-level MCP settings and which committed layout it loads.

The core skill text, payload, upgrade logic, and scan pipeline do not change. The
install matrix is covered by integration tests (`tests/integration/`), so a new
adapter gains end-to-end coverage by registering in the existing fixtures.
