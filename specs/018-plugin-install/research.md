# Research: Plugin Install

**Feature**: 018-plugin-install | **Date**: 2026-09-18

Every Technical Context unknown is resolved below. Web facts were checked on the date
above; the per-host table (R2) is the kind of thing that drifts, so R2 also names the
test that pins each assumption we control and the manual check in quickstart.md for
the ones we cannot.

---

## R1. Plugin package format: Agent Plugins 1.0.0 at the repository root, plus two vendor layouts

**Decision**: make the repository root itself an installable plugin in the open **Agent
Plugins 1.0.0** format — `plugin.json` (manifest), `mcp.json` (MCP servers),
`skills/secscan/SKILL.md` (the plugin-form skill) — and add the two vendor layouts that
do not read it: `.claude-plugin/plugin.json` + `.mcp.json` (Claude Code) and
`gemini-extension.json` + `commands/secscan.toml` (Gemini CLI). No `.cursor-plugin/` or
`.devin-plugin/` manifests.

**Rationale**:
- Agent Plugins 1.0.0 (agent-plugins.org; TSC includes Amazon, Cursor, Microsoft,
  OpenAI, Vercel) defines exactly the two components we need — skills and MCP servers —
  and is loaded natively by **Cursor** ("A plugin that conforms to the Agent Plugins
  specification loads in Cursor without changes"), **GitHub Copilot** (VS Code, CLI, app —
  "Agent Plugins is an open standard … that works across … GitHub Copilot in VS Code,
  GitHub Copilot CLI, and the GitHub Copilot app") and **Devin** ("plugins packaged per
  the open Agent Plugins 1.0.0 spec … load too"). Three of the six hosts from one file
  set, and the spec is vendor-neutral, which is exactly FR-002's intent.
- **Claude Code** reads `.claude-plugin/plugin.json` with `skills/` and `.mcp.json` at
  the plugin root and installs from a git URL / local path through a marketplace
  (`/plugin marketplace add …` then `/plugin install secscan@…` — which requires a
  `.claude-plugin/marketplace.json`, deferred with publication) or directly with
  `claude --plugin-dir <root>`, the guaranteed route this feature documents. Devin's manifest precedence is
  `.devin-plugin > .claude-plugin > root plugin.json`, so Devin will pick the Claude
  layout; both layouts point at the same `skills/secscan/SKILL.md` and an equivalent
  MCP entry, so the choice is immaterial.
- **Gemini CLI** installs extensions from a GitHub URL or local path
  (`gemini extensions install <source> [--ref]`) into `~/.gemini/extensions/`, reading
  `gemini-extension.json` (`mcpServers` with `${extensionPath}` expansion) and TOML
  commands from `commands/`. The existing `GeminiAdapter.render_entrypoint` already
  produces that TOML, so the command file is a render of the same source.
- **Windsurf** has no git-installable plugin format (its plugin store is curated) but
  supports a single user-level `~/.codeium/windsurf/mcp_config.json` ("Windsurf only
  supports global config"). Its plugin form is therefore MCP registration only (R2, R7);
  the skill form remains the recommended Windsurf path and the docs say so.
- The plugin root **must be the git checkout root** for install-by-URL to work on
  every host (Claude marketplaces and Gemini extensions clone a repo and read its
  root; Devin supports `#subdir` but Gemini does not). Rendered plugin files therefore
  live at the repository root, not under `src/`.
- Agent Plugins §7.1 requires skills to conform to the Agent Skills spec — the format
  `skill_core/SKILL.md` already uses (`installer/agents/base.py` docstring).

**Alternatives considered**:
- *Vendor manifests only, no Agent Plugins manifest* — would need `.cursor-plugin/`,
  a Copilot layout and `.devin-plugin/` separately; three files where one standard
  file serves all three. Rejected.
- *Agent Plugins manifest only* — Claude Code and Gemini CLI do not load it. Rejected
  for FR-002 ("every existing adapter target that has a native plugin mechanism").
- *A separate `plugin/` subdirectory as the plugin root* — Gemini extensions cannot
  install a subdirectory; Claude marketplaces can but need a `marketplace.json`.
  Rejected.
- *Also shipping `.claude-plugin/marketplace.json`* so Claude users can `marketplace add`
  the repo directly — useful but strictly a distribution convenience; deferred to the
  release process with publication (spec FR-003).

**Duplicate-loading risk**: a host that reads both a vendor layout and `mcp.json`
could register the tool provider twice. Devin documents that legacy layouts never read
`mcp.json`; VS Code documents that the formats "keep their own layouts". This cannot
be asserted in CI (no hosts in the test environment); quickstart.md §5 lists the
one-line manual check per host.

---

## R2. Per-host user-level registration (installer `--plugin`)

**Decision**: each `Adapter` gains a `plugin` descriptor with one of two registration
mechanisms, chosen per host by what the host documents as its user-level surface:

| Host | Plugin layout it loads | User-level registration the installer performs | Mechanism |
|---|---|---|---|
| claude | `.claude-plugin/` + `.mcp.json` | `claude mcp add-json --scope user secscan '<stdio json>'`; prints `claude --plugin-dir <root>` for the skill/command | host CLI (the user file `~/.claude.json` is host-owned; not edited directly) |
| cursor | Agent Plugins root | merge `mcpServers.secscan` into `~/.cursor/mcp.json` | JSON merge |
| copilot | Agent Plugins root | merge `mcpServers.secscan` into `~/.copilot/mcp-config.json` | JSON merge |
| windsurf | none (MCP only) | merge `mcpServers.secscan` into `~/.codeium/windsurf/mcp_config.json` | JSON merge |
| devin | `.claude-plugin/` (fallback) / Agent Plugins root | merge `mcpServers.secscan` into `~/.config/devin/mcp_config.json` (`%APPDATA%\devin\mcp_config.json`); prints `devin plugins install --local <root>` for the full plugin | JSON merge (+ printed host command) |
| gemini | `gemini-extension.json` | `gemini extensions install <root>` when `gemini` is on `PATH`; otherwise merge `mcpServers.secscan` into `~/.gemini/settings.json` | host CLI, JSON-merge fallback |
| agents | — | none; help names the generic route (attach `mcp.json`'s stdio entry to any MCP host) | — |

**Rationale**: FR-013/FR-014 require user-level registration and forbid project writes;
FR-017 requires per-host help. A JSON merge keyed on the server name `secscan` is
idempotent, preserves other servers, and is fully testable under a redirected `HOME`.
Host CLIs are used only where the user file is host-owned (Claude) or where the host
CLI delivers the complete plugin in one step (Gemini). When a required host CLI is
absent or the target file is unwritable, the installer fails naming the path/command
it tried and never falls back to a project write (spec edge case).

**Alternatives considered**: editing `~/.claude.json` directly (host-owned, large,
schema undocumented — rejected); always shelling out to host CLIs (untestable without
hosts, several hosts have no CLI for MCP — rejected); registering at project level
(rejected by spec Q5).

**Windows**: paths use `%APPDATA%` where the host documents it (Devin), otherwise the
same `~`-relative path under `USERPROFILE`. The user install record uses
`%APPDATA%\secscan\`.

---

## R3. Tool-provider implementation: official `mcp` SDK as an optional extra

**Decision**: implement `pipeline/mcp_server.py` on the official MCP Python SDK
(`mcp>=2.1,<3`, `FastMCP`, stdio transport), declared as
`[project.optional-dependencies] plugin = ["mcp>=2.1,<3"]`. The base install and the
copied skill payload are unchanged (FR-023).

**Rationale**:
- Protocol conformance is now non-trivial: the 2026-07-28 specification made MCP
  stateless with per-request `_meta.io.modelcontextprotocol/*` metadata and a
  `server/discover` probe, while clients still fall back to the legacy `initialize`
  handshake. A hand-rolled JSON-RPC server would have to track both generations and
  every host's negotiation quirks — a maintenance burden with no product value.
- The SDK's statelessness model matches spec decisions Q2/Q4 exactly: "A server
  processes each request independently; no state should be inferred from previous
  requests" — every tool takes `workdir`, the server holds nothing.
- `mcp` 2.2.0 was published 2026-09-07 (11 days ago) and 2.1.1 on 2026-08-25; the
  `>=2.1,<3` range admits both and excludes the 1.x line that predates the current
  protocol. Pure-Python wheels; no build environment; nothing downloaded at run time
  (constitution technology constraints).
- The dependency set is heavier than the project's stdlib-first habit (`pydantic`,
  `starlette`, `httpx`, `opentelemetry-api`, `pyjwt`). Making it an *extra* keeps
  the skill form dependency-free and is the reason the decision is compatible with
  FR-023; a plugin host launching the server must have the extra provisioned (R11).

**Alternatives considered**:
- *stdlib JSON-RPC server* (the feature-011 style): rejected for conformance risk
  across two protocol generations; revisit only if the SDK's dependency weight
  becomes a shipping problem.
- *Streamable HTTP transport*: rejected — a local tool has no reason to open a port
  (FR-021), and every target host supports stdio.
- *Exposing the payload's `python -m pipeline.scan_cli` as a "shell" tool*: rejected —
  it is the command-composition surface the plugin form exists to remove.

---

## R4. Bounded `run`: cooperative deadline with `ScanPaused`

**Decision**: `run_scan` gains `deadline: float | None` (a monotonic timestamp from the
injected `clock`). A new exception `ScanPaused(stage, checkpoint, reason="deadline")`
(sibling of `AgentHandoff` in `run.py`) is raised when `clock() >= deadline` at any of
these boundaries — and only these:

| Boundary | Why it is safe to stop there |
|---|---|
| Before each checkpointed stage (`_stage`, `_stage_list`, and the `should_skip`-guarded `business_flow_analysis` / `finding_triage` rounds) | The previous stage's artifact and `state.json` record are written; resume skips it via `should_skip` |
| Each iteration of the batch poll loop (`BatchRoundRunner`, `triage.run_batch`), after at least one poll in this call | The batch reference is in the ledger; a re-run "resumes the same batch" (SKILL.md, feature 012) |

**Not boundaries (corrected during implementation)**: between segments, flows or
triage packets, and between the un-checkpointed deterministic passes (`misconfig` …
`generate_report`). The analysis stages re-drive from their first unit on resume and
the deterministic passes re-run every call, so a pause there persists nothing and the
next call would pause at the same place — a livelock the parity test reproduced with an
accelerated clock. The post-analysis deterministic block is therefore one
un-checkpointable unit (FR-007 allows it to run past the bound).

**Guaranteed progress**: a pause is only permitted once the call has completed at
least one checkpointed stage that was *not* reused (`progressed` flag). A resume whose
pre-checkpoint work alone (file hashing, reused-stage checks) exceeds the bound still
advances one checkpoint per call, so the bound can slow a scan but never stall it.

`store.save_state()` is called before raising so `status` reports the checkpoint.
The CLI (`cmd_run`) never passes a deadline, so it is unchanged; only
`secscan_run` does. The default bound is **45 s** (`plugin.run_bound_s`, validated
5..3600, env `SECSCAN_PLUGIN_RUN_BOUND_S`), overridable per call with `time_budget_s`.

**Rationale**: spec Q2 chose checkpoint-and-return over background work. Every
boundary above is one the pipeline *already* persists behind for interruption
recovery (FR-018 of feature 012, the resume tests), so pausing there changes no
artifact. A single un-checkpointable unit (one external tool run, one graph build)
may overrun the bound — the spec allows this (FR-007) and the tool result declares
`overran_bound: true` when it happens. 45 s sits under the common default tool-call
limits of the target hosts (which range from ~60 s upward) with margin for one
boundary check latency; it is a config key, not a constant, precisely because those
limits differ.

**Alternatives considered**: a background thread/process with a job handle (rejected
by Q2: orphan risk, state outside `.secscan/`, breaks "no work after return");
SIGALRM-style pre-emption (rejected: could interrupt a write mid-stage — exactly what
the boundary list prevents); a fixed constant (rejected: host limits differ).

---

## R5. Concurrency: `.secscan/run.lock`

**Decision**: `run_scan` acquires `.secscan/run.lock` (JSON: `pid`, `started_at`,
`scan_id`, `driver: "cli" | "plugin"`, `tool_version`) with `O_EXCL` semantics and
releases it in a `finally`. A lock whose `pid` is not alive is reclaimed silently. A
live lock makes `secscan_run` return `state: "locked"` (naming the running scan and
driver) and makes `cmd_run` exit 1 with the same information on stderr. `status` shows
it. The file is not `*.json`, so it is outside the determinism comparison like
`scan.log`, and it is removed on exit.

**Rationale**: FR-008 requires refusal keyed on the scan root regardless of who drives.
Filesystem exclusivity is the only mechanism shared by two provider instances and the
CLI. Stale-pid reclaim covers the "provider killed mid-run" edge case without operator
action.

**Alternatives considered**: in-process lock (rejected: provider instances are
independent processes); `state.json` flag (rejected: `state.json` is an artifact-adjacent
file the store owns; a crash would leave it set with no pid to test).

---

## R6. Progress to the host: `McpSink`

**Decision**: a new `McpSink` implementing the existing `Sink` protocol
(`write(event, rendered)`, `finalize`, `close`) forwards each rendered line as an MCP
`notifications/message` (level `info`; `warning` for `EventKind.WARNING`/`STAGE_FAILED`)
and, when the client supplied a `progressToken`, as `notifications/progress` with
`progress=index, total=total` for segment events. `secscan_run` builds its reporter as
`ProgressReporter(level, [McpSink(ctx), FileSink(log_path)])` — the terminal sink is
omitted, so nothing reaches stderr (FR-009). Heartbeat behaviour is unchanged (the
reporter owns it).

**Rationale**: `progress.py` is the single writer by constitution/AGENTS.md; a sink is
the designed extension point (feature 011 plan: "stages depend on a narrow
`ProgressReporter` interface and never on a terminal"). The rendered lines are the
same strings already covered by the `scan.log` redaction sweep, so no new content class
reaches the host.

**Alternatives considered**: embedding progress in the tool result (rejected by FR-009);
writing to stderr (permitted by the stdio spec but would duplicate `scan.log` into host
logs and bypass the level model).

---

## R7. Skill/plugin guidance from one source

**Decision**: split `skill_core/SKILL.md` into the core body plus a marked include
(`<!-- driver -->`) and two driver texts, `skill_core/drivers/shell.md` (today's "Run the
pipeline with the scan command…" section, verbatim) and `skill_core/drivers/tools.md`
(the tool-call equivalent: call `secscan_run`, on `awaiting_reasoning` call
`secscan_list_requests`/`secscan_get_request`, answer with `secscan_submit_answer`,
call `secscan_run` again; on `in_progress` call `secscan_run` again). `Adapter.render_entrypoint`
renders the skill form with the shell driver (unchanged output — a golden test pins it);
`installer/plugin.py` renders the plugin form with the tools driver into
`skills/secscan/SKILL.md`, the same body as the MCP `secscan` prompt.

**Rationale**: FR-018 forbids a second hand-maintained copy; the only text that
legitimately differs between forms is *how to invoke the pipeline*, so that is the only
text that is parameterised. Rules, stage list, the business-flow question, the
per-request reasoning instructions and the output contract are shared verbatim.

**Alternatives considered**: two full SKILL.md files (rejected by FR-018); a plugin skill
that only says "use the secscan tools" (rejected: the reasoning instructions are the
skill's substance and must be present for hosts that show skills but not prompts).

---

## R8. Rendered files are committed and freshness-tested

**Decision**: `secscan plugin render` writes the nine plugin files from
`SKILL.md` + drivers + `TOOL_VERSION` + adapter metadata; `secscan plugin check` exits
non-zero when any committed file differs from its render; `tests/unit/test_plugin_render.py`
asserts the same. Manifest `version` fields equal `TOOL_VERSION`; `description` equals
the SKILL.md frontmatter description.

**Rationale**: hosts clone the repository, so the plugin files must exist in git —
they cannot be produced at install time. Committing renders plus a drift test is the
standard way to keep generated files single-sourced; SC-007 ("a test that mutates the
source asserts both surfaces change") is satisfied directly.

**Alternatives considered**: a git pre-commit hook (rejected: not enforceable in CI
alone); making the committed files the source and the skill a render of *them*
(rejected: inverts the existing single source and breaks every adapter test).

---

## R9. Precedence when a project carries a skill install (FR-015)

**Decision**: `secscan_run`, `secscan_status`, `secscan_report`, `secscan_init` first
call `installer.core.detect_installs(workdir)`. If any manifest is present, the tool
**delegates** to that payload by subprocess with `PYTHONPATH=<skill>/scripts`. A pinned
payload that ships this feature — detected structurally by the presence of
`<skill>/scripts/pipeline/mcp_server.py`, never by comparing `TOOL_VERSION`, which does
not change between commits (docs/getting-started.md) — is driven through its own
`python -m pipeline.mcp_server --oneshot <tool> <json>` — a handler-only entry that
never imports `mcp` and prints the result envelope on stdout — so the bound and every
result state are honoured by the pinned engine itself. An older payload is driven
through its `python -m pipeline.scan_cli <cmd> --workdir … -q` and its exit code /
stdout lines are mapped to result states; the bound cannot be honoured, so the result
declares `bound: "unsupported by pinned payload v<X>"` and the call runs to completion.
The result carries `driver: {"form": "skill", "tool_version": <pinned>,
"plugin_version": TOOL_VERSION, "delegated": true}`. Subprocess stderr is forwarded as
`notifications/message` so progress is preserved. The public CLI gains no flag. A
manifest that names a missing entrypoint or payload directory yields `state: "error"`
with `reason: "corrupt skill install"` and the repair command; the plugin never falls
back to its own engine (spec edge case).

`secscan_get_request`, `secscan_list_requests` and `secscan_submit_answer` are pure
file operations against `.secscan/handoff/` and need no delegation — their behaviour
is identical for both engines by construction.

**Rationale**: spec Q1 chose "project skill install always wins". Subprocess delegation
is the only way to run a *different* pinned version from a process that has its own
copy of the engine imported. The plugin's Python environment is a superset of the base
dependencies, so the pinned payload runs exactly as it does from an agent shell.

**Alternatives considered**: importing the pinned payload's modules dynamically
(rejected: two versions of `pipeline` in one interpreter); refusing to run when
versions differ (rejected: Q1 chose delegation, and it is the more useful behaviour).

---

## R10. Tool input safety

**Decision**: `workdir` is the only path-typed input. `request_id` is matched against
the *listing* of `.secscan/handoff/requests/*.json` (`Path.name` equality) rather than
used to build a path, so `..` or absolute ids cannot escape the directory.
`secscan_report` takes `repo` (validated against the workspace's member names by the
existing `report_view.render`) and `format`. No tool accepts a file path to read.

**Rationale**: FR-022. Structural prevention beats validation.

---

## R11. Launch reference and provisioning

**Decision**: the committed MCP entries launch the server through **uv** with the
plugin root as the project:

```json
{ "type": "stdio", "command": "uv",
  "args": ["run", "--project", "${PLUGIN_ROOT}", "--extra", "plugin", "secscan", "mcp"],
  "env": { "UV_PROJECT_ENVIRONMENT": "${PLUGIN_DATA}/venv" } }
```

(`${CLAUDE_PLUGIN_ROOT}` in `.mcp.json`, `${extensionPath}` in `gemini-extension.json`;
the `env` line is used only in the Agent Plugins `mcp.json`, whose clients define
`${PLUGIN_DATA}` — Devin documents it as "a persistent, writable per-plugin data
directory".) `secscan init --ai <host> --plugin` runs `uv sync --extra plugin` in the
plugin root once so the first host launch is offline; the `secscan mcp` process itself
never resolves or fetches anything.

**Rationale**: the version that runs is exactly the checked-out plugin content (git
ref pinned by the host's install), which is what "install by reference" means. `uv` is
the project's documented toolchain (AGENTS.md, getting-started.md) and Agent Plugins
§7.2.1 requires `command` to be a bare executable or `./`-relative path — `uv` is a
bare executable; a `./bin/secscan-mcp` shell wrapper was considered and rejected
because it would need a Windows twin and adds nothing `uv run` does not do.

**Constitution note**: environment resolution is an install-time action performed by
the operator (`secscan init --plugin`) or by the host's first launch after its own
install step — never by a scan stage, never into the scanned project. Documented in
`docs/agent-integration.md` with the `uv sync` pre-provisioning step and an
`--offline` note.

**Alternatives considered**: `uvx secscan==<ver> mcp` from a package index (rejected:
publication is out of scope, spec FR-003); vendoring dependencies into the plugin
(rejected: tree-sitter wheels are platform-specific).

---

## R12. Answer validation at submit time (FR-006)

**Decision**: `pipeline/answers_io.py` exposes `validate_answer(request_doc, content) ->
list[str]` and `write_response(handoff_dir, request_id, content)`. Validation is *exactly
the acceptance test the resume path applies*, selected by the request's `stage`:

| Request stage | Accepted when | Source of truth |
|---|---|---|
| `segment_analysis` (ids `<segment>-l<level>`) | `FindingNormalizer.parse(content)` succeeds (structured findings JSON, optional `needs_escalation`); per-finding conformance is left to the normalizer on resume, which declares rejections as coverage notes — identical to the skill path | `normalize_findings.py`, `escalate.py` |
| `business_flow_analysis` (`flow-…`) | `schemas.validate("flow_answer", json)` | `business_flow.py:640` |
| `finding_triage` (`triage-SEC-…`) | `schemas.is_valid("triage_answer", json)` | `triage.py:324` |

Rejections return the jsonschema `path` and `message` per error (never the instance).
Accepted content is written to `handoff/responses/<id>.json` verbatim when given as a
string, or as canonical JSON when given as an object — the same file the skill path
writes, so FR-020 parity holds and `AgentMediatedClient._read_response` consumes it.

**Rationale**: validating *more* strictly than the resume path would make the plugin
form reject what the skill form accepts (a parity break); validating less would let
the pipeline discover the defect later. Matching the pipeline's own gate is the only
choice consistent with FR-006 and FR-020 together.
