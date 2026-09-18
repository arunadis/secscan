# Implementation Plan: Plugin Install

**Branch**: `018-plugin-install` | **Date**: 2026-09-18 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/018-plugin-install/spec.md`

## Summary

secscan reaches an agent today by copying the skill payload into a per-agent directory
inside the scanned project (`installer/core.py`, seven `Adapter`s). This feature adds a
second, additive **plugin form** without touching the skill form:

1. **Tool provider** — a stdio MCP server (`secscan mcp`, module `pipeline/mcp_server.py`)
   built on the official `mcp` Python SDK, shipped as an optional extra
   `secscan[plugin]`. It exposes seven tools (`secscan_init`, `secscan_run`,
   `secscan_status`, `secscan_list_requests`, `secscan_get_request`,
   `secscan_submit_answer`, `secscan_report`), one prompt (`secscan`, the rendered skill
   guidance) and read-only resources for the shipped prompts/schemas. Every tool takes
   a required `workdir`; the server holds no state (research R3, spec Q2/Q4).
   `secscan_run` calls the existing `run_scan` with a new cooperative **deadline**: the
   driver raises a new `ScanPaused` before the next checkpointed stage or at a
   batch-poll iteration once the bound elapses (never between segments — those
   re-drive on resume, R4 as corrected during implementation), the tool returns
   `state: "in_progress"`, and the next call resumes from the existing checkpoints.
   A pause is only allowed after the call completed one non-reused stage, so every
   call makes progress. Progress reaches the host
   through a new `McpSink` plugged into the existing `ProgressReporter` (R6). Concurrent
   runs on one root are refused by a `.secscan/run.lock` honoured by the CLI too (R5).
2. **Plugin package** — the repository root becomes an installable plugin in the open
   **Agent Plugins 1.0.0** format (`plugin.json` + `mcp.json` + `skills/secscan/SKILL.md`,
   loaded natively by Cursor, GitHub Copilot and Devin) plus the two vendor layouts that
   do not read it: `.claude-plugin/plugin.json` + `.mcp.json` (Claude Code; Devin honours
   it as a fallback as well) and `gemini-extension.json` + `commands/secscan.toml`
   (Gemini CLI). Windsurf has no git-installable plugin format; its plugin form is the
   user-level MCP registration written by the installer (R1, R2). All committed plugin
   files are **rendered** from the single skill source and `TOOL_VERSION` by
   `secscan plugin render`, and a test fails when they are stale (R8; FR-018).
3. **Installer** — `secscan init --ai <host> --plugin` registers the tool provider in
   the host's *user-level* settings (JSON merge into the host's MCP config file, or the
   host's own CLI where the file is host-owned), records the install in a user-level
   record, and writes nothing into the project (R7; FR-013/014). Without `--plugin` the
   installer is byte-for-byte today's behaviour. When a project already carries a skill
   install, the tool provider delegates to that pinned payload by subprocess and reports
   its version (R9; FR-015).

## Technical Context

**Language/Version**: Python 3.11+ (constitution technology constraint; `mcp` requires ≥3.10)

**Primary Dependencies**: existing (`click`, `pyyaml`, `jsonschema`, tree-sitter wheels) plus **one new optional extra** `plugin = ["mcp>=2.1,<3"]` — the official MCP Python SDK (2.2.0 released 2026-09-07, 2.1.1 on 2026-08-25; pure-Python wheels). Chosen over a hand-rolled JSON-RPC server because the protocol now spans two negotiation generations (legacy `initialize` handshake and the 2026-07-28 per-request-metadata/`server/discover` model) and conformance drift is a real risk (research R3). The base install and the copied skill payload gain **no** dependency (FR-023).

**Storage**: everything under the scan root's `.secscan/` exactly as today. New non-artifact file `.secscan/run.lock` (removed on exit; not `*.json`, so outside the determinism comparison like `scan.log`). New user-level record `${XDG_CONFIG_HOME:-~/.config}/secscan/plugin-installs.json` (`%APPDATA%\secscan\` on Windows). Committed, rendered plugin files at the repository root (see Project Structure).

**Testing**: pytest — unit (tool handlers called in-process with a fake reporter; deadline/pause with injected clock; lock acquisition; `McpSink`; registration JSON merge under a redirected `HOME`), integration (stdio round-trip through the SDK client against a subprocess server over the existing fixtures; skill-vs-plugin artifact parity reusing `test_determinism._artifacts`; delegation to a project skill install; `--plugin` install matrix; rendered-plugin-files freshness), contract (tool input/output JSON schemas in `contracts/`; `plugin.json`/`mcp.json` validated against a vendored copy of the Agent Plugins 1.0.0 schemas — no network in tests), ruff.

**Target Platform**: local developer machine (macOS/Linux; Windows paths handled for the user-level record and host config locations), launched by an agent host as a stdio subprocess

**Project Type**: CLI security scanner + agent skill, gaining an MCP tool-provider surface and plugin packaging

**Performance Goals**: `secscan_run` returns within `plugin.run_bound_s` (default 45 s) plus at most one un-checkpointable stage; tool-call overhead per operation negligible (one config load + one `ArtifactStore`); `secscan_get_request` is a file read; server start-up < 1 s after environment is provisioned

**Constraints**: artifacts byte-identical between plugin-form and skill-form runs (FR-020, SC-003); no stderr writes from the server during a scan (progress → MCP notifications + `scan.log`); no network from the server (FR-021); stdout summary lines and CLI exit codes unchanged (FR-010); answers written only to `handoff/responses/` (FR-006); no operation reads arbitrary project files (FR-022); nothing written into the project by a plugin install (FR-014); no new dependency for the skill form (FR-023)

**Scale/Scope**: one new pipeline module (`mcp_server.py`, ~500 lines incl. schemas), one new installer module (`plugin.py`: render + register + user record), edits to `run.py` (deadline + lock + `ScanPaused`), `progress.py` (sink), `state.py` (lock helpers), `scan_cli.py` (lock refusal), `installer/cli.py` (`mcp`, `plugin render|check`, `init --plugin`), `installer/agents/*` (per-host registration table), `config/loader.py` (`plugin.run_bound_s`), `skill_core/SKILL.md` split into core body + two driver sections; ~9 committed plugin files; docs in `README.md`, `docs/agent-integration.md`, `docs/cli-reference.md`, `docs/configuration.md`, `docs/artifacts.md`, `docs/getting-started.md`, `AGENTS.md`

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Evaluation | Result |
|-----------|-----------|--------|
| I. Determinism Before Intelligence | The tool provider is a transport, not a stage: every operation calls the same `run_scan`, `run_init`, `latest_report` the CLI calls, with the same arguments. The deadline is checked only at boundaries that already persist and resume (checkpointed stage starts, batch-poll iterations) and never alters what a unit writes; where a `run` happens to stop is not recorded in any artifact (`state.json` is already excluded from the two-run comparison). `run.lock` is not an artifact. Rendered plugin files are pure functions of `SKILL.md` + `TOOL_VERSION` and a freshness test enforces it. The server opens no network connection; `uv run` resolving the `[plugin]` extra is an *install-time* action the operator performs (documented `secscan init --plugin` pre-provisions it), never a scan-time fetch. | PASS |
| II. Context Is a Managed Resource | `secscan_get_request` returns the on-disk request document verbatim — the packet was built and budget-checked by `AgentMediatedClient.run` (`request.budget.check(...)`) before it was written. The tool adds nothing. No partitioning, escalation or budget logic changes. | PASS |
| III. Secrets Never Reach a Model | The only content the server hands to a host is: request documents (already redacted), answer-validation errors (schema paths and messages, never document excerpts — errors are rendered with the jsonschema `path`/`validator`, not the failing `instance`), rendered progress lines (the same strings the redaction sweep already covers via `scan.log`), report renderings (already redacted), and `status` counts/paths. `secscan_report` and `secscan_get_request` are the only operations that return document bodies; neither can address a file outside `.secscan/handoff/requests/` or `.secscan/reports/`. Exception text in tool errors passes through `Redactor` exactly as `cmd_run` does. Registration writes carry only a command line — never credentials — and the user record holds form/version/host only. The contract redaction sweep is extended to every tool result produced in the integration lifecycle test. | PASS |
| IV. Evidence Over Assertion | `secscan_submit_answer` performs the same acceptance test the pipeline performs on resume (`FindingNormalizer.parse` for segment answers, `flow_answer` / `triage_answer` schema for the others) and refuses *before* writing; what it writes is byte-identical to what the skill path would have written, so the downstream evidence gates (location resolution, citation re-verification) run unchanged. Tool results expose the CLI's settled outcomes as explicit states (FR-010) rather than a new judgement. | PASS |
| V. Honest Uncertainty | New explicit states, never silence: `in_progress` (deadline) names the checkpoint reached; `locked` names the running scan; `delegated` names the pinned payload version and, when the pinned payload predates the bounded-run capability, declares `bound: "unsupported by pinned payload vX"` instead of pretending to honour it; a corrupt project install is reported, never silently bypassed. Windsurf's plugin form is documented as MCP-registration-only (no skill/prompt surface) rather than claimed equivalent. | PASS |
| VI. Observe, Never Attack | New project-level writes: none beyond today's (`.secscan/`, optional `.gitignore` line). Plugin install writes user-level host settings and the user record only. The tool provider runs subprocesses only for (a) the same external scanners the CLI already runs and (b) delegation to the project's own pinned payload — both read-only against the project (the existing manifest/lockfile hash check covers both forms in the parity test). | PASS |

**Development Workflow & Quality Gates**: additive schemas only (report/usage untouched; tool I/O schemas are new documents); `plugin.run_bound_s` is one additive, strictly validated config key; extensibility as data preserved (per-host registration locations are a table on the adapters, no pipeline change); honest documentation reconciled in the same change set (README Status/Roadmap/install/exit codes, `docs/`, `AGENTS.md` naming table gains the plugin surfaces).

No violations. Complexity Tracking is empty.

**Post-implementation note (2026-09-18)**: two design refinements surfaced under test and
are recorded in research R4/R9: (1) per-segment/flow/packet deadline boundaries were
dropped — the analysis stages re-drive from their first unit on resume, so pausing
there livelocked with an accelerated clock; the boundaries are checkpointed stages and
batch polls, with a guaranteed-progress rule; (2) the serving layer was split into
`pipeline/mcp_app.py` (excluded from the payload) because the copied payload must not
import `installer` or `mcp` — `mcp_server.py` locates project skill installs by manifest
path instead of via `installer.core`.

**Post-design re-check (2026-09-18)**: Phase 0/1 artifacts hold the gates. The data model
(data-model.md) introduces no artifact field that varies by install form — `run.lock` and
the user install record are outside `.secscan/**/*.json`, and the report is untouched.
The tool contract (contracts/mcp-tools.md) has no operation that accepts a file path other
than `workdir`; `secscan_get_request` resolves ids against the `handoff/requests` listing,
so path traversal is structurally impossible (R10). `submit_answer` validation errors are
rendered without the offending instance (III). The `ScanPaused` boundary set is
enumerated (R4) and each boundary is one the pipeline already persists behind. Rendered
plugin files derive from `skill_core/SKILL.md` + `skill_core/drivers/*.md` +
`TOOL_VERSION` through `installer/plugin.py`, and `tests/unit/test_plugin_render.py`
fails on drift (R8). Delegation (R9) always runs the pinned payload's own
`pipeline.scan_cli` — the plugin's engine never touches a project that carries a skill
install.

## Project Structure

### Documentation (this feature)

```text
specs/018-plugin-install/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/
│   ├── mcp-tools.md         # tool/prompt/resource surface, result states, JSON schemas
│   ├── plugin-manifests.md  # committed plugin files, per-host layout, launch reference
│   └── cli-plugin.md        # `secscan mcp`, `secscan plugin render|check`, `init --plugin`,
│                            #   lock semantics, user install record
├── checklists/requirements.md
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created by /speckit-plan)
```

### Source Code (repository root)

```text
plugin.json                    # NEW (rendered): Agent Plugins 1.0.0 manifest — Cursor, Copilot, Devin
mcp.json                       # NEW (rendered): Agent Plugins MCP config, ${PLUGIN_ROOT} launch
.claude-plugin/plugin.json     # NEW (rendered): Claude Code manifest (Devin fallback)
.mcp.json                      # NEW (rendered): Claude Code MCP config, ${CLAUDE_PLUGIN_ROOT}
gemini-extension.json          # NEW (rendered): Gemini CLI extension, ${extensionPath}
commands/secscan.toml          # NEW (rendered): Gemini command (GeminiAdapter.render_entrypoint)
skills/secscan/SKILL.md        # NEW (rendered): plugin-form skill = core body + tools driver

src/
├── pipeline/
│   ├── mcp_server.py          # NEW: FastMCP app; 7 tools, 1 prompt, resources; result states;
│   │                          #   McpSink wiring; delegation to a project skill install;
│   │                          #   `--oneshot <tool> <json>` entry (no `mcp` import) used by
│   │                          #   delegation into a pinned payload of this version or newer
│   ├── run.py                 # run_scan(deadline=..., driver=...); deadline checks before
│   │                          #   checkpointed stages (+ batch polls in batch_runner/triage),
│   │                          #   guaranteed-progress flag; run.lock acquire/release
│   ├── batch_runner.py        # poll loop honours the injected deadline (raises ScanPaused)
│   ├── progress.py            # McpSink (Sink protocol) — no behavioural change to others
│   ├── state.py               # RUN_LOCK_NAME, acquire_run_lock/release/read (stale-pid aware)
│   ├── scan_cli.py            # cmd_run: locked → EXIT_ERROR with the running scan named;
│   │                          #   cmd_status: lock + handoff shown; summary lines unchanged
│   ├── answers_io.py          # NEW: validate_answer / write_response / submit / list_requests
│   └── mcp_app.py             # NEW: MCP serving layer (SDK import, tool registration,
│                              #   prompt + resources); excluded from the copied payload
├── installer/
│   ├── cli.py                 # `mcp` command; `plugin render|check`; `init --plugin`; help
│   ├── plugin.py              # NEW: render committed plugin files from the single source;
│   │                          #   per-host user-level registration (JSON merge / host CLI);
│   │                          #   user install record
│   ├── core.py                # detect_installs unchanged; InstallResult.form; help table
│   └── agents/*.py            # per-host: user_mcp_config path OR register_command; plugin
│                              #   layout key (agent-plugins | claude | gemini | mcp-only)
├── config/loader.py           # plugin.run_bound_s (int, 5..3600, default 45), env override
└── skill_core/
    ├── SKILL.md               # core body; "Run the pipeline" section becomes an include marker
    └── drivers/
        ├── shell.md           # today's shell-command driver text (skill form)
        └── tools.md           # NEW: tool-call driver text (plugin form)

pyproject.toml                 # [project.optional-dependencies] plugin = ["mcp>=2.1,<3"];
                               # package-data: skill_core/drivers/*.md

tests/
├── unit/
│   ├── test_mcp_server.py         # NEW: handlers in-process; result states; id resolution;
│   │                              #   error redaction; prompt/resources
│   ├── test_run_deadline.py       # NEW: ScanPaused at each boundary with injected clock;
│   │                              #   CLI path never pauses
│   ├── test_run_lock.py           # NEW: acquire/refuse/stale reclaim; CLI refusal message
│   ├── test_answers_io.py         # NEW: validation per kind, rejection leaves no file,
│   │                              #   accepted file byte-identical to skill-path write
│   ├── test_progress.py           # extend: McpSink
│   ├── test_plugin_render.py      # NEW: rendered files == committed files; version == TOOL_VERSION
│   ├── test_plugin_register.py    # NEW: JSON merge idempotent, preserves other servers,
│   │                              #   HOME redirected; unwritable → error names path
│   └── test_config_plugin.py      # NEW: plugin.run_bound_s validation/env
├── integration/
│   ├── test_mcp_lifecycle.py      # NEW: stdio client ↔ subprocess server: init→run→requests→
│   │                              #   submit→run→report on fixture; redaction sweep of results
│   ├── test_plugin_parity.py      # NEW: skill-driven vs tool-driven artifacts byte-identical
│   ├── test_plugin_delegation.py  # NEW: project skill install present → delegated state,
│   │                              #   pinned version reported; corrupt install → error
│   ├── test_install_matrix.py     # extend: --plugin per host, nothing written in project
│   └── test_installed_payload.py  # extend: skill form unchanged with plugin extra absent
└── contract/
    ├── test_mcp_tool_schemas.py   # NEW: tool I/O documents validate against contracts/ schemas
    └── test_plugin_manifests.py   # NEW: plugin.json/mcp.json vs vendored Agent Plugins schemas

docs/
├── agent-integration.md   # skill form vs plugin form; per-host install table; precedence
├── cli-reference.md       # mcp, plugin render|check, init --plugin, lock refusal
├── configuration.md       # plugin.run_bound_s, SECSCAN_PLUGIN_RUN_BOUND_S
├── artifacts.md           # run.lock (not an artifact)
├── getting-started.md     # "install as a plugin" path
├── README.md              # Status, install section, roadmap, exit codes unchanged
└── AGENTS.md              # naming table: plugin surfaces; `[plugin]` extra; render check
```

**Structure Decision**: single project, existing layout. The MCP surface is one new
`pipeline/mcp_server.py` module that calls the same public functions the CLI calls; the
plugin packaging is one new `installer/plugin.py` module plus rendered files at the
repository root (a plugin root must be the git checkout root for install-by-URL to work
on every host). No new package. One new *optional* dependency group.

## Complexity Tracking

No constitution violations to justify.
