# Data Model: Plugin Install

**Feature**: 018-plugin-install | **Date**: 2026-09-18

Everything here is either (a) a new non-artifact file, (b) a user-level record, (c) an
in-memory result shape returned over MCP, or (d) a committed, rendered plugin file.
**No existing artifact schema changes**; `report.json`, `usage.json`, `state.json`
stage records and the handoff request/response files are untouched (FR-020).

## 1. Install form (enum)

| Value | Meaning | Where recorded |
|---|---|---|
| `skill` | Payload copied into the project (today's model) | project `.<host>/skills/secscan/.install-manifest.json` (unchanged) |
| `plugin` | Tool provider registered in the engineer's user-level host settings | user install record (§3) |

## 2. Plugin descriptor (per `Adapter`, static data)

Added to each adapter class in `installer/agents/*.py`; consumed by `installer/plugin.py`.

| Field | Type | Values / notes |
|---|---|---|
| `plugin_layout` | enum | `agent-plugins` (cursor, copilot, devin), `claude` (claude, devin fallback), `gemini`, `mcp-only` (windsurf), `none` (agents) |
| `user_mcp_config` | path template or `None` | e.g. `~/.cursor/mcp.json`, `~/.codeium/windsurf/mcp_config.json`, `~/.copilot/mcp-config.json`, `~/.config/devin/mcp_config.json` (`%APPDATA%\devin\mcp_config.json` on Windows), `~/.gemini/settings.json` (fallback only) |
| `register_command` | list[str] template or `None` | `["claude","mcp","add-json","--scope","user","secscan","{json}"]`; `["gemini","extensions","install","{root}"]` |
| `install_hint` | str | host command printed for the full plugin (e.g. `devin plugins install --local {root}`; Claude `claude --plugin-dir {root}`) |
| `root_placeholder` | str | `${PLUGIN_ROOT}` / `${CLAUDE_PLUGIN_ROOT}` / `${extensionPath}` — used only in rendered files |

Validation: exactly one of `user_mcp_config` / `register_command` is the primary
mechanism for hosts with `plugin_layout != none`; Gemini declares both (CLI primary,
file fallback). Asserted by `tests/unit/test_plugin_register.py`.

## 3. User install record

Path: `${XDG_CONFIG_HOME:-~/.config}/secscan/plugin-installs.json`
(`%APPDATA%\secscan\plugin-installs.json` on Windows). Canonical JSON, sorted keys,
trailing newline (`store.canonical_json`). Not an artifact; never inside a project.

```json
{
  "record_version": 1,
  "installs": {
    "cursor": {
      "form": "plugin",
      "tool_version": "0.1.0",
      "plugin_root": "/Users/x/src/secscan",
      "registered_in": "/Users/x/.cursor/mcp.json",
      "registered_via": "json-merge",
      "installed_at": "2026-09-18T10:00:00Z"
    }
  }
}
```

| Field | Type | Rule |
|---|---|---|
| `record_version` | int | `1`; additive changes only |
| `installs.<host>` | object | one entry per host key (`installer.agents.supported()`) |
| `form` | `"plugin"` | the skill form is never recorded here |
| `tool_version` | str | `TOOL_VERSION` at install time |
| `plugin_root` | absolute path | the checkout the launch reference points at |
| `registered_in` | path or command string | what was written / run (FR-013) |
| `registered_via` | `json-merge` \| `host-cli` | |
| `installed_at` | RFC 3339 UTC | wall clock is allowed here — this is not an artifact |

Upgrade semantics (FR-016): re-running `init --plugin` for a host compares
`tool_version`; downgrade → `DowngradeRefused` unless `--force` (reusing
`installer/upgrade.py`); config-schema change is flagged by the same `plan_upgrade`
logic evaluated against the *project's* `.secscan/config.yaml` at first `secscan_init`
of that project (the plugin has no project manifest to compare, so the check moves to
init time and its note is returned in the `secscan_init` result).

## 4. Run lock (`.secscan/run.lock`)

Not an artifact: no envelope, not `*.json`, removed on exit, excluded from the
determinism comparison and included in the redaction sweep (it contains no content
that could carry a credential, but the sweep is the cheap proof).

```json
{"pid": 4242, "started_at": 1758190000.0, "scan_id": "20260918T100000Z-ab12cd",
 "driver": "plugin", "tool_version": "0.1.0"}
```

| Field | Rule |
|---|---|
| `pid` | acquiring process; a lock whose pid is not alive is stale and reclaimed |
| `driver` | `cli` \| `plugin` \| `delegated` (plugin running the project's pinned payload — the subprocess writes `cli`; the parent does not take a second lock) |

State transitions: `absent → held (O_EXCL create) → absent (finally)`. `held` with a live
pid → `secscan_run` returns `locked`, `cmd_run` exits 1.

## 5. Scan state as reported by `secscan_status`

A read-only projection over existing state (`ArtifactStore.stage_summary`,
handoff directories, reports, the lock, and `detect_installs`). No new persisted field.

```json
{
  "workdir": "/abs/project", "configured": true, "scan_id": "…",
  "stages": {"discover_repo": "done", "segment_analysis": "running", "...": "…"},
  "handoff": {"pending": 3, "answered": 1},
  "lock": null | {"pid": 4242, "driver": "cli", "started_at": …},
  "latest_report": "/abs/project/.secscan/reports/<id>.md" | null,
  "driver": {"form": "plugin" | "skill", "tool_version": "0.1.0",
             "plugin_version": "0.1.0", "delegated": false}
}
```

## 6. Operation result envelope (all tools)

Every tool returns a JSON object with a closed `state` vocabulary; the schemas live in
[contracts/mcp-tools.md](contracts/mcp-tools.md).

| `state` | Returned by | Meaning | CLI equivalent |
|---|---|---|---|
| `ok` | all | settled successfully | exit 0 |
| `not_ready` | `init`, `status` | project not initialised / environment check failed | exit 2 |
| `awaiting_reasoning` | `run` | pending request ids listed; call `list_requests`/`get_request` | exit 3 |
| `in_progress` | `run` | deadline reached at a checkpoint; call `run` again | — (new) |
| `locked` | `run` | another scan holds the root's lock | exit 1 (new message) |
| `report_defect` | `run` | report published with quarantined sections | exit 4 |
| `endpoint_failed` | `run` | provider refused after retries; re-run resumes | exit 1 |
| `rejected` | `submit_answer` | validation errors listed; nothing written | — |
| `error` | all | config/argument error, corrupt delegated install, unwritable path | exit 1 |

Common fields: `state`, `tool_version`, `driver` (§5), optional `message` (redacted),
optional `summary` (the three frozen stdout lines, verbatim, for `run`).

## 7. Reasoning request / answer (unchanged)

| File | Writer | Shape |
|---|---|---|
| `.secscan/handoff/requests/<id>.json` | pipeline (`AgentMediatedClient._write_request`) | `{request_id, stage, escalation_level, estimated_tokens, budget, instructions, prompt, context_packet}` — returned verbatim by `secscan_get_request` |
| `.secscan/handoff/responses/<id>.json` | agent (skill path) **or** `secscan_submit_answer` | answer content only — findings JSON, `flow_answer`, or `triage_answer` |

`request_id` grammar (existing): `<segment-id>-l<level>` \| `flow-<hash>-l<level>` \|
`triage-SEC-NNNN`; the `stage` field selects the validator (research R12).

## 8. Rendered plugin files (committed)

| File | Rendered from | Host(s) |
|---|---|---|
| `plugin.json` | `TOOL_VERSION`, SKILL.md frontmatter (`name`, `description`, `license`), repo URL | cursor, copilot, devin |
| `mcp.json` | launch reference (research R11) with `${PLUGIN_ROOT}`/`${PLUGIN_DATA}` | cursor, copilot, devin |
| `.claude-plugin/plugin.json` | same metadata | claude, devin (fallback) |
| `.mcp.json` | launch reference with `${CLAUDE_PLUGIN_ROOT}` | claude, devin |
| `gemini-extension.json` | metadata + launch reference with `${extensionPath}` | gemini |
| `commands/secscan.toml` | `GeminiAdapter.render_entrypoint(plugin skill text)` | gemini |
| `skills/secscan/SKILL.md` | core body + `drivers/tools.md` | all skill-reading hosts |

Invariants (asserted by `tests/unit/test_plugin_render.py` and
`tests/contract/test_plugin_manifests.py`): every `version` == `TOOL_VERSION`; every
`description` == SKILL.md frontmatter description; `plugin.json`/`mcp.json` validate
against the vendored Agent Plugins 1.0.0 schemas (`tests/fixtures/agent_plugins/`);
`mcp.json` has exactly the top-level keys `$schema` and `mcpServers` (spec §7.2.1);
`skills/secscan/SKILL.md` body minus the driver section == skill-form body minus the
driver section.

## 9. Configuration (additive)

| Key | Type | Default | Validation | Env override |
|---|---|---|---|---|
| `plugin.run_bound_s` | int | `45` | `5 <= v <= 3600` | `SECSCAN_PLUGIN_RUN_BOUND_S` |

Follows the `output.level` precedent (feature 011): strict `validate_config`, one
`Config` property, documented in `docs/configuration.md`.

## 10. Skill source split

| Path | Content | Consumers |
|---|---|---|
| `skill_core/SKILL.md` | frontmatter + core body with one `<!-- driver -->` marker | both renders |
| `skill_core/drivers/shell.md` | today's "Run the pipeline with the scan command…" text, verbatim | skill form (`Adapter.render_entrypoint`) |
| `skill_core/drivers/tools.md` | tool-call driver text | plugin form (`installer/plugin.py`), MCP `secscan` prompt |

Golden test: rendering the skill form for every adapter before and after the split
yields byte-identical files (the split is a refactor with zero output change).
