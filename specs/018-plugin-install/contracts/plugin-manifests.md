# Contract: committed plugin files

**Feature**: 018-plugin-install | **Rendered by**: `secscan plugin render` |
**Drift gate**: `secscan plugin check` and `tests/unit/test_plugin_render.py`

The repository root is the plugin root (research R1). Every file below is generated
from `src/skill_core/SKILL.md` (+ `drivers/`), `pipeline.state.TOOL_VERSION` and adapter
metadata; hand edits are overwritten by the next render and fail the drift test.
Placeholders are host-defined and expanded by the host, never by secscan.

## 1. Agent Plugins 1.0.0 (Cursor, GitHub Copilot, Devin)

### `plugin.json`

```json
{
  "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
  "name": "secscan",
  "version": "<TOOL_VERSION>",
  "description": "<SKILL.md frontmatter description, single line>",
  "license": "Apache-2.0",
  "repository": "<repo URL>",
  "keywords": ["security", "sast", "vulnerability", "code-review", "cwe"]
}
```

Constraints (spec §5): `name` matches `^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$` with no `--`/`..`;
no component configuration inline.

### `mcp.json`

```json
{
  "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
  "mcpServers": {
    "secscan": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--project", "${PLUGIN_ROOT}", "--extra", "plugin", "secscan", "mcp"],
      "env": {"UV_PROJECT_ENVIRONMENT": "${PLUGIN_DATA}/venv"},
      "cwd": "${PLUGIN_ROOT}"
    }
  }
}
```

Constraints (spec §7.2.1): exactly the top-level keys `$schema` and `mcpServers`; `type`
present; `command` a bare executable token; `cwd` is `${PLUGIN_ROOT}`; placeholders only
in `args`/`env`/`cwd`.

### `skills/secscan/SKILL.md`

Agent Skills format: the core frontmatter (`name: secscan`, `description`, `license`,
`metadata.version = TOOL_VERSION`) and the core body with the **tools driver**
(`skill_core/drivers/tools.md`) at the `<!-- driver -->` marker. Discovered as
`skills/secscan/` (immediate child of `skills/`; spec §7.1). No `scripts/` — the plugin
form never asks the agent to run a script.

## 2. Claude Code (also Devin's fallback layout)

### `.claude-plugin/plugin.json`

```json
{
  "name": "secscan",
  "version": "<TOOL_VERSION>",
  "description": "<same description>",
  "author": {"name": "<from pyproject authors, if present>"},
  "license": "Apache-2.0",
  "repository": "<repo URL>",
  "keywords": ["security", "sast", "vulnerability", "code-review", "cwe"]
}
```

Only `plugin.json` lives inside `.claude-plugin/`; skills stay at `skills/`.

### `.mcp.json`

```json
{
  "mcpServers": {
    "secscan": {
      "command": "uv",
      "args": ["run", "--project", "${CLAUDE_PLUGIN_ROOT}", "--extra", "plugin", "secscan", "mcp"]
    }
  }
}
```

Invocation after install: `/secscan:secscan` (plugin-namespaced skill) and the MCP
prompt `secscan`; both render the same guidance.

## 3. Gemini CLI

### `gemini-extension.json`

```json
{
  "name": "secscan",
  "version": "<TOOL_VERSION>",
  "description": "<same description>",
  "mcpServers": {
    "secscan": {
      "command": "uv",
      "args": ["run", "--project", "${extensionPath}", "--extra", "plugin", "secscan", "mcp"],
      "cwd": "${extensionPath}"
    }
  }
}
```

### `commands/secscan.toml`

`GeminiAdapter.render_entrypoint(<plugin-form skill text>, "secscan")` — the existing
TOML translation (`description` + multi-line `prompt`, `$ARGUMENTS` → `{{args}}`),
applied to the tools-driver render instead of the shell-driver render. Invocation
`/secscan`.

## 4. Windsurf (MCP registration only)

No committed file. `secscan init --ai windsurf --plugin` merges the stdio entry from
§1 `mcp.json` (with `${PLUGIN_ROOT}` replaced by the absolute plugin root, since
Windsurf defines no placeholder) into `~/.codeium/windsurf/mcp_config.json`. Guidance
reaches the model through tool descriptions and the `secscan` prompt only; the docs
state that the skill form remains the recommended Windsurf path.

## 5. Cross-vendor (`agents`)

No plugin form. `secscan agents` and `secscan init --help` name the generic route: add
the §1 stdio entry to the host's MCP configuration by hand.

## 6. Invariants asserted in tests

| Invariant | Test |
|---|---|
| Each committed file == its render | `tests/unit/test_plugin_render.py` |
| All `version` fields == `TOOL_VERSION`; all descriptions == SKILL.md frontmatter | `test_plugin_render.py` |
| `plugin.json`, `mcp.json` validate against vendored `tests/fixtures/agent_plugins/{plugin,mcp}.schema.json` (1.0.0) | `tests/contract/test_plugin_manifests.py` |
| `mcp.json` top-level keys are exactly `$schema`, `mcpServers` | `test_plugin_manifests.py` |
| `.mcp.json` / `gemini-extension.json` / `mcp.json` server args differ **only** in the root placeholder | `test_plugin_manifests.py` |
| `skills/secscan/SKILL.md` body with the driver section removed == skill-form body with the driver section removed, for every adapter | `test_plugin_render.py` |
| No committed plugin file contains an absolute path or a credential-shaped token (redaction sweep) | `tests/contract/test_artifact_redaction.py` (extended glob) |
| Skill-form render for every adapter is byte-identical before/after the SKILL.md driver split | `tests/integration/test_install_matrix.py` golden files |

## 7. What cannot be asserted in CI

Whether each host actually loads the layout it documents. `quickstart.md` §5 gives the
one-line manual check per host; results are recorded in the PR description, not in
tests.
