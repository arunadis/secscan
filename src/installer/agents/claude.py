"""Claude Code adapter — `.claude/skills/<name>/SKILL.md`.

Docs: https://code.claude.com/docs/en/skills
"""

from __future__ import annotations

from installer.agents.base import Adapter


class ClaudeAdapter(Adapter):
    key = "claude"
    label = "Claude Code"
    skills_subdir = (".claude", "skills")
    invocation = "/{name}"
    # Plugin form (feature 018): `.claude-plugin/plugin.json` + `.mcp.json` at the
    # checkout root. The user-level MCP file (`~/.claude.json`) is host-owned, so
    # registration goes through the host CLI.
    plugin_layout = "claude"
    register_command = ("claude", "mcp", "add-json", "--scope", "user", "secscan", "{json}")
    install_hint = "claude --plugin-dir {root}"
    root_placeholder = "${CLAUDE_PLUGIN_ROOT}"
