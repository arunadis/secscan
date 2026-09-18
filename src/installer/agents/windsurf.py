"""Windsurf (Cascade) adapter — `.windsurf/skills/<name>/SKILL.md`."""

from __future__ import annotations

from installer.agents.base import Adapter


class WindsurfAdapter(Adapter):
    key = "windsurf"
    label = "Windsurf (Cascade)"
    skills_subdir = (".windsurf", "skills")
    invocation = "@{name}"
    # Plugin form (feature 018): Windsurf has no installable plugin format; only the
    # MCP tool provider is registered (user-level, the only scope Windsurf reads).
    plugin_layout = "mcp-only"
    user_mcp_config = "~/.codeium/windsurf/mcp_config.json"
