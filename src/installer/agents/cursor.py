"""Cursor adapter — `.cursor/skills/<name>/SKILL.md`.

Docs: https://cursor.com/docs/skills
"""

from __future__ import annotations

from installer.agents.base import Adapter


class CursorAdapter(Adapter):
    key = "cursor"
    label = "Cursor"
    skills_subdir = (".cursor", "skills")
    invocation = "/{name}"
    # Plugin form (feature 018): Cursor loads the Agent Plugins 1.0.0 root manifest.
    plugin_layout = "agent-plugins"
    user_mcp_config = "~/.cursor/mcp.json"
    install_hint = "Cursor: Settings > Plugins > install from path {root}"
    # Cursor honours model auto-invocation; scanning is expensive, so require an
    # explicit request from the user.
    extra_frontmatter = {"disable-model-invocation": True}
