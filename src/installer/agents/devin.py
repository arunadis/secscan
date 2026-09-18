"""Devin adapter — `.devin/skills/<name>/SKILL.md`.

Docs: https://docs.devin.ai/cli/extensibility/skills/creating-skills
"""

from __future__ import annotations

from installer.agents.base import Adapter


class DevinAdapter(Adapter):
    key = "devin"
    label = "Devin"
    skills_subdir = (".devin", "skills")
    invocation = "/{name}"
    # Plugin form (feature 018): Devin loads the Claude layout (fallback) and the
    # Agent Plugins root manifest; `devin plugins install` delivers the full plugin.
    plugin_layout = "agent-plugins"
    user_mcp_config = "~/.config/devin/mcp_config.json"
    install_hint = "devin plugins install --local {root}"
    extra_frontmatter = {
        # Discoverable by the model, and explicitly invocable by the user.
        "triggers": ["user", "model"],
        "argument-hint": "[path-to-scan] [--profile quick|full|audit]",
    }
