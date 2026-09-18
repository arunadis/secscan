"""GitHub Copilot adapter — `.github/skills/<name>/SKILL.md`.

Docs: https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills
"""

from __future__ import annotations

from installer.agents.base import Adapter


class CopilotAdapter(Adapter):
    key = "copilot"
    label = "GitHub Copilot"
    skills_subdir = (".github", "skills")
    invocation = "/{name}"
    extra_frontmatter = {"license": "Apache-2.0"}
    # Plugin form (feature 018): Copilot (VS Code, CLI, app) loads Agent Plugins 1.0.0.
    plugin_layout = "agent-plugins"
    user_mcp_config = "~/.copilot/mcp-config.json"
    install_hint = "install the Agent Plugin from {root} in Copilot"
