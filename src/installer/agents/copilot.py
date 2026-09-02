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
