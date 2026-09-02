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
