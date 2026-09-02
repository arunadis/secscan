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
    extra_frontmatter = {
        # Discoverable by the model, and explicitly invocable by the user.
        "triggers": ["user", "model"],
        "argument-hint": "[path-to-scan] [--profile quick|full|audit]",
    }
