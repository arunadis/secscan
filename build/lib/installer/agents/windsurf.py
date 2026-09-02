"""Windsurf (Cascade) adapter — `.windsurf/skills/<name>/SKILL.md`."""

from __future__ import annotations

from installer.agents.base import Adapter


class WindsurfAdapter(Adapter):
    key = "windsurf"
    label = "Windsurf (Cascade)"
    skills_subdir = (".windsurf", "skills")
    invocation = "@{name}"
