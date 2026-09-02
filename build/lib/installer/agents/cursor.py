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
    # Cursor honours model auto-invocation; scanning is expensive, so require an
    # explicit request from the user.
    extra_frontmatter = {"disable-model-invocation": True}
