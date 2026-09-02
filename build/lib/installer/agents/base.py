"""Agent adapter base (FR-021, research.md R1).

The core skill is agent-agnostic: one `SKILL.md` in the Agent Skills open format.
Adapters are thin — they decide *where* the skill lives, add agent-specific
frontmatter, and (for Gemini) translate the format entirely. Supporting a new
agent means adding an adapter, never changing the core.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

FRONTMATTER_DELIMITER = "---"


def split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Split an Agent Skills document into (frontmatter, body)."""
    stripped = text.lstrip()
    if not stripped.startswith(FRONTMATTER_DELIMITER):
        return {}, text
    parts = stripped.split(FRONTMATTER_DELIMITER, 2)
    if len(parts) < 3:
        return {}, text
    front = yaml.safe_load(parts[1]) or {}
    return front, parts[2].lstrip("\n")


def join_frontmatter(front: dict[str, Any], body: str) -> str:
    rendered = yaml.safe_dump(front, sort_keys=False, default_flow_style=False).rstrip()
    return f"{FRONTMATTER_DELIMITER}\n{rendered}\n{FRONTMATTER_DELIMITER}\n\n{body.rstrip()}\n"


class Adapter:
    """Base adapter: writes the core `SKILL.md` unchanged into the agent's path."""

    #: registry key used by ``--ai``
    key: str = ""
    #: human label for messages
    label: str = ""
    #: project-relative directory the agent scans for skills
    skills_subdir: tuple[str, ...] = ()
    #: how the user invokes the installed command
    invocation: str = "/{name}"
    #: entrypoint filename inside the skill directory
    entrypoint_name: str = "SKILL.md"
    #: extra frontmatter merged over the core's
    extra_frontmatter: dict[str, Any] = {}

    # ------------------------------------------------------------- locations

    def skills_dir(self, project_root: Path) -> Path:
        return Path(project_root).joinpath(*self.skills_subdir)

    def skill_dir(self, project_root: Path, name: str) -> Path:
        return self.skills_dir(project_root) / name

    def entrypoint(self, project_root: Path, name: str) -> Path:
        return self.skill_dir(project_root, name) / self.entrypoint_name

    def invocation_hint(self, name: str) -> str:
        return self.invocation.format(name=name)

    # -------------------------------------------------------------- render

    def render_entrypoint(self, core_text: str, name: str) -> str:
        """Transform the core skill document for this agent."""
        front, body = split_frontmatter(core_text)
        front["name"] = name
        merged = {**front, **self.extra_frontmatter}
        return join_frontmatter(merged, body)

    def parse_entrypoint(self, path: Path) -> dict[str, Any]:
        """Read back name/description/body — used by tests and upgrades."""
        front, body = split_frontmatter(Path(path).read_text())
        return {
            "name": front.get("name", ""),
            "description": front.get("description", ""),
            "frontmatter": front,
            "body": body,
        }
