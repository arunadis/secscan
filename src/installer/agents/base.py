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
#: Feature 018: the one paragraph that differs between install forms — how the
#: pipeline is invoked — is an include in the core body, resolved per form.
DRIVER_MARKER = "<!-- driver -->"
DRIVERS = ("shell", "tools")
_SKILL_CORE = Path(__file__).resolve().parent.parent.parent / "skill_core"


def skill_source_text() -> str:
    return (_SKILL_CORE / "SKILL.md").read_text()


def driver_text(driver: str) -> str:
    if driver not in DRIVERS:
        raise ValueError(f"unknown skill driver {driver!r}; expected one of {DRIVERS}")
    return (_SKILL_CORE / "drivers" / f"{driver}.md").read_text()


def resolve_driver(core_text: str, driver: str) -> str:
    """Replace the driver marker with the named driver text (exactly once)."""
    if core_text.count(DRIVER_MARKER) != 1:
        raise ValueError("SKILL.md must contain exactly one driver marker")
    return core_text.replace(DRIVER_MARKER, driver_text(driver).rstrip("\n"))


def render_skill(driver: str, core_text: str | None = None) -> str:
    """The core skill document with the given driver resolved (frontmatter intact)."""
    return resolve_driver(core_text if core_text is not None else skill_source_text(), driver)


def strip_driver(text: str) -> str:
    """The body with whichever driver text it carries removed — for parity tests."""
    for driver in DRIVERS:
        text = text.replace(driver_text(driver).rstrip("\n"), DRIVER_MARKER)
    return text


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

    #: Which driver the skill form renders (feature 018): the shell driver, so a
    #: per-project install keeps instructing the shell commands it always did.
    driver: str = "shell"

    # ------------------------------------------------- plugin form (feature 018)
    #: Which committed plugin layout this host loads: ``agent-plugins`` (root
    #: plugin.json + mcp.json), ``claude`` (.claude-plugin/ + .mcp.json), ``gemini``
    #: (gemini-extension.json), ``mcp-only`` (no plugin format; MCP registration
    #: only) or ``none`` (no plugin form).
    plugin_layout: str = "none"
    #: User-level MCP configuration file the installer merges ``mcpServers.secscan``
    #: into (``~`` expands to the user's home). ``None`` when the host's file is
    #: host-owned and a CLI must be used instead.
    user_mcp_config: str | None = None
    #: Host CLI invocation that registers the tool provider at user level.
    #: ``{json}`` is replaced with the stdio server entry, ``{root}`` with the plugin
    #: root. ``None`` when the JSON merge is the mechanism.
    register_command: tuple[str, ...] | None = None
    #: Command the engineer runs to load the *full* plugin (skill + tools) from the
    #: checkout; printed after registration.
    install_hint: str | None = None
    #: Placeholder the host expands to the plugin root in committed MCP entries.
    root_placeholder: str = "${PLUGIN_ROOT}"

    @property
    def install_forms(self) -> tuple[str, ...]:
        if self.plugin_layout == "none":
            return ("skill",)
        return ("skill", "plugin")

    def render_entrypoint(self, core_text: str, name: str) -> str:
        """Transform the core skill document for this agent."""
        if DRIVER_MARKER in core_text:
            core_text = resolve_driver(core_text, self.driver)
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
