"""Plugin form of secscan (feature 018): committed plugin files and user-level registration.

Two halves:

* **render** — the repository root is an installable plugin in the open Agent
  Plugins 1.0.0 format (``plugin.json`` + ``mcp.json`` + ``skills/secscan/SKILL.md``)
  plus the two vendor layouts that do not read it (Claude Code, Gemini CLI). Every
  file is a pure function of the single skill source, ``TOOL_VERSION`` and adapter
  metadata; ``check()`` reports drift and a unit test fails on it (FR-018).
* **register** — ``secscan init --ai <host> --plugin`` records the tool provider in
  the engineer's *user-level* host settings (JSON merge, or the host CLI where the
  file is host-owned), records the install in a user-level record, and writes
  nothing into the project (FR-013, FR-014, FR-016).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from installer.agents import ADAPTERS, Adapter, get_adapter
from installer.agents.base import render_skill, split_frontmatter
from installer.agents.gemini import GeminiAdapter
from installer.upgrade import DowngradeRefused, version_tuple
from pipeline.state import (
    PLUGIN_INSTALLS_RECORD,
    TOOL_VERSION,
    canonical_json,
    user_config_dir,
)

PLUGIN_NAME = "secscan"
REPOSITORY_URL = "https://github.com/arunadis/secscan"
KEYWORDS = ["security", "sast", "vulnerability", "code-review", "cwe"]
AGENT_PLUGINS_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
AGENT_PLUGINS_MCP_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"

#: Committed plugin files, relative to the plugin (repository) root.
RENDERED_FILES: tuple[str, ...] = (
    "plugin.json",
    "mcp.json",
    ".claude-plugin/plugin.json",
    ".mcp.json",
    "gemini-extension.json",
    "commands/secscan.toml",
    "skills/secscan/SKILL.md",
)


class PluginError(RuntimeError):
    """Raised when the plugin form cannot be rendered or registered."""


# ------------------------------------------------------------------- render


def _metadata() -> dict[str, Any]:
    front, _body = split_frontmatter(render_skill("tools"))
    description = " ".join(str(front.get("description", "")).split())
    return {
        "name": PLUGIN_NAME,
        "version": TOOL_VERSION,
        "description": description,
        "license": str(front.get("license", "Apache-2.0")),
        "repository": REPOSITORY_URL,
        "keywords": list(KEYWORDS),
    }


def launch_entry(placeholder: str, *, agent_plugins: bool = False) -> dict[str, Any]:
    """The stdio server entry every layout shares; only the root placeholder differs.

    ``uv run --project <root> --extra plugin secscan mcp`` runs exactly the checked-out
    plugin content (research R11). The Agent Plugins layout also pins the resolved
    environment into the host's per-plugin data directory.
    """
    entry: dict[str, Any] = {
        "command": "uv",
        "args": ["run", "--project", placeholder, "--extra", "plugin", "secscan", "mcp"],
    }
    if agent_plugins:
        entry = {
            "type": "stdio",
            **entry,
            "env": {"UV_PROJECT_ENVIRONMENT": "${PLUGIN_DATA}/venv"},
            "cwd": placeholder,
        }
    return entry


def _json(document: Any) -> str:
    return canonical_json(document)


def render_all(root: Path | None = None) -> dict[str, str]:
    """Every committed plugin file as ``{relative path: content}``."""
    meta = _metadata()
    skill_text = render_skill("tools")
    claude = get_adapter("claude")
    gemini = get_adapter("gemini")
    assert isinstance(gemini, GeminiAdapter)

    plugin_json = {"$schema": AGENT_PLUGINS_SCHEMA, **meta}
    mcp_json = {
        "$schema": AGENT_PLUGINS_MCP_SCHEMA,
        "mcpServers": {PLUGIN_NAME: launch_entry("${PLUGIN_ROOT}", agent_plugins=True)},
    }
    claude_plugin = dict(meta)
    claude_mcp = {"mcpServers": {PLUGIN_NAME: launch_entry(claude.root_placeholder)}}
    gemini_ext = {
        "name": meta["name"],
        "version": meta["version"],
        "description": meta["description"],
        "mcpServers": {
            PLUGIN_NAME: {**launch_entry(gemini.root_placeholder), "cwd": gemini.root_placeholder}
        },
    }
    return {
        "plugin.json": _json(plugin_json),
        "mcp.json": _json(mcp_json),
        ".claude-plugin/plugin.json": _json(claude_plugin),
        ".mcp.json": _json(claude_mcp),
        "gemini-extension.json": _json(gemini_ext),
        "commands/secscan.toml": gemini.render_entrypoint(skill_text, PLUGIN_NAME),
        "skills/secscan/SKILL.md": skill_text if skill_text.endswith("\n") else skill_text + "\n",
    }


def check(root: Path) -> list[str]:
    """Committed files that differ from their render (or are missing), sorted."""
    root = Path(root)
    stale: list[str] = []
    for relative, content in render_all(root).items():
        path = root / relative
        if not path.exists() or path.read_text() != content:
            stale.append(relative)
    return sorted(stale)


def write_all(root: Path) -> list[str]:
    root = Path(root)
    written: list[str] = []
    for relative, content in render_all(root).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != content:
            path.write_text(content)
            written.append(relative)
    return sorted(written)


def find_plugin_root(start: Path | None = None) -> Path:
    """The secscan checkout containing ``plugin.json`` (walks up from this file)."""
    here = Path(start) if start is not None else Path(__file__).resolve()
    for candidate in [here, *here.parents]:
        manifest = candidate / "plugin.json"
        if manifest.is_file():
            try:
                if json.loads(manifest.read_text()).get("name") == PLUGIN_NAME:
                    return candidate
            except ValueError:
                continue
    raise PluginError("run from a secscan checkout or pass --plugin-root")


# ------------------------------------------------------------ registration


@dataclass
class RegisterResult:
    agent: str
    plugin_root: Path
    registered_in: str
    registered_via: str  # json-merge | host-cli
    previous_version: str | None = None
    notes: list[str] = field(default_factory=list)
    install_hint: str | None = None

    def render(self) -> str:
        adapter = ADAPTERS[self.agent]
        lines = [
            f"Registered {PLUGIN_NAME} v{TOOL_VERSION} as a plugin for {adapter.label}",
            f"  plugin root: {self.plugin_root}",
            f"  registered:  {self.registered_in}  ({self.registered_via})",
        ]
        if self.previous_version and self.previous_version != TOOL_VERSION:
            lines.append(f"  upgraded from v{self.previous_version}")
        for note in self.notes:
            lines.append(f"  ! {note}")
        if self.install_hint:
            lines.append(f"  next: {self.install_hint}")
        lines.append(
            f"  restart {adapter.label}; nothing was written into the project"
            + (" (skill loads from the plugin, tools from the MCP server)"
               if adapter.plugin_layout != "mcp-only" else
               " (tools only: Windsurf has no plugin skill surface — the skill form is "
               "recommended for Windsurf)")
        )
        return "\n".join(lines)


def user_record_path(environ: dict[str, str] | None = None) -> Path:
    return user_config_dir(environ) / PLUGIN_INSTALLS_RECORD


def read_record(environ: dict[str, str] | None = None) -> dict[str, Any]:
    path = user_record_path(environ)
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        return {"record_version": 1, "installs": {}}
    if not isinstance(doc, dict):
        return {"record_version": 1, "installs": {}}
    doc.setdefault("record_version", 1)
    doc.setdefault("installs", {})
    return doc


def write_record(record: dict[str, Any], environ: dict[str, str] | None = None) -> Path:
    path = user_record_path(environ)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(record))
    return path


def _expand_user_path(
    template: str, agent: str, environ: dict[str, str], *, windows: bool | None = None
) -> Path:
    windows = (os.name == "nt") if windows is None else windows
    if windows and agent == "devin" and environ.get("APPDATA"):
        # Devin documents %APPDATA%\devin\mcp_config.json on Windows.
        return Path(environ["APPDATA"]) / "devin" / "mcp_config.json"
    home = environ.get("HOME") or environ.get("USERPROFILE")
    base = Path(home) if home else Path.home()
    return Path(template.replace("~", str(base), 1))


def _merge_mcp_entry(path: Path, entry: dict[str, Any]) -> None:
    """Idempotent merge of ``mcpServers.secscan``; every other key is preserved."""
    document: dict[str, Any] = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text() or "{}")
        except ValueError as exc:
            raise PluginError(f"{path} is not valid JSON; fix it before registering") from exc
        if not isinstance(loaded, dict):
            raise PluginError(f"{path} must contain a JSON object")
        document = loaded
    servers = document.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
    servers[PLUGIN_NAME] = entry
    document["mcpServers"] = servers
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n")
    except OSError as exc:
        raise PluginError(f"cannot write {path}: {exc}") from exc


def provision(root: Path, *, run: Any = subprocess.run, environ: dict[str, str] | None = None
              ) -> str | None:
    """``uv sync --extra plugin`` in the plugin root so the host's first launch is offline.

    Returns a note when the step was skipped (no ``uv``); never raises on failure —
    registration still proceeds and the note names the manual command.
    """
    env = environ if environ is not None else os.environ
    uv = shutil.which("uv", path=env.get("PATH"))
    manual = f'pip install -e "{root}[plugin]"'
    if uv is None:
        return f"uv not found; provision the plugin environment by hand: {manual}"
    proc = run([uv, "sync", "--extra", "plugin"], cwd=str(root), capture_output=True,
               text=True, check=False)
    if proc.returncode != 0:
        return f"uv sync --extra plugin failed ({proc.returncode}); run it by hand or: {manual}"
    return None


def register(
    agent: str,
    plugin_root: Path,
    *,
    force: bool = False,
    environ: dict[str, str] | None = None,
    run: Any = subprocess.run,
    skip_provision: bool = False,
) -> RegisterResult:
    """Register the tool provider for ``agent`` at user level (FR-013/FR-014/FR-016)."""
    environ = dict(environ if environ is not None else os.environ)
    try:
        adapter: Adapter = get_adapter(agent)
    except KeyError:
        raise PluginError(f"unknown agent '{agent}'") from None
    if adapter.plugin_layout == "none":
        raise PluginError(
            f"the {adapter.label} target has no plugin form; add the mcp.json entry to your "
            "host by hand"
        )
    plugin_root = Path(plugin_root).resolve()
    if not (plugin_root / "plugin.json").is_file():
        raise PluginError(f"{plugin_root} is not a secscan plugin root (no plugin.json)")

    record = read_record(environ)
    previous = record["installs"].get(agent)
    previous_version = str(previous.get("tool_version")) if previous else None
    if previous_version and version_tuple(previous_version) > version_tuple(TOOL_VERSION):
        if not force:
            raise DowngradeRefused(PLUGIN_NAME, previous_version, TOOL_VERSION)

    notes: list[str] = []
    if not skip_provision:
        note = provision(plugin_root, run=run, environ=environ)
        if note:
            notes.append(note)

    entry = launch_entry(str(plugin_root))
    registered_in: str
    registered_via: str
    if adapter.register_command is not None:
        executable = adapter.register_command[0]
        found = shutil.which(executable, path=environ.get("PATH"))
        if found is None and adapter.user_mcp_config is None:
            raise PluginError(
                f"{executable} is not on PATH; the {adapter.label} user-level registration goes "
                f"through it: {' '.join(adapter.register_command)}"
            )
        if found is not None:
            argv = [
                found if part == executable else
                part.replace("{json}", json.dumps(entry)).replace("{root}", str(plugin_root))
                for part in adapter.register_command
            ]
            proc = run(argv, capture_output=True, text=True, check=False, env=environ)
            if proc.returncode != 0:
                raise PluginError(
                    f"{' '.join(argv[:3])} failed ({proc.returncode}): {proc.stderr.strip()}"
                )
            registered_in = " ".join(argv)
            registered_via = "host-cli"
        else:
            assert adapter.user_mcp_config is not None
            path = _expand_user_path(adapter.user_mcp_config, agent, environ)
            _merge_mcp_entry(path, entry)
            registered_in = str(path)
            registered_via = "json-merge"
            notes.append(f"{executable} not found; registered the MCP server only in {path}")
    else:
        assert adapter.user_mcp_config is not None
        path = _expand_user_path(adapter.user_mcp_config, agent, environ)
        _merge_mcp_entry(path, entry)
        registered_in = str(path)
        registered_via = "json-merge"

    record["installs"][agent] = {
        "form": "plugin",
        "tool_version": TOOL_VERSION,
        "plugin_root": str(plugin_root),
        "registered_in": registered_in,
        "registered_via": registered_via,
        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    write_record(record, environ)

    hint = adapter.install_hint.format(root=plugin_root) if adapter.install_hint else None
    return RegisterResult(
        agent=agent, plugin_root=plugin_root, registered_in=registered_in,
        registered_via=registered_via, previous_version=previous_version, notes=notes,
        install_hint=hint,
    )


def describe_forms() -> list[tuple[str, str, str, str]]:
    """(key, label, skills path, forms) rows for ``secscan agents`` (FR-017)."""
    rows = []
    for adapter in sorted(ADAPTERS.values(), key=lambda a: a.key):
        forms = ", ".join(adapter.install_forms)
        if adapter.plugin_layout == "mcp-only":
            forms += " (MCP only)"
        rows.append((adapter.key, adapter.label, "/".join(adapter.skills_subdir), forms))
    return rows
