"""Installer core: scaffolding, in-place upgrade, and ignore handling.

Implements FR-020 (per-project install pinning a version; re-run performs an
in-place upgrade preserving config and artifacts, flagging schema changes),
FR-021 (agent-agnostic core + adapters), and FR-022 (registers an invocable
command in the target agent).

The payload is copied into the project so each project pins its own scanner
version and the agent can run the deterministic scripts without a global install.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from config.loader import CONFIG_VERSION
from installer import upgrade as upgrade_mod
from installer.agents import ADAPTERS, Adapter, get_adapter, supported
from installer.upgrade import DowngradeRefused
from pipeline.state import TOOL_VERSION

SKILL_NAME = "secscan"
#: re-exported so callers need only one import to locate an install
MANIFEST_NAME = upgrade_mod.MANIFEST_NAME
CONFIG_SCHEMA_VERSION = CONFIG_VERSION
SCAN_DIR_ENTRY = ".secscan/"

_SRC = Path(__file__).resolve().parent.parent
_SKILL_CORE = _SRC / "skill_core"

#: Payload layout: (source, destination relative to the installed skill dir).
_PAYLOAD_DIRS: tuple[tuple[Path, str], ...] = (
    (_SKILL_CORE / "prompts", "prompts"),
    (_SKILL_CORE / "schemas", "schemas"),
    # Versioned knowledge bases: applicability rules, framework controls, stack
    # descriptors, end-of-support data. The pipeline reads these at scan time, so
    # an installed payload without them cannot classify or calibrate anything.
    (_SKILL_CORE / "data", "data"),
    (_SRC / "profiles", "profiles"),
    (_SRC / "pipeline", "scripts/pipeline"),
    (_SRC / "config", "scripts/config"),
)
_PAYLOAD_FILES: tuple[tuple[Path, str], ...] = ((_SKILL_CORE / "cwe_map.json", "cwe_map.json"),)

_EXCLUDE_NAMES = {"__pycache__", ".pytest_cache", ".DS_Store"}


class InstallError(RuntimeError):
    """Raised when installation cannot proceed."""


@dataclass
class InstallResult:
    action: str  # installed | upgraded
    agent: str
    skill_dir: Path
    entrypoint: Path
    invocation: str
    previous_version: str | None = None
    config_schema_changed: bool = False
    notes: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [
            f"{self.action.capitalize()} {SKILL_NAME} v{TOOL_VERSION} for "
            f"{ADAPTERS[self.agent].label}",
            f"  skill:   {self.skill_dir}",
            f"  command: {self.invocation}",
        ]
        if self.previous_version and self.previous_version != TOOL_VERSION:
            lines.append(f"  upgraded from v{self.previous_version}")
        for note in self.notes:
            lines.append(f"  ! {note}")
        lines.append("")
        lines.append("Next: run the init command to generate config and check your environment:")
        lines.append("  secscan init .")
        return "\n".join(lines)


# --------------------------------------------------------------------- install


def install(
    project_root: Path | str,
    agent: str,
    *,
    force: bool = False,
    commit_artifacts: bool = False,
) -> InstallResult:
    """Scaffold (or upgrade) the scanning skill in ``project_root`` for ``agent``."""
    project_root = Path(project_root).resolve()
    try:
        adapter = get_adapter(agent)
    except KeyError:
        raise InstallError(
            f"unknown agent '{agent}'. Supported agents: {', '.join(supported())}"
        ) from None

    project_root.mkdir(parents=True, exist_ok=True)
    skill_dir = adapter.skill_dir(project_root, SKILL_NAME)
    entrypoint = adapter.entrypoint(project_root, SKILL_NAME)

    try:
        plan = upgrade_mod.plan_upgrade(
            skill_dir,
            skill=SKILL_NAME,
            tool_version=TOOL_VERSION,
            config_schema_version=CONFIG_SCHEMA_VERSION,
            config_exists=(project_root / ".secscan" / "config.yaml").exists(),
            force=force,
        )
    except DowngradeRefused as exc:
        raise InstallError(str(exc)) from None

    notes = list(plan.notes)
    action = "upgraded" if plan.is_upgrade else "installed"

    if plan.is_upgrade:
        # Drop the old payload so files this version no longer ships do not linger.
        upgrade_mod.remove_stale_payload(skill_dir)

    written = _write_payload(skill_dir, adapter, entrypoint)
    config_schema_changed = plan.config_schema_changed

    _write_manifest(skill_dir, adapter, entrypoint, written)

    if commit_artifacts:
        notes.append(
            f"{SCAN_DIR_ENTRY} was NOT added to .gitignore; scan artifacts will be committed"
        )
    else:
        if ensure_ignored(project_root):
            notes.append(f"added {SCAN_DIR_ENTRY} to .gitignore")

    return InstallResult(
        action=action,
        agent=agent,
        skill_dir=skill_dir,
        entrypoint=entrypoint,
        invocation=adapter.invocation_hint(SKILL_NAME),
        previous_version=plan.previous_version,
        config_schema_changed=config_schema_changed,
        notes=notes,
    )


# --------------------------------------------------------------------- payload


def _write_payload(skill_dir: Path, adapter: Adapter, entrypoint: Path) -> list[str]:
    """Copy the payload; returns installed paths relative to ``skill_dir``."""
    skill_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    core_text = (_SKILL_CORE / "SKILL.md").read_text()
    entrypoint.parent.mkdir(parents=True, exist_ok=True)
    entrypoint.write_text(adapter.render_entrypoint(core_text, SKILL_NAME))
    written.append(_relative(entrypoint, skill_dir))

    for source, destination in _PAYLOAD_FILES:
        target = skill_dir / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        written.append(destination)

    for source, destination in _PAYLOAD_DIRS:
        if not source.is_dir():
            continue
        for path in sorted(source.rglob("*")):
            if not path.is_file() or _excluded(path):
                continue
            relative = f"{destination}/{path.relative_to(source).as_posix()}"
            target = skill_dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            written.append(relative)

    # Make the copied scripts runnable as `python -m pipeline...` from scripts/.
    (skill_dir / "scripts" / "__init__.py").unlink(missing_ok=True)
    return sorted(set(written))


def _excluded(path: Path) -> bool:
    return any(part in _EXCLUDE_NAMES for part in path.parts) or path.suffix == ".pyc"


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        # Gemini keeps the command file outside the payload directory.
        return f"../{path.name}"


# -------------------------------------------------------------------- manifest


def _write_manifest(
    skill_dir: Path, adapter: Adapter, entrypoint: Path, files: list[str]
) -> None:
    upgrade_mod.write_manifest(
        skill_dir,
        {
            "skill": SKILL_NAME,
            "agent": adapter.key,
            "tool_version": TOOL_VERSION,
            "config_schema_version": CONFIG_SCHEMA_VERSION,
            "entrypoint": _relative(entrypoint, skill_dir),
            "invocation": adapter.invocation_hint(SKILL_NAME),
            "files": files,
        },
    )


# ---------------------------------------------------------------- ignore rules


def ensure_ignored(project_root: Path) -> bool:
    """Add ``.secscan/`` to .gitignore. Returns True when modified."""
    path = Path(project_root) / ".gitignore"
    if path.exists():
        text = path.read_text()
        if any(line.strip() == SCAN_DIR_ENTRY for line in text.splitlines()):
            return False
        separator = "" if text.endswith("\n") or not text else "\n"
        path.write_text(
            f"{text}{separator}\n# secscan artifacts (opt in to commit by removing this)\n"
            f"{SCAN_DIR_ENTRY}\n"
        )
        return True
    path.write_text(
        "# secscan artifacts (opt in to commit by removing this)\n" f"{SCAN_DIR_ENTRY}\n"
    )
    return True


def installed_manifest(project_root: Path, agent: str) -> dict | None:
    """Public read of the install manifest for a given agent."""
    adapter = get_adapter(agent)
    return upgrade_mod.read_manifest(adapter.skill_dir(Path(project_root).resolve(), SKILL_NAME))


def detect_installs(project_root: Path) -> list[dict]:
    """Every agent this project has the skill installed for."""
    found: list[dict] = []
    for key in supported():
        manifest = installed_manifest(project_root, key)
        if manifest:
            found.append(manifest)
    return found
