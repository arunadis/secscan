"""In-place upgrade support (FR-020).

Re-running the installer in an installed project replaces the skill payload while
preserving the project's configuration and scan artifacts, and flags configuration
schema changes instead of silently applying new defaults.

Downgrades are refused unless explicitly forced, so a project pinned to a newer
scanner is not quietly rolled back.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

MANIFEST_NAME = ".install-manifest.json"


class DowngradeRefused(RuntimeError):
    """Installed version is newer than the one being installed."""

    def __init__(self, skill: str, installed: str, candidate: str) -> None:
        self.installed = installed
        self.candidate = candidate
        super().__init__(
            f"this project has {skill} v{installed} installed, which is newer than "
            f"v{candidate}. Re-run with --force to downgrade."
        )


@dataclass
class UpgradePlan:
    """What re-installing over an existing install will do."""

    is_upgrade: bool
    previous_version: str | None = None
    previous_files: list[str] = field(default_factory=list)
    config_schema_changed: bool = False
    notes: list[str] = field(default_factory=list)


def manifest_path(skill_dir: Path) -> Path:
    return Path(skill_dir) / MANIFEST_NAME


def read_manifest(skill_dir: Path) -> dict | None:
    path = manifest_path(skill_dir)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        # A corrupt manifest is treated as "not installed": the payload is
        # rewritten wholesale, which is the safe outcome.
        return None


def write_manifest(skill_dir: Path, manifest: dict) -> None:
    manifest_path(skill_dir).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def version_tuple(value: str) -> tuple[int, ...]:
    out: list[int] = []
    for chunk in str(value).split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


def is_newer(candidate: str, current: str) -> bool:
    return version_tuple(candidate) > version_tuple(current)


def plan_upgrade(
    skill_dir: Path,
    *,
    skill: str,
    tool_version: str,
    config_schema_version: int,
    config_exists: bool,
    force: bool,
) -> UpgradePlan:
    """Decide how to proceed over any existing install. Raises on refused downgrade."""
    previous = read_manifest(skill_dir)
    if previous is None:
        return UpgradePlan(is_upgrade=False)

    installed_version = str(previous.get("tool_version", "0"))
    if is_newer(installed_version, tool_version) and not force:
        raise DowngradeRefused(skill, installed_version, tool_version)

    plan = UpgradePlan(
        is_upgrade=True,
        previous_version=installed_version,
        previous_files=list(previous.get("files") or []),
    )

    old_schema = previous.get("config_schema_version")
    if old_schema is not None and int(old_schema) != int(config_schema_version):
        plan.config_schema_changed = True
        plan.notes.append(
            f"configuration schema changed (v{old_schema} -> v{config_schema_version}); "
            "the next scan will validate your config and report any required updates"
        )
    if config_exists:
        plan.notes.append("existing configuration and scan artifacts were preserved")
    return plan


def remove_stale_payload(skill_dir: Path, keep: tuple[str, ...] = (MANIFEST_NAME,)) -> None:
    """Delete the previous payload so files a new version dropped do not linger.

    Only files *inside* the skill directory are touched — never the project's
    configuration or `.secscan/` artifacts, which live elsewhere.
    """
    skill_dir = Path(skill_dir)
    if not skill_dir.exists():
        return

    for path in sorted(skill_dir.rglob("*")):
        if path.is_file() and path.name not in keep:
            path.unlink()

    # Prune emptied directories, deepest first.
    for directory in sorted(
        (d for d in skill_dir.rglob("*") if d.is_dir()),
        key=lambda d: len(d.parts),
        reverse=True,
    ):
        if not any(directory.iterdir()):
            directory.rmdir()
