"""Payload resource resolution across the source and installed layouts.

The same deterministic scripts run from two different trees:

  source layout                  installed layout (per-project skill)
  -------------------------      ----------------------------------------
  src/pipeline/*.py              <skill>/scripts/pipeline/*.py
  src/config/*.py                <skill>/scripts/config/*.py
  src/skill_core/schemas/        <skill>/schemas/
  src/skill_core/prompts/        <skill>/prompts/
  src/skill_core/cwe_map.json    <skill>/cwe_map.json
  src/skill_core/data/           <skill>/data/
  src/profiles/builtin.yaml      <skill>/profiles/builtin.yaml

Resolving resources by searching both layouts keeps one code path for both, so an
installed skill is genuinely self-contained.
"""

from __future__ import annotations

import functools
from pathlib import Path

#: this file lives in <root>/pipeline/, so <root> is one level up
_PACKAGE_ROOT = Path(__file__).resolve().parent.parent


class ResourceNotFound(FileNotFoundError):
    def __init__(self, name: str, candidates: list[Path]) -> None:
        listing = "\n  ".join(str(c) for c in candidates)
        super().__init__(f"payload resource '{name}' not found. Looked in:\n  {listing}")


def _candidates(*relative: str) -> list[Path]:
    tail = Path(*relative)
    return [
        # source layout: src/skill_core/... or src/profiles/...
        _PACKAGE_ROOT / tail,
        # installed layout: scripts/pipeline -> scripts -> <skill>
        _PACKAGE_ROOT.parent / tail,
    ]


@functools.cache
def _resolve(name: str, *layouts: tuple[str, ...]) -> Path:
    tried: list[Path] = []
    for layout in layouts:
        for candidate in _candidates(*layout):
            tried.append(candidate)
            if candidate.exists():
                return candidate
    raise ResourceNotFound(name, tried)


def schema_dir() -> Path:
    return _resolve("schemas", ("skill_core", "schemas"), ("schemas",))


def cwe_map_path() -> Path:
    return _resolve("cwe_map.json", ("skill_core", "cwe_map.json"), ("cwe_map.json",))


def prompts_dir() -> Path:
    return _resolve("prompts", ("skill_core", "prompts"), ("prompts",))


def data_dir() -> Path:
    """Directory holding the versioned knowledge bases (applicability, controls, ...)."""
    return _resolve("data", ("skill_core", "data"), ("data",))


def data_path(name: str) -> Path:
    """Resolve one shipped data file, e.g. ``applicability.json``.

    These are the extensibility seam: adding a stack, an applicability rule, or a
    framework control is a data change, never a pipeline change.
    """
    return _resolve(f"data/{name}", ("skill_core", "data", name), ("data", name))


def profiles_path() -> Path:
    return _resolve(
        "profiles/builtin.yaml", ("profiles", "builtin.yaml"), ("profiles", "builtin.yaml")
    )
