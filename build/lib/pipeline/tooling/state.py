"""Tooling artifact writers (feature 008).

One canonical write path for the three tooling artifacts so byte-identity is
guaranteed everywhere (store ``canonical_json``, sorted keys, trailing
newline). These helpers take the **store directory** (the ``.secscan``
dir) and always write under its ``tooling/`` child.

Schemas: specs/008-external-scanner-integration/contracts/data-contracts.md
§2 (availability), §3 (runs), §5 (suppressions). Where a full ``ArtifactStore``
exists the artifacts are re-written per scan, but the payload shape is
identical and contract-tested either way.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pipeline.state import canonical_json


def _write(store_dir: Path, relative: str, payload: dict[str, Any]) -> Path:
    path = Path(store_dir) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(payload))
    return path


def write_availability(store_dir: Path, records: list[dict[str, Any]]) -> Path:
    return _write(store_dir, "tooling/availability.json", {"tools": records})


def write_run_records(store_dir: Path, records: list[dict[str, Any]]) -> Path:
    return _write(store_dir, "tooling/runs.json", {"runs": records})


def read_availability(store_dir: Path) -> list[dict[str, Any]]:
    """Last init-persisted availability, or [] — informational only (R8)."""
    path = Path(store_dir) / "tooling" / "availability.json"
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return []
    return list(payload.get("tools") or [])
