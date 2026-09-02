"""End-of-support data for declared language, runtime and framework versions.

Loads the pinned ``eol.json`` snapshot (FR-034, research.md A3). Emitting the
findings themselves lands with User Story 4.

Two properties matter more than coverage here:

* **Offline and deterministic.** The dataset ships with the payload; nothing is
  fetched at scan time. Refresh is an explicit operator action.
* **Staleness is reportable.** An out-of-date snapshot is disclosed rather than
  presented as current. Reporting "supported" from data that expired months ago
  would be precisely the unearned confidence this feature removes.
"""

from __future__ import annotations

import functools
import json
from dataclasses import dataclass
from datetime import date
from typing import Any

from pipeline import resources

DATA_FILE = "eol.json"


@dataclass(frozen=True)
class SupportStatus:
    """Where a version sits relative to its support window."""

    product: str
    cycle: str
    #: True past end of support, False within it, None when undetermined.
    past_eol: bool | None
    eol_date: str | None
    reason: str | None = None

    @property
    def determined(self) -> bool:
        return self.past_eol is not None


@functools.lru_cache(maxsize=1)
def _data() -> dict[str, Any]:
    return json.loads(resources.data_path(DATA_FILE).read_text())


def version() -> str:
    return str(_data()["version"])


def dataset_date() -> date:
    return date.fromisoformat(_data()["dataset_date"])


def staleness_threshold_days() -> int:
    return int(_data()["staleness_threshold_days"])


def staleness(today: date | None = None) -> tuple[int, bool]:
    """``(age_in_days, is_stale)`` for the shipped snapshot."""
    today = today or date.today()
    age = (today - dataset_date()).days
    return age, age > staleness_threshold_days()


def product_for(identifier: str) -> str | None:
    """Map a manifest/package identifier to a dataset product id.

    Package-manager names and dataset product ids do not coincide, so the mapping
    is data (``identifier_map``) rather than a heuristic.
    """
    return _data()["identifier_map"].get(identifier)


def _cycle_of(product: str, version_string: str) -> dict[str, Any] | None:
    """Longest matching release cycle for a version, e.g. '9.0.1' -> cycle '9'."""
    cycles = _data()["products"].get(product) or []
    best: dict[str, Any] | None = None
    for entry in cycles:
        cycle = str(entry["cycle"])
        if version_string == cycle or version_string.startswith(cycle + "."):
            if best is None or len(cycle) > len(str(best["cycle"])):
                best = entry
    return best


def status_for(identifier: str, version_string: str, today: date | None = None) -> SupportStatus:
    """Support status for a declared dependency version.

    Returns an *undetermined* status rather than guessing whenever the product is
    unmapped, the cycle is unknown, or the dataset records no end-of-support date.
    An undetermined status must never be reported as supported.
    """
    product = product_for(identifier)
    if product is None:
        return SupportStatus(identifier, version_string, None, None, "product not in dataset")
    cycle = _cycle_of(product, version_string)
    if cycle is None:
        return SupportStatus(product, version_string, None, None, "release cycle not in dataset")
    eol = cycle.get("eol")
    if eol is False or eol is None:
        return SupportStatus(
            product, str(cycle["cycle"]), None, None, "no end-of-support date published"
        )
    today = today or date.today()
    return SupportStatus(product, str(cycle["cycle"]), date.fromisoformat(eol) < today, eol)
