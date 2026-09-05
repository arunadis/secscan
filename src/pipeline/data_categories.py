"""Deterministic regulated-data category detection (feature 015, FR-022).

Signals ship in the versioned regimes dataset; detection is substring matching over
source text or node identities. Never probabilistic, never model-derived: the same
text yields the same categories, and a miss is a declared coverage fact (the
flow-analysis round sees exactly what was detected).
"""

from __future__ import annotations

import functools

DATA_CATEGORIES = ("personal-data", "health-data", "financial-data")


@functools.cache
def _signal_rules() -> dict[str, tuple[str, ...]]:
    from pipeline.business_flow import regimes_dataset

    rules: dict[str, list[str]] = {}
    for regime in regimes_dataset().get("regimes") or []:
        for category in regime.get("regulated_data_categories") or []:
            bucket = rules.setdefault(str(category["category"]), [])
            bucket.extend(str(signal) for signal in category.get("signals") or [])
    return {category: tuple(sorted(set(signals))) for category, signals in rules.items()}


def detect_text(text: str) -> list[str]:
    """Categories whose shipped signals appear in ``text`` (lowered substring)."""
    lowered = text.lower()
    return sorted(
        category
        for category, signals in _signal_rules().items()
        if any(signal in lowered for signal in signals)
    )


def detect_node_key(node_key: str) -> list[str]:
    """Categories detectable from a node identity alone (path/symbol names)."""
    return detect_text(node_key.replace(":", " ").replace("#", " ").replace("/", " "))
