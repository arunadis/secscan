"""CWE / OWASP taxonomy support (FR-012, research.md R6).

The dataset ships with the skill payload so classification is deterministic and
offline. Analysis output MUST reference a CWE present here — hallucinated ids are
rejected by :func:`validate_cwe`.
"""

from __future__ import annotations

import functools
import json

from pipeline import resources

CWE_MAP_PATH = resources.cwe_map_path()

#: Severity band thresholds (CVSS-style), highest first.
_BANDS: tuple[tuple[float, str], ...] = (
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
)

_BAND_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}


class UnknownCWE(ValueError):
    """Raised when a finding references a CWE outside the shipped dataset."""


@functools.lru_cache(maxsize=1)
def _data() -> dict:
    return json.loads(CWE_MAP_PATH.read_text())


def known_cwes() -> frozenset[str]:
    return frozenset(_data()["cwes"])


def validate_cwe(cwe: str) -> str:
    if cwe not in _data()["cwes"]:
        raise UnknownCWE(f"{cwe} is not in the shipped CWE dataset (v{_data()['version']})")
    return cwe


def info(cwe: str) -> dict:
    return dict(_data()["cwes"][validate_cwe(cwe)])


def name_for(cwe: str) -> str:
    return info(cwe)["name"]


def owasp_for(cwe: str) -> str | None:
    """Human-readable OWASP label, or ``None`` when unmapped.

    The key may reference the 2021 Top 10 or the LLM Top 10 block (spec 007);
    both ship in the same dataset so a finding's label is always resolvable.
    """
    key = info(cwe).get("owasp")
    if not key:
        return None
    data = _data()
    return data["owasp_top10_2021"].get(key) or data.get("llm_top10_2025", {}).get(key)


def domain_for(cwe: str) -> str | None:
    """Vulnerability domain used to select specialized guidance (FR-011)."""
    return info(cwe).get("domain")


def compliance_refs(cwe: str) -> list[str]:
    """Only well-established, unambiguous control mappings (spec Q3)."""
    return list(info(cwe).get("compliance") or [])


def default_severity(cwe: str) -> float:
    return float(info(cwe).get("default_severity", 5.0))


def band_for(score: float) -> str:
    """Derive the severity band from a CVSS-style score (finding-schema rule 1)."""
    if score < 0.0 or score > 10.0:
        raise ValueError(f"severity score out of range: {score}")
    for threshold, band in _BANDS:
        if score >= threshold:
            return band
    return "None"


def band_rank(band: str) -> int:
    return _BAND_ORDER.get(band, 99)


def band_at_least(band: str, minimum: str) -> bool:
    """True when ``band`` is at least as severe as ``minimum``."""
    return band_rank(band) <= band_rank(minimum)


def domains() -> list[str]:
    return sorted({d for c in _data()["cwes"].values() if (d := c.get("domain"))})
