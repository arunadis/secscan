"""T089: findings across every severity band, for the report consistency gate.

The shape that matters here is `mismatched_band`: a finding **published** at
Medium whose weakness class **defaults** to High. `_recommendations` used to derive
its section pointer from the class default, so this finding produced
"see the High section" in a report whose only section was Medium.

That is the literal defect FR-040 removes, and it is invisible to any fixture
whose published bands happen to agree with their class defaults — which is why the
band and the class are chosen to disagree deliberately.
"""

from __future__ import annotations

from typing import Any

#: (cwe, published score, published band, class default band) — the last column is
#: what makes each case interesting, not decoration.
BAND_CASES: tuple[tuple[str, float, str, str], ...] = (
    ("CWE-89", 9.8, "Critical", "Critical"),
    ("CWE-862", 8.2, "High", "High"),
    ("CWE-79", 6.1, "Medium", "Medium"),
    ("CWE-20", 3.1, "Low", "Medium"),
    # The defect shape: published Medium, class defaults to High.
    ("CWE-862", 5.0, "Medium", "High"),
    # The inverse: published High, class defaults to Medium. Guards against a
    # "use the higher of the two" fix, which would look correct on the case above.
    ("CWE-79", 7.6, "High", "Medium"),
)


def finding(
    index: int,
    cwe: str,
    score: float,
    band: str,
    *,
    verified: bool = True,
) -> dict[str, Any]:
    """One schema-shaped finding published at ``band``."""
    status = "verified" if verified else "plausible"
    verification: dict[str, Any] = {"status": status, "path": ["r:a.py#f"] if verified else []}
    if not verified:
        verification["gap"] = "no externally controllable source could be traced"

    reproduction: dict[str, Any] = {
        "preconditions": "A local/test deployment.",
        "expected_behavior": "The value is neutralized before the unsafe operation.",
        "trigger": "Invoke `a.py#f` with `SECSCAN-CANARY-1`.",
        "mode": "observed" if verified else "hypothesis",
        "target_scope": "local/test",
    }
    if verified:
        reproduction["observed_behavior"] = "The canary reached the unsafe operation."
        reproduction["traced_trail"] = ["r:a.py#f"]
    else:
        reproduction["outcome_to_check"] = (
            "Whether the canary reaches the unsafe operation. The scanner did not observe this."
        )

    return {
        "id": f"SEC-{index:04d}",
        "cwe": cwe,
        "severity_score": score,
        "severity_band": band,
        "confidence": 0.9 if verified else 0.5,
        "location": {
            "repo": "r",
            "file": "a.py",
            "symbol": "f",
            "line_start": 10,
            "line_end": 20,
            "tier": "symbol",
            "symbol_confirmed": True,
        },
        "description": "A value reaches an unsafe operation.",
        "evidence": [{"repo": "r", "file": "a.py", "symbol": "f", "reason": "unsafe call"}],
        "attack_scenario": "An attacker supplies a crafted value.",
        "impact": "Unauthorized data access.",
        "recommendation": "Neutralize the value.",
        "source": "analysis",
        "status": "reported",
        "verification": verification,
        "reproduction": reproduction,
    }


def findings(verified: bool = True) -> list[dict[str, Any]]:
    return [
        finding(i, cwe, score, band, verified=verified)
        for i, (cwe, score, band, _default) in enumerate(BAND_CASES, start=1)
    ]


def report(recommendations: list[str] | None = None, verified: bool = True) -> dict[str, Any]:
    """A report carrying findings in every band."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in findings(verified=verified):
        grouped.setdefault(item["severity_band"], []).append(item)
    return {
        "scan_id": "s",
        "workspace": {"id": "w", "members": ["r"]},
        "execution_mode": "agent-mediated",
        "profile": {"name": "full"},
        "executive_summary": "Scanned 1 repository. 6 findings.",
        "findings_by_band": grouped,
        "recommendations": recommendations if recommendations is not None else [],
        "coverage": {"repos_analyzed": ["r"], "segments_analyzed": 1},
    }


#: Bands the fixture actually publishes — what a section pointer may name.
PUBLISHED_BANDS = frozenset(band for _c, _s, band, _d in BAND_CASES)
