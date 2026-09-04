"""T015: conformance of triage verdict answers to schemas/triage_answer.json.

Covers contracts/triage-round.md §4: the closed verdict vocabulary and every
conditional requirement (citations iff refute/downgrade, question iff flagged).
"""

from __future__ import annotations

import pytest

from pipeline.schemas import is_valid

CITATION = {
    "repo": "shop",
    "file": "src/security.py",
    "line_start": 4,
    "line_end": 9,
    "pattern": "RoleAuthorizationFilter",
}


def base(verdict: str, **extra) -> dict:
    return {"finding_id": "SEC-0007", "verdict": verdict, **extra}


VALID = {
    "confirmed": base("confirmed"),
    "confirmed+rationale": base("confirmed", rationale="stands"),
    "flagged": base("flagged", user_question="Is this value dev-only?"),
    "flagged+hint": base(
        "flagged",
        user_question="Dev-only?",
        settling_evidence_hint="deployment manifests",
    ),
    "refuted": base("refuted", rationale="filter chain covers it", citations=[CITATION]),
    "downgraded": base(
        "downgraded",
        rationale="no credentials forwarded",
        citations=[dict(CITATION, symbol="filter_chain")],
    ),
}

INVALID = {
    "unknown verdict": base("maybe"),
    "missing finding_id": {"verdict": "confirmed"},
    "extra key": dict(VALID["confirmed"], surprise=True),
    "flagged without question": base("flagged"),
    "flagged with citations": base(
        "flagged", user_question="q", citations=[CITATION]
    ),
    "refuted without rationale": base("refuted", citations=[CITATION]),
    "refuted without citations": base("refuted", rationale="guarded"),
    "refuted with empty citations": base("refuted", rationale="guarded", citations=[]),
    "refuted with question": base(
        "refuted", rationale="guarded", citations=[CITATION], user_question="q"
    ),
    "confirmed with citations": base("confirmed", citations=[CITATION]),
    "citation missing pattern": base(
        "refuted",
        rationale="guarded",
        citations=[{k: v for k, v in CITATION.items() if k != "pattern"}],
    ),
    "citation extra key": base(
        "refuted",
        rationale="guarded",
        citations=[dict(CITATION, note="x")],
    ),
    "zero line_start": base(
        "refuted", rationale="guarded", citations=[dict(CITATION, line_start=0)]
    ),
    "hint on confirmed": base("confirmed", settling_evidence_hint="h"),
}


@pytest.mark.parametrize("name", sorted(VALID))
def test_valid_verdicts(name: str) -> None:
    assert is_valid("triage_answer", VALID[name]), name


@pytest.mark.parametrize("name", sorted(INVALID))
def test_invalid_verdicts(name: str) -> None:
    assert not is_valid("triage_answer", INVALID[name]), name
