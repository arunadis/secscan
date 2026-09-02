"""T009: detection provenance and honest grading for credential findings.

Contract C4 (FR-008, FR-009, FR-010): heuristic detections carry strictly lower
confidence than format matches and are never presented as confirmed; test-code
findings are reported but graded lower in both confidence and severity, with the
context named.
"""

from __future__ import annotations

from pipeline.redact import SecretHit
from pipeline.secret_findings import findings_from_hits


def _hit(origin: str, label: str, line: int = 10) -> SecretHit:
    return SecretHit(origin=origin, label=label, line=line)


def test_format_detection_keeps_high_confidence() -> None:
    finding = findings_from_hits([_hit("src/main/Auth.java", "aws-access-key")], "repo")[0]
    assert finding["detection"] == "format"
    assert finding["code_context"] == "production"
    assert finding["confidence"] == 0.95


def test_heuristic_detection_is_lower_confidence_and_states_basis() -> None:
    finding = findings_from_hits([_hit("src/main/Auth.java", "high-entropy-secret")], "repo")[0]
    assert finding["detection"] == "heuristic"
    assert finding["confidence"] < 0.95
    # FR-009: the description states the heuristic basis rather than asserting exposure.
    assert "review" in finding["description"].lower()
    assert "hard-coded in source" not in finding["description"]


def test_test_code_is_reported_but_graded_lower() -> None:
    prod = findings_from_hits([_hit("src/main/java/Auth.java", "assigned-secret")], "repo")[0]
    test = findings_from_hits(
        [_hit("src/test/java/AuthTest.java", "assigned-secret")], "repo"
    )[0]
    assert test["code_context"] == "test"
    assert prod["code_context"] == "production"
    assert test["confidence"] < prod["confidence"]
    assert test["severity_score"] < prod["severity_score"]
    assert "test" in test["description"].lower()


def test_confidence_ordering_format_beats_heuristic_beats_test_code() -> None:
    """C4: format-prod > heuristic-prod > format-test > heuristic-test."""
    format_prod = findings_from_hits([_hit("src/main/a.py", "aws-access-key")], "r")[0]
    heuristic_prod = findings_from_hits([_hit("src/main/a.py", "high-entropy-secret")], "r")[0]
    format_test = findings_from_hits([_hit("tests/test_a.py", "aws-access-key")], "r")[0]
    heuristic_test = findings_from_hits([_hit("tests/test_a.py", "high-entropy-secret")], "r")[0]
    assert format_prod["confidence"] > heuristic_prod["confidence"]
    assert heuristic_prod["confidence"] > format_test["confidence"]
    assert format_test["confidence"] > heuristic_test["confidence"]
