"""T011: additive finding-schema fields and the heuristic-verification invariant.

Contract C5: `detection` and `code_context` are optional, enum-typed, and change
no existing field; and any emitted finding with `detection == "heuristic"` must
never carry `verification.status == "verified"` (FR-008).
"""

from __future__ import annotations

from pipeline.redact import SecretHit
from pipeline.schemas import is_valid, validate
from pipeline.secret_findings import findings_from_hits
from pipeline.verify import apply_verification
from tests.contract.test_schemas import valid_finding

_GRAPH = {
    "nodes": [
        {"id": "repo:src/main/Auth.java", "repo": "repo", "path": "src/main/Auth.java",
         "type": "file"}
    ]
}


def test_finding_schema_accepts_new_optional_fields() -> None:
    finding = valid_finding()
    finding["detection"] = "heuristic"
    finding["code_context"] = "test"
    validate("finding", finding)
    assert is_valid("finding", finding)


def test_finding_schema_rejects_bad_enum_values() -> None:
    finding = valid_finding()
    finding["detection"] = "guess"
    assert not is_valid("finding", finding)
    finding = valid_finding()
    finding["code_context"] = "staging"
    assert not is_valid("finding", finding)


def test_finding_without_new_fields_still_validates() -> None:
    """Additivity: existing producers emit no new field and remain valid."""
    validate("finding", valid_finding())


def test_heuristic_finding_is_never_verified_end_to_end() -> None:
    """C4/C5 invariant over the real emission + verification pipeline."""
    hits = [SecretHit(origin="src/main/Auth.java", label="high-entropy-secret", line=10)]
    raw = findings_from_hits(hits, "repo")
    kept, _ = apply_verification(raw, _GRAPH, [])
    assert kept[0]["detection"] == "heuristic"
    assert kept[0]["verification"]["status"] != "verified"
