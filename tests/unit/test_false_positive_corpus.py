"""T016: the false-positive corpus produces zero credential findings (FR-011, C6).

End-to-end at the deterministic layer: corpus line → redactor → findings. Every
known false positive must produce no hit (and therefore no finding), and every
suppression must be recorded as an inspectable Detection Decision (FR-004).
"""

from __future__ import annotations

from pipeline.redact import Redactor
from pipeline.secret_findings import findings_from_hits


def test_false_positive_corpus_produces_zero_findings() -> None:
    from tests.fixtures.identifier_corpus import IDENTIFIERS

    redactor = Redactor()
    for line, token, why in IDENTIFIERS:
        result = redactor.redact(line, origin="src/app.ts")
        findings = findings_from_hits(result.hits, "repo")
        assert findings == [], f"finding from false positive ({why}): {token}"
        assert result.blocked == 0, f"blocked ({why}): {result.warnings}"


def test_every_suppression_is_an_inspectable_decision() -> None:
    """FR-004: suppressed matches record file, line, rule, and reason."""
    from tests.fixtures.identifier_corpus import IDENTIFIERS

    redactor = Redactor()
    for line, _token, _why in IDENTIFIERS:
        result = redactor.redact(line, origin="src/app.ts")
        for decision in result.exempted:
            assert decision.origin == "src/app.ts"
            assert decision.line >= 1
            assert decision.rule
            assert decision.reason
            assert decision.decision in ("exempt-identifier", "exempt-message")
            assert decision.classification
