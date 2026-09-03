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


def test_runtime_reference_corpus_produces_zero_findings() -> None:
    """Feature 010 FR-012 / SC-001: `"$VAR"` wiring is never a credential finding."""
    from tests.fixtures.runtime_reference_corpus import REFERENCES

    redactor = Redactor()
    for origin, line, why in REFERENCES:
        result = redactor.redact(line, origin=origin)
        findings = findings_from_hits(result.hits, "repo")
        assert findings == [], f"finding from runtime reference ({why}): {line}"
        assert result.blocked == 0, f"blocked ({why}): {result.warnings}"
        assert [e.decision for e in result.exempted] == ["exempt-reference"] * len(
            result.exempted
        ) and result.exempted, f"no exempt-reference decision ({why})"


def test_every_suppression_is_an_inspectable_decision() -> None:
    """FR-004 (003) / FR-005 (010): suppressed matches record file, line, rule, reason."""
    from tests.fixtures.identifier_corpus import IDENTIFIERS
    from tests.fixtures.runtime_reference_corpus import REFERENCES

    redactor = Redactor()
    samples = [("src/app.ts", line) for line, _token, _why in IDENTIFIERS]
    samples += [(origin, line) for origin, line, _why in REFERENCES]
    for origin, line in samples:
        result = redactor.redact(line, origin=origin)
        for decision in result.exempted:
            assert decision.origin == origin
            assert decision.line >= 1
            assert decision.rule
            assert decision.reason
            assert decision.decision in ("exempt-identifier", "exempt-message", "exempt-reference")
            assert decision.classification
