"""005:T002 — additive `code_excerpt` property on the finding schema.

Contract: specs/005-html-report-code-snippets/contracts/report-artifacts.md.
The property is optional (additivity: existing producers and historical reports
remain valid), `status="unavailable"` carries a `reason` and no `lines`, and
`status="ok"` carries ordered excerpt lines with cited/truncation flags.
"""

from __future__ import annotations

from pipeline.schemas import is_valid, validate
from tests.contract.test_schemas import valid_finding


def _ok_excerpt() -> dict:
    return {
        "repo": "shop",
        "file": "src/orders/repository.py",
        "cited_start": 41,
        "cited_end": 48,
        "window_start": 38,
        "window_end": 51,
        "language": "python",
        "lines": [
            {"number": n, "text": f"line {n}", "cited": 41 <= n <= 48, "truncated": False}
            for n in range(38, 52)
        ],
        "truncated": False,
        "status": "ok",
    }


def test_finding_with_ok_excerpt_validates() -> None:
    finding = valid_finding()
    finding["code_excerpt"] = _ok_excerpt()
    validate("finding", finding)
    assert is_valid("finding", finding)


def test_finding_with_unavailable_excerpt_validates() -> None:
    finding = valid_finding()
    finding["code_excerpt"] = {
        "repo": "shop",
        "file": "src/orders/repository.py",
        "cited_start": 41,
        "cited_end": 48,
        "window_start": 41,
        "window_end": 48,
        "truncated": False,
        "status": "unavailable",
        "reason": "source file not found at report time",
    }
    validate("finding", finding)
    assert is_valid("finding", finding)


def test_unavailable_excerpt_without_reason_is_rejected() -> None:
    finding = valid_finding()
    finding["code_excerpt"] = {
        "repo": "shop",
        "file": "src/orders/repository.py",
        "cited_start": 41,
        "cited_end": 48,
        "window_start": 41,
        "window_end": 48,
        "truncated": False,
        "status": "unavailable",
    }
    assert not is_valid("finding", finding)


def test_excerpt_with_unknown_status_is_rejected() -> None:
    finding = valid_finding()
    excerpt = _ok_excerpt()
    excerpt["status"] = "partial"
    finding["code_excerpt"] = excerpt
    assert not is_valid("finding", finding)


def test_excerpt_with_extra_field_is_rejected() -> None:
    """additionalProperties: false keeps the projection stable (Constitution I)."""
    finding = valid_finding()
    excerpt = _ok_excerpt()
    excerpt["raw_source"] = "secret"
    finding["code_excerpt"] = excerpt
    assert not is_valid("finding", finding)


def test_finding_without_excerpt_still_validates() -> None:
    """Additivity: producers that emit no excerpt remain valid (no version bump)."""
    validate("finding", valid_finding())
