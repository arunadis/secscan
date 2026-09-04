"""Feature 014 T023: narrative reference resolution + quarantine (FR-010).

Pinned contract (clarification Q5): quarantine + publish — the offending
section is omitted, the omission is declared in the report, the scan signals
the defect via exit status, and a residual strict check holds the invariant for
everything that ships. ANY SEC-id token in a scanned section is a reference.
"""

from __future__ import annotations

import pytest

from pipeline import consistency, generate_report


def _report() -> dict:
    return {
        "scan_id": "x",
        "findings_by_band": {"Medium": [{"id": "SEC-0001"}, {"id": "SEC-0002"}]},
    }


# ------------------------------------------------------------- the resolver


def test_clean_narrative_passes_through_unchanged() -> None:
    report = _report()
    review = "The workspace shows SEC-0001 and SEC-0002 clustering around auth."
    kept, quarantined = generate_report.resolve_narrative_references(report, review)
    assert kept == review
    assert quarantined == []


def test_dangling_id_quarantines_the_section() -> None:
    report = _report()
    review = "Systemic risk is concentrated in SEC-0001 and SEC-0006."
    kept, quarantined = generate_report.resolve_narrative_references(report, review)
    assert kept == ""
    assert quarantined == [
        {
            "section": "system_review",
            "dangling_id": "SEC-0006",
            "reason": "identifier not admitted to the report",
        }
    ]


def test_dangling_id_in_attack_paths_quarantines_the_entry() -> None:
    report = _report()
    report["attack_paths"] = [
        {"description": "chain", "finding_ids": ["SEC-0001", "SEC-0002"]},
        {"description": "ghost chain via SEC-9999", "finding_ids": ["SEC-9999"]},
    ]
    kept, quarantined = generate_report.resolve_narrative_references(report, "")
    assert report["attack_paths"] == [
        {"description": "chain", "finding_ids": ["SEC-0001", "SEC-0002"]}
    ]
    assert any(
        q["section"] == "attack_paths" and q["dangling_id"] == "SEC-9999"
        for q in quarantined
    )


def test_cross_system_findings_dangling_id_removed() -> None:
    report = _report()
    report["cross_system_findings"] = ["SEC-0001", "SEC-0007"]
    _kept, quarantined = generate_report.resolve_narrative_references(report, "")
    assert report["cross_system_findings"] == ["SEC-0001"]
    assert [q["dangling_id"] for q in quarantined] == ["SEC-0007"]


def test_quarantine_is_deterministic() -> None:
    report = _report()
    review = "See SEC-0006 and SEC-0003; also SEC-0001."
    review += "\n\nAlso SEC-0006 again."
    first = generate_report.resolve_narrative_references(report, review)
    report2 = _report()
    second = generate_report.resolve_narrative_references(report2, review)
    assert first == second
    ids = [q["dangling_id"] for q in first[1]]
    assert ids == sorted(set(ids))


# ----------------------------------------------------- the residual strict rule


def test_residual_reference_rule_catches_a_survivor() -> None:
    """Post-quarantine dangling references are pipeline bugs: strict gate fires."""
    problems = consistency.check(_report(), system_review="Cluster at SEC-9999.")
    assert any(p.rule == "dangling-finding-reference" for p in problems)


def test_residual_rule_passes_clean_reports() -> None:
    problems = consistency.check(_report(), system_review="See SEC-0001.")
    assert not [p for p in problems if p.rule == "dangling-finding-reference"]


def test_enforce_raises_on_residual_reference() -> None:
    with pytest.raises(consistency.ReportInconsistent):
        consistency.enforce(_report(), system_review="Cluster at SEC-9999.")
