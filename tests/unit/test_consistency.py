"""T089–T090: the report consistency gate (FR-040–FR-042).

Each case is a defect that survived the reviewed benchmark's own review process,
because none of them is a technical error — they are the report disagreeing with
itself, which costs credibility even when every individual claim is sound.
"""

from __future__ import annotations

import pytest

from pipeline import controls
from pipeline.consistency import ReportInconsistent, check, enforce


def finding(
    identifier="SEC-0001",
    band="Medium",
    cwe="CWE-79",
    status="plausible",
    path=(),
    **extra,
) -> dict:
    doc = {
        "id": identifier,
        "cwe": cwe,
        "severity_score": 4.3,
        "severity_band": band,
        "confidence": 0.5,
        "location": {"repo": "web", "file": "a.ts", "line_start": 1, "line_end": 2},
        "description": "d",
        "evidence": [{"repo": "web", "file": "a.ts", "reason": "r"}],
        "attack_scenario": "a",
        "impact": "i",
        "recommendation": "rec",
        "source": "analysis",
        "status": "reported",
        "verification": {"status": status, "path": list(path)},
        "reproduction": {
            "preconditions": "p",
            "expected_behavior": "e",
            "mode": "observed" if status == "verified" else "hypothesis",
            "target_scope": "local/test",
            "trigger": "Send `GET /x` with SECSCAN-CANARY-1.",
            **(
                {"observed_behavior": "o"}
                if status == "verified"
                else {"outcome_to_check": "c"}
            ),
        },
    }
    doc.update(extra)
    return doc


def report(*findings: dict, recommendations=(), summary="Scanned 1 repository.") -> dict:
    grouped: dict[str, list[dict]] = {}
    for item in findings:
        grouped.setdefault(item["severity_band"], []).append(item)
    return {
        "scan_id": "s",
        "workspace": {"id": "w", "members": ["web"]},
        "execution_mode": "agent-mediated",
        "profile": {"name": "full"},
        "executive_summary": summary,
        "findings_by_band": grouped,
        "recommendations": list(recommendations),
        "coverage": {"repos_analyzed": ["web"], "segments_analyzed": 1},
    }


READ_GUIDANCE = "Read these as leads to confirm, not as confirmed vulnerabilities."


def test_a_consistent_report_passes() -> None:
    doc = report(finding(status="verified"), recommendations=["... see the Medium section."])
    assert check(doc) == []


def test_dangling_section_reference_is_caught() -> None:
    """The benchmark's literal defect: 'see the High section' with no High section."""
    doc = report(
        finding(band="Medium", status="verified"),
        recommendations=["Address 1 Cross-site Scripting finding (CWE-79); see the High section."],
    )
    problems = check(doc)
    assert any(p.rule == "dangling-section-reference" for p in problems)
    assert "does not contain" in str(problems[0])


def test_observation_without_verification_is_caught() -> None:
    """FR-008: the pipeline never ran anything, so it may not claim it saw anything."""
    doc = finding(status="plausible")
    doc["reproduction"]["mode"] = "observed"
    doc["reproduction"]["observed_behavior"] = "the canary reached the sink unchanged"
    problems = check(report(doc, summary=READ_GUIDANCE))
    assert any(p.rule == "unearned-observation" for p in problems)


def test_trail_without_a_traced_path_is_caught() -> None:
    """FR-005: the trail that strung together a pipe and a hosting config file."""
    doc = finding(status="plausible", path=())
    doc["reproduction"]["traced_trail"] = ["web:pipes/comment.pipe.ts", "firebase.json"]
    problems = check(report(doc, summary=READ_GUIDANCE))
    assert any(p.rule == "trail-without-a-path" for p in problems)


def test_trail_entry_off_the_path_is_caught() -> None:
    doc = finding(status="verified", path=("web:a.ts#f",))
    doc["reproduction"]["traced_trail"] = ["web:a.ts#f", "firebase.json"]
    problems = check(report(doc))
    assert any(p.rule == "trail-entry-off-path" for p in problems)
    assert "firebase.json" in str(problems[0]) or "firebase.json" in str(problems[-1])


def test_impact_contradicting_a_credited_control_is_caught() -> None:
    """FR-023: a reduced severity beside the impact the control prevents."""
    doc = finding(status="verified")
    doc["framework_control"] = {
        "state": controls.STATE_CREDITED,
        "control": "angular-dom-sanitizer",
    }
    doc["impact"] = "Script execution in the victim's browser."
    problems = check(report(doc))
    assert any(p.rule == "impact-contradicts-credited-control" for p in problems)


def test_reproduction_contradicting_its_own_narrative_is_caught() -> None:
    """FR-011: the benchmark printed a localhost probe beside 'the host is fixed'."""
    doc = finding(status="verified")
    doc["impact"] = "The scheme and host are fixed by baseUrl so the request cannot be forced."
    doc["reproduction"]["trigger"] = "Invoke fetchUser with `http://127.0.0.1:9/SECSCAN-CANARY-1`."
    problems = check(report(doc))
    assert any(p.rule == "repro-contradicts-narrative" for p in problems)


def test_omitted_trigger_without_a_reason_is_caught() -> None:
    doc = finding(status="verified")
    del doc["reproduction"]["trigger"]
    problems = check(report(doc))
    assert any(p.rule == "trigger-omitted-without-reason" for p in problems)


def test_missing_read_guidance_is_caught_when_nothing_was_verified() -> None:
    """FR-041: stating '0 verified' without saying what it means invites misreading."""
    problems = check(report(finding(status="plausible"), summary="Scanned 1 repository."))
    assert any(p.rule == "missing-read-guidance" for p in problems)


def test_read_guidance_satisfies_the_rule() -> None:
    problems = check(report(finding(status="plausible"), summary=READ_GUIDANCE))
    assert not any(p.rule == "missing-read-guidance" for p in problems)


def test_enforce_blocks_the_write() -> None:
    """FR-042: a gate, not a warning."""
    doc = report(
        finding(band="Medium", status="verified"),
        recommendations=["see the Critical section."],
    )
    with pytest.raises(ReportInconsistent) as exc:
        enforce(doc)
    assert "report withheld" in str(exc.value)
    assert exc.value.problems


def test_enforce_can_be_relaxed_for_historical_artifacts() -> None:
    doc = report(
        finding(band="Medium", status="verified"),
        recommendations=["see the Critical section."],
    )
    problems = enforce(doc, strict=False)
    assert problems  # reported, but not raised


def test_findings_are_deterministically_ordered() -> None:
    doc = report(
        finding(band="Medium", status="verified"),
        recommendations=["see the High section.", "see the Critical section."],
    )
    assert [str(p) for p in check(doc)] == [str(p) for p in check(doc)]


# ------------------------------ the "see the High section" shape (T089 fixture)


def test_section_pointer_uses_the_published_band_not_the_class_default() -> None:
    """FR-040 at its source: `_recommendations` derives the pointer correctly.

    `CWE-862` defaults to High but is published here at Medium. The old code keyed
    the pointer off the class default and emitted "see the High section" into a
    report with no High section.
    """
    from pipeline.generate_report import _recommendations
    from tests.fixtures.all_bands import finding

    published = [finding(1, "CWE-862", 5.0, "Medium")]
    lines = _recommendations(published)
    assert lines
    assert "Medium section" in lines[0], lines[0]
    assert "High section" not in lines[0]


def test_section_pointer_does_not_simply_take_the_higher_band() -> None:
    """The inverse case, which a 'use the higher of the two' fix would fail."""
    from pipeline.generate_report import _recommendations
    from tests.fixtures.all_bands import finding

    lines = _recommendations([finding(1, "CWE-79", 7.6, "High")])
    assert "High section" in lines[0], lines[0]
    assert "Medium section" not in lines[0]


def test_a_class_published_in_two_bands_names_both() -> None:
    """Naming one would leave the other's findings unreachable from the summary."""
    from pipeline.generate_report import _recommendations
    from tests.fixtures.all_bands import finding

    lines = _recommendations(
        [finding(1, "CWE-79", 6.1, "Medium"), finding(2, "CWE-79", 7.6, "High")]
    )
    assert "High" in lines[0] and "Medium" in lines[0], lines[0]


def test_every_band_survives_the_gate_with_correct_pointers() -> None:
    """The whole fixture, end to end through the real recommendation builder."""
    from pipeline.generate_report import _recommendations
    from tests.fixtures.all_bands import PUBLISHED_BANDS, findings, report

    doc = report(recommendations=_recommendations(findings()))
    assert set(doc["findings_by_band"]) == set(PUBLISHED_BANDS)
    assert check(doc) == [], "\n".join(str(p) for p in check(doc))


def test_the_gate_still_catches_a_pointer_at_an_absent_band() -> None:
    """Proves the case above passes because it is correct, not because it is lax."""
    from tests.fixtures.all_bands import report

    doc = report(recommendations=["Address 1 finding (CWE-89); see the None section."])
    assert any(p.rule == "dangling-section-reference" for p in check(doc))
