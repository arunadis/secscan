"""T020: verification and reproduction output (quickstart Scenario 7, SC-011)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline import run as run_mod
from pipeline.redact import Redactor
from tests.integration.conftest import oracle_responder


@pytest.fixture
def audit_result(configured_shop: Path):
    return run_mod.run_scan(
        configured_shop, responder=oracle_responder, full=True, profile="audit"
    )


def test_high_severity_findings_are_verified_or_document_the_gap(audit_result) -> None:
    """SC-011: Critical/High carry `verified`, or `plausible` with the gap stated."""
    high = [
        f
        for f in audit_result.reported_findings
        if f["severity_band"] in ("Critical", "High")
    ]
    assert high, "fixture should yield Critical/High findings"
    for finding in high:
        verification = finding["verification"]
        assert verification["status"] in ("verified", "plausible")
        if verification["status"] == "plausible":
            assert verification.get("gap"), finding["id"]
        else:
            assert verification.get("path"), finding["id"]


def test_every_reported_finding_has_a_reproduction_block(audit_result) -> None:
    """FR-030 + FR-008: complete, and honest about what was actually established.

    `observed_behavior` is no longer unconditional. Only a finding verified end to
    end may claim an observation; everything else states the outcome to check and
    says the scanner did not observe it. Asserting otherwise would require the
    pipeline to fabricate observations, which is the defect this feature removes.
    """
    assert audit_result.reported_findings
    for finding in audit_result.reported_findings:
        repro = finding["reproduction"]
        assert repro["preconditions"]
        assert repro["expected_behavior"]
        assert repro["target_scope"] == "local/test"

        verified = finding["verification"]["status"] == "verified"
        assert repro["mode"] == ("observed" if verified else "hypothesis")
        if verified:
            assert repro["observed_behavior"]
            assert "outcome_to_check" not in repro
        else:
            assert repro["outcome_to_check"]
            assert "observed_behavior" not in repro, (
                f"{finding['id']} is {finding['verification']['status']} yet claims an "
                "observation the pipeline never made"
            )

        # A trigger is present only when an achievable probe exists (FR-009/FR-010).
        assert bool(repro.get("trigger")) != bool(repro.get("trigger_omitted_reason"))


def test_traced_trail_contains_only_traced_nodes(audit_result) -> None:
    """FR-005/FR-006, SC-003: a trail rendered as a path must actually be one."""
    for finding in audit_result.reported_findings:
        trail = finding["reproduction"].get("traced_trail")
        if not trail:
            continue
        path = finding["verification"].get("path") or []
        assert path, f"{finding['id']} carries a trail with no traced path"
        # Supporting evidence must not have been concatenated into the trail.
        evidence_files = {e["file"] for e in finding["evidence"]}
        for entry in trail:
            assert entry in path or not any(
                f in entry for f in evidence_files - set(path)
            ), f"{finding['id']}: '{entry}' is evidence, not a traced edge"


def test_reproduction_triggers_use_benign_canaries_and_no_secrets(audit_result) -> None:
    """FR-030: non-destructive canary values; redaction applies to repro blocks."""
    redactor = Redactor()
    destructive = ("DROP TABLE", "DELETE FROM", "rm -rf", "shutdown", "TRUNCATE")
    for finding in audit_result.reported_findings:
        trigger = finding["reproduction"].get("trigger")
        if not trigger:
            continue  # no achievable probe; nothing to keep benign (FR-010)
        assert "CANARY" in trigger.upper(), trigger
        for token in destructive:
            assert token.lower() not in trigger.lower(), trigger
        assert not redactor.scan(trigger), trigger
        assert "Pr0d-Sh0p-DB-2024!" not in trigger


def test_disproven_findings_never_appear_in_the_report(audit_result) -> None:
    """FR-029: disproven findings are kept out entirely."""
    for finding in audit_result.reported_findings:
        assert finding["verification"]["status"] != "disproven"
    raw = audit_result.report_path.read_text()
    assert "disproven" not in raw.lower()


def test_report_ranks_verified_above_plausible_within_a_band(audit_result) -> None:
    """FR-029: verification-aware ranking."""
    for band, findings in audit_result.report["findings_by_band"].items():
        statuses = [f["verification"]["status"] for f in findings]
        verified_positions = [i for i, s in enumerate(statuses) if s == "verified"]
        plausible_positions = [i for i, s in enumerate(statuses) if s == "plausible"]
        if verified_positions and plausible_positions:
            assert max(verified_positions) < min(plausible_positions), band


def test_reproduction_appears_inline_in_both_renderings(audit_result) -> None:
    """Q2: inline per finding, human-readable AND machine-readable."""
    markdown = audit_result.report_path.read_text()
    assert "#### Reproduction" in markdown
    assert "Preconditions" in markdown
    for findings in audit_result.report["findings_by_band"].values():
        for finding in findings:
            assert "reproduction" in finding


def test_verified_findings_pass_confidence_floor_regardless_of_score(configured_shop: Path) -> None:
    """FR-029: a traced path outweighs the heuristic confidence score."""
    result = run_mod.run_scan(
        configured_shop,
        responder=oracle_responder,
        full=True,
        profile="full",
        overrides={"report_thresholds": {"min_confidence": 0.99}},
    )
    verified = [
        f for f in result.reported_findings if f["verification"]["status"] == "verified"
    ]
    assert verified, "verified findings must survive a 0.99 confidence floor"
    assert any(f["confidence"] < 0.99 for f in verified)


# ------------------------------------------------ report self-consistency (US6)
#
# T091. FR-044 matters as much as the rest: precision must not be bought by
# deleting the honesty markers that let a careful reader calibrate.


def test_report_is_internally_consistent(audit_result) -> None:
    """FR-040/FR-042, SC-010: no dangling reference, no self-contradiction."""
    import json
    from pathlib import Path

    from pipeline.consistency import check

    report = json.loads(Path(audit_result.report_json_path).read_text())["payload"]
    problems = check(report)
    assert problems == [], "\n".join(str(p) for p in problems)


def test_recommendation_section_pointers_resolve(audit_result) -> None:
    """The 'see the High section' defect, asserted against a real report."""
    import json
    from pathlib import Path

    report = json.loads(Path(audit_result.report_json_path).read_text())["payload"]
    present = {band for band, items in report["findings_by_band"].items() if items}
    for line in report["recommendations"]:
        for band in ("Critical", "High", "Medium", "Low", "None"):
            if f"{band} section" in line:
                assert band in present, f"{line!r} points at an absent section"


def test_honesty_markers_are_preserved(audit_result) -> None:
    """FR-044: the properties the independent review credited must survive.

    Reducing over-claiming by removing the verdict badges and gap statements would
    trade one kind of dishonesty for another.
    """
    import json
    from pathlib import Path

    report = json.loads(Path(audit_result.report_json_path).read_text())["payload"]
    assert "statically verified" in report["executive_summary"]
    for finding in audit_result.reported_findings:
        assert finding["verification"]["status"] in ("verified", "plausible")
        if finding["verification"]["status"] == "plausible":
            assert finding["verification"].get("gap"), (
                f"{finding['id']} is plausible but documents no verification gap"
            )
    assert "coverage" in report
    assert "resolution_tiers" in report["coverage"]
