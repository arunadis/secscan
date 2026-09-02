"""T040–T042: control evaluation, calibration, and host ownership.

Between them these decide whether a finding's severity reflects what was actually
established. The reviewed benchmark got all three wrong at once: it never looked
for the framework control that was holding the finding to non-exploitable, it left
confidence at 0.85 while admitting reachability was unconfirmed, and it filed the
real trust-boundary risk as a footnote on the wrong weakness class.
"""

from __future__ import annotations

import pytest

from pipeline import calibrate as calibrate_mod
from pipeline import controls, hosts


def graph(*nodes: dict) -> dict:
    return {"nodes": list(nodes), "edges": []}


def node(node_id: str, repo="web", path="a.ts", parsed=True, annotations=()) -> dict:
    return {
        "id": node_id,
        "repo": repo,
        "type": "function",
        "path": path,
        "parsed": parsed,
        "annotations": list(annotations),
        "line_start": 1,
        "line_end": 5,
    }


def finding(cwe="CWE-79", status="plausible", path=(), gap="") -> dict:
    verification = {"status": status, "path": list(path)}
    if gap:
        verification["gap"] = gap
    return {
        "id": "SEC-0001",
        "cwe": cwe,
        "severity_score": 6.1,
        "confidence": 0.85,
        "location": {"repo": "web", "file": "a.ts", "symbol": "f", "line_start": 1, "line_end": 5},
        "evidence": [],
        "impact": "Script execution in the victim's browser.",
        "verification": verification,
    }


# ------------------------------------------------------------------ controls


def test_credited_when_the_control_covers_the_path_with_no_bypass() -> None:
    g = graph(node("web:a.ts#f"))
    state = controls.evaluate(finding(path=["web:a.ts#f"]), g, {"angular"})
    assert state["state"] == controls.STATE_CREDITED
    assert state["control"] == "angular-dom-sanitizer"


def test_bypass_on_the_path_discredits_the_control() -> None:
    g = graph(node("web:a.ts#f", annotations=["control_bypass"]))
    state = controls.evaluate(finding(path=["web:a.ts#f"]), g, {"angular"})
    assert state["state"] == controls.STATE_BYPASSED
    assert state["bypass_site"]["file"] == "a.ts"


def test_bypass_off_the_path_leaves_this_finding_alone() -> None:
    """FR-022b: unrelated code must not inflate an unrelated finding."""
    g = graph(
        node("web:a.ts#f"),
        node("web:other.ts#g", path="other.ts", annotations=["control_bypass"]),
    )
    state = controls.evaluate(finding(path=["web:a.ts#f"]), g, {"angular"})
    assert state["state"] == controls.STATE_CREDITED


def test_unparsed_file_on_the_path_blocks_crediting() -> None:
    """FR-022a: partial path knowledge is not full path knowledge."""
    g = graph(node("web:a.ts#f"), node("web:t.html", path="t.html", parsed=False))
    state = controls.evaluate(finding(path=["web:a.ts#f", "web:t.html"]), g, {"angular"})
    assert state["state"] == controls.STATE_UNASSESSED
    assert "no parser" in state["unassessed_reason"]


def test_unrecognized_framework_is_unassessed() -> None:
    state = controls.evaluate(finding(), graph(), set())
    assert state["state"] == controls.STATE_UNASSESSED
    assert "no framework was recognized" in state["unassessed_reason"]


def test_framework_without_such_a_control_is_absent_not_unassessed() -> None:
    """A determined answer produces no coverage gap (Edge Cases)."""
    state = controls.evaluate(finding(cwe="CWE-89"), graph(), {"angular"})
    assert state["state"] == controls.STATE_ABSENT


def test_framework_that_does_not_escape_by_default_is_unassessed() -> None:
    """Jinja2 autoescaping is off unless configured — presence proves nothing."""
    state = controls.evaluate(finding(), graph(), {"jinja2"})
    assert state["state"] == controls.STATE_UNASSESSED
    assert "does not escape by default" in state["unassessed_reason"]


# --------------------------------------------------------------- calibration


def test_credited_control_reduces_severity_and_reframes_impact() -> None:
    """FR-023: no narrative may describe an impact the control prevents."""
    doc = finding(status="verified")
    doc["framework_control"] = {
        "state": controls.STATE_CREDITED,
        "control": "angular-dom-sanitizer",
    }
    calibrate_mod.apply_calibration([doc])
    assert doc["severity_score"] < 6.1
    assert doc["calibration"]["caps_applied"][0]["rule"] == "framework-control-credited"
    assert "Script execution" not in doc["impact"]
    assert "sanitizer strips" in doc["impact"]


def test_unassessed_control_caps_confidence_without_inflating_severity() -> None:
    """FR-022c: an unknown is not evidence the control is missing."""
    doc = finding(status="verified")
    doc["framework_control"] = {"state": controls.STATE_UNASSESSED, "unassessed_reason": "why"}
    calibrate_mod.apply_calibration([doc])
    assert doc["severity_score"] == 6.1
    assert doc["confidence"] <= calibrate_mod.UNASSESSED_CONFIDENCE_CEILING


def test_unproven_finding_cannot_outrank_a_verified_one() -> None:
    """FR-020, the post-condition stated as a property of the scan."""
    proven = finding(status="verified")
    proven["id"] = "SEC-0002"
    proven["severity_score"] = 7.0
    unproven = finding(status="plausible", gap="no externally controllable source could be traced")
    unproven["severity_score"] = 9.8
    calibrate_mod.apply_calibration([proven, unproven])
    assert unproven["severity_score"] < proven["severity_score"]
    calibrate_mod.assert_ranking_invariant([proven, unproven])


def test_severity_is_left_alone_when_nothing_was_verified() -> None:
    """A blanket 'unproven means Low' would invent a false-negative class.

    With nothing verified there is nothing to outrank, so only confidence is
    capped — otherwise genuine findings drop below the profile threshold and
    vanish from the report, which is the same error pointing the other way.
    """
    doc = finding(status="plausible", gap="no externally controllable source could be traced")
    doc["severity_score"] = 8.2
    calibrate_mod.apply_calibration([doc])
    assert doc["severity_score"] == 8.2
    assert doc["confidence"] <= calibrate_mod.UNCONFIRMED_CONFIDENCE_CEILING


def test_no_record_when_nothing_was_capped() -> None:
    doc = finding(status="verified")
    doc["confidence"] = 0.4
    doc["framework_control"] = {"state": controls.STATE_ABSENT}
    calibrate_mod.apply_calibration([doc])
    assert "calibration" not in doc


def test_ranking_invariant_detects_a_failure() -> None:
    proven = finding(status="verified")
    proven["severity_score"] = 5.0
    unproven = finding(status="plausible", gap="no externally controllable source")
    unproven["severity_score"] = 9.0
    with pytest.raises(AssertionError):
        calibrate_mod.assert_ranking_invariant([proven, unproven])


# ------------------------------------------------------------ host ownership


WORKSPACE = {
    "members": [{"name": "web"}, {"name": "api"}],
    "integrations": [
        {"from_repo": "web", "to_repo": "api", "endpoints_or_channels": ["https://api.internal/v1"]}
    ],
}


def test_sibling_member_host_is_internal() -> None:
    """FR-024a: no third-party trust finding for a host we own."""
    verdict = hosts.classify("api", WORKSPACE)
    assert verdict.ownership == hosts.INTERNAL
    assert verdict.reportable is False


def test_declared_integration_host_is_internal() -> None:
    assert hosts.classify("api.internal", WORKSPACE).ownership == hosts.INTERNAL


def test_unowned_host_is_external() -> None:
    verdict = hosts.classify("node-hnapi.herokuapp.com", WORKSPACE)
    assert verdict.ownership == hosts.EXTERNAL
    assert verdict.reportable is True


def test_loopback_is_internal() -> None:
    assert hosts.classify("127.0.0.1", WORKSPACE).ownership == hosts.INTERNAL


def test_undetermined_ownership_defaults_to_external() -> None:
    """FR-024b: an unknown never silently exempts a host.

    Note the deliberate asymmetry with applicability: there an unknown retains a
    finding by not suppressing, here by defaulting to external. Same rule — an
    unknown never buys silence.
    """
    verdict = hosts.classify("some-host.example", {})
    assert verdict.ownership == hosts.EXTERNAL
    assert "could not be determined" in verdict.reason


def test_hosts_are_extracted_from_source() -> None:
    text = 'const base = "https://node-hnapi.herokuapp.com"; // see https://docs.example.com'
    assert hosts.extract_hosts(text) == {"node-hnapi.herokuapp.com"}
