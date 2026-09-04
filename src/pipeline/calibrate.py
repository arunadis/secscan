"""Verification-aware severity and confidence calibration (FR-020, FR-023).

Analysis proposes a severity from what the code looks like. This stage adjusts it
for what the pipeline actually *established*, and records why. The reviewed
benchmark scan is the argument for its existence: two findings filed at 4.3
(Medium), neither verified end to end, one carrying confidence 0.85 while its own
verification note admitted reachability was unconfirmed. An independent reviewer
rated them Low and Informational.

The invariant worth stating plainly: after calibration, no unproven finding
outranks a proven one. Everything else here is bookkeeping in service of that.
"""

from __future__ import annotations

from typing import Any

from pipeline import controls, cwe

#: Confidence ceiling when reachability from an external source was never
#: confirmed. Unproven is not the same as unlikely, so severity is *not* given a
#: fixed ceiling — see `_severity_ceiling`.
UNCONFIRMED_CONFIDENCE_CEILING = 0.5

#: Gap kept between the weakest verified finding and the strongest unproven one.
_RANK_GAP = 0.1

#: Ceiling applied when framework-control state could not be established. The
#: severity is NOT raised - an unknown is not evidence the control is missing -
#: but the confidence must show that something material was not checked.
UNASSESSED_CONFIDENCE_CEILING = 0.6

#: How far a credited control pulls severity down. A control that stops script
#: execution but still permits markup injection has not made the finding vanish.
CREDITED_CONTROL_FACTOR = 0.5


def _reachability_unconfirmed(finding: dict[str, Any]) -> bool:
    verification = finding.get("verification") or {}
    if verification.get("status") == "verified":
        return False
    gap = str(verification.get("gap") or "")
    return "reachability" in gap or "externally controllable source" in gap or not gap


def _severity_ceiling(findings: list[dict[str, Any]]) -> float | None:
    """Highest severity an unproven finding may carry in this scan (FR-020).

    The requirement is *relative*: an unproven finding must not outrank a proven
    one. It deliberately is not "unproven means Low" — an absolute ceiling would
    push genuine findings below the profile's reporting threshold and invent a
    false-negative class, which is the same category of error, just pointing the
    other way. When nothing was verified there is nothing to outrank, so severity
    is left alone and only confidence is capped.
    """
    verified = [
        float(f.get("severity_score", 0.0))
        for f in findings
        if (f.get("verification") or {}).get("status") == "verified"
    ]
    return round(min(verified) - _RANK_GAP, 1) if verified else None


def calibrate(finding: dict[str, Any], severity_ceiling: float | None = None) -> dict[str, Any]:
    """Adjust severity and confidence in place; returns the calibration record."""
    proposed_severity = float(finding.get("severity_score", 0.0))
    proposed_confidence = float(finding.get("confidence", 0.0))
    severity = proposed_severity
    confidence = proposed_confidence
    caps: list[dict[str, str]] = []

    control = finding.get("framework_control") or {}
    state = control.get("state")

    if state == controls.STATE_CREDITED:
        reduced = round(severity * CREDITED_CONTROL_FACTOR, 1)
        if reduced < severity:
            caps.append(
                {
                    "rule": "framework-control-credited",
                    "reason": (
                        f"the framework's default control '{control.get('control')}' applies "
                        "on the traced path with no bypass, so the impact is limited to what "
                        "that control still permits"
                    ),
                }
            )
            severity = reduced

    elif state == controls.STATE_UNASSESSED:
        if confidence > UNASSESSED_CONFIDENCE_CEILING:
            caps.append(
                {
                    "rule": "framework-control-unassessed",
                    "reason": (
                        "whether a framework default control applies could not be "
                        f"established ({control.get('unassessed_reason', 'reason not recorded')}); "
                        "confidence is capped and severity is left unchanged rather than "
                        "inflated on the assumption that no control exists"
                    ),
                }
            )
            confidence = UNASSESSED_CONFIDENCE_CEILING

    # Feature 014 (FR-003, clarification Q1): an advisory with no usage evidence
    # caps confidence and reframes its narrative — but severity is NEVER adjusted
    # by usage, and the finding is NEVER suppressed.
    usage = finding.get("usage") or {}
    if usage.get("state") == "none-found" and confidence > UNCONFIRMED_CONFIDENCE_CEILING:
        caps.append(
            {
                "rule": "usage-none-found",
                "reason": (
                    "no import, config reference, or literal dynamic use of this package "
                    "was found in the affected member's source; the advisory applies only "
                    "if the package is exercised"
                ),
            }
        )
        confidence = min(confidence, UNCONFIRMED_CONFIDENCE_CEILING)

    if _reachability_unconfirmed(finding):
        over_severity = severity_ceiling is not None and severity > severity_ceiling
        if over_severity or confidence > UNCONFIRMED_CONFIDENCE_CEILING:
            caps.append(
                {
                    "rule": "plausible-unconfirmed-reachability",
                    "reason": (
                        "no externally controllable source was traced to this location, so "
                        "the finding is unproven and must not outrank one that was verified "
                        "end to end"
                    ),
                }
            )
            if severity_ceiling is not None:
                severity = min(severity, severity_ceiling)
            confidence = min(confidence, UNCONFIRMED_CONFIDENCE_CEILING)

    finding["severity_score"] = round(severity, 1)
    finding["severity_band"] = cwe.band_for(finding["severity_score"])
    finding["confidence"] = round(confidence, 2)

    record: dict[str, Any] = {}
    if caps:
        record = {
            "proposed_severity": round(proposed_severity, 1),
            "proposed_confidence": round(proposed_confidence, 2),
            "caps_applied": caps,
        }
        finding["calibration"] = record
    return record


def reframe_for_control(finding: dict[str, Any]) -> None:
    """Rewrite the narrative to the residual risk a credited control permits (FR-023).

    Without this, a finding can carry a reduced severity beside an impact
    paragraph describing the very outcome the control prevents — the report
    contradicting itself in the one place a reader looks first.
    """
    control = finding.get("framework_control") or {}
    if control.get("state") != controls.STATE_CREDITED:
        return
    control_id = str(control.get("control", ""))
    residual = ""
    for framework in controls.frameworks():
        residual = controls.residual_impact(framework["id"], control_id)
        if residual:
            break
    if not residual:
        return
    finding["impact"] = (
        f"{residual} The originally proposed impact is not achievable while this control "
        f"is in place; what remains is described above."
    )


def reframe_for_usage(finding: dict[str, Any]) -> None:
    """Conditional narrative for an advisory with no usage evidence (FR-003).

    The finding stands — an unused vulnerable package stays reported — but the
    narrative must not assert an exploitation chain no evidence supports.
    """
    usage = finding.get("usage") or {}
    if usage.get("state") != "none-found":
        return
    dependency = finding.get("dependency") or {}
    package = str(dependency.get("package") or "the package")
    members = dependency.get("affected_members") or []
    where = f"member '{members[0]}'" if members else "the scanned source"
    original_impact = str(finding.get("impact") or "")
    finding["attack_scenario"] = (
        f"No import or reference to {package} was found in {where}. Exploitation "
        "presupposes the vulnerable code path executes; that precondition was "
        "not established in the scanned source."
    )
    finding["impact"] = (
        f"{original_impact} No usage of {package} was found in {where}, so this "
        "impact applies only if the package is exercised at runtime — verify "
        "whether it ships in the deployed artifact before prioritizing."
    )


def apply_calibration(findings: list[dict[str, Any]]) -> None:
    """Calibrate every finding in place, then reframe credited-control narratives.

    The severity ceiling is computed across the whole set first, because "must not
    outrank a verified finding" is a property of the scan, not of one finding.
    """
    ceiling = _severity_ceiling(findings)
    for finding in findings:
        calibrate(finding, ceiling)
        reframe_for_control(finding)
        reframe_for_usage(finding)


def assert_ranking_invariant(findings: list[dict[str, Any]]) -> None:
    """Raise when an unproven finding outranks a proven one (FR-020 post-condition)."""
    verified = [
        float(f["severity_score"])
        for f in findings
        if (f.get("verification") or {}).get("status") == "verified"
    ]
    unproven = [
        float(f["severity_score"])
        for f in findings
        if (f.get("verification") or {}).get("status") != "verified"
        and _reachability_unconfirmed(f)
    ]
    if verified and unproven and max(unproven) >= min(verified):
        raise AssertionError(
            f"calibration failed: an unproven finding scores {max(unproven)} while a "
            f"verified one scores {min(verified)}"
        )
