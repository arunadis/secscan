"""Feature 017 T011 (US2, FR-004): a real scan report folds the client-asserted-
identity family around the trust-point anchor (provenance contract §family)."""

from __future__ import annotations

import json
from pathlib import Path

from tests.fixtures import header_identity_app

_EMPTY = json.dumps({"needs_escalation": False, "escalation_reason": "", "findings": []})


def _answer(request) -> str:
    """Report the same weakness family on a route file that exists in the fixture
    (pack anchors at the middleware; model reports the route-side usage)."""
    payload = request.payload or {}
    sources = payload.get("source") or {}
    key = next((k for k in sources if "routes/clients.js" in k), None)
    if key is None:
        return _EMPTY
    return json.dumps(
        {
            "needs_escalation": False,
            "escalation_reason": "",
            "findings": [
                {
                    "cwe": "CWE-290",
                    "severity_score": 8.5,
                    "confidence": 0.8,
                    # file named exactly as the packet names it; repo resolved by
                    # normalization against the code model's default member
                    "location": {
                        "file": key,
                        "symbol": "router",
                        "line_start": 9,
                        "line_end": 12,
                    },
                    "description": (
                        "Every query scopes by req.userEmail, populated from the "
                        "x-user-email header — trust flows from the header."
                    ),
                    "evidence": [
                        {
                            "file": key,
                            "symbol": "router",
                            "reason": (
                                "router.use(authenticateUser) gates these queries "
                                "on the x-user-email header"
                            ),
                        }
                    ],
                    "attack_scenario": "Set the header to a victim's email.",
                    "impact": "Cross-tenant access.",
                    "recommendation": "Verify a credential in the middleware before dispatch.",
                }
            ],
        }
    )


def test_report_folds_the_family_around_the_anchor(tmp_path: Path) -> None:
    header_identity_app.build(tmp_path)
    from pipeline import run as run_mod
    from tests.integration.conftest import write_config

    write_config(tmp_path)
    result = run_mod.run_scan(tmp_path, responder=_answer)

    rendered = Path(result.report_path).read_text()
    assert "**Related findings**" in rendered  # anchor block lists the family
    assert "part of the" in rendered and "family" in rendered  # dependent links back
    identity = next(
        f
        for f in result.findings
        if f["cwe"] == "CWE-290" and f["location"].get("symbol") == "authenticateUser"
    )
    anchor_id = identity["id"]
    dependents = [
        f
        for f in result.findings
        if any(
            r.get("type") == "dependent" and r.get("target_id") == anchor_id
            for r in f.get("relationships") or []
        )
    ]
    assert dependents, (
        "no dependent link formed — model finding and pack anchor never joined "
        "the same identity-channel family"
    )


def test_anchor_is_the_pack_origin_not_the_model() -> None:
    """Anchor selection ties to provenance, not to accidental scan order."""
    import copy

    from pipeline.correlate_findings import correlate
    from tests.unit.test_family_grouping import BACKEND, FRONTEND

    # report the frontend first; the pack record must still anchor
    findings = [copy.deepcopy(FRONTEND), copy.deepcopy(BACKEND)]
    findings[0]["id"] = "SEC-0001"
    findings[1]["id"] = "SEC-0002"
    out = correlate(findings)
    dependents = [
        f
        for f in out
        if any(r.get("type") == "dependent" for r in f.get("relationships") or [])
    ]
    assert len(dependents) == 1
    assert dependents[0]["id"] == "SEC-0001"  # the frontend client
    anchor = next(f for f in out if f["id"] == "SEC-0002")
    assert anchor["tool_ref"].startswith("identity-archetype@")
