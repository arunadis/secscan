"""Feature 017 T002/T005 (US1): deterministic pack finding + model finding at the
same trust point — provenance must be preserved, and the deterministic record must
survive with its rule identity (contracts/provenance-and-families.md).

T002 reproduces the observed disappearance first: which pipeline seam absorbs the
pack finding? The failing assertion names it.
"""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.state import ArtifactStore
from tests.fixtures import header_identity_app

_CWE_290_ORACLE_ANSWER = {
    "needs_escalation": False,
    "escalation_reason": "",
    "findings": [],
}

_MODEL_ANSWER = {
    "needs_escalation": False,
    "escalation_reason": "",
    "findings": [
        {
            "cwe": "CWE-290",
            "severity_score": 9.1,
            "confidence": 0.8,
            "location": {
                "file": "src/middleware/auth.js",
                "symbol": "authenticateUser",
                "line_start": 4,
                "line_end": 5,
            },
            "description": (
                "The middleware trusts a client-supplied identity header "
                "without any credential (model-derived finding)."
            ),
            "evidence": [
                {
                    "file": "src/middleware/auth.js",
                    "symbol": "authenticateUser",
                    "reason": "reads identity from the request header and dispatches",
                }
            ],
            "attack_scenario": "The caller picks any identity.",
            "impact": "Impersonation.",
            "recommendation": "Verify a credential before dispatch.",
        }
    ],
}


def _answer(request) -> str:
    payload = request.payload or {}
    source_files = list((payload.get("source") or {}).keys())
    if any("middleware/auth.js" in f for f in source_files):
        answer = json.loads(json.dumps(_MODEL_ANSWER))
        for finding in answer["findings"]:
            repo = payload.get("repos") or ["header-identity-app"]
            finding["location"]["repo"] = repo[0]
            finding["evidence"][0]["repo"] = repo[0]
        return json.dumps(answer)
    return json.dumps(_CWE_290_ORACLE_ANSWER)


def test_pack_and_model_findings_at_one_trust_point_both_visible(tmp_path: Path) -> None:
    header_identity_app.build(tmp_path)
    from pipeline import run as run_mod
    from tests.integration.conftest import write_config

    write_config(tmp_path)
    result = run_mod.run_scan(tmp_path, responder=_answer)

    anchor_location = (
        "src/middleware/auth.js",
        "authenticateUser",
    )
    hits = [
        f
        for f in result.findings
        if f["cwe"] == "CWE-290"
        and f["location"]["file"].endswith(anchor_location[0])
        and f["location"].get("symbol") == anchor_location[1]
    ]
    assert hits, "no finding at the trust point at all"
    # The deterministic rule's provenance must be visible somewhere at the
    # trust point — either as its own record or as merged evidence naming it.
    deterministic_visible = any(
        f.get("detection") == "format"
        or "identity-archetype" in json.dumps(f.get("evidence") or [])
        or str(f.get("tool_ref") or "").startswith("identity-archetype")
        for f in hits
    )
    assert deterministic_visible, (
        "the deterministic pack finding vanished without provenance at the trust "
        f"point; records present: {[(f.get('detection'), f.get('tool_ref')) for f in hits]}"
    )


def test_findings_local_keeps_the_deterministic_record(tmp_path: Path) -> None:
    """Where the pack finding lives pre-correlation: findings/local identity."""
    header_identity_app.build(tmp_path)
    from pipeline import run as run_mod
    from tests.integration.conftest import write_config

    write_config(tmp_path)
    run_mod.run_scan(tmp_path, responder=_answer)
    store = ArtifactStore(tmp_path)
    names = sorted(store.glob("findings/local/*.json"))
    assert names, "no local findings persisted at all"
    locals_all = []
    for path in names:
        payload = store.read(f"findings/local/{path.name}")
        locals_all.extend(payload.get("findings") or [])
    deterministic = [
        f
        for f in locals_all
        if str(f.get("tool_ref") or "").startswith("identity-archetype")
    ]
    assert deterministic, (
        "the identity-archetype finding never entered the local finding set — "
        "evaluate_segment produced nothing or normalization rejected it"
    )
    assert deterministic[0].get("detection") == "format"
