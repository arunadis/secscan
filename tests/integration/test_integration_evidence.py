"""Feature 014 T008: integration evidence end to end (FR-004).

The stale-Firebase-rules class from the cross-check, in deterministic form: a
misconfiguration finding for middleware the member never integrated must carry
`integration.state == "no-integration-found"`, declare it, and lead remediation
with removal — while still being reported.
"""

from __future__ import annotations

import json
from pathlib import Path

from pipeline import run as run_mod
from tests.integration.conftest import silent_responder, write_config


def test_misconfig_findings_carry_integration_state(tmp_path: Path) -> None:
    from tests.fixtures import misconfig_integration

    workspace = misconfig_integration.build(tmp_path)
    write_config(workspace)
    run_mod.run_scan(workspace, responder=silent_responder, full=True)

    correlated = json.loads(
        (workspace / ".secscan" / "findings" / "correlated.json").read_text()
    )["payload"]["findings"]
    misconfig_findings = [
        f for f in correlated if str(f.get("tool_ref", "")).startswith("misconfig:")
    ]
    assert misconfig_findings, "the fixture's CORS snippet produced no misconfig finding"

    for finding in misconfig_findings:
        block = finding.get("integration") or {}
        assert block.get("state") in ("integrated", "no-integration-found", "undetermined"), (
            f"{finding['id']}: misconfig finding is silent on integration"
        )

    cors = [f for f in misconfig_findings if "cors" in str(f.get("tool_ref", ""))]
    assert cors, "no CORS misconfig finding"
    block = cors[0]["integration"]
    assert block["state"] == "no-integration-found", block
    assert "remove" in cors[0]["recommendation"].lower()
    assert cors[0].get("status") != "rejected", "no-integration-found must not suppress"
