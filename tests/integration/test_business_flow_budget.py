"""T042: depth-ceiling degradation (feature 015, FR-012, US4; SC-005).

A flow still undetermined at the profile's escalation ceiling is declared with the
ceiling named as the reason — never over-run, never silently truncated, and the
scan completes with the rest of its findings intact. Oversized packets (budget can
never fit the smallest slice) are likewise declared and skipped.
"""

from __future__ import annotations

import json
from pathlib import Path

from pipeline import run as run_mod
from pipeline.budget import TokenBudget
from pipeline.business_flow import FlowRound
from pipeline.state import ArtifactStore
from tests.fixtures.flow_app import build
from tests.integration.conftest import oracle_responder, write_config


def _always_undetermined(request) -> str:
    """Flow answers: undetermined at every level; segments: shared oracle."""
    payload = request.payload
    if "flow" in payload:
        return json.dumps(
            {
                "flow_id": payload["flow"]["id"],
                "assessment": "undetermined",
                "undetermined_reasons": ["actor posture cannot be established from the packet"],
            }
        )
    return oracle_responder(request)


def test_depth_ceiling_is_named_not_silent(tmp_path: Path):
    root = build(tmp_path)
    write_config(root, {"business_flow": {"enabled": True}})
    result = run_mod.run_scan(root, responder=_always_undetermined, full=True)
    flows_doc = ArtifactStore(result.scan_root).read("business-flows.json")

    undetermined = flows_doc["coverage"]["undetermined"]
    assert len(undetermined) == len(flows_doc["coverage"]["reconstructed"])
    for entry in undetermined:
        assert entry["reasons"], "undetermined without a stated reason is a defect"
        assert any("ceiling" in reason for reason in entry["reasons"])

    # The rest of the scan is unaffected: code-level findings still report.
    assert json.dumps(result.report["findings_by_band"])  # report materialized
    assert result.report.get("flow_coverage", {}).get("undetermined")


def test_oversized_packet_is_declared_never_sent():
    """Smallest slice bigger than the budget ⇒ declared oversized, nothing sent."""
    from pipeline.usage import UsageTracker

    class NoopClient:
        calls = 0

        def run(self, request):
            NoopClient.calls += 1
            raise AssertionError("over-budget packets must never be sent")

    flow = {
        "id": "flow:ws:huge",
        "name": "/big",
        "actor": {"kind": "anonymous", "determination": "inferred"},
        "partial": False,
        "steps": [
            {
                "node_id": "shop:src/app.py#@/big",
                "operation": "entry",
                "annotations": [],
                "data_categories": [],
            }
        ],
    }
    budget = TokenBudget(
        max_context_tokens=1, max_output_tokens=1, escalation_threshold=0.75
    )
    result = FlowRound(
        client=NoopClient(), usage=UsageTracker(), budget=budget
    ).run([flow])
    assert result.oversized == {"flow:ws:huge": "budget-ceiling"}
    assert NoopClient.calls == 0
