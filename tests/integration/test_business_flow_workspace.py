"""T020: multi-repo business-flow stitching end to end (feature 015, FR-015/016).

web -> api is a DECLARED sync-api integration, so those steps stitch into one flow
with per-step repo attribution. api -> worker is UNDECLARED, so any flow touching it
is partial with gap_reason "integration-undeclared" — declared, never inferred.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import run as run_mod
from pipeline.state import ArtifactStore
from tests.fixtures.flow_workspace import DECLARED_INTEGRATIONS, GROUND_TRUTH, build
from tests.integration.conftest import oracle_responder, write_config


def _flow_oracle(request) -> str:
    """Answer flow-analysis requests as clean; segment packets via the oracle."""
    payload = request.payload
    if "flow" in payload:
        return json.dumps(
            {"flow_id": payload["flow"]["id"], "assessment": "clean", "findings": []}
        )
    return oracle_responder(request)


@pytest.fixture
def workspace_repo(tmp_path: Path) -> Path:
    root = build(tmp_path)
    write_config(
        root,
        {
            "workspace": {
                "members": [
                    {"name": name, "path": name}
                    for name in sorted(GROUND_TRUTH["members"])
                ],
                "integrations": DECLARED_INTEGRATIONS,
            },
            "business_flow": {"enabled": True},
        },
    )
    return root


def test_declared_integration_stitches_flow(workspace_repo: Path):
    """FR-015: web -> api (declared sync-api) stitches into one flow, and every
    step keeps its repo attribution."""
    result = run_mod.run_scan(workspace_repo, responder=_flow_oracle, full=True)
    flows_doc = ArtifactStore(result.scan_root).read("business-flows.json")

    multi_repo_flows = [
        flow
        for flow in flows_doc["flows"]
        if len({s["node_id"].split(":", 1)[0] for s in flow["steps"]}) > 1
    ]
    assert multi_repo_flows, "expected at least one flow stitched across web -> api"
    for flow in multi_repo_flows:
        repos = {s["node_id"].split(":", 1)[0] for s in flow["steps"]}
        assert repos == GROUND_TRUTH["stitched_repos_in_flow"]
        legs = [s["integration_leg"] for s in flow["steps"] if s.get("integration_leg")]
        assert legs and all(leg["type"] == "sync-api" for leg in legs)


def test_undeclared_hop_is_partial_and_declared(workspace_repo: Path):
    """FR-016: api -> worker is undeclared, so no worker steps stitch, and the
    affected flow is declared partial with the exact machine-readable reason."""
    result = run_mod.run_scan(workspace_repo, responder=_flow_oracle, full=True)
    flows_doc = ArtifactStore(result.scan_root).read("business-flows.json")

    # Worker's own flow (rooted in worker) legitimately has worker steps; what
    # must NOT exist is worker steps stitched into another repo's flow via the
    # undeclared hop.
    foreign_flows_with_worker_steps = [
        flow["id"]
        for flow in flows_doc["flows"]
        if not flow["steps"][0]["node_id"].startswith("worker:")
        and any(step["node_id"].startswith("worker:") for step in flow["steps"])
    ]
    assert not foreign_flows_with_worker_steps

    partial = {
        entry["flow_id"]: entry["gap_reasons"]
        for entry in flows_doc["coverage"]["partial"]
    }
    assert partial, "expected at least one partial flow"
    assert any(
        GROUND_TRUTH["partial_reason"] in reasons for reasons in partial.values()
    )
