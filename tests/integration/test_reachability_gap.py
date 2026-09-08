"""Feature 016 T020 (US2): unwired substrate declares the reachability gap,
and presence-confirmed missing-auth findings demote while it is active
(contracts/traceability-contract.md §1.3/§3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline import build_code_graph, dataflow, discover_repo
from pipeline.state import ArtifactStore
from pipeline.verify import apply_verification
from tests.fixtures import unwired_connectivity_app


@pytest.fixture()
def substrate(tmp_path: Path) -> tuple[dict, list]:
    app_root = unwired_connectivity_app.build(tmp_path)
    store = ArtifactStore(tmp_path)
    workspace = discover_repo.run(
        store, [{"name": app_root.name, "path": app_root.name}], []
    )
    graph = build_code_graph.run(store, workspace)
    flows = dataflow.trace_flows(graph)
    return graph, flows


def test_fixture_guarantees_zero_connectivity(substrate) -> None:
    graph, flows = substrate
    assert unwired_connectivity_app.GROUND_TRUTH["zero_traced_flows"]
    assert flows == []
    assert dataflow.reachability_unconfirmed(graph, flows)


def test_gap_note_carries_counts_and_guidance(substrate) -> None:
    graph, flows = substrate
    note = dataflow.reachability_gap_note(graph, flows)
    assert note is not None
    assert unwired_connectivity_app.GROUND_TRUTH["coverage_note_contains"] in note
    assert "entry point(s)" in note and "security-relevant operation(s)" in note
    assert "presence-confirmed verdicts" in note


def test_gap_is_silent_when_tracing_connects(tmp_path: Path) -> None:
    from tests.fixtures import header_identity_app

    app_root = header_identity_app.build(tmp_path)
    store = ArtifactStore(tmp_path)
    workspace = discover_repo.run(
        store, [{"name": app_root.name, "path": app_root.name}], []
    )
    graph = build_code_graph.run(store, workspace)
    flows = dataflow.trace_flows(graph)
    assert dataflow.reachability_gap_note(graph, flows) is None


def test_missing_auth_presence_finding_demotes_under_the_gap(substrate) -> None:
    graph, flows = substrate
    repo = graph["nodes"][0]["repo"]
    finding = {
        "id": "SEC-0001",
        "cwe": "CWE-306",
        "detection": "format",
        "location": {"repo": repo, "file": "src/app.py", "symbol": "create_order"},
        "evidence": [],
    }
    kept, disproven = apply_verification([finding], graph, flows)
    assert not disproven
    assert kept[0]["verification"]["status"] == "plausible"
    assert "reachability unconfirmed" in kept[0]["verification"]["gap"]


def test_secret_presence_finding_holds_verified_under_the_gap(substrate) -> None:
    graph, flows = substrate
    repo = graph["nodes"][0]["repo"]
    finding = {
        "id": "SEC-0002",
        "cwe": "CWE-798",
        "detection": "format",
        "location": {"repo": repo, "file": "src/app.py", "symbol": "list_orders"},
        "evidence": [],
    }
    kept, _ = apply_verification([finding], graph, flows)
    assert kept[0]["verification"]["status"] == "verified"
    assert kept[0]["verification"]["basis"] == "presence"
