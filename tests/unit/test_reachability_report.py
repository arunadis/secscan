"""Feature 016 T018/T019: reachability-gap trigger and summary wording
(contracts/traceability-contract.md §2/§3)."""

from __future__ import annotations

import copy

from pipeline.dataflow import reachability_unconfirmed, trace_flows
from pipeline.generate_report import build_report


def _endpoint_node() -> dict:
    return {
        "id": "app:src/api.py#@GET /x",
        "repo": "app",
        "path": "src/api.py",
        "type": "endpoint",
        "route": "GET /x",
        "annotations": ["trust_boundary", "user_controlled_input"],
    }


def _datastore_node() -> dict:
    return {
        "id": "app:<datastore>#execute",
        "repo": "app",
        "path": "<datastore>",
        "type": "datastore",
        "symbol": "execute",
    }


_DOMAIN = {
    "app": None,
}


def test_gap_fires_only_when_both_sides_exist_and_nothing_connects() -> None:
    both = {"nodes": [_endpoint_node(), _datastore_node()], "edges": []}
    assert reachability_unconfirmed(both, trace_flows(both))
    no_endpoints = {"nodes": [_datastore_node()], "edges": []}
    assert not reachability_unconfirmed(no_endpoints, [])
    no_data = {"nodes": [_endpoint_node()], "edges": []}
    assert not reachability_unconfirmed(no_data, [])
    connected = {
        "nodes": [_endpoint_node(), _datastore_node()],
        "edges": [{"from": _endpoint_node()["id"], "to": _datastore_node()["id"],
                   "type": "reads"}],
    }
    assert not reachability_unconfirmed(connected, trace_flows(connected))


def _report(findings: list[dict], coverage_overrides: dict | None = None) -> dict:
    from config.profiles import resolve

    findings_out = []
    for i, finding in enumerate(findings, start=1):
        f = copy.deepcopy(finding)
        f.setdefault("id", f"SEC-{i:04d}")
        f.setdefault("cwe", "CWE-798")
        f.setdefault("severity_score", 9.1)
        f.setdefault("severity_band", "Critical")
        f.setdefault("confidence", 0.9)
        f.setdefault(
            "location",
            {"repo": "app", "file": "src/x.py", "line_start": 1, "line_end": 1},
        )
        f.setdefault("description", "d")
        f.setdefault("evidence", [{"repo": "app", "file": "src/x.py", "reason": "r"}])
        f.setdefault("attack_scenario", "a")
        f.setdefault("impact", "i")
        f.setdefault("recommendation", "r")
        f.setdefault("status", "correlated")
        findings_out.append(f)
    from pipeline.usage import UsageTracker

    overrides = coverage_overrides or {}
    return build_report(
        scan_id="20260907T000000Z-deadbeef",
        workspace={"id": "ws-demo", "members": [{"name": "app"}]},
        execution_mode="agent-mediated",
        policy_source="default",
        profile=resolve("full"),
        findings=findings_out,
        usage=UsageTracker(),
        segments_analyzed=1,
        coverage_gaps=overrides.get("coverage_gaps"),
        gap_records=overrides.get("gap_records"),
        graph=overrides.get("graph"),
    )


def _verified_finding(basis: str) -> dict:
    return {
        "verification": {"status": "verified", "basis": basis,
                         "path": ["app:src/x.py#f"]},
    }


def test_summary_splits_traced_and_presence_counts() -> None:
    report = _report([_verified_finding("traced"), _verified_finding("presence")])
    summary = report["executive_summary"]
    assert "1 statically verified with a complete source-to-sink path" in summary
    assert "1 presence-confirmed" in summary


def test_no_complete_path_claim_for_presence_confirmed() -> None:
    report = _report([_verified_finding("presence")])
    summary = report["executive_summary"]
    assert "complete source-to-sink path" not in summary
    assert "presence-confirmed" in summary


def test_presence_only_summary_adds_the_qualifier() -> None:
    report = _report([_verified_finding("presence")])
    summary = report["executive_summary"]
    assert "reachability from an entry point was not traced" in summary


def test_zero_verified_summary_keeps_prior_honest_wording() -> None:
    """FR-041 wording must survive the basis split (feature 016 may not regress it)."""
    report = _report([{"verification": {"status": "plausible",
                                        "gap": "no externally controllable source"}}])
    summary = report["executive_summary"]
    assert "leads to confirm" in summary
    assert "traced end to end" not in summary
