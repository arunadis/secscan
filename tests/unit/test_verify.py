"""T010: the CWE-798 auto-verify shortcut applies only to format detections.

Contract C4 / research R4: "presence in source is itself the finding" holds only
when presence is confirmed by a known credential format. A heuristic-only match
takes the standard trace path and cannot come out `verified` without one.
"""

from __future__ import annotations

from pipeline.dataflow import trace_flows
from pipeline.verify import apply_verification

_GRAPH = {
    "nodes": [
        {"id": "repo:src/main/Auth.java", "repo": "repo", "path": "src/main/Auth.java",
         "type": "file"}
    ]
}


def _finding(detection: str | None) -> dict:
    finding = {
        "cwe": "CWE-798",
        "location": {"repo": "repo", "file": "src/main/Auth.java", "line_start": 10},
    }
    if detection is not None:
        finding["detection"] = detection
    return finding


def test_format_detection_auto_verifies() -> None:
    kept, _ = apply_verification([_finding("format")], _GRAPH, [])
    assert kept[0]["verification"]["status"] == "verified"


def test_heuristic_detection_cannot_auto_verify() -> None:
    kept, _ = apply_verification([_finding("heuristic")], _GRAPH, [])
    verdict = kept[0]["verification"]
    assert verdict["status"] == "plausible"
    assert verdict.get("gap")


def test_analysis_findings_without_provenance_auto_verify_as_before() -> None:
    """Backward compatibility: LLM-stage CWE-798 findings carry no `detection`."""
    kept, _ = apply_verification([_finding(None)], _GRAPH, [])
    assert kept[0]["verification"]["status"] == "verified"


# ---------------------------------------------------------- feature 016
# A guard implicated by the finding can never refute it: verification would
# otherwise turn "this authentication is fake" into its own disproof.


_FLOW_GRAPH = {
    "nodes": [
        {"id": "repo:src/routes.py", "repo": "repo", "path": "src/routes.py",
         "type": "file", "annotations": ["trust_boundary", "user_controlled_input"],
         "symbol": "list_clients"},
        {"id": "repo:src/middleware.py#auth", "repo": "repo", "path": "src/middleware.py",
         "type": "function", "symbol": "auth",
         "annotations": ["authentication_required"]},
        {"id": "repo:<datastore>:execute", "repo": "repo", "path": "<datastore>",
         "type": "datastore", "symbol": "execute", "annotations": []},
    ],
    "edges": [
        {"from": "repo:src/routes.py", "to": "repo:src/middleware.py#auth", "type": "calls"},
        {"from": "repo:src/middleware.py#auth",
         "to": "repo:<datastore>:execute", "type": "calls"},
    ],
}


def _auth_finding(**extra) -> dict:
    finding = {
        "cwe": "CWE-306",
        "location": {"repo": "repo", "file": "src/routes.py", "symbol": "list_clients"},
        "evidence": [],
    }
    finding.update(extra)
    return finding


def test_implicated_guard_cannot_disprove_the_finding() -> None:
    kept, disproven = apply_verification(
        [_auth_finding(evidence=[{"file": "src/middleware.py", "symbol": "auth",
                                  "reason": "auth() accepts any header without a credential"}])],
        _FLOW_GRAPH,
        trace_flows(_FLOW_GRAPH),
    )
    assert not disproven
    assert kept[0]["verification"]["status"] in ("verified", "plausible")


def test_implicated_guard_via_related_symbols_cannot_disprove_either() -> None:
    kept, disproven = apply_verification(
        [_auth_finding(related_symbols=["src/middleware.py#auth"])], _FLOW_GRAPH,
        trace_flows(_FLOW_GRAPH)
    )
    assert not disproven
    assert kept[0]["verification"]["status"] in ("verified", "plausible")


def test_independent_control_still_disproves() -> None:
    """A control the finding does NOT implicate, on the traced path, refutes."""
    graph = {
        "nodes": [
            _FLOW_GRAPH["nodes"][0],
            {"id": "repo:src/guard.py#verify_jwt", "repo": "repo",
             "path": "src/guard.py", "type": "function", "symbol": "verify_jwt",
             "annotations": ["authentication_required"]},
            _FLOW_GRAPH["nodes"][2],
        ],
        "edges": [
            {"from": "repo:src/routes.py", "to": "repo:src/guard.py#verify_jwt",
             "type": "calls"},
            {"from": "repo:src/guard.py#verify_jwt",
             "to": "repo:<datastore>:execute", "type": "calls"},
        ],
    }
    kept, disproven = apply_verification([_auth_finding()], graph, trace_flows(graph))
    assert not kept
    assert disproven[0]["verification"]["status"] == "disproven"


# ---------------------------------------------------------- feature 016 / US2
# FR-008/FR-009: presence vs traced basis, and demotion while the run-level
# reachability gap is active (contracts/traceability-contract.md §1).


def test_presence_basis_on_no_flow_presence_verdict() -> None:
    kept, _ = apply_verification([_finding("format")], _GRAPH, [])
    assert kept[0]["verification"]["basis"] == "presence"


def test_traced_basis_on_flow_verified() -> None:
    # CWE-89 is outside the authn/authz disprove set, so a complete traced
    # path verifies — the verdict must record that a path was walked.
    finding = _auth_finding(cwe="CWE-89")
    kept, _ = apply_verification([finding], _FLOW_GRAPH, trace_flows(_FLOW_GRAPH))
    assert kept[0]["verification"]["status"] == "verified"
    assert kept[0]["verification"]["basis"] == "traced"


def test_reachability_gap_demotes_cwe_306_presence_findings() -> None:
    graph = {"nodes": _FLOW_GRAPH["nodes"], "edges": _FLOW_GRAPH["edges"]}
    # sever the trail: no flow can be traced, so the gap is active
    graph["edges"] = []
    finding = _auth_finding(detection="format")
    kept, _ = apply_verification(
        [finding], graph, trace_flows(graph), reachability_unconfirmed=True
    )
    assert kept[0]["verification"]["status"] == "plausible"
    assert "reachability unconfirmed" in kept[0]["verification"]["gap"]


def test_presence_native_classes_hold_their_verdict_under_the_gap() -> None:
    for cwe_id in ("CWE-798", "CWE-522", "CWE-352"):
        finding = {"cwe": cwe_id, "detection": "format",
                   "location": {"repo": "repo", "file": "src/main/Auth.java"}}
        kept, _ = apply_verification(
            [finding], _GRAPH, [], reachability_unconfirmed=True
        )
        assert kept[0]["verification"]["status"] == "verified", cwe_id
        assert kept[0]["verification"]["basis"] == "presence", cwe_id


def test_flag_defaults_to_computation_from_graph_and_flows() -> None:
    """Standalone/resume parity (contracts §3): no flag plumbing required."""
    from pipeline.verify import apply_verification as apply_v

    endpoint = {
        "id": "repo:src/routes.py#@GET /clients",
        "repo": "repo",
        "path": "src/routes.py",
        "type": "endpoint",
        "route": "GET /clients",
        "annotations": ["trust_boundary", "user_controlled_input"],
    }
    graph = {"nodes": [*_FLOW_GRAPH["nodes"], endpoint], "edges": []}
    finding = _auth_finding(detection="format")
    kept, _ = apply_v([finding], graph, [])
    assert kept[0]["verification"]["status"] == "plausible"


# ---------------------------------------------------------- feature 017 / US1
# FR-001: CWE-290 joins the presence-verified classes, including the
# reachability-gap demotion parity with CWE-306.


def test_cwe290_format_presence_verifies_without_a_flow() -> None:
    finding = {"cwe": "CWE-290", "detection": "format",
               "location": {"repo": "repo", "file": "src/main/Auth.java",
                            "line_start": 10}}
    kept, _ = apply_verification([finding], _GRAPH, [])
    assert kept[0]["verification"]["status"] == "verified"
    assert kept[0]["verification"]["basis"] == "presence"


def test_cwe290_demotes_under_active_reachability_gap() -> None:
    finding = {"cwe": "CWE-290", "detection": "format",
               "location": {"repo": "repo", "file": "src/main/Auth.java",
                            "line_start": 10}}
    kept, _ = apply_verification(
        [finding], _GRAPH, [], reachability_unconfirmed=True
    )
    assert kept[0]["verification"]["status"] == "plausible"
    assert "reachability unconfirmed" in kept[0]["verification"]["gap"]


def test_cwe290_heuristic_detection_stays_on_the_trace_path() -> None:
    finding = {"cwe": "CWE-290", "detection": "heuristic",
               "location": {"repo": "repo", "file": "src/main/Auth.java",
                            "line_start": 10}}
    kept, _ = apply_verification([finding], _GRAPH, [])
    # heuristic doubt ⇒ never presence-verified; plausible with the reachability gap
    assert kept[0]["verification"]["status"] == "plausible"
