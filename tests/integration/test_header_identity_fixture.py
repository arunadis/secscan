"""Feature 016 T012 (US1): the reference miss becomes visible in the graph.

Stages 1–3 over the header-identity fixture: wiring registrations must produce
real edges, the header-reading middleware must read as an attacker-controlled
source, and flow tracing must connect an endpoint through the guard to a store.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline import build_code_graph, dataflow, discover_repo
from pipeline.state import ArtifactStore
from tests.fixtures import header_identity_app


@pytest.fixture()
def graph(tmp_path: Path) -> dict:
    app_root = header_identity_app.build(tmp_path)
    store = ArtifactStore(tmp_path)
    workspace = discover_repo.run(
        store, [{"name": app_root.name, "path": app_root.name}], []
    )
    return build_code_graph.run(store, workspace)


def _edges(graph: dict, kind: str) -> set[tuple[str, str]]:
    return {(e["from"], e["to"]) for e in graph["edges"] if e["type"] == kind}


def test_wiring_registrations_produce_handler_edges_to_the_guard(graph: dict) -> None:
    handlers = _edges(graph, "handler")
    guard = "header-identity-app:src/middleware/auth.js#authenticateUser"
    for file, _name in header_identity_app.GROUND_TRUTH["wired_edges"]:
        assert any(
            source.startswith(f"header-identity-app:{file}#@") and target
            in {
                guard,
                "header-identity-app:src/middleware/verifyJwt.js#verifyJwt",
            }
            for source, target in handlers
        ), f"no endpoint→guard edge for {file}"


def test_header_reading_middleware_is_an_attacker_controlled_source(graph: dict) -> None:
    guard = next(
        n
        for n in graph["nodes"]
        if n.get("id") == "header-identity-app:src/middleware/auth.js#authenticateUser"
    )
    for annotation in (
        "user_controlled_input",
        "authentication_required",
        "security_sink",
    ):
        assert annotation in guard["annotations"]


def test_convenience_driver_calls_open_datastore_edges(graph: dict) -> None:
    assert any(
        target.startswith("header-identity-app:<datastore>#")
        for _, target in _edges(graph, "writes")
    )


def test_a_flow_connects_endpoint_through_guard_to_store(graph: dict) -> None:
    flows = dataflow.trace_flows(graph)
    guard = "header-identity-app:src/middleware/auth.js#authenticateUser"
    through_guard = [flow for flow in flows if guard in flow.path]
    assert through_guard, "no traced flow passes through the middleware"
    assert any(flow.complete for flow in through_guard)


def test_real_credential_guard_never_reads_as_unattached(graph: dict) -> None:
    node = next(
        n
        for n in graph["nodes"]
        if n.get("symbol") == "verifyJwt" and n.get("type") == "function"
    )
    assert "unattached_security_guard" not in node.get("annotations", [])


# ------------------------------------------------------------------- US4 scan


def test_full_scan_reports_the_trust_function_and_never_the_safe_pattern(
    tmp_path: Path,
) -> None:
    """FR-014 end to end: the deterministic archetype survives every downstream
    stage — including the triage round — at the trust point itself."""
    from pipeline import run as run_mod
    from tests.integration.conftest import oracle_responder, silent_responder, write_config

    header_identity_app.build(tmp_path)
    scan_root = tmp_path
    write_config(scan_root)
    result = run_mod.run_scan(
        scan_root,
        responder=lambda request: oracle_responder(request) or silent_responder(request),
    )
    truth = header_identity_app.GROUND_TRUTH["anchor_finding"]
    anchor = [
        f
        for f in result.findings
        if f["cwe"] == truth["cwe"]
        and f["location"].get("symbol") == truth["symbol"]
        and f["location"]["file"].endswith(truth["file"])
    ]
    locations = [
        (f["cwe"], f["location"].get("file"), f["location"].get("symbol"))
        for f in result.findings
    ]
    assert anchor, f"CWE-290 anchor finding missing — reproduced the original miss: {locations}"
    assert anchor[0].get("detection") == "format"
    assert anchor[0]["verification"]["status"] == "verified"
    # weak wiring exists → the flow endpoint → guard → store is real: traced is
    # the stronger basis; presence would only appear when the flow is absent.
    assert anchor[0]["verification"]["basis"] in ("traced", "presence")
    unsafe_names = tuple(header_identity_app.GROUND_TRUTH["safe_symbols"])
    assert not any(
        f["location"].get("symbol") in unsafe_names for f in result.findings
    )
