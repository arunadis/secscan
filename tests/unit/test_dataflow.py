"""Feature 016 T007: Flow completeness reports construction truth.

Before this fix, ``complete`` compared node ids against display labels — endpoint
sources carry route labels (``GET /x [repo]``), never their node ids — so every
endpoint-anchored flow was silently "incomplete" and could never verify. Truncated
walks are never emitted by ``trace()`` (flows are built only at a sink), so a built
flow is complete by construction.
"""

from __future__ import annotations

from pipeline.dataflow import trace_flows


def _graph() -> dict:
    return {
        "nodes": [
            {
                "id": "shop:src/api/orders.py#@GET /orders",
                "repo": "shop",
                "path": "src/api/orders.py",
                "type": "endpoint",
                "symbol": "list_orders",
                "route": "GET /orders",
                "annotations": ["trust_boundary", "user_controlled_input"],
            },
            {
                "id": "shop:src/middleware/auth.py#authenticateUser",
                "repo": "shop",
                "path": "src/middleware/auth.py",
                "type": "function",
                "symbol": "authenticateUser",
                "annotations": ["authentication_required"],
            },
            {
                "id": "shop:<datastore>#get",
                "repo": "shop",
                "path": "<datastore>",
                "type": "datastore",
                "symbol": "get",
                "annotations": ["security_sink"],
            },
        ],
        "edges": [
            {
                "from": "shop:src/api/orders.py#@GET /orders",
                "to": "shop:src/middleware/auth.py#authenticateUser",
                "type": "handler",
            },
            {
                "from": "shop:src/middleware/auth.py#authenticateUser",
                "to": "shop:<datastore>#get",
                "type": "reads",
            },
        ],
    }


def test_endpoint_sourced_flow_is_complete() -> None:
    """The exact shape that hid the timesheet middleware: entry → guard → store."""
    flows = trace_flows(_graph())
    assert len(flows) == 1
    flow = flows[0]
    assert flow.complete
    assert flow.path == (
        "shop:src/api/orders.py#@GET /orders",
        "shop:src/middleware/auth.py#authenticateUser",
        "shop:<datastore>#get",
    )
    assert "authentication_required" in flow.validations[0]


def test_symbol_sourced_flow_is_complete() -> None:
    graph = _graph()
    graph["nodes"][0]["type"] = "file"
    del graph["nodes"][0]["route"]
    flows = trace_flows(graph)
    assert len(flows) == 1
    assert flows[0].complete


def test_no_sink_means_no_flow_not_incomplete_flow() -> None:
    graph = _graph()
    graph["edges"] = graph["edges"][:1]  # the trail stops at the guard
    flows = trace_flows(graph)
    assert flows == []
