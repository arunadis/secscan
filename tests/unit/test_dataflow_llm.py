"""Spec 007, T020/T027: LLM data-flow tracing unit tests.

Flow categories (contracts §4 llm_findings):
- direct:   endpoint/user_controlled_input -> llm_prompt_sink        (CWE-1427)
- indirect: external_content_source -> llm_invocation                (CWE-1427)
- sensitive: sensitive_data -> llm_prompt_sink                       (CWE-200)
- output:   llm_invocation -> security_sink, unvalidated             (CWE-116)
"""

from __future__ import annotations

from pipeline.dataflow import FlowGraph, trace_flows

REPO = "app"


def _node(
    nid: str, *, ntype: str = "function", path: str = "app/llm.py", ann: tuple = ()
) -> dict:
    node = {
        "id": nid,
        "repo": REPO,
        "type": ntype,
        "path": path,
    }
    if ann:
        node["annotations"] = sorted(ann)
    return node


def _graph(nodes: list[dict], edges: list[tuple[str, str]]) -> dict:
    return {
        "nodes": nodes,
        "edges": [{"from": a, "to": b, "type": "calls"} for a, b in edges],
    }


def test_user_input_traced_to_prompt_sink() -> None:
    graph = _graph(
        [
            _node(f"{REPO}:app/api.py#@POST /chat", ntype="endpoint", path="app/api.py"),
            _node(f"{REPO}:app/api.py#chat", path="app/api.py", ann=("user_controlled_input",)),
            _node(
                f"{REPO}:app/llm.py#respond",
                path="app/llm.py",
                ann=("llm_prompt_sink", "llm_invocation"),
            ),
        ],
        [
            (f"{REPO}:app/api.py#@POST /chat", f"{REPO}:app/api.py#chat"),
            (f"{REPO}:app/api.py#chat", f"{REPO}:app/llm.py#respond"),
        ],
    )
    flows = trace_flows(graph)
    assert any(
        flow.sink.endswith("respond") and "chat" in flow.source for flow in flows
    )


def test_external_content_traced_to_invocation() -> None:
    graph = _graph(
        [
            _node(
                f"{REPO}:app/ingest.py#fetch",
                path="app/ingest.py",
                ann=("external_content_source",),
            ),
            _node(f"{REPO}:app/llm.py#respond", path="app/llm.py", ann=("llm_invocation",)),
        ],
        [(f"{REPO}:app/ingest.py#fetch", f"{REPO}:app/llm.py#respond")],
    )
    flow_graph = FlowGraph.from_document(graph)
    flows = flow_graph.trace(f"{REPO}:app/ingest.py#fetch")
    assert any(flow.sink.endswith("respond") for flow in flows)


def test_sensitive_data_traced_to_prompt_sink() -> None:
    graph = _graph(
        [
            _node(f"{REPO}:app/data.py#load_profile", path="app/data.py", ann=("sensitive_data",)),
            _node(
                f"{REPO}:app/llm.py#respond",
                path="app/llm.py",
                ann=("llm_prompt_sink", "llm_invocation"),
            ),
        ],
        [(f"{REPO}:app/data.py#load_profile", f"{REPO}:app/llm.py#respond")],
    )
    flow_graph = FlowGraph.from_document(graph)
    flows = flow_graph.trace(f"{REPO}:app/data.py#load_profile")
    assert any(flow.sink.endswith("respond") for flow in flows)


def test_invocation_output_traced_to_interpreter_sink() -> None:
    graph = _graph(
        [
            _node(f"{REPO}:app/llm.py#ask", path="app/llm.py", ann=("llm_invocation",)),
            _node(f"{REPO}:app/db.py#run", path="app/db.py", ann=("security_sink",)),
        ],
        [(f"{REPO}:app/llm.py#ask", f"{REPO}:app/db.py#run")],
    )
    flow_graph = FlowGraph.from_document(graph)
    flows = flow_graph.trace(f"{REPO}:app/llm.py#ask")
    assert any(flow.sink.endswith("run") for flow in flows)


def test_validated_output_flow_carries_the_validation_note() -> None:
    graph = _graph(
        [
            _node(f"{REPO}:app/llm.py#ask", path="app/llm.py", ann=("llm_invocation",)),
            _node(
                f"{REPO}:app/guard.py#check",
                path="app/guard.py",
                ann=("authorization_required",),
            ),
            _node(f"{REPO}:app/db.py#run", path="app/db.py", ann=("security_sink",)),
        ],
        [
            (f"{REPO}:app/llm.py#ask", f"{REPO}:app/guard.py#check"),
            (f"{REPO}:app/guard.py#check", f"{REPO}:app/db.py#run"),
        ],
    )
    flow_graph = FlowGraph.from_document(graph)
    flows = flow_graph.trace(f"{REPO}:app/llm.py#ask")
    assert flows and flows[0].validations


def test_boundary_labeled_node_marks_the_flow_as_validated() -> None:
    graph = _graph(
        [
            _node(
                f"{REPO}:app/ingest.py#fetch",
                path="app/ingest.py",
                ann=("external_content_source",),
            ),
            _node(
                f"{REPO}:app/label.py#label_untrusted",
                path="app/label.py",
                ann=("boundary_labeled",),
            ),
            _node(f"{REPO}:app/llm.py#respond", path="app/llm.py", ann=("llm_invocation",)),
        ],
        [
            (f"{REPO}:app/ingest.py#fetch", f"{REPO}:app/label.py#label_untrusted"),
            (f"{REPO}:app/label.py#label_untrusted", f"{REPO}:app/llm.py#respond"),
        ],
    )
    flow_graph = FlowGraph.from_document(graph)
    flows = flow_graph.trace(f"{REPO}:app/ingest.py#fetch")
    assert flows
    assert any("boundary_labeled" in v for v in flows[0].validations)


def test_non_llm_repo_has_no_llm_traces() -> None:
    graph = _graph(
        [
            _node(f"{REPO}:app/add.py#add"),
            _node(f"{REPO}:app/show.py#show"),
        ],
        [(f"{REPO}:app/add.py#add", f"{REPO}:app/show.py#show")],
    )
    assert trace_flows(graph) == []


def test_prompt_sink_stops_the_trace_like_any_sink() -> None:
    graph = _graph(
        [
            _node(f"{REPO}:app/api.py#@POST /chat", ntype="endpoint", path="app/api.py"),
            _node(
                f"{REPO}:app/llm.py#respond",
                path="app/llm.py",
                ann=("llm_prompt_sink", "llm_invocation"),
            ),
            _node(f"{REPO}:app/db.py#run", path="app/db.py", ann=("security_sink",)),
        ],
        [
            (f"{REPO}:app/api.py#@POST /chat", f"{REPO}:app/llm.py#respond"),
            (f"{REPO}:app/llm.py#respond", f"{REPO}:app/db.py#run"),
        ],
    )
    flows = trace_flows(graph)
    # The direct flow terminates at the prompt sink; it does not continue to db.
    respond_flows = [f for f in flows if f.sink.endswith("respond")]
    assert respond_flows
    assert all(not f.path[-1].endswith("run") for f in respond_flows)
