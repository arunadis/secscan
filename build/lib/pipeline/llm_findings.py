"""Flow-derived LLM/modern-exploit findings (spec 007, FR-002/FR-003/FR-008a).

Findings are derived from traced flows over graph annotations — never from
model prose. Categories:

- direct injection (CWE-1427): endpoint/user-controlled input reaches an
  interpolated instruction-bearing context (``llm_prompt_sink``)
- indirect injection (CWE-1427): third-party content
  (``external_content_source``) reaches a model invocation, with the model's
  declared capabilities named as reachable impact
- sensitive data in context (CWE-200): ``sensitive_data`` reaches a prompt sink
- insecure output handling (CWE-116): model output (``llm_invocation``) reaches
  an interpreter sink without a demonstrated validation on the path

Every finding carries a tri-state mitigation (constitution V): a traced
validation proves ``demonstrated``; otherwise ``undetermined`` with the reason —
an unknown neither suppresses nor inflates.
"""

from __future__ import annotations

from typing import Any

from pipeline.dataflow import Flow, FlowGraph

#: deterministic confidence per category (documented constants, like misconfig)
_CONFIDENCE = {
    "direct": 0.9,
    "sensitive-context": 0.85,
    "indirect": 0.8,
    "output-handling": 0.8,
}

_CWE = {
    "direct": "CWE-1427",
    "indirect": "CWE-1427",
    "sensitive-context": "CWE-200",
    "output-handling": "CWE-116",
}

_UNDETERMINED_MITIGATION = {
    "control": "isolation-boundary",
    "state": "undetermined",
    "reason": (
        "no isolation boundary, validation, or human-approval control could be "
        "traced on the path from the untrusted source to the model context"
    ),
}

_TITLES = {
    "direct": "User-controlled input is interpolated into instruction-bearing model context",
    "indirect": "Third-party content reaches model context without a demonstrated boundary",
    "sensitive-context": "Sensitive data enters model context",
    "output-handling": "Model output reaches an interpreter without demonstrated validation",
}


def _mitigation(flow: Flow | None) -> dict[str, str]:
    if flow is not None and flow.validations:
        return {"control": "validation", "state": "demonstrated"}
    return dict(_UNDETERMINED_MITIGATION)


def _location(node: dict[str, Any]) -> dict[str, Any]:
    line = int(node.get("line_start") or 1)
    return {
        "repo": node["repo"],
        "file": node["path"],
        **({"symbol": node["symbol"]} if node.get("symbol") else {}),
        "line_start": line,
        "line_end": int(node.get("line_end") or line),
    }


def _capabilities(flow_graph: FlowGraph, sink_id: str) -> list[str]:
    """Names of tool declarations directly callable from the sink's context."""
    reachable: list[str] = []
    for target, _kind in flow_graph.outgoing.get(sink_id, ()):
        node = flow_graph.nodes.get(target) or {}
        if "tool_declaration" in (node.get("annotations") or []):
            reachable.append(node.get("symbol") or node["path"])
    return sorted(set(reachable))


def _find_best_flow(
    flows: list[Flow], sink_id: str
) -> tuple[str, Flow] | None:
    """First (source, flow) pair reaching ``sink_id``, deterministically."""
    for source, traced in sorted(flows, key=lambda item: item[0]):
        for flow in traced:
            if flow.path and flow.path[-1] == sink_id:
                return source, flow
    return None


def _evidence_entry(
    node: dict[str, Any], reason: str
) -> dict[str, Any]:
    entry = {
        "repo": node["repo"],
        "file": node["path"],
        "reason": reason,
    }
    if node.get("symbol"):
        entry["symbol"] = node["symbol"]
    return entry


def run(graph: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive LLM findings from the code graph's flows (deterministic)."""
    flow_graph = FlowGraph.from_document(graph)
    nodes = flow_graph.nodes

    source_groups: list[tuple[str, str]] = []  # (source id, category when prompt-sink)
    invocation_ids: list[str] = []
    prompt_sink_ids: list[str] = []
    for node_id in sorted(nodes):
        marks = set(nodes[node_id].get("annotations") or [])
        node_type = nodes[node_id]["type"]
        if "llm_invocation" in marks:
            invocation_ids.append(node_id)
        if "llm_prompt_sink" in marks:
            prompt_sink_ids.append(node_id)
        if "external_content_source" in marks:
            source_groups.append((node_id, "indirect"))
        if "sensitive_data" in marks:
            source_groups.append((node_id, "sensitive-context"))
        if node_type == "endpoint" or "user_controlled_input" in marks:
            source_groups.append((node_id, "direct"))

    traced: list[tuple[str, list[Flow]]] = []
    for source_id, _kind in source_groups:
        traced.append((source_id, flow_graph.trace(source_id)))
    for source_id in invocation_ids:
        traced.append((source_id, flow_graph.trace(source_id)))

    findings: list[dict[str, Any]] = []
    emitted: set[tuple[str, str]] = set()

    def candidate_flow(category: str, sink_id: str, sinks: list[str]) -> tuple[str, Flow] | None:
        wanted = sink_id if category != "output-handling" else None
        for source_id, flows in traced:
            kind = _source_category(nodes, source_id)
            for flow in flows:
                target = flow.path[-1] if flow.path else ""
                if category != kind:
                    continue
                if category == "output-handling":
                    if target not in sinks:
                        continue
                    return source_id, flow
                elif target == wanted:
                    return source_id, flow
        return None

    interp_sinks = [
        node_id
        for node_id in sorted(nodes)
        if "security_sink" in (nodes[node_id].get("annotations") or [])
        and "llm_prompt_sink" not in (nodes[node_id].get("annotations") or [])
        and "llm_invocation" not in (nodes[node_id].get("annotations") or [])
    ]

    for sink_id in prompt_sink_ids:
        node = nodes[sink_id]
        for category in ("sensitive-context", "direct"):
            hit = candidate_flow(category, sink_id, [])
            if hit is None:
                continue
            source_id, flow = hit
            key = (sink_id, category)
            if key in emitted:
                continue
            emitted.add(key)
            source_node = nodes[source_id]
            findings.append(
                _finding(
                    category,
                    node,
                    source_node,
                    flow,
                    capabilities=[],
                    flow_graph=flow_graph,
                )
            )

    for sink_id in invocation_ids:
        if (sink_id, "indirect") in emitted:
            continue
        hit = candidate_flow("indirect", sink_id, [])
        if hit is None:
            continue
        source_id, flow = hit
        emitted.add((sink_id, "indirect"))
        findings.append(
            _finding(
                "indirect",
                nodes[sink_id],
                nodes[source_id],
                flow,
                capabilities=_capabilities(flow_graph, sink_id),
                flow_graph=flow_graph,
            )
        )

    for sink_id in interp_sinks:
        hit = candidate_flow("output-handling", sink_id, interp_sinks)
        if hit is None or (sink_id, "output-handling") in emitted:
            continue
        source_id, flow = hit
        emitted.add((sink_id, "output-handling"))
        findings.append(
            _finding(
                "output-handling",
                nodes[sink_id],
                nodes[source_id],
                flow,
                capabilities=[],
                flow_graph=flow_graph,
            )
        )

    # Same-symbol combinations: a single function that both ingests/declares and
    # invokes builds no call edge to itself, yet the exposure is real. These are
    # presence-style observations recorded deterministically.
    for node_id in sorted(nodes):
        node = nodes[node_id]
        # Only symbol-granularity nodes: a whole file carrying both marks is
        # coverage metadata, not a situated exposure.
        if node["type"] not in ("function", "class"):
            continue
        marks = set(node.get("annotations") or [])
        combos: list[str] = []
        if "sensitive_data" in marks and "llm_prompt_sink" in marks:
            combos.append("sensitive-context")
        if "external_content_source" in marks and "llm_invocation" in marks:
            if "boundary_labeled" not in marks:
                # Self-contained ingestion with a demonstrated data boundary is
                # the deliberate safe pattern (spec US2); labels on the traced
                # path carry the same effect via verify._mitigated.
                combos.append("indirect")
        if (
            "llm_invocation" in marks
            and "security_sink" in marks
            and "llm_prompt_sink" not in marks
        ):
            combos.append("output-handling")
        if "user_controlled_input" in marks and "llm_prompt_sink" in marks:
            combos.append("direct")
        for category in combos:
            key = (node_id, category)
            if key in emitted:
                continue
            emitted.add(key)
            findings.append(
                _finding(
                    category,
                    node,
                    node,
                    None,
                    capabilities=_capabilities(flow_graph, node_id),
                    flow_graph=flow_graph,
                )
            )

    return sorted(
        findings,
        key=lambda f: (
            f["location"]["repo"],
            f["location"]["file"],
            f["location"]["line_start"],
            f["cwe"],
        ),
    )


def _source_category(nodes: dict[str, dict[str, Any]], source_id: str) -> str:
    marks = set(nodes.get(source_id, {}).get("annotations") or [])
    node_type = nodes.get(source_id, {}).get("type")
    if "external_content_source" in marks:
        return "indirect"
    if "sensitive_data" in marks:
        return "sensitive-context"
    if "llm_invocation" in marks:
        return "output-handling"
    if node_type == "endpoint" or "user_controlled_input" in marks:
        return "direct"
    return ""


def _label(node: dict[str, Any]) -> str:
    return f"{node['repo']}:{node['path']}" + (
        f"#{node['symbol']}" if node.get("symbol") else ""
    )


def _finding(
    category: str,
    sink_node: dict[str, Any],
    source_node: dict[str, Any],
    flow: Flow | None,
    *,
    capabilities: list[str],
    flow_graph: FlowGraph,
) -> dict[str, Any]:
    title = _TITLES[category]
    source_label = flow.source if flow is not None else _label(source_node)
    sink_label = flow.sink if flow is not None else _label(sink_node)
    evidence = [
        _evidence_entry(source_node, f"untrusted source: {source_label}"),
        _evidence_entry(sink_node, f"model context sink: {sink_label}"),
    ]
    if capabilities:
        tools = ", ".join(capabilities)
        evidence.append(
            _evidence_entry(
                sink_node,
                f"capabilities reachable from this context: {tools}",
            )
        )
    impact = {
        "direct": "An attacker overrides application intent; reachable tools "
        "and data follow the injected instruction.",
        "indirect": "Attacker-authored text inside ingested content steers the "
        "model; reachable tools and data follow.",
        "sensitive-context": "Sensitive data leaves the trust boundary via model context.",
        "output-handling": "Model-authored text reaches an interpreter where it "
        "can execute unintended logic.",
    }[category]
    scenario = {
        "direct": "A user embeds instruction text in input the application "
        "interpolates into its prompt.",
        "indirect": "An attacker plants instruction text in content the "
        "application later ingests into model context.",
        "sensitive-context": "A prompt built from sensitive data exposes it to "
        "the model provider or downstream consumers.",
        "output-handling": "Model output, influenced by injected instructions, "
        "is executed or interpreted unvalidated.",
    }[category]
    recommendation = {
        "direct": "Keep instructions static; pass user input as separately "
        "structured data and validate before inclusion.",
        "indirect": "Label third-party content as quoted data, keep it out of "
        "instruction channels, and scope reachable tools.",
        "sensitive-context": "Exclude sensitive records from prompt construction "
        "or redact before inclusion.",
        "output-handling": "Validate and constrain model output before it "
        "reaches execution, query, or rendering.",
    }[category]
    return {
        "cwe": _CWE[category],
        "confidence": _CONFIDENCE[category],
        "location": _location(sink_node),
        "description": title,
        "evidence": evidence,
        "attack_scenario": scenario,
        "impact": impact,
        "recommendation": recommendation,
        "mitigation": _mitigation(flow),
        "tool_ref": f"llm:{category}",
    }
