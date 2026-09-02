"""Security data-flow tracing (FR-010).

Walks the code graph from externally controllable *sources* (endpoint handlers,
user-input annotated symbols) to security *sinks* (data-store execution, command
execution) and records the transforms and validations along the way, so analysis
can reason about whether the boundary between source and sink is enforced —
without seeing unrelated code.

The traced paths are also what :mod:`pipeline.verify` uses to decide whether a
finding is `verified` (complete path) or `plausible` (partial path).
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

MAX_PATH_LENGTH = 12

_VALIDATION_HINTS = (
    "authorization_required",
    "authentication_required",
    # spec 007: third-party content wrapped in an explicit data-only boundary
    # before reaching model context
    "boundary_labeled",
)


@dataclass
class Flow:
    source: str
    sink: str
    path: tuple[str, ...]
    transforms: tuple[str, ...] = ()
    validations: tuple[str, ...] = ()
    crosses_repo: bool = False

    @property
    def complete(self) -> bool:
        return bool(self.path) and self.path[0] == self.source and self.path[-1] == self.sink

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "transforms": list(self.transforms),
            "validations": list(self.validations),
            "sink": self.sink,
            "crosses_repo": self.crosses_repo,
        }


@dataclass
class FlowGraph:
    """Adjacency view of the code graph used for flow tracing."""

    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    outgoing: dict[str, list[tuple[str, str]]] = field(default_factory=lambda: defaultdict(list))

    @classmethod
    def from_document(cls, graph: dict[str, Any]) -> FlowGraph:
        instance = cls(nodes={node["id"]: node for node in graph["nodes"]})
        for edge in graph["edges"]:
            # `renders` is traversable: it is what lets a trace continue from the
            # code supplying a value into the template that writes it to the DOM.
            # Without it a front-end injection flow stops at the data layer, which
            # is why the reviewed benchmark could not trace one at all.
            if edge["type"] in (
                "calls",
                "handler",
                "reads",
                "writes",
                "publishes",
                "consumes",
                "renders",
            ):
                instance.outgoing[edge["from"]].append((edge["to"], edge["type"]))
        for key in instance.outgoing:
            instance.outgoing[key].sort()
        return instance

    def annotations(self, node_id: str) -> set[str]:
        return set((self.nodes.get(node_id) or {}).get("annotations") or [])

    def label(self, node_id: str) -> str:
        node = self.nodes.get(node_id)
        if node is None:
            return node_id
        if node["type"] == "endpoint":
            return f"{node.get('route', 'endpoint')} ({node['repo']})"
        symbol = node.get("symbol") or node["path"]
        return f"{node['repo']}:{node['path']}#{symbol}" if node.get("symbol") else node["id"]

    # ------------------------------------------------------------- tracing

    def sources(self) -> list[str]:
        # `external_content_source` (spec 007): third-party content that can
        # reach model context is attacker-influenceable without an attacker ever
        # touching the application - the indirect injection channel.
        found = [
            node_id
            for node_id, node in self.nodes.items()
            if node["type"] == "endpoint"
            or {
                "user_controlled_input",
                "external_content_source",
            }
            & set(node.get("annotations") or [])
        ]
        return sorted(found)

    def is_sink(self, node_id: str) -> bool:
        node = self.nodes.get(node_id) or {}
        if node.get("type") == "datastore":
            return True
        # `llm_prompt_sink` (spec 007): interpolated instruction-bearing model
        # context is an interpreter boundary like any other security sink.
        # `llm_invocation` terminates indirect traces: third-party content
        # reaching a model call is the finding, even without interpolation.
        return bool(
            {"security_sink", "llm_prompt_sink", "llm_invocation"}
            & set(node.get("annotations") or [])
        )

    def trace(self, source: str, max_length: int = MAX_PATH_LENGTH) -> list[Flow]:
        """Breadth-first search from ``source`` to reachable sinks."""
        flows: list[Flow] = []
        queue: deque[tuple[str, tuple[str, ...]]] = deque([(source, (source,))])
        seen: set[str] = {source}

        while queue:
            current, path = queue.popleft()
            if len(path) > max_length:
                continue
            for target, _kind in self.outgoing.get(current, ()):
                if target in seen:
                    continue
                new_path = path + (target,)
                if self.is_sink(target):
                    flows.append(self._build_flow(source, target, new_path))
                    continue
                seen.add(target)
                queue.append((target, new_path))
        return flows

    def _build_flow(self, source: str, sink: str, path: tuple[str, ...]) -> Flow:
        transforms: list[str] = []
        validations: list[str] = []
        repos = set()
        for node_id in path:
            node = self.nodes.get(node_id) or {}
            repos.add(node.get("repo"))
            marks = set(node.get("annotations") or [])
            for hint in _VALIDATION_HINTS:
                if hint in marks:
                    validations.append(f"{hint} at {self.label(node_id)}")
            if node_id not in (source, sink) and node.get("symbol"):
                transforms.append(self.label(node_id))
        return Flow(
            source=self.label(source),
            sink=self.label(sink),
            path=path,
            transforms=tuple(transforms),
            validations=tuple(sorted(set(validations))),
            crosses_repo=len([r for r in repos if r]) > 1,
        )


def trace_flows(graph: dict[str, Any], limit_per_source: int = 8) -> list[Flow]:
    """All source-to-sink flows in the graph (deterministically ordered)."""
    flow_graph = FlowGraph.from_document(graph)
    flows: list[Flow] = []
    for source in flow_graph.sources():
        traced = flow_graph.trace(source)
        flows.extend(sorted(traced, key=lambda f: (f.sink, f.path))[:limit_per_source])
    return flows


def flows_for_segment(
    graph: dict[str, Any], segment: dict[str, Any], all_flows: list[Flow] | None = None
) -> list[Flow]:
    """Flows whose path touches any file in ``segment``."""
    flows = all_flows if all_flows is not None else trace_flows(graph)
    files = set(segment["files"])
    repos = set(segment["repos"])
    nodes = {node["id"]: node for node in graph["nodes"]}

    relevant: list[Flow] = []
    for flow in flows:
        for node_id in flow.path:
            node = nodes.get(node_id)
            if node and node["repo"] in repos and node["path"] in files:
                relevant.append(flow)
                break
    return sorted(relevant, key=lambda f: (f.source, f.sink))


def find_flow_for_location(
    flows: list[Flow], graph: dict[str, Any], repo: str, path: str, symbol: str | None
) -> Flow | None:
    """The best flow whose sink (or path) matches a finding's location."""
    nodes = {node["id"]: node for node in graph["nodes"]}
    best: Flow | None = None
    for flow in flows:
        for index, node_id in enumerate(flow.path):
            node = nodes.get(node_id)
            if not node or node["repo"] != repo or node["path"] != path:
                continue
            if symbol and node.get("symbol") not in (symbol, None):
                continue
            # Prefer flows where the match is at/near the sink.
            if best is None or index >= len(flow.path) - 2:
                best = flow
                break
    return best
