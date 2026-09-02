"""Stage 4: bounded context packets (FR-005, FR-006, FR-006a, FR-007).

Each packet carries the segment's purpose, entry points, call-graph and data-flow
summaries, security-relevant symbols, and *only* the source needed for the
current escalation level — after mandatory redaction, and within budget.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from pipeline.budget import TokenBudget, estimate_mapping_tokens, estimate_tokens
from pipeline.dataflow import Flow, flows_for_segment
from pipeline.discover_repo import member_paths
from pipeline.redact import Redactor, SecretHit
from pipeline.state import ArtifactStore

#: Escalation levels (FR-006): what source each level includes.
LEVEL_FUNCTION = 1  # security-relevant symbols only
LEVEL_NEIGHBOURS = 2  # + calling/called code in the segment
LEVEL_SEGMENT = 3  # + the full segment and its data flows
LEVEL_CROSS = 4  # + cross-segment/repo context


def number_lines(text: str) -> str:
    """Prefix each line with its 1-based number: ``  7| code``.

    Applied at every escalation level (FR-002). The cost is 3-5 characters per
    line; the alternative is a model reporting line numbers it inferred by
    counting, which is exactly how the benchmark's locations drifted. Line numbers
    are advisory even so — :mod:`pipeline.locate` re-derives every published range
    from the code model — but a correct hint costs nothing and makes omission
    markers unambiguous.
    """
    lines = text.splitlines()
    if not lines:
        return text
    width = len(str(len(lines)))
    return "\n".join(f"{index:>{width}}| {line}" for index, line in enumerate(lines, start=1))


class ContextBuilder:
    def __init__(
        self,
        store: ArtifactStore,
        workspace: dict[str, Any],
        graph: dict[str, Any],
        budget: TokenBudget,
        redactor: Redactor,
    ) -> None:
        self.store = store
        self.workspace = workspace
        self.graph = graph
        self.budget = budget
        self.redactor = redactor
        self.roots = member_paths(store, workspace)
        self.nodes_by_file: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for node in graph["nodes"]:
            self.nodes_by_file.setdefault((node["repo"], node["path"]), []).append(node)
        self.warnings: list[str] = []
        #: segment id -> redaction hits, the evidence for hard-coded-secret findings
        self.secret_hits: dict[str, list[SecretHit]] = {}
        #: structured coverage-gap records (feature 004, FR-010) — the legacy
        #: warning strings above stay for compatibility; these carry the cause.
        self.gap_records: list[dict[str, Any]] = []

    # ----------------------------------------------------------------- api

    def build(
        self,
        segment: dict[str, Any],
        level: int = LEVEL_FUNCTION,
        flows: list[Flow] | None = None,
    ) -> dict[str, Any]:
        segment_flows = flows if flows is not None else flows_for_segment(self.graph, segment)
        sources, dropped = self._sources_for(segment, level)

        redacted, redaction = self.redactor.redact_mapping(sources)
        if redaction.warnings:
            self.warnings.extend(
                f"{segment['id']}: {warning}" for warning in redaction.warnings
            )
        if redaction.hits:
            existing = {
                (h.origin, h.label, h.line) for h in self.secret_hits.get(segment["id"], [])
            }
            for hit in redaction.hits:
                if (hit.origin, hit.label, hit.line) not in existing:
                    self.secret_hits.setdefault(segment["id"], []).append(hit)
                    existing.add((hit.origin, hit.label, hit.line))
                if hit.blocked:
                    record = {
                        "cause": "blocked-value",
                        "file": hit.origin,
                        "segment_id": segment["id"],
                        "line": hit.line,
                    }
                    if record not in self.gap_records:
                        self.gap_records.append(record)

        packet: dict[str, Any] = {
            "segment_id": segment["id"],
            "escalation_level": level,
            "purpose": segment["purpose"],
            "domains": list(segment.get("domains") or []),
            "entrypoints": list(segment.get("entrypoints") or []),
            "call_graph_summary": self._call_summary(segment),
            "data_flows": [flow.to_dict() for flow in segment_flows[:12]],
            "security_relevant_symbols": self._security_symbols(segment),
            "source": redacted,
            "token_budget": self.budget.to_dict(),
            "redaction": {
                "applied": True,
                "redacted_items": redaction.redacted,
                "blocked_items": redaction.blocked,
                #: suppression decisions, inspectable rather than silent (FR-004).
                #: Values are omitted: the packet is an artifact, and the value
                #: is readable in source anyway.
                "exempted_items": [
                    {
                        "origin": e.origin,
                        "line": e.line,
                        "rule": e.rule,
                        "classification": e.classification,
                        "reason": e.reason,
                        "decision": e.decision,
                    }
                    for e in redaction.exempted
                ],
                "rules_version": self.redactor.rules_version,
            },
        }
        packet["estimated_tokens"] = self._packet_tokens(packet)

        # Structural parts pushed us over budget: shed source files (never truncate).
        while packet["estimated_tokens"] > self.budget.max_context_tokens and packet["source"]:
            largest = max(
                sorted(packet["source"]), key=lambda k: estimate_tokens(packet["source"][k])
            )
            del packet["source"][largest]
            dropped.append(largest)
            packet["estimated_tokens"] = self._packet_tokens(packet)

        if dropped:
            self.warnings.append(
                f"{segment['id']}: {len(set(dropped))} file(s) exceeded the "
                f"{self.budget.max_context_tokens}-token budget at level {level} and were "
                f"analyzed separately or deferred: {', '.join(sorted(set(dropped)))}"
            )
            for path in sorted(set(dropped)):
                self.gap_records.append(
                    {"cause": "budget-dropped", "file": path, "segment_id": segment["id"]}
                )
        return packet

    def write(self, packet: dict[str, Any]) -> Path:
        name = f"{packet['segment_id']}-l{packet['escalation_level']}.json"
        return self.store.write(
            f"context-packets/{name}", "build_context", packet, "context_packet"
        )

    # ----------------------------------------------------------- internals

    def _packet_tokens(self, packet: dict[str, Any]) -> int:
        structural = estimate_tokens(
            "\n".join(
                [
                    packet["purpose"],
                    packet["call_graph_summary"],
                    " ".join(packet["entrypoints"]),
                    " ".join(packet["security_relevant_symbols"]),
                    " ".join(str(flow) for flow in packet["data_flows"]),
                ]
            )
        )
        return structural + estimate_mapping_tokens(packet["source"])

    def _read(self, repo: str, relative: str) -> str | None:
        root = self.roots.get(repo)
        if root is None:
            return None
        try:
            return (root / relative).read_text(errors="replace")
        except OSError:
            return None

    def _sources_for(self, segment: dict[str, Any], level: int) -> tuple[dict[str, str], list[str]]:
        """Source text for the level, plus files shed to fit the budget.

        Files omitted *because of the escalation level* are not a coverage gap —
        that narrowing is the whole point of starting small (FR-006). Only files
        dropped to satisfy the token budget are reported as gaps.
        """
        repo = segment["repos"][0]
        files = list(segment["files"])

        if level >= LEVEL_SEGMENT:
            selected = files
        else:
            interesting = self._interesting_files(segment)
            if level == LEVEL_FUNCTION:
                selected = interesting or files[:1]
            else:  # LEVEL_NEIGHBOURS
                selected = sorted(set(interesting) | set(self._neighbours(segment, interesting)))
                selected = selected or files[:2]

        sources: dict[str, str] = {}
        for relative in sorted(selected):
            text = self._read(repo, relative)
            if text is None:
                continue
            if level == LEVEL_FUNCTION:
                text = self._slice_symbols(repo, relative, text)
            else:
                text = number_lines(text)
            sources[relative] = text

        return self.budget.trim_to_fit(sources)

    def _interesting_files(self, segment: dict[str, Any]) -> list[str]:
        """Files carrying security annotations — the level-1 focus.

        Files whose language has no grammar are *always* included. They carry no
        annotations because nothing about their interior was analyzed, so ranking
        them by annotation would silently analyze whichever one sorts first and
        report nothing about the rest. Not knowing which file is interesting is a
        reason to look at all of them, not a reason to guess (FR-003c, FR-029).
        The token budget still applies and still reports whatever it sheds.
        """
        repo = segment["repos"][0]
        interesting: list[str] = []
        for relative in segment["files"]:
            nodes = self.nodes_by_file.get((repo, relative), [])
            marks: set[str] = set()
            unparsed = False
            for node in nodes:
                marks.update(node.get("annotations") or [])
                if node.get("parsed") is False:
                    unparsed = True
            if unparsed or marks & {
                "security_sink",
                "user_controlled_input",
                "trust_boundary",
                "sensitive_data",
            }:
                interesting.append(relative)
        return sorted(interesting)

    def _neighbours(self, segment: dict[str, Any], focus: list[str]) -> list[str]:
        """Files directly calling into or called from ``focus`` within the segment."""
        repo = segment["repos"][0]
        focus_ids = {
            node["id"]
            for relative in focus
            for node in self.nodes_by_file.get((repo, relative), [])
        }
        index = {node["id"]: node for node in self.graph["nodes"]}
        neighbours: set[str] = set()
        for edge in self.graph["edges"]:
            if edge["type"] not in ("calls", "handler"):
                continue
            for a, b in ((edge["from"], edge["to"]), (edge["to"], edge["from"])):
                if a in focus_ids:
                    other = index.get(b)
                    if other and other["repo"] == repo and other["path"] in segment["files"]:
                        neighbours.add(other["path"])
        return sorted(neighbours)

    def _slice_symbols(self, repo: str, relative: str, text: str) -> str:
        """Keep only annotated symbol bodies (plus a header) for level 1.

        Emits **original** line numbers, so a narrowed packet still describes the
        file on disk. Without them the analysing model counts lines in a document
        that exists nowhere, which is why every location in the reviewed benchmark
        scan was wrong by one or two lines (research.md A6).
        """
        nodes = [
            node
            for node in self.nodes_by_file.get((repo, relative), [])
            if node.get("line_start") and node.get("annotations")
        ]
        lines = text.splitlines()
        if not nodes:
            return number_lines(text)
        keep: set[int] = set(range(0, min(12, len(lines))))  # imports / module header
        for node in nodes:
            start = max(0, int(node["line_start"]) - 2)
            end = min(len(lines), int(node.get("line_end", node["line_start"])) + 1)
            keep.update(range(start, end))
        width = len(str(len(lines)))
        out: list[str] = []
        previous = -1
        for index in sorted(keep):
            if previous != -1 and index > previous + 1:
                omitted = index - previous - 1
                out.append(f"{'':>{width}}| ... {omitted} unrelated line(s) omitted ...")
            out.append(f"{index + 1:>{width}}| {lines[index]}")
            previous = index
        return "\n".join(out)

    def _call_summary(self, segment: dict[str, Any]) -> str:
        repo = segment["repos"][0]
        index = {node["id"]: node for node in self.graph["nodes"]}
        seen: set[str] = set()
        lines: list[str] = []
        for edge in self.graph["edges"]:
            if edge["type"] not in ("calls", "handler"):
                continue
            source = index.get(edge["from"])
            target = index.get(edge["to"])
            if not source or not target:
                continue
            if source["repo"] != repo or source["path"] not in segment["files"]:
                continue
            arrow = (
                f"{source.get('route') or source.get('symbol') or source['path']}"
                f" -> {target.get('symbol') or target['path']}"
            )
            if arrow in seen:
                continue
            seen.add(arrow)
            lines.append(arrow)
        return "\n".join(sorted(lines)[:40])

    def _security_symbols(self, segment: dict[str, Any]) -> list[str]:
        repo = segment["repos"][0]
        found: set[str] = set()
        for relative in segment["files"]:
            for node in self.nodes_by_file.get((repo, relative), []):
                if node.get("symbol") and node.get("annotations"):
                    found.add(f"{relative}#{node['symbol']}")
        return sorted(found)


def run(
    store: ArtifactStore,
    workspace: dict[str, Any],
    graph: dict[str, Any],
    segments: list[dict[str, Any]],
    budget: TokenBudget,
    redactor: Redactor,
) -> tuple[list[dict[str, Any]], list[str]]:
    builder = ContextBuilder(store, workspace, graph, budget, redactor)
    packets: list[dict[str, Any]] = []
    for segment in segments:
        packet = builder.build(segment, LEVEL_FUNCTION)
        builder.write(packet)
        packets.append(packet)
    return packets, builder.warnings


def main() -> None:  # pragma: no cover - CLI wrapper
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    args = parser.parse_args()
    from config.loader import load

    store = ArtifactStore(args.workdir)
    config = load(store.dir)
    segments = [store.read(p.name and f"segments/{p.name}") for p in store.glob("segments/*.json")]
    packets, warnings = run(
        store,
        store.read("workspace.json"),
        store.read("code-graph.json"),
        segments,
        TokenBudget.from_dict(config.budgets),
        Redactor(config.redaction_patterns),
    )
    print(f"built {len(packets)} context packet(s); {len(warnings)} warning(s)")


if __name__ == "__main__":  # pragma: no cover
    main()
