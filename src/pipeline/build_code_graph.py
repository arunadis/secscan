"""Stage 2: multi-language code graph (FR-002, FR-003).

Per-file facts are merged into a deterministic ``{nodes, edges}`` document with
stable ids (``<repo>:<path>#<symbol>``) so incremental scans can diff it. Call
edges are name-based in v1 and marked as such.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

from pipeline.discover_repo import LANGUAGE_BY_SUFFIX, any_language_for, member_paths
from pipeline.extract import (
    TEMPLATE_LANGUAGES,
    FileFacts,
    extract_file,
    supported_languages,
)
from pipeline.extract.config_files import is_config
from pipeline.state import ArtifactStore, iter_source_files


def node_id(repo: str, path: str, symbol: str | None = None) -> str:
    return f"{repo}:{path}#{symbol}" if symbol else f"{repo}:{path}"


class GraphBuilder:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: set[tuple[str, str, str, bool, str]] = set()
        #: symbol name -> node ids defining it (name-based call resolution)
        self.by_symbol: dict[str, set[str]] = {}
        self.facts: dict[tuple[str, str], FileFacts] = {}
        #: (repo, template sink node id) -> identifiers it renders, resolved to
        #: `renders` edges once every symbol is known
        self.template_bindings: dict[tuple[str, str], set[str]] = {}
        #: (repo, path, route|None, target, line) registration facts awaiting
        #: the second pass (feature 016, FR-001/FR-002)
        self.wiring_facts: list[tuple[str, str, str | None, str, int]] = []
        #: (repo, path) -> endpoint node ids registered by that file
        self.endpoints_in_file: dict[tuple[str, str], list[str]] = {}
        #: wiring facts whose target resolved to no in-repo symbol (FR-010)
        self.unresolved_wiring: list[dict[str, Any]] = []

    # ------------------------------------------------------------- building

    def add_node(self, **fields: Any) -> str:
        identifier = fields["id"]
        existing = self.nodes.get(identifier)
        if existing is None:
            self.nodes[identifier] = {k: v for k, v in fields.items() if v not in (None, [], ())}
        else:
            merged = set(existing.get("annotations") or []) | set(fields.get("annotations") or [])
            if merged:
                existing["annotations"] = sorted(merged)
        return identifier

    def add_edge(
        self, source: str, target: str, kind: str, *, cross_repo: bool = False, resolution: str = ""
    ) -> None:
        self.edges.add((source, target, kind, cross_repo, resolution))

    def add_template(self, repo: str, path: str, text: str) -> None:
        """Represent a view template and its untrusted-markup bindings (FR-025).

        Each binding becomes a `template_sink` node, and a `renders` edge links it
        back to the code symbol supplying the bound value so a data-flow trace can
        reach the DOM rather than stopping at the data layer.
        """
        from pipeline.extract.templates import bound_identifiers, extract_template_sinks

        file_node = self.add_node(
            id=node_id(repo, path),
            repo=repo,
            type="template",
            path=path,
            language="html",
            parsed=True,
            format=path.rsplit(".", 1)[-1].lower(),
            file_class="template",
        )
        for sink in extract_template_sinks(text):
            sink_node = self.add_node(
                id=node_id(repo, path, sink.symbol),
                repo=repo,
                type="template",
                path=path,
                symbol=sink.symbol,
                language="html",
                line_start=sink.line,
                line_end=sink.line,
                parsed=True,
                format=sink.framework,
                file_class="template",
                annotations=["template_sink", "security_sink"],
            )
            self.add_edge(file_node, sink_node, "contains")
            self.template_bindings.setdefault((repo, sink_node), set()).update(
                bound_identifiers(sink)
            )

    def add_config(self, repo: str, path: str) -> None:
        """Represent a configuration file so it belongs to a segment (FR-026)."""
        from pipeline.extract.config_files import classify

        config = classify(path)
        if config is None:
            return
        self.add_node(
            id=node_id(repo, path),
            repo=repo,
            type="config",
            path=path,
            parsed=False,
            format=config.format,
            file_class=config.file_class,
            annotations=list(config.annotations),
        )

    def resolve_template_bindings(self) -> None:
        """Link each template sink to the symbols that could supply its value.

        Matching is case-insensitive because a template binds an *instance*
        (`comment.content`) while the code declares a *type* (`class Comment`).
        Name-based and best-effort, like the call edges (001 R2) — an unmatched
        binding simply produces no edge, so the sink is still represented.
        """
        lowered: dict[str, set[str]] = {}
        for name, ids in self.by_symbol.items():
            lowered.setdefault(name.lower(), set()).update(ids)

        for (repo, sink_node), names in sorted(self.template_bindings.items()):
            for name in sorted(names):
                for target in sorted(lowered.get(name.lower(), ())):
                    if self.nodes[target]["repo"] != repo or target == sink_node:
                        continue
                    self.add_edge(target, sink_node, "renders", resolution="name-based")

    def add_unparsed_file(self, repo: str, path: str, language: str) -> str:
        """Represent a file whose language has no grammar, at file granularity.

        Deliberately carries no ``symbol``/``line_start``/``line_end``: nothing
        about its interior was analyzed and claiming otherwise would be the kind of
        unearned precision this feature removes. The node exists so a finding here
        resolves at the *file* tier rather than being rejected (FR-003c).
        """
        return self.add_node(
            id=node_id(repo, path),
            repo=repo,
            type="file",
            path=path,
            language=language,
            parsed=False,
            file_class="source",
        )

    def add_file(self, repo: str, facts: FileFacts, text: str = "") -> None:
        self.facts[(repo, facts.path)] = facts
        # Some raw-markup sinks live in *code*, not templates: React's
        # `dangerouslySetInnerHTML`, Go's `template.HTML(...)`. They are both a
        # sink and a documented bypass of the framework's default escaping, so
        # annotating them here is what lets control evaluation discredit a control
        # on the traced path (FR-022) instead of crediting it by default.
        if text:
            self._annotate_inline_template_sinks(facts, text)
            self._annotate_bypass_sites(facts, text)
            self._annotate_llm_integration(facts, text)
        file_node = self.add_node(
            id=node_id(repo, facts.path),
            repo=repo,
            type="file",
            path=facts.path,
            language=facts.language,
            parsed=True,
            file_class="source",
            imports=facts.imports,
            annotations=facts.annotations,
            outbound_hosts=facts.outbound_hosts,
            data_categories=facts.data_categories,
        )

        for symbol in facts.symbols:
            identifier = self.add_node(
                id=node_id(repo, facts.path, symbol.name),
                repo=repo,
                type="class" if symbol.kind == "class" else "function",
                path=facts.path,
                symbol=symbol.name,
                language=facts.language,
                line_start=symbol.line_start,
                line_end=symbol.line_end,
                annotations=list(symbol.annotations),
            )
            self.add_edge(file_node, identifier, "contains")
            self.by_symbol.setdefault(symbol.name, set()).add(identifier)

        for endpoint in facts.endpoints:
            endpoint_node = self.add_node(
                id=node_id(repo, facts.path, f"@{endpoint.route}"),
                repo=repo,
                type="endpoint",
                path=facts.path,
                symbol=endpoint.symbol,
                route=endpoint.route,
                language=facts.language,
                line_start=endpoint.line,
                annotations=["trust_boundary", "user_controlled_input"],
            )
            handler = node_id(repo, facts.path, endpoint.symbol)
            if handler in self.nodes:
                self.add_edge(endpoint_node, handler, "handler")
            self.endpoints_in_file.setdefault((repo, facts.path), []).append(endpoint_node)

        for access in facts.data_access:
            store_node = self.add_node(
                id=node_id(repo, "<datastore>", access.detail or access.operation),
                repo=repo,
                type="datastore",
                path="<datastore>",
                symbol=access.detail,
                annotations=["security_sink"] if access.operation == "execute" else [],
            )
            caller = node_id(repo, facts.path, access.symbol)
            if caller in self.nodes:
                kind = {"read": "reads", "write": "writes"}.get(access.operation, "writes")
                self.add_edge(caller, store_node, kind)

        for wire in facts.wiring:
            self.wiring_facts.append((repo, facts.path, wire.route, wire.target, wire.line))

    def _annotate_bypass_sites(self, facts: FileFacts, text: str) -> None:
        """Mark symbols that call a documented control-bypass syntax (feature 014).

        `bypassSecurityTrustHtml` and friends are calls, not markup sinks, so the
        sink extractor never sees them — yet they are exactly what discredits a
        framework control for template sinks (member-wide bypass scan, FR-006).
        Only shipped-catalogue syntaxes count; inventing one would silently
        discredit controls we know nothing about.
        """
        from pipeline.controls import all_bypass_syntaxes

        for syntax in all_bypass_syntaxes():
            start = text.find(syntax)
            if start == -1:
                continue
            line = text.count("\n", 0, start) + 1
            matched = False
            for symbol in facts.symbols:
                if symbol.line_start <= line <= symbol.line_end:
                    symbol.annotations = tuple(
                        sorted(set(symbol.annotations) | {"control_bypass"})
                    )
                    matched = True
            if not matched:
                # module-level call: mark the file node itself
                facts.annotations = sorted(set(facts.annotations) | {"control_bypass"})

    def _annotate_llm_integration(self, facts: FileFacts, text: str) -> None:
        """Mark LLM integration points so the modern-exploit category can trace
        to them (spec 007, FR-001 FR-002)."""
        from pipeline.extract import llm_integration

        marks = llm_integration.annotate(text, facts.symbols, language=facts.language)
        if not marks.file_annotations and not marks.symbol_annotations:
            return
        facts.annotations = sorted(set(facts.annotations) | set(marks.file_annotations))
        annotated = []
        for symbol in facts.symbols:
            merged = set(symbol.annotations) | set(marks.marks_for(symbol.name))
            if merged != set(symbol.annotations):
                symbol.annotations = tuple(sorted(merged))
            annotated.append(symbol)
        facts.symbols = annotated

    def _annotate_inline_template_sinks(self, facts: FileFacts, text: str) -> None:
        """Mark symbols containing a raw-markup sink written in code."""
        from pipeline.controls import all_bypass_syntaxes
        from pipeline.extract.templates import extract_template_sinks

        bypasses = all_bypass_syntaxes()
        for sink in extract_template_sinks(text):
            marks = ["template_sink", "security_sink"]
            # Only credit `control_bypass` when the marker is a *documented*
            # bypass in the shipped catalogue — inventing one would let this
            # silently discredit controls it knows nothing about.
            if any(sink.marker in syntax or syntax in sink.expression for syntax in bypasses):
                marks.append("control_bypass")
            for symbol in facts.symbols:
                if symbol.line_start <= sink.line <= symbol.line_end:
                    symbol.annotations = tuple(sorted(set(symbol.annotations) | set(marks)))

    #: identifier families that mean "security decision" when they name a
    #: function (feature 016, FR-006 contingency when the shipped catalogue
    #: cannot load; the catalogue in identity_archetype_rules.json is the
    #: single source of truth and is always used when available).
    #: test/scaffold paths neither call production guards nor count as users
    _TESTISH_PATH = re.compile(r"(?:__tests__|/tests?/|\.test\.|\.spec\.|_test\.)")

    def _guard_name_patterns(self) -> tuple[re.Pattern[str], ...]:
        from pipeline import identity_rules

        return identity_rules.load_guard_names()

    def resolve_wiring(self) -> None:
        """Attach registration-style guards after every symbol exists (feature
        016, FR-001/FR-002): the wired name may be defined in a file parsed
        after the one registering it, so resolution is a second pass like
        :meth:`resolve_calls`.

        Edges made here: the wiring file *calls* the guard (so the call-graph
        summary names the relationship), and every endpoint the registration
        scopes — the whole file for a `use(…)` attachment, the named route for
        a route-argument attachment — gains a `handler` edge, which is what lets
        a flow traverse entry point → guard → sink. Names resolving to no
        in-repo symbol make no edge and are recorded in ``unresolved_wiring``
        (contracts/graph-wiring-contract.md §6).
        """
        unresolved: dict[tuple[str, str, int], str] = {}
        facts_sorted = sorted(
            set(self.wiring_facts),
            key=lambda f: (f[0], f[1], f[2] or "", f[3], f[4]),
        )
        for repo, path, route, target_name, line in facts_sorted:
            targets = sorted(
                t
                for t in self.by_symbol.get(target_name, ())
                if self.nodes[t]["repo"] == repo
            )
            if not targets:
                unresolved[(path, line, target_name)] = "no in-repo symbol with this name"
                continue
            file_node = node_id(repo, path)
            for target in targets:
                self.add_edge(file_node, target, "calls", resolution="name-based")
            for endpoint_node in self.endpoints_in_file.get((repo, path), ()):
                if route is not None and self.nodes[endpoint_node].get("route") != route:
                    continue
                for target in targets:
                    self.add_edge(endpoint_node, target, "handler", resolution="name-based")
        self.unresolved_wiring = [
            {"file": file, "line": line, "name": name, "reason": reason}
            for (file, line, name), reason in sorted(unresolved.items())
        ]

    def annotate_unattached_guards(self) -> None:
        """Function nodes with guard-meaningful names and no inbound edge from
        production code get the ``unattached_security_guard`` annotation
        (feature 016, FR-006). Containment by their own file and references from
        test files do not count as attachment."""
        guard_names = self._guard_name_patterns()
        inbound: dict[str, set[str]] = {}
        for source, target, kind, _cross, _resolution in self.edges:
            if kind == "contains":
                continue
            source_path = source.split(":", 1)[-1].split("#", 1)[0]
            inbound.setdefault(target, set()).add(source_path)
        for identifier in sorted(self.nodes):
            node = self.nodes[identifier]
            if node.get("type") != "function":
                continue
            symbol = node.get("symbol") or ""
            if not any(pattern.match(symbol) for pattern in guard_names):
                continue
            referrers = {
                path
                for path in inbound.get(identifier, ())
                if not self._TESTISH_PATH.search(path) and path != node["path"]
            }
            if referrers:
                continue
            node["annotations"] = sorted(
                set(node.get("annotations") or []) | {"unattached_security_guard"}
            )

    def resolve_calls(self) -> None:
        """Name-based call edge resolution (documented v1 limitation)."""
        for (repo, path), facts in sorted(self.facts.items()):
            for call in facts.calls:
                caller = node_id(repo, path, call.caller)
                if caller not in self.nodes:
                    caller = node_id(repo, path)
                target_name = call.callee.split(".")[-1]
                for target in sorted(self.by_symbol.get(target_name, ())):
                    if target == caller:
                        continue
                    self.add_edge(
                        caller,
                        target,
                        "calls",
                        cross_repo=self.nodes[target]["repo"] != repo,
                        resolution="name-based",
                    )

    def to_document(self) -> dict[str, Any]:
        nodes = [self.nodes[key] for key in sorted(self.nodes)]
        edges = [
            {
                "from": source,
                "to": target,
                "type": kind,
                **({"cross_repo": True} if cross_repo else {}),
                **({"resolution": resolution} if resolution else {}),
            }
            for source, target, kind, cross_repo, resolution in sorted(self.edges)
        ]
        # FR-010: present even when empty — an absent key would be ambiguous
        # between "old artifact" and "nothing unresolved".
        unresolved = sorted(
            self.unresolved_wiring, key=lambda e: (e["file"], e["line"], e["name"])
        )
        return {"nodes": nodes, "edges": edges, "unresolved_wiring": unresolved}


def language_for(path: Path) -> str | None:
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower())


def run(store: ArtifactStore, workspace: dict[str, Any]) -> dict[str, Any]:
    builder = GraphBuilder()
    grammars = set(supported_languages())
    for repo, root in sorted(member_paths(store, workspace).items()):
        for path in iter_source_files(root):
            relative = path.relative_to(root).as_posix()
            language = language_for(path)

            # Configuration is represented before anything else, because several
            # config files (`package.json`, `firebase.json`) also carry a suffix
            # that would otherwise route them to a language parser.
            if is_config(relative):
                builder.add_config(repo, relative)
                continue

            # No grammar for this language: represent the file so a finding in it
            # can still resolve, then move on without claiming to have read it.
            if language is None or language not in grammars:
                unmodelled = any_language_for(path.suffix)
                if unmodelled is not None:
                    builder.add_unparsed_file(repo, relative, unmodelled)
                continue

            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue

            if language in TEMPLATE_LANGUAGES:
                builder.add_template(repo, relative, text)
                continue

            facts = extract_file(relative, text, language)
            if facts is None:
                builder.add_unparsed_file(repo, relative, language)
                continue
            builder.add_file(repo, facts, text)

    builder.resolve_calls()
    builder.resolve_wiring()
    builder.resolve_template_bindings()
    builder.annotate_unattached_guards()
    document = builder.to_document()
    store.write("code-graph.json", "build_code_graph", document, "code_graph")
    return document


def main() -> None:  # pragma: no cover - CLI wrapper
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    args = parser.parse_args()
    store = ArtifactStore(args.workdir)
    document = run(store, store.read("workspace.json"))
    print(f"graph: {len(document['nodes'])} nodes, {len(document['edges'])} edges")


if __name__ == "__main__":  # pragma: no cover
    main()
