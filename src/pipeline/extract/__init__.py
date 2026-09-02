"""Multi-language extraction layer (research.md R2).

One tree-sitter query pass per language yields normalized :class:`FileFacts`:
symbols, imports, call sites, HTTP entry points, data access, and security
annotations. Call edges are name-based in v1 (documented limitation) — precise
resolution is a later deep-analysis tier.

Determinism: results are sorted; parsing is from bytes with fixed encoding.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from typing import Any

from tree_sitter import Language, Node, Parser

from pipeline.extract import enrichers

#: language -> (module name, tree-sitter language callable attribute)
_GRAMMARS: dict[str, tuple[str, str]] = {
    "python": ("tree_sitter_python", "language"),
    "java": ("tree_sitter_java", "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    # `.tsx` needs the JSX-capable entry point. Before feature 002 it was mapped
    # to `language_typescript`, which does not accept JSX, so every `.tsx` file
    # produced parse errors and React's `dangerouslySetInnerHTML` was invisible
    # to the pipeline (research.md A1).
    "tsx": ("tree_sitter_typescript", "language_tsx"),
    "go": ("tree_sitter_go", "language"),
    # Markup and view templates. One grammar covers the lot, because unsafe
    # bindings are attributes in otherwise-valid markup: Angular `[innerHTML]`,
    # Vue `v-html`, Thymeleaf `th:utext`, JSP `escapeXml="false"`.
    "html": ("tree_sitter_html", "language"),
}

#: Languages whose files are templates rather than code. They get symbol/call
#: extraction skipped and template-sink extraction instead.
TEMPLATE_LANGUAGES = frozenset({"html"})

#: node types that declare a callable/type, per language
_DEFINITION_NODES: dict[str, dict[str, str]] = {
    "python": {"function_definition": "function", "class_definition": "class"},
    "java": {
        "method_declaration": "function",
        "constructor_declaration": "function",
        "class_declaration": "class",
        "interface_declaration": "class",
    },
    "javascript": {
        "function_declaration": "function",
        "method_definition": "function",
        "class_declaration": "class",
    },
    "typescript": {
        "function_declaration": "function",
        "method_definition": "function",
        "class_declaration": "class",
        "interface_declaration": "class",
    },
    "go": {"function_declaration": "function", "method_declaration": "function"},
}
#: `.tsx` is TypeScript with JSX: same declarations, same calls, same imports.
_DEFINITION_NODES["tsx"] = dict(_DEFINITION_NODES["typescript"])

_CALL_NODES: dict[str, tuple[str, ...]] = {
    "python": ("call",),
    "java": ("method_invocation", "object_creation_expression"),
    "javascript": ("call_expression", "new_expression"),
    "typescript": ("call_expression", "new_expression"),
    "go": ("call_expression",),
}
_CALL_NODES["tsx"] = _CALL_NODES["typescript"]

_IMPORT_NODES: dict[str, tuple[str, ...]] = {
    "python": ("import_statement", "import_from_statement"),
    "java": ("import_declaration",),
    "javascript": ("import_statement", "import_declaration"),
    "typescript": ("import_statement", "import_declaration"),
    "go": ("import_declaration", "import_spec"),
}
_IMPORT_NODES["tsx"] = _IMPORT_NODES["typescript"]


class GrammarUnavailable(RuntimeError):
    """Raised when a grammar cannot be loaded (falls back to heuristics)."""


@functools.cache
def _parser_for(language: str) -> Parser | None:
    spec = _GRAMMARS.get(language)
    if spec is None:
        return None
    module_name, attribute = spec
    try:
        module = __import__(module_name)
        ts_language = Language(getattr(module, attribute)())
        return Parser(ts_language)
    except Exception:  # pragma: no cover - missing/broken grammar
        return None


def supported_languages() -> tuple[str, ...]:
    return tuple(sorted(_GRAMMARS))


# --------------------------------------------------------------------- facts


@dataclass
class Symbol:
    name: str
    kind: str  # function | class
    line_start: int
    line_end: int
    decorators: tuple[str, ...] = ()
    annotations: tuple[str, ...] = ()


@dataclass
class Endpoint:
    symbol: str
    kind: str  # http | cli | consumer | rpc
    route: str
    line: int


@dataclass
class CallSite:
    caller: str
    callee: str
    line: int


@dataclass
class DataAccess:
    symbol: str
    operation: str  # read | write | execute
    detail: str
    line: int
    unsafe_interpolation: bool = False


@dataclass
class FileFacts:
    path: str
    language: str
    symbols: list[Symbol] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    data_access: list[DataAccess] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)
    parse_errors: int = 0

    def symbol_at(self, line: int) -> str:
        """Innermost symbol containing ``line`` (deterministic tie-breaking)."""
        candidates = [
            s for s in self.symbols if s.line_start <= line <= s.line_end and s.kind == "function"
        ]
        if not candidates:
            candidates = [s for s in self.symbols if s.line_start <= line <= s.line_end]
        if not candidates:
            return "<module>"
        return min(candidates, key=lambda s: (s.line_end - s.line_start, s.name)).name

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "language": self.language,
            "symbols": [
                {
                    "name": s.name,
                    "kind": s.kind,
                    "line_start": s.line_start,
                    "line_end": s.line_end,
                    "decorators": list(s.decorators),
                    "annotations": list(s.annotations),
                }
                for s in self.symbols
            ],
            "imports": list(self.imports),
            "endpoints": [
                {"symbol": e.symbol, "kind": e.kind, "route": e.route, "line": e.line}
                for e in self.endpoints
            ],
            "data_access": [
                {
                    "symbol": d.symbol,
                    "operation": d.operation,
                    "detail": d.detail,
                    "line": d.line,
                    "unsafe_interpolation": d.unsafe_interpolation,
                }
                for d in self.data_access
            ],
            "annotations": list(self.annotations),
        }


# ------------------------------------------------------------------ traversal


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _name_of(node: Node, source: bytes) -> str:
    named = node.child_by_field_name("name")
    if named is not None:
        return _text(named, source)
    for child in node.named_children:
        if child.type in (
            "identifier",
            "field_identifier",
            "property_identifier",
            "type_identifier",
        ):
            return _text(child, source)
    return "<anonymous>"


def _callee_name(node: Node, source: bytes) -> str:
    function = node.child_by_field_name("function") or node.child_by_field_name("constructor")
    target = function if function is not None else node
    text = _text(target, source).strip()
    text = text.split("(")[0].strip()
    return text.rsplit("\n", 1)[-1].strip()


def extract_file(path: str, text: str, language: str) -> FileFacts | None:
    """Extract facts from one file; ``None`` when no grammar is available."""
    parser = _parser_for(language)
    if parser is None:
        return None

    source = text.encode("utf-8")
    tree = parser.parse(source)
    facts = FileFacts(path=path, language=language)

    definitions = _DEFINITION_NODES.get(language, {})
    call_types = _CALL_NODES.get(language, ())
    import_types = _IMPORT_NODES.get(language, ())

    stack: list[tuple[Node, str]] = [(tree.root_node, "<module>")]
    while stack:
        node, enclosing = stack.pop()
        node_type = node.type

        if node_type == "ERROR":
            facts.parse_errors += 1

        current = enclosing
        if node_type in definitions:
            name = _name_of(node, source)
            symbol = Symbol(
                name=name,
                kind=definitions[node_type],
                line_start=node.start_point[0] + 1,
                line_end=node.end_point[0] + 1,
                decorators=enrichers.decorators_for(node, source, language),
            )
            facts.symbols.append(symbol)
            current = name

        if node_type in import_types:
            facts.imports.append(_text(node, source).strip().replace("\n", " ")[:200])

        if node_type in call_types:
            facts.calls.append(
                CallSite(
                    caller=current,
                    callee=_callee_name(node, source),
                    line=node.start_point[0] + 1,
                )
            )

        for child in reversed(node.named_children):
            stack.append((child, current))

    facts.symbols.sort(key=lambda s: (s.line_start, s.name))
    facts.calls.sort(key=lambda c: (c.line, c.callee))
    facts.imports = sorted(set(facts.imports))

    enrichers.enrich(facts, text)
    return facts
