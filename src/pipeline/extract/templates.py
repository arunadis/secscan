"""Template sink extraction (FR-025, FR-025a).

The reviewed benchmark scan analysed no markup template at all. Its code model
held only `.ts` and `.js` files, so no segment could see a DOM binding — in a
front-end framework, exactly where injection lives. The four `[innerHTML]` sinks
the injection finding rested on were found by a human afterwards, and finding them
changed both the finding's conclusion and its severity.

Two extraction strategies, chosen per research.md A1:

**Attribute sinks.** Angular `[innerHTML]`, Vue `v-html`, Thymeleaf `th:utext` and
JSP `escapeXml="false"` are all plain attributes in otherwise-valid markup, so the
HTML grammar locates them with no per-dialect grammar involved. This is why one
new dependency covers six dialects.

**Delimiter sinks.** Jinja/Django `|safe` and Go `template.HTML` need delimiter
awareness rather than markup structure, so they get a deterministic lexical pass.
A tree-sitter dialect grammar would have meant an sdist-only 0.1.x dependency
needing a compiler at install time, for no additional sink coverage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Attribute names that render their value as raw markup. Matched
#: case-insensitively against attribute names in the parsed tree.
ATTRIBUTE_SINKS: dict[str, str] = {
    "[innerhtml]": "angular",
    "[outerhtml]": "angular",
    "ng-bind-html": "angular",
    "v-html": "vue",
    "th:utext": "thymeleaf",
    "data-ng-bind-html": "angular",
}

#: Expression-level sinks found by a delimiter pass rather than by structure.
_DELIMITER_SINKS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"\{\{[^}]*\|\s*safe\s*\}\}"), "jinja2", "|safe filter"),
    (re.compile(r"\{%\s*autoescape\s+(?:false|off)\s*%\}"), "jinja2", "autoescape disabled"),
    (re.compile(r"\bmark_safe\s*\("), "django", "mark_safe()"),
    (re.compile(r"\bMarkup\s*\("), "jinja2", "Markup()"),
    (re.compile(r"dangerouslySetInnerHTML"), "react", "dangerouslySetInnerHTML"),
    (re.compile(r"escapeXml\s*=\s*[\"']false[\"']"), "jsp", 'escapeXml="false"'),
    (re.compile(r"<%=(?!\s*--)"), "jsp", "raw scriptlet expression"),
    (
        re.compile(r"\btemplate\.(?:HTML|HTMLAttr|JS|JSAttr|URL|CSS|Srcset)\s*\("),
        "go-html-template",
        "safe-string type conversion",
    ),
)


@dataclass(frozen=True)
class TemplateSink:
    """An untrusted-data binding that renders as markup."""

    line: int
    #: attribute name or expression that makes it a sink
    marker: str
    #: framework whose control this bypasses, when identifiable
    framework: str
    #: the bound expression, when the binding exposes one
    expression: str = ""

    @property
    def symbol(self) -> str:
        """Stable, readable symbol name for the graph node."""
        return f"{self.marker}@{self.line}"


def _attribute_sinks(text: str) -> list[TemplateSink]:
    """Attribute sinks via the HTML grammar, falling back to a lexical scan.

    The grammar is preferred because it will not match an attribute name inside a
    comment or a text node. The fallback exists so a dialect the grammar chokes on
    still yields sinks rather than silence.
    """
    found: list[TemplateSink] = []
    try:
        from pipeline.extract import _parser_for

        parser = _parser_for("html")
    except Exception:  # pragma: no cover - defensive
        parser = None

    if parser is not None:
        source = text.encode("utf-8")
        tree = parser.parse(source)
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == "attribute":
                name_node = node.child_by_field_name("name") or (
                    node.children[0] if node.children else None
                )
                if name_node is not None:
                    name = source[name_node.start_byte : name_node.end_byte].decode(
                        "utf-8", "replace"
                    )
                    framework = ATTRIBUTE_SINKS.get(name.lower())
                    if framework:
                        value = source[node.start_byte : node.end_byte].decode("utf-8", "replace")
                        found.append(
                            TemplateSink(
                                line=node.start_point[0] + 1,
                                marker=name,
                                framework=framework,
                                expression=value,
                            )
                        )
            stack.extend(node.children)
        if found:
            return found

    for index, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        for attribute, framework in ATTRIBUTE_SINKS.items():
            if attribute in lowered:
                found.append(
                    TemplateSink(
                        line=index, marker=attribute, framework=framework, expression=line.strip()
                    )
                )
    return found


def extract_template_sinks(text: str) -> list[TemplateSink]:
    """Every untrusted-markup binding in ``text``, deterministically ordered."""
    sinks = list(_attribute_sinks(text))
    for pattern, framework, marker in _DELIMITER_SINKS:
        for match in pattern.finditer(text):
            line = text[: match.start()].count("\n") + 1
            snippet = text.splitlines()[line - 1].strip() if text.splitlines() else ""
            sinks.append(
                TemplateSink(line=line, marker=marker, framework=framework, expression=snippet)
            )

    # Deduplicate: one sink per (line, marker). A dialect can be matched by both
    # strategies, and reporting it twice would inflate the sink count.
    seen: set[tuple[int, str]] = set()
    unique: list[TemplateSink] = []
    for sink in sorted(sinks, key=lambda s: (s.line, s.marker)):
        key = (sink.line, sink.marker)
        if key not in seen:
            seen.add(key)
            unique.append(sink)
    return unique


#: Identifiers referenced inside a binding expression, used to link a template
#: sink back to the code that supplies the value (the `renders` edge, FR-025).
_BOUND_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*")

_EXPRESSION_NOISE = frozenset(
    {
        # sink syntax itself
        "innerHTML", "outerHTML", "html", "__html", "safe", "mark_safe", "Markup",
        "template", "HTML", "escapeXml", "dangerouslySetInnerHTML", "utext",
        "autoescape", "endautoescape", "on", "off",
        # language keywords and literals
        "true", "false", "null", "undefined", "None", "True", "False", "this",
        "return", "byte", "new", "var", "let", "const", "function", "class",
        # markup structure that is never a data supplier
        "div", "span", "p", "a", "img", "br", "ul", "li", "table", "tr", "td",
        "section", "article", "header", "footer", "nav", "form", "input", "button",
        "value", "out", "Write",
    }
)


def bound_identifiers(sink: TemplateSink) -> tuple[str, ...]:
    """Field/variable names a sink renders, for linking back to their source.

    Over-inclusive by design: a spurious candidate simply fails to match any
    symbol and produces no edge, whereas a missing one loses a real link. The
    filter therefore removes only tokens that can never be a data supplier.
    """
    found: list[str] = []
    for match in _BOUND_IDENTIFIER.finditer(sink.expression):
        token = match.group()
        parts = token.split(".")
        head, tail = parts[0], parts[-1]
        if head in _EXPRESSION_NOISE or tail in _EXPRESSION_NOISE:
            continue
        # Both ends matter. `comment.content` renders the *field* `content`, which
        # is not a symbol in the code model, but `comment` resolves to the type
        # that declares it — and that type IS a symbol. Offering both gives the
        # linker a chance to connect the sink to its data supplier either way.
        for candidate in (tail, head):
            if len(candidate) >= 3 and candidate not in _EXPRESSION_NOISE:
                found.append(candidate)
    return tuple(sorted(set(found)))
