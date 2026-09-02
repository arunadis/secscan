"""T058: template sink extraction, one case per dialect (FR-025).

Covers the full research.md A1 catalogue. Until now these dialects were exercised
only indirectly through `test_coverage.py`'s integration assertions, so a
regression in any single dialect's pattern would surface as a confusing
whole-pipeline failure rather than a named one.

The two-strategy split is the thing under test: attribute sinks come from the HTML
grammar, delimiter sinks from a deterministic lexical pass. One grammar covers six
dialects because unsafe bindings are attributes in otherwise-valid markup.
"""

from __future__ import annotations

import pytest

from pipeline.extract.templates import (
    ATTRIBUTE_SINKS,
    bound_identifiers,
    extract_template_sinks,
)

#: (dialect, source, expected marker) — the A1 catalogue.
DIALECTS: tuple[tuple[str, str, str], ...] = (
    ("angular-innerhtml", '<p [innerHTML]="comment.content"></p>', "[innerHTML]"),
    ("angular-outerhtml", '<p [outerHTML]="comment.content"></p>', "[outerHTML]"),
    ("angular-ng-bind", '<p ng-bind-html="comment.content"></p>', "ng-bind-html"),
    ("vue-v-html", '<div v-html="post.body"></div>', "v-html"),
    ("thymeleaf-utext", '<span th:utext="${user.about}"></span>', "th:utext"),
    ("jsp-escapexml", '<c:out value="${user.about}" escapeXml="false" />', 'escapeXml="false"'),
    ("jsp-scriptlet", "<div><%= userInput %></div>", "raw scriptlet expression"),
    ("jinja2-safe", "<div>{{ body|safe }}</div>", "|safe filter"),
    ("jinja2-autoescape", "{% autoescape off %}{{ body }}{% endautoescape %}",
     "autoescape disabled"),
    ("jinja2-markup", "return Markup(user_supplied)", "Markup()"),
    ("django-mark-safe", "return mark_safe(user_supplied)", "mark_safe()"),
    ("react-dangerously", "return <p dangerouslySetInnerHTML={{__html: body}} />;",
     "dangerouslySetInnerHTML"),
    ("go-template-html", "w.Write([]byte(template.HTML(userInput)))",
     "safe-string type conversion"),
)


@pytest.mark.parametrize(("dialect", "source", "marker"), DIALECTS, ids=[d[0] for d in DIALECTS])
def test_each_dialect_sink_is_detected(dialect: str, source: str, marker: str) -> None:
    markers = {sink.marker for sink in extract_template_sinks(source)}
    assert marker in markers, f"{dialect}: expected {marker!r}, found {sorted(markers)}"


@pytest.mark.parametrize(("dialect", "source", "marker"), DIALECTS, ids=[d[0] for d in DIALECTS])
def test_each_sink_reports_a_usable_line_and_framework(
    dialect: str, source: str, marker: str
) -> None:
    sink = next(s for s in extract_template_sinks(source) if s.marker == marker)
    assert sink.line >= 1
    assert sink.framework
    assert sink.symbol.startswith(marker)


def test_line_numbers_are_correct_in_a_multiline_template() -> None:
    source = "<div>\n  <h1>Title</h1>\n  <p [innerHTML]=\"c.body\"></p>\n</div>\n"
    sink = next(s for s in extract_template_sinks(source) if s.marker == "[innerHTML]")
    assert sink.line == 3


def test_safe_markup_produces_no_sink() -> None:
    """Interpolation that the framework escapes is not a sink."""
    for safe in (
        "<p>{{ comment.content }}</p>",
        '<p title="{{ x }}">text</p>',
        "<div>{{ body }}</div>",
        "<p>{% if user %}hello{% endif %}</p>",
    ):
        assert extract_template_sinks(safe) == [], safe


def test_sinks_are_deduplicated_and_ordered() -> None:
    """A dialect matched by both strategies must not be counted twice."""
    source = '<p [innerHTML]="a"></p>\n<p [innerHTML]="b"></p>\n'
    sinks = extract_template_sinks(source)
    assert [s.line for s in sinks] == [1, 2]
    assert len(sinks) == 2


def test_extraction_is_deterministic() -> None:
    source = '<div v-html="a"></div>\n<p [innerHTML]="b"></p>\n<span>{{ c|safe }}</span>\n'
    first = [(s.line, s.marker) for s in extract_template_sinks(source)]
    second = [(s.line, s.marker) for s in extract_template_sinks(source)]
    assert first == second == sorted(first)


def test_attribute_names_are_matched_case_insensitively() -> None:
    """Markup is case-insensitive; `[innerHTML]` and `[innerhtml]` are one sink."""
    assert all(name == name.lower() for name in ATTRIBUTE_SINKS)
    assert extract_template_sinks('<p [INNERHTML]="x"></p>')


def test_bound_identifiers_link_a_sink_to_its_data_supplier() -> None:
    """Both ends of a dotted expression, so a `renders` edge can resolve either."""
    sink = next(s for s in extract_template_sinks('<p [innerHTML]="comment.content"></p>'))
    names = bound_identifiers(sink)
    assert "content" in names  # the field
    assert "comment" in names  # the type that declares it


def test_bound_identifiers_exclude_markup_and_sink_syntax() -> None:
    sink = next(s for s in extract_template_sinks('<div v-html="post.body"></div>'))
    names = bound_identifiers(sink)
    assert "div" not in names
    assert "html" not in names
