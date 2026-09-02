"""Deterministic LLM-integration recognition (spec 007, FR-001, R3).

Pattern-driven, versioned-data backed (``llm_integrations.json``): SDK client
calls, raw HTTP calls to model API endpoints, and local/self-hosted model
endpoints are recognized by code shape and recorded as graph annotations.
Matched text is never copied anywhere — annotations are shape marks, and
invalid data fails the build at load, never a scan (misconfig precedent).

Annotations emitted (all in the code_graph schema enum):

- ``llm_invocation`` — symbol issues a recognized model call
- ``llm_prompt_sink`` — symbol both invokes a model and assembles its context
  (a traceable sink for untrusted-input flows)
- ``external_content_source`` — symbol ingests third-party content that could
  reach model context (an indirect-injection source)
- ``tool_declaration`` — symbol declares a callable exposed to the model
- ``llm_undetermined`` — file/symbol assembles prompt-shaped context but no
  recognized integration is present; an honest undetermined posture, never
  silence and never assumed safety (constitution V)
"""

from __future__ import annotations

import functools
import json
import re
from dataclasses import dataclass, field

from pipeline import resources

DATA_FILE = "llm_integrations.json"


class InvalidIntegrationData(RuntimeError):
    """Recognition data that fails validation fails the build, not the scan."""


@dataclass(frozen=True)
class AnnotationFacts:
    file_annotations: frozenset[str] = frozenset()
    symbol_annotations: frozenset[tuple[str, str]] = frozenset()

    def marks_for(self, symbol_name: str) -> frozenset[str]:
        return frozenset(
            mark for name, mark in self.symbol_annotations if name == symbol_name
        )


@dataclass(frozen=True)
class _Dataset:
    sdk: tuple[re.Pattern[str], ...]
    http: tuple[re.Pattern[str], ...]
    local: tuple[re.Pattern[str], ...]
    readers: tuple[re.Pattern[str], ...]
    tools: tuple[re.Pattern[str], ...]
    hints: tuple[re.Pattern[str], ...]
    boundary: tuple[re.Pattern[str], ...] = ()
    hint_notes: tuple[tuple[re.Pattern[str], str], ...] = ()


@functools.cache
def _patterns() -> _Dataset:
    document = json.loads(resources.data_path(DATA_FILE).read_text())
    ids: set[str] = set()
    groups: list[tuple[str, list[dict]]] = [
        (
            key,
            document[key],
        )
        for key in (
            "sdk_modules",
            "http_endpoints",
            "local_endpoints",
            "external_content_readers",
            "tool_declarations",
            "candidate_hints",
            "boundary_patterns",
        )
    ]
    compiled: dict[str, list[re.Pattern[str]]] = {}
    hint_notes: list[tuple[re.Pattern[str], str]] = []
    for key, entries in groups:
        bucket = compiled.setdefault(key, [])
        for entry in entries:
            if entry.get("id") in ids:
                raise InvalidIntegrationData(f"duplicate id: {entry['id']}")
            ids.add(entry["id"])
            if key == "http_endpoints":
                for suffix in entry["host_suffixes"]:
                    bucket.append(
                        re.compile(r"https?://[A-Za-z0-9.\-]*" + re.escape(suffix))
                    )
                continue
            if key == "local_endpoints":
                hosts = "|".join(re.escape(h) for h in entry["hosts"])
                ports = "|".join(str(p) for p in entry["ports"])
                bucket.append(re.compile(rf"http://(?:{hosts}):(?:{ports})\b"))
                continue
            for pattern in entry.get("patterns") or ():
                try:
                    compiled_pattern = re.compile(pattern)
                except re.error as exc:
                    raise InvalidIntegrationData(
                        f"{entry['id']}: pattern does not compile: {exc}"
                    ) from exc
                bucket.append(compiled_pattern)
                if key == "candidate_hints":
                    hint_notes.append((compiled_pattern, str(entry["note"])))
    return _Dataset(
        sdk=tuple(compiled["sdk_modules"]),
        http=tuple(compiled["http_endpoints"]),
        local=tuple(compiled["local_endpoints"]),
        readers=tuple(compiled["external_content_readers"]),
        tools=tuple(compiled["tool_declarations"]),
        hints=tuple(compiled["candidate_hints"]),
        boundary=tuple(compiled["boundary_patterns"]),
        hint_notes=tuple(hint_notes),
    )


def _any(patterns: tuple[re.Pattern[str], ...], text: str) -> bool:
    return any(pattern.search(text) for pattern in patterns)


@dataclass
class _Work:
    file_marks: set[str] = field(default_factory=set)
    symbol_marks: dict[str, set[str]] = field(default_factory=dict)


def annotate(
    text: str, symbols: list, language: str | None = None
) -> AnnotationFacts:
    """Derive LLM annotations for one file's text and its symbols.

    ``symbols`` are FileFacts symbols (``name``/``line_start``/``line_end``);
    bodies are sliced by line, matching the enrichers precedent.
    """
    data = _patterns()
    lines = text.splitlines()
    work = _Work()
    recognized = (
        _any(data.sdk, text) or _any(data.http, text) or _any(data.local, text)
    )

    for symbol in symbols:
        decorator_text = "\n".join(getattr(symbol, "decorators", ()) or ())
        body = decorator_text + "\n" + "\n".join(
            lines[symbol.line_start - 1 : symbol.line_end]
        )
        marks: set[str] = set()
        invokes = _any(data.sdk, body) or _any(data.http, body) or _any(
            data.local, body
        )
        if invokes:
            marks.add("llm_invocation")
            if _constructs_interpolated_context(body):
                marks.add("llm_prompt_sink")
        if _any(data.readers, body):
            marks.add("external_content_source")
            work.file_marks.add("external_content_source")
        if _any(data.tools, body):
            marks.add("tool_declaration")
        if _any(data.boundary, body):
            # A demonstrated data-only boundary: named so downstream stages can
            # suppress indirect exposure (self-contained ingestion) or record
            # the mitigation on traced flows (spec US2 acceptance 2).
            marks.add("boundary_labeled")
        if not recognized and any(h.search(body) for h in data.hints):
            marks.add("llm_undetermined")
            work.file_marks.add("llm_undetermined")
        if marks:
            work.symbol_marks.setdefault(symbol.name, set()).update(marks)
            work.file_marks.update(marks)

    if not recognized and _any(data.hints, text):
        work.file_marks.add("llm_undetermined")

    return AnnotationFacts(
        file_annotations=frozenset(work.file_marks),
        symbol_annotations=frozenset(
            (name, mark)
            for name, marks in sorted(work.symbol_marks.items())
            for mark in sorted(marks)
        ),
    )


#: assignments or JSON-style arguments that construct instruction-bearing
#: context (`messages =`, `"prompt":`, ...)
_ASSIGNMENT = re.compile(r"['\"]?(messages|system_prompt|prompt)['\"]?\s*[=:]")
#: interpolation signals inside a construction window (f-string hole, string
#: concat of a variable, .format substitution, template placeholder)
_INTERP = re.compile(
    r"f['\"][^#\n]*\{[A-Za-z_]|\$\{[A-Za-z_]|\+[^=]\s*[A-Za-z_'\"]|\.format\s*\("
)


def _constructs_interpolated_context(body: str) -> bool:
    """True when instruction-bearing context is built with interpolation.

    A plain ``messages = [{"role": ..., "content": constant}]`` is *not* a sink:
    statically defined prompts with separately structured data must not be
    flagged (spec Scenario 2). The sink signal is interpolation INTO a prompt
    or message construction window — that is where untrusted text can become
    instruction. Deterministic and line-window based (6 lines cover an opened
    list/string literal in the grammar-backed languages).
    """
    lines = body.splitlines()
    for index, line in enumerate(lines):
        if not _ASSIGNMENT.search(line):
            continue
        window = [line]
        if line.count("[") > line.count("]"):
            for follow in lines[index + 1 :]:
                window.append(follow)
                if follow.count("]") >= 1:
                    break
        if _INTERP.search("\n".join(window)):
            return True
    return False


def hint_notes_for(text: str) -> list[str]:
    """The dataset notes for any candidate hints ``text`` matches (sorted)."""
    data = _patterns()
    return sorted({note for pattern, note in data.hint_notes if pattern.search(text)})
