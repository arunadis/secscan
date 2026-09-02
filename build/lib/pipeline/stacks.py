"""Stack descriptors: template forms and package ecosystems per language.

Loads the versioned ``stacks.json`` knowledge base (FR-025a, FR-025b, FR-030d).

**Scope of "the languages the code model parses."** This module is the single place
that answers it, because the phrase is otherwise ambiguous: ``LANGUAGE_BY_SUFFIX``
maps eight language names, but only some have a grammar. A *grammar-backed*
language is one with an entry in ``pipeline.extract._GRAMMARS``; ``sql`` and
``terraform`` are enumerated for pattern scanning but are not grammar-backed and
impose no template or ecosystem requirement.
"""

from __future__ import annotations

import functools
import json
from typing import Any

from pipeline import resources

DATA_FILE = "stacks.json"


class UnknownStack(KeyError):
    """Raised when a language or ecosystem is not described in the dataset."""


@functools.lru_cache(maxsize=1)
def _data() -> dict[str, Any]:
    return json.loads(resources.data_path(DATA_FILE).read_text())


def version() -> str:
    return str(_data()["version"])


def grammar_backed_languages() -> tuple[str, ...]:
    """Languages with a parser grammar, deterministically ordered."""
    return tuple(sorted(entry["language"] for entry in _data()["languages"]))


def ecosystems_for_grammar_backed() -> tuple[str, ...]:
    """Distinct package ecosystems across grammar-backed languages.

    Languages sharing an ecosystem count once: JavaScript, TypeScript and TSX all
    resolve to npm, so five language entries span four ecosystems (FR-030d).
    """
    return tuple(sorted({e["ecosystem"] for e in _data()["languages"] if e.get("ecosystem")}))


def language_entry(language: str) -> dict[str, Any]:
    for entry in _data()["languages"]:
        if entry["language"] == language:
            return dict(entry)
    raise UnknownStack(f"{language} is not a grammar-backed language in {DATA_FILE}")


def template_forms_for(language: str) -> tuple[str, ...]:
    return tuple(language_entry(language).get("template_forms") or ())


def ecosystem_for(language: str) -> str | None:
    return language_entry(language).get("ecosystem")


def template_form(form_id: str) -> dict[str, Any]:
    for entry in _data()["template_forms"]:
        if entry["id"] == form_id:
            return dict(entry)
    raise UnknownStack(f"unknown template form: {form_id}")


def template_suffixes() -> dict[str, tuple[str, ...]]:
    """Suffix -> the template form ids that claim it (one suffix may serve several)."""
    out: dict[str, set[str]] = {}
    for entry in _data()["template_forms"]:
        for suffix in entry.get("suffixes") or ():
            out.setdefault(suffix.lower(), set()).add(entry["id"])
    return {suffix: tuple(sorted(ids)) for suffix, ids in sorted(out.items())}


def ecosystem(ecosystem_id: str) -> dict[str, Any]:
    for entry in _data()["ecosystems"]:
        if entry["id"] == ecosystem_id:
            return dict(entry)
    raise UnknownStack(f"unknown ecosystem: {ecosystem_id}")


def all_ecosystems() -> tuple[dict[str, Any], ...]:
    return tuple(dict(e) for e in sorted(_data()["ecosystems"], key=lambda e: e["id"]))


def file_class_for(filename: str) -> str | None:
    """Security-relevant file class for a bare filename, or ``None``.

    Drives the per-file-class coverage statement so a reader can tell coverage
    from silence (FR-029).
    """
    for file_class, names in sorted(_data()["file_classes"].items()):
        if filename in names:
            return file_class
    return None


def file_class_names() -> tuple[str, ...]:
    return ("source", "template", *sorted(_data()["file_classes"]))


def is_test_code(path: str) -> bool:
    """Deterministic test-code classification from path conventions (FR-010).

    Pure glob matching over the versioned ``test_path_patterns`` data — no
    content inspection, so classification is stable and auditable. ``fnmatch``
    is not path-aware (``*`` crosses separators), which is what the patterns
    rely on; matching is case-insensitive for Windows-authored trees.
    """
    from fnmatch import fnmatch

    lowered = path.lower()
    for stack, patterns in sorted(_data().get("test_path_patterns", {}).items()):
        if stack.startswith("_"):
            continue
        if any(fnmatch(lowered, pattern.lower()) for pattern in patterns):
            return True
    return False
