"""Schema loading and validation for pipeline artifacts.

Schemas live in the installed skill payload (``skill_core/schemas``) so the same
files validate artifacts whether the pipeline runs standalone or is invoked by a
coding agent from an installed skill directory.
"""

from __future__ import annotations

import functools
import json
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from pipeline import resources

SCHEMA_DIR = resources.schema_dir()
SCHEMA_VERSION = "1"


class SchemaError(ValueError):
    """Raised when a document does not conform to its schema."""

    def __init__(self, name: str, errors: list[str]) -> None:
        self.schema_name = name
        self.errors = errors
        joined = "\n  - ".join(errors)
        super().__init__(f"{name} validation failed:\n  - {joined}")


@functools.cache
def _registry() -> Registry:
    registry = Registry()
    for path in sorted(SCHEMA_DIR.glob("*.json")):
        doc = json.loads(path.read_text())
        registry = registry.with_resource(doc["$id"], Resource.from_contents(doc))
    return registry


@functools.cache
def validator_for(name: str) -> Draft202012Validator:
    """Return a cached validator for ``name`` (e.g. ``finding``)."""
    path = SCHEMA_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"unknown schema: {name} ({path})")
    schema = json.loads(path.read_text())
    return Draft202012Validator(schema, registry=_registry())


def validate(name: str, document: Any) -> None:
    """Validate ``document``, raising :class:`SchemaError` listing every problem."""
    errors = sorted(validator_for(name).iter_errors(document), key=lambda e: list(e.path))
    if errors:
        messages = []
        for err in errors:
            location = "/".join(str(p) for p in err.path) or "<root>"
            messages.append(f"{location}: {err.message}")
        raise SchemaError(name, messages)


def is_valid(name: str, document: Any) -> bool:
    return validator_for(name).is_valid(document)
