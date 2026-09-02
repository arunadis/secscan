"""Line-based GraphQL schema facts (feature 004, research R3).

No grammar wheel: the depth-DoS leg needs only the type-reference graph, which a
delimiter pass extracts deterministically. Types, their field→type references,
and cycles in that graph (Article → comments → Comment → article → Article).
"""

from __future__ import annotations

import re

_TYPE_START = "type "
_SCALAR_OR_BUILTIN = frozenset({"ID", "String", "Int", "Float", "Boolean"})
_ARGS = re.compile(r"\([^)]*\)")


def parse_schema(text: str) -> dict[str, list[str]]:
    """Map each type name to the user-defined types its fields reference."""
    refs: dict[str, list[str]] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith(_TYPE_START):
            name = line[len(_TYPE_START) :].split("{", 1)[0].strip().split(" ", 1)[0].strip()
            if name:
                current = name
                refs.setdefault(current, [])
            continue
        if line == "}":
            current = None
            continue
        if current is None or ":" not in line:
            continue
        # Field args carry their own colons (`first: Int`); strip them so the
        # return type is what follows the *last* colon.
        target = _ARGS.sub("", line)
        target = target.rsplit(":", 1)[1]
        target = target.replace("[", " ").replace("]", " ").replace("!", " ")
        target = target.replace(",", " ").strip().split(" ", 1)[0] if target.strip() else ""
        if target and target not in _SCALAR_OR_BUILTIN:
            refs[current].append(target)
    return refs

def find_cycles(refs: dict[str, list[str]]) -> list[list[str]]:
    """Every elementary cycle path, deterministically ordered (iterative DFS)."""
    cycles: list[list[str]] = []
    for start in sorted(refs):
        stack: list[tuple[str, list[str]]] = [(start, [])]
        while stack:
            node, path = stack.pop()
            path = [*path, node]
            for nxt in sorted(refs.get(node, []), reverse=True):
                if nxt == start and len(path) > 1:
                    cycles.append([*path, start])
                elif nxt not in path and nxt >= start:
                    stack.append((nxt, path))
    return cycles
