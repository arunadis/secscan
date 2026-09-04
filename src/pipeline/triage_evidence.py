"""Deterministic re-verification of triage verdict citations (feature 013, FR-007).

A verdict's citations are claims about the repository. This module re-checks each
one against the tree and the code model — file exists under the cited member,
cited lines are in range, the claimed ``pattern`` occurs verbatim within them,
and an optional symbol resolves against the code graph. A verdict applies only
when EVERY citation verifies; the evidence check, not the reasoning that proposed
it, is the gate (same standard as :mod:`pipeline.crosscheck`).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def verify_citations(
    citations: list[dict[str, Any]],
    *,
    roots: dict[str, Path],
    graph: dict[str, Any],
) -> tuple[bool, list[dict[str, Any]]]:
    """Re-verify every citation. Returns (all_pass, per-citation results)."""
    node_ids = {
        str(node.get("id", "")) for node in (graph.get("nodes") or [])
    }
    results: list[dict[str, Any]] = []
    for citation in citations:
        repo = str(citation.get("repo") or "")
        file = str(citation.get("file") or "")
        line_start = int(citation.get("line_start") or 0)
        line_end = int(citation.get("line_end") or 0)
        pattern = str(citation.get("pattern") or "")
        symbol = citation.get("symbol")

        failures: list[str] = []
        path: Path | None = None
        root = roots.get(repo)
        if root is None:
            failures.append(f"'{repo}' is not a workspace member")
        elif file:
            candidate = root / file
            if candidate.is_file():
                path = candidate
            else:
                failures.append(f"'{file}' does not exist under member '{repo}'")

        text = ""
        if path is not None:
            try:
                text = path.read_text(errors="replace")
            except OSError as exc:
                failures.append(f"'{file}' could not be read ({exc.strerror or exc})")

        if path is not None and text:
            lines = text.splitlines()
            if line_start < 1 or line_start > len(lines):
                failures.append(
                    f"'{file}' has {len(lines)} line(s); citation starts at {line_start}"
                )
            elif line_end < line_start:
                failures.append("citation line range is inverted")
            else:
                window = "\n".join(lines[line_start - 1 : line_end])
                if pattern not in window:
                    failures.append(
                        f"pattern {pattern[:40]!r}{'…' if len(pattern) > 40 else ''} "
                        "is not present at the cited lines"
                    )

        if symbol:
            if f"{repo}:{file}#{symbol}" not in node_ids:
                failures.append(
                    f"symbol '{symbol}' does not resolve against the code model"
                )

        results.append(
            {
                "repo": repo,
                "file": file,
                "line_start": line_start,
                "line_end": line_end,
                "verified": not failures,
                **({"failures": failures} if failures else {}),
            }
        )
    return all(r["verified"] for r in results), results
