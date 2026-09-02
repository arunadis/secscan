"""Tiered location resolution (FR-001–FR-004, FR-007).

The code model is the sole authority for a finding's line range. Analysis output
is treated as a *claim about where* something is, never as the measurement itself:
context packets present source with unrelated lines omitted, so a model counting
lines is counting in a document that does not exist on disk. Every reported
location is therefore re-derived here.

Resolution is tiered so that language coverage is never a precondition for
reporting a finding (contracts/accuracy-contracts.md §1):

``symbol``
    The language is parsed. The location resolves to a declared symbol and the
    line range is taken from the code model, discarding whatever was reported.

``file``
    The language has no grammar. The file is verified to exist with the reported
    line inside its bounds. A positive result — just a weaker guarantee.

*rejected*
    Not even the file can be verified. The finding is dropped with a reason. This
    is the only outcome that removes a finding, and it exists because publishing a
    location the pipeline could not confirm is precisely the defect this feature
    removes.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

TIER_SYMBOL = "symbol"
TIER_FILE = "file"


@dataclass(frozen=True)
class Resolution:
    """The outcome of resolving one finding's location."""

    tier: str | None
    file: str = ""
    symbol: str | None = None
    line_start: int = 1
    line_end: int = 1
    symbol_confirmed: bool = False
    alternatives_existed: bool = False
    chosen_by: str | None = None
    rejected_reason: str | None = None

    @property
    def resolved(self) -> bool:
        return self.tier is not None

    def apply_to(self, finding: dict[str, Any]) -> None:
        """Overwrite the finding's location with the resolved one (in place)."""
        location = finding["location"]
        location["file"] = self.file
        location["line_start"] = self.line_start
        location["line_end"] = self.line_end
        location["tier"] = self.tier
        location["symbol_confirmed"] = self.symbol_confirmed
        if self.symbol:
            location["symbol"] = self.symbol
        elif "symbol" in location and not self.symbol_confirmed:
            # Keep the reported name — it is still a useful hint — but the caller
            # can see from symbol_confirmed that nothing verified it.
            pass
        if self.alternatives_existed:
            location["alternatives_existed"] = True
        if self.chosen_by:
            location["chosen_by"] = self.chosen_by


class Resolver:
    """Resolves finding locations against the code model."""

    def __init__(
        self,
        graph: dict[str, Any],
        roots: dict[str, Path] | None = None,
        analyzed_files: set[tuple[str, str]] | None = None,
    ) -> None:
        self.roots = roots or {}
        #: (repo, path) -> nodes, so a file's symbols are one lookup away
        self.by_file: dict[tuple[str, str], list[dict[str, Any]]] = {}
        #: (repo, symbol) -> nodes, for resolving a symbol reported against the
        #: wrong file (a common and harmless model error)
        self.by_symbol: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for node in graph.get("nodes") or []:
            self.by_file.setdefault((node["repo"], node["path"]), []).append(node)
            if node.get("symbol"):
                self.by_symbol.setdefault((node["repo"], node["symbol"]), []).append(node)
        #: when provided, a location outside the analyzed set cannot be confirmed
        self.analyzed_files = analyzed_files

    # ------------------------------------------------------------------ api

    def resolve(self, finding: dict[str, Any]) -> Resolution:
        location = finding.get("location") or {}
        repo = str(location.get("repo", ""))
        path = str(location.get("file", ""))
        symbol = location.get("symbol") or None
        reported_start = int(location.get("line_start") or 1)
        reported_end = int(location.get("line_end") or reported_start)

        if not path:
            return Resolution(None, rejected_reason="the finding names no file")

        if self.analyzed_files is not None and (repo, path) not in self.analyzed_files:
            return Resolution(
                None,
                rejected_reason=(
                    f"'{path}' was not among the files analyzed for this segment, so the "
                    "reported location could not be confirmed"
                ),
            )

        nodes = self.by_file.get((repo, path)) or []
        if not nodes:
            return Resolution(
                None,
                rejected_reason=(
                    f"'{path}' is not present in the code model for repository '{repo}'"
                ),
            )

        if symbol:
            resolved = self._resolve_symbol(repo, path, symbol, nodes)
            if resolved is not None:
                return resolved

        return self._resolve_file(repo, path, symbol, nodes, reported_start, reported_end)

    # ------------------------------------------------------------ internals

    def _resolve_symbol(
        self, repo: str, path: str, symbol: str, nodes: list[dict[str, Any]]
    ) -> Resolution | None:
        """Symbol tier, or ``None`` when the symbol cannot be confirmed."""
        same_file = self._with_lines(n for n in nodes if n.get("symbol") == symbol)
        candidates = same_file
        chosen_by: str | None = None

        if not candidates:
            # The symbol exists in this repository but was attributed to the wrong
            # file. Prefer the code model's answer over the reported path.
            elsewhere = self._with_lines(self.by_symbol.get((repo, symbol)) or ())
            if not elsewhere:
                return None
            candidates = elsewhere
            chosen_by = "symbol found elsewhere in the repository; reported path corrected"

        ordered = sorted(candidates, key=lambda n: n["id"])
        chosen = ordered[0]
        ambiguous = len(ordered) > 1
        if ambiguous and chosen_by is None:
            chosen_by = "lowest node id among same-file definitions"
        elif ambiguous:
            chosen_by = f"{chosen_by}; lowest node id among {len(ordered)} definitions"

        start = int(chosen["line_start"])
        end = int(chosen.get("line_end") or start)
        return Resolution(
            tier=TIER_SYMBOL,
            file=chosen["path"],
            symbol=symbol,
            line_start=start,
            line_end=max(start, end),
            symbol_confirmed=True,
            alternatives_existed=ambiguous,
            chosen_by=chosen_by,
        )

    def _resolve_file(
        self,
        repo: str,
        path: str,
        symbol: str | None,
        nodes: list[dict[str, Any]],
        reported_start: int,
        reported_end: int,
    ) -> Resolution:
        """File tier: verify the file and clamp the reported line into its bounds."""
        total = self._line_count(repo, path)
        if total == 0:
            return Resolution(
                None,
                rejected_reason=(
                    f"'{path}' could not be read at the scanned revision, so the reported "
                    "location could not be verified"
                ),
            )

        start = reported_start
        end = max(reported_start, reported_end)
        chosen_by = None
        if total is not None and start > total:
            # The reported line does not exist. Clamping keeps a real code fact
            # rather than discarding it over a bad number, but the adjustment is
            # recorded so nobody mistakes it for a measurement.
            start = total
            end = total
            chosen_by = f"reported line {reported_start} exceeds the file's {total} lines; clamped"
        elif total is not None:
            end = min(end, total)

        return Resolution(
            tier=TIER_FILE,
            file=path,
            symbol=symbol,
            line_start=start,
            line_end=end,
            symbol_confirmed=False,
            chosen_by=chosen_by,
        )

    @staticmethod
    def _with_lines(nodes: Any) -> list[dict[str, Any]]:
        """Only nodes that actually carry a line range can resolve at symbol tier."""
        return [n for n in nodes if n.get("line_start")]

    def _line_count(self, repo: str, path: str) -> int | None:
        """Lines in the file, ``None`` when unknown, ``0`` when unreadable."""
        root = self.roots.get(repo)
        if root is None:
            return None  # no filesystem access: accept the file node as verification
        try:
            return len((root / path).read_text(errors="replace").splitlines()) or 1
        except OSError:
            return 0


def apply_resolution(
    findings: list[dict[str, Any]],
    graph: dict[str, Any],
    roots: dict[str, Path] | None = None,
    analyzed_files: set[tuple[str, str]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve every finding's location; returns ``(kept, rejected)``.

    Runs before deduplication so that findings differing only in the line numbers
    a model guessed collapse into one (FR-007).
    """
    resolver = Resolver(graph, roots, analyzed_files)
    kept: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for finding in findings:
        resolution = resolver.resolve(finding)
        if not resolution.resolved:
            finding["status"] = "rejected"
            finding["rejection_reason"] = (
                f"location could not be resolved: {resolution.rejected_reason}"
            )
            rejected.append(finding)
            continue
        resolution.apply_to(finding)
        kept.append(finding)
    return kept, rejected
