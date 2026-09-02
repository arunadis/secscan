"""T021: tiered location resolution (FR-001–FR-004, FR-007).

The premise under test: analysis output is a *claim* about where something is, and
the code model is the measurement. Every case below feeds a deliberately wrong or
unverifiable location and asserts what the pipeline publishes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline.locate import TIER_FILE, TIER_SYMBOL, Resolver, apply_resolution
from pipeline.normalize_findings import resolve_and_dedupe


def graph(*nodes: dict) -> dict:
    return {"nodes": list(nodes), "edges": []}


def node(repo="r", path="a.py", symbol=None, start=None, end=None, parsed=True) -> dict:
    out = {
        "id": f"{repo}:{path}" + (f"#{symbol}" if symbol else ""),
        "repo": repo,
        "type": "function" if symbol else "file",
        "path": path,
        "parsed": parsed,
    }
    if symbol:
        out["symbol"] = symbol
    if start:
        out["line_start"] = start
        out["line_end"] = end or start
    return out


def finding(repo="r", path="a.py", symbol=None, start=1, end=1) -> dict:
    location = {"repo": repo, "file": path, "line_start": start, "line_end": end}
    if symbol:
        location["symbol"] = symbol
    # `confidence` is always present on a normalized finding; dedupe uses it to
    # pick a winner among collapsed duplicates.
    return {
        "id": "SEC-0001",
        "cwe": "CWE-89",
        "confidence": 0.9,
        "location": location,
        "evidence": [],
    }


# ------------------------------------------------------------- symbol tier


def test_symbol_tier_overwrites_the_reported_line_range() -> None:
    """FR-001: the code model is the sole authority, not the model's count."""
    g = graph(node(path="a.py"), node(path="a.py", symbol="f", start=41, end=48))
    resolution = Resolver(g).resolve(finding(symbol="f", start=39, end=39))
    assert resolution.tier == TIER_SYMBOL
    assert (resolution.line_start, resolution.line_end) == (41, 48)
    assert resolution.symbol_confirmed is True


def test_symbol_tier_applies_to_the_finding_in_place() -> None:
    g = graph(node(path="a.py"), node(path="a.py", symbol="f", start=10, end=20))
    doc = finding(symbol="f", start=7, end=7)
    Resolver(g).resolve(doc).apply_to(doc)
    assert doc["location"]["line_start"] == 10
    assert doc["location"]["line_end"] == 20
    assert doc["location"]["tier"] == TIER_SYMBOL
    assert doc["location"]["symbol_confirmed"] is True


def test_ambiguous_symbol_is_resolved_deterministically_and_recorded() -> None:
    """FR-004: pick one, the same one every time, and say that others existed."""
    g = graph(
        node(path="a.py"),
        node(path="a.py", symbol="f", start=5, end=6),
        {
            "id": "r:a.py#f#2",
            "repo": "r",
            "type": "function",
            "path": "a.py",
            "symbol": "f",
            "line_start": 30,
            "line_end": 31,
        },
    )
    first = Resolver(g).resolve(finding(symbol="f"))
    second = Resolver(g).resolve(finding(symbol="f"))
    assert first.alternatives_existed is True
    assert first.chosen_by
    assert (first.line_start, first.line_end) == (second.line_start, second.line_end)


def test_symbol_attributed_to_the_wrong_file_is_corrected() -> None:
    """A common, harmless model error: right symbol, wrong path."""
    g = graph(
        node(path="a.py"),
        node(path="b.py"),
        node(path="b.py", symbol="handler", start=12, end=15),
    )
    resolution = Resolver(g).resolve(finding(path="a.py", symbol="handler"))
    assert resolution.tier == TIER_SYMBOL
    assert resolution.file == "b.py"
    assert (resolution.line_start, resolution.line_end) == (12, 15)
    assert "elsewhere" in (resolution.chosen_by or "")


# --------------------------------------------------------------- file tier


def test_file_tier_when_the_language_has_no_grammar(tmp_path: Path) -> None:
    """FR-003/FR-003c/SC-001a: reported, not dropped, and honestly labelled."""
    (tmp_path / "legacy.rb").write_text("class A\n  def b\n  end\nend\n")
    g = graph(node(path="legacy.rb", parsed=False))
    resolution = Resolver(g, roots={"r": tmp_path}).resolve(
        finding(path="legacy.rb", symbol="b", start=2, end=2)
    )
    assert resolution.tier == TIER_FILE
    assert resolution.symbol_confirmed is False
    assert resolution.resolved is True


def test_file_tier_keeps_the_unconfirmed_symbol_as_a_hint(tmp_path: Path) -> None:
    (tmp_path / "legacy.rb").write_text("a\nb\nc\n")
    g = graph(node(path="legacy.rb", parsed=False))
    doc = finding(path="legacy.rb", symbol="find_by_id", start=2, end=2)
    Resolver(g, roots={"r": tmp_path}).resolve(doc).apply_to(doc)
    assert doc["location"]["symbol"] == "find_by_id"
    assert doc["location"]["symbol_confirmed"] is False
    assert doc["location"]["tier"] == TIER_FILE


def test_out_of_bounds_line_is_clamped_and_recorded(tmp_path: Path) -> None:
    """Losing a real finding over a bad line number would be the worse error."""
    (tmp_path / "legacy.rb").write_text("one\ntwo\nthree\n")
    g = graph(node(path="legacy.rb", parsed=False))
    resolution = Resolver(g, roots={"r": tmp_path}).resolve(
        finding(path="legacy.rb", start=999, end=999)
    )
    assert resolution.tier == TIER_FILE
    assert resolution.line_start == 3
    assert "clamped" in (resolution.chosen_by or "")


def test_symbol_without_a_line_range_falls_back_to_file_tier(tmp_path: Path) -> None:
    """A node carrying no line range cannot support a symbol-tier claim."""
    (tmp_path / "a.py").write_text("x = 1\n")
    g = graph(node(path="a.py"), node(path="a.py", symbol="f"))
    resolution = Resolver(g, roots={"r": tmp_path}).resolve(finding(symbol="f"))
    assert resolution.tier == TIER_FILE


# ---------------------------------------------------------------- rejection


def test_file_absent_from_the_code_model_is_rejected() -> None:
    """FR-003: never publish a location the pipeline could not confirm."""
    resolution = Resolver(graph(node(path="a.py"))).resolve(finding(path="hallucinated.py"))
    assert resolution.resolved is False
    assert "not present in the code model" in (resolution.rejected_reason or "")


def test_unreadable_file_is_rejected(tmp_path: Path) -> None:
    g = graph(node(path="gone.rb", parsed=False))
    resolution = Resolver(g, roots={"r": tmp_path}).resolve(finding(path="gone.rb"))
    assert resolution.resolved is False
    assert "could not be read" in (resolution.rejected_reason or "")


def test_finding_with_no_file_is_rejected() -> None:
    doc = {"id": "SEC-0001", "cwe": "CWE-89", "location": {"repo": "r"}, "evidence": []}
    assert Resolver(graph()).resolve(doc).resolved is False


def test_location_outside_the_analyzed_set_is_rejected() -> None:
    """A file shed to satisfy the token budget cannot have been observed."""
    g = graph(node(path="shed.py"), node(path="shed.py", symbol="f", start=1, end=2))
    resolver = Resolver(g, analyzed_files={("r", "kept.py")})
    resolution = resolver.resolve(finding(path="shed.py", symbol="f"))
    assert resolution.resolved is False
    assert "not among the files analyzed" in (resolution.rejected_reason or "")


def test_rejected_findings_carry_a_reason_and_are_separated() -> None:
    g = graph(node(path="a.py"), node(path="a.py", symbol="f", start=3, end=4))
    kept, rejected = apply_resolution(
        [finding(symbol="f"), finding(path="nope.py")], g
    )
    assert len(kept) == 1 and len(rejected) == 1
    assert rejected[0]["status"] == "rejected"
    assert rejected[0]["rejection_reason"].startswith("location could not be resolved")


# --------------------------------------------------- ordering against dedupe


def test_resolution_precedes_dedupe_so_guessed_lines_collapse() -> None:
    """FR-007: same CWE, same symbol, two different guessed lines -> one finding.

    This is the ordering the requirement pins down. Deduplicating first would keep
    both, because the guessed line numbers differ; resolving first makes them
    identical and the pair collapses.
    """
    g = graph(node(path="a.py"), node(path="a.py", symbol="f", start=41, end=48))
    a = finding(symbol="f", start=39, end=39)
    b = finding(symbol="f", start=44, end=44)
    b["id"] = "SEC-0002"
    kept, rejected = resolve_and_dedupe([a, b], g)
    assert not rejected
    assert len(kept) == 1, "findings differing only in guessed line numbers must collapse"
    assert kept[0]["location"]["line_start"] == 41


def test_dedupe_keeps_genuinely_distinct_locations() -> None:
    g = graph(
        node(path="a.py"),
        node(path="a.py", symbol="f", start=1, end=2),
        node(path="a.py", symbol="g", start=10, end=12),
    )
    a = finding(symbol="f")
    b = finding(symbol="g")
    b["id"] = "SEC-0002"
    kept, _ = resolve_and_dedupe([a, b], g)
    assert len(kept) == 2


# ------------------------------------------------------------- determinism


@pytest.mark.parametrize("run", range(3))
def test_resolution_is_deterministic(run: int) -> None:
    g = graph(
        node(path="a.py"),
        node(path="a.py", symbol="f", start=5, end=9),
        node(path="a.py", symbol="f", start=20, end=25),
    )
    resolution = Resolver(g).resolve(finding(symbol="f"))
    assert (resolution.line_start, resolution.line_end) == (5, 9)
