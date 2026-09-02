"""T022/T023: location accuracy end to end (quickstart Scenarios 1–2).

The oracle responder deliberately counts lines *within the packet*, reproducing
the real failure mode that made every location in the reviewed benchmark scan
wrong by one or two lines. These tests assert the pipeline corrects it rather than
publishing the guess.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import run as run_mod
from tests.fixtures.unparsed_language import build_unparsed
from tests.integration.conftest import oracle_responder, write_config


@pytest.fixture
def shop_scan(configured_shop: Path):
    """Full agent-mediated scan of the seeded shop fixture."""
    return run_mod.run_scan(configured_shop, responder=oracle_responder, full=True)


def _reported(result) -> list[dict]:
    report = json.loads(Path(result.report_json_path).read_text())["payload"]
    return [f for items in report["findings_by_band"].values() for f in items]


def _graph_symbols(scan_root: Path) -> dict[tuple, tuple[int, int]]:
    graph_path = scan_root / ".secscan" / "code-graph.json"
    payload = json.loads(graph_path.read_text())["payload"]
    return {
        (n["repo"], n["path"], n.get("symbol")): (
            n["line_start"],
            n.get("line_end", n["line_start"]),
        )
        for n in payload["nodes"]
        if n.get("symbol") and n.get("line_start")
    }


# ----------------------------------------------------- Scenario 1: exactness


def test_symbol_tier_locations_match_the_code_model_exactly(shop_scan, configured_shop) -> None:
    """SC-001: zero drift. The published range is the code model's range."""
    symbols = _graph_symbols(configured_shop)
    checked = 0
    for finding in _reported(shop_scan):
        location = finding["location"]
        if location.get("tier") != "symbol":
            continue
        key = (location["repo"], location["file"], location.get("symbol"))
        assert key in symbols, f"{finding['id']} claims symbol tier for an unknown symbol"
        assert (location["line_start"], location["line_end"]) == symbols[key], (
            f"{finding['id']} location drifted from the code model"
        )
        checked += 1
    assert checked, "no symbol-tier finding was produced, so nothing was verified"


def test_every_reported_finding_declares_a_resolution_tier(shop_scan) -> None:
    """FR-003a: a reader can tell a symbol-level guarantee from a file-level one."""
    findings = _reported(shop_scan)
    assert findings
    for finding in findings:
        assert finding["location"].get("tier") in ("symbol", "file"), finding["id"]


def test_no_finding_admits_an_unmatched_location(shop_scan) -> None:
    """FR-003b: the old 'could not be matched to the code graph' verdict is gone."""
    for finding in _reported(shop_scan):
        gap = (finding.get("verification") or {}).get("gap") or ""
        assert "could not be matched to the code graph" not in gap, finding["id"]


def test_report_records_resolution_tiers(shop_scan) -> None:
    tiers = json.loads(Path(shop_scan.report_json_path).read_text())["payload"]["coverage"][
        "resolution_tiers"
    ]
    assert set(tiers) == {"symbol", "file", "rejected"}
    assert tiers["symbol"] + tiers["file"] == len(_reported(shop_scan))


def test_context_packets_carry_line_numbers(configured_shop, shop_scan) -> None:
    """FR-002: remove the cause, not just the symptom (research.md A6)."""
    packets = sorted((configured_shop / ".secscan" / "context-packets").glob("*.json"))
    assert packets
    numbered = 0
    for path in packets:
        for text in json.loads(path.read_text())["payload"]["source"].values():
            for line in text.splitlines():
                if line.strip():
                    assert "|" in line[:8], f"unnumbered source line: {line!r}"
                    break
            numbered += 1
    assert numbered, "no packet carried source"


# ------------------------------------------- Scenario 2: unmodelled languages


@pytest.fixture
def unparsed_scan(tmp_path: Path):
    repo = build_unparsed(tmp_path)
    write_config(repo)
    return repo, run_mod.run_scan(repo, responder=oracle_responder, full=True)


def test_unparsed_language_findings_are_reported_not_dropped(unparsed_scan) -> None:
    """SC-001a: language coverage is never a precondition for reporting.

    Before feature 002 a Ruby repository produced no graph nodes at all, so every
    finding in it was rejected for an unresolvable location and the scan reported
    nothing — the worst available failure mode for a security tool.
    """
    _repo, result = unparsed_scan
    findings = _reported(result)
    assert findings, "a repository in an unmodelled language reported nothing"
    assert all(f["location"]["tier"] == "file" for f in findings)
    assert all(f["location"]["symbol_confirmed"] is False for f in findings)


def test_unparsed_language_files_are_represented_in_the_graph(unparsed_scan) -> None:
    """FR-003c: represented at file granularity, claiming nothing about the interior."""
    repo, _result = unparsed_scan
    payload = json.loads((repo / ".secscan" / "code-graph.json").read_text())["payload"]
    ruby = [n for n in payload["nodes"] if n["path"].endswith(".rb")]
    assert ruby, "no node was emitted for the Ruby sources"
    for node in ruby:
        assert node["parsed"] is False
        assert "symbol" not in node
        assert "line_start" not in node


def test_unparsed_language_scan_rejects_nothing_for_location(unparsed_scan) -> None:
    _repo, result = unparsed_scan
    tiers = json.loads(Path(result.report_json_path).read_text())["payload"]["coverage"][
        "resolution_tiers"
    ]
    assert tiers["rejected"] == 0
    assert tiers["symbol"] == 0
    assert tiers["file"] > 0
