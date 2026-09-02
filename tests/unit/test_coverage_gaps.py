"""T040: structured, impact-assessed coverage gaps (FR-009, FR-010; contract D4).

Every blocked value and budget-dropped file produces a gap_details record with
cause, file, segment, criticality, and a concrete impact statement; critical
gaps render first; audit outcomes and blocking gaps reach the Markdown report.
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.fixtures.missed_detection_sites import build_fixture


def _scan(tmp_path: Path, site: str):
    from pipeline import run as run_mod
    from tests.integration.conftest import silent_responder, write_config

    root = build_fixture(site, tmp_path / site)
    write_config(root)
    run_mod.run_scan(root, responder=silent_responder, full=True)
    reports = root / ".secscan" / "reports"
    report = json.loads(next(reports.glob("*.json")).read_text())["payload"]
    markdown = next(reports.glob("*.md")).read_text()
    return report, markdown


def test_blocked_value_in_security_config_is_a_critical_gap(tmp_path: Path) -> None:
    """D4: the misconfig_spring fixture's blocked value lands in gap_details."""
    report, _ = _scan(tmp_path, "misconfig_spring")
    details = report["coverage"].get("gap_details") or []
    blocked = [d for d in details if d["cause"] == "blocked-value"]
    assert blocked, "no blocked-value gap detail recorded"
    detail = blocked[0]
    assert detail["file"].endswith("WebSecurityConfig.java")
    assert detail["segment_id"]
    assert detail["security_critical"] is True
    assert "security" in detail["impact"].lower() or "rule" in detail["impact"].lower()


def test_legacy_gaps_strings_are_unchanged(tmp_path: Path) -> None:
    """D4 additive: the legacy string array still exists alongside gap_details."""
    report, _ = _scan(tmp_path, "misconfig_spring")
    assert isinstance(report["coverage"].get("gaps"), list)
    assert all(isinstance(g, str) for g in report["coverage"]["gaps"])


def test_audit_outcomes_render_in_markdown(tmp_path: Path) -> None:
    """D4: audit outcomes render in Markdown — previously JSON-only."""
    _, markdown = _scan(tmp_path, "advisory_npm_marked")
    assert "Dependency audit" in markdown


def test_gap_details_classification_and_ordering() -> None:
    """D4: criticality follows the data-driven conventions; critical sorts first."""
    from pipeline.generate_report import _gap_details

    graph = {
        "nodes": [
            {"repo": "r", "path": "src/main/java/com/example/WebSecurityConfig.java",
             "annotations": ["trust_boundary"]},
            {"repo": "r", "path": "src/main/java/com/example/Utils.java",
             "annotations": []},
        ]
    }
    records = [
        {"cause": "budget-dropped", "file": "src/main/java/com/example/Utils.java",
         "segment_id": "seg-1"},
        {"cause": "blocked-value",
         "file": "src/main/java/com/example/WebSecurityConfig.java",
         "segment_id": "seg-1", "line": 5},
    ]
    details = _gap_details(records, graph)
    assert details[0]["file"].endswith("WebSecurityConfig.java")
    assert details[0]["security_critical"] is True
    assert "line 5" in details[0]["impact"]
    assert details[1]["security_critical"] is False
    assert "token budget" in details[1]["impact"]


def test_gap_details_are_deterministic(tmp_path: Path) -> None:
    """D4/Principle I: identical input, identical gap details."""
    first, _ = _scan(tmp_path / "a", "misconfig_spring")
    second, _ = _scan(tmp_path / "b", "misconfig_spring")
    assert first["coverage"].get("gap_details") == second["coverage"].get("gap_details")
