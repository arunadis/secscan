"""T019: end-to-end agent-mediated scan (quickstart Scenario 1).

Asserts finding completeness, budget compliance, usage reporting, seeded-vuln
detection, and the SC-001 scale property.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline import run as run_mod
from pipeline.redact import Redactor
from pipeline.state import ArtifactStore
from tests.fixtures.build_fixture import load_ground_truth
from tests.integration.conftest import oracle_responder, silent_responder, write_config


@pytest.fixture
def scan_result(configured_shop: Path):
    return run_mod.run_scan(configured_shop, responder=oracle_responder, full=True)


# ----------------------------------------------------------------- scenario 1


def test_scan_completes_and_produces_a_report(scan_result) -> None:
    assert scan_result.report_path.exists()
    assert scan_result.report_json_path.exists()
    assert scan_result.report["scan_id"]
    assert scan_result.report["execution_mode"] == "agent-mediated"


def test_no_analysis_invocation_exceeded_its_budget(scan_result) -> None:
    """SC-001: 100% of invocations stay within the configured context budget."""
    assert scan_result.usage["invocations"] > 0
    budget = scan_result.config.budgets["max_context_tokens"]
    for packet in scan_result.context_packets:
        assert packet["estimated_tokens"] <= budget, packet["segment_id"]
        assert packet["token_budget"]["max_context_tokens"] == budget


def test_whole_repository_is_never_loaded_into_one_context(scan_result) -> None:
    """The core constraint: bounded context, not the repository."""
    total_repo_files = len(scan_result.all_source_files)
    assert total_repo_files > 5
    for packet in scan_result.context_packets:
        assert len(packet["source"]) < total_repo_files


def test_every_finding_is_complete(scan_result) -> None:
    """SC-002: location, evidence, severity, confidence on 100% of findings."""
    findings = scan_result.reported_findings
    assert findings, "expected at least one finding on the seeded fixture"
    for finding in findings:
        assert finding["id"].startswith("SEC-")
        assert finding["cwe"].startswith("CWE-")
        assert finding["owasp_top10"]
        assert 0.0 <= finding["severity_score"] <= 10.0
        assert finding["severity_band"] in ("Critical", "High", "Medium", "Low", "None")
        assert 0.0 <= finding["confidence"] <= 1.0
        location = finding["location"]
        assert location["file"] and location["line_start"] >= 1
        assert location["symbol"]
        assert finding["evidence"]
        assert finding["attack_scenario"] and finding["impact"] and finding["recommendation"]


def test_seeded_true_positives_are_found(scan_result) -> None:
    """SC-009: known true positives are identified."""
    truth = load_ground_truth(Path(scan_result.scan_root))
    expected_files = {
        v["file"] for v in truth["seeded"] if v["expect_reported"]
    }
    reported_files = {f["location"]["file"] for f in scan_result.reported_findings}
    missing = expected_files - reported_files
    assert not missing, f"seeded vulnerabilities not reported: {sorted(missing)}"


def test_usage_summary_is_emitted(scan_result) -> None:
    """FR-019 + SC-004: usage/cost summary with savings vs maximal-context baseline."""
    usage = scan_result.usage
    assert usage["total_input_tokens"] > 0
    assert usage["by_stage"]
    assert usage["baseline_comparison"]["savings_factor"] >= 1.0
    assert "Savings vs maximal-context baseline" in scan_result.report_path.read_text()


def test_artifacts_exist_for_every_stage(scan_result) -> None:
    """FR-016: every stage leaves a durable artifact."""
    store = ArtifactStore(scan_result.scan_root)
    for relative in (
        "workspace.json",
        "code-graph.json",
        "usage.json",
    ):
        assert store.exists(relative), relative
    assert store.glob("repository/*.manifest.json")
    assert store.glob("segments/*.json")
    assert store.glob("context-packets/*.json")


def test_no_unredacted_secret_reaches_a_context_packet(scan_result) -> None:
    """FR-006a: redaction happens before anything could reach a model."""
    redactor = Redactor()
    for packet in scan_result.context_packets:
        assert packet["redaction"]["applied"] is True
        for path, text in packet["source"].items():
            assert "Pr0d-Sh0p-DB-2024!" not in text, path
            assert not redactor.scan(text), path


def test_segments_follow_security_boundaries_not_line_counts(scan_result) -> None:
    """FR-004: segments are meaningful boundaries with entry points and deps."""
    segments = scan_result.segments
    assert len(segments) >= 3
    names = {s["name"].lower() for s in segments}
    assert any("order" in n for n in names)
    assert any("admin" in n for n in names)
    for segment in segments:
        assert segment["purpose"]
        assert segment["files"]
        assert segment["repos"]


def test_clean_repository_reports_scanned_and_clean(tmp_path: Path) -> None:
    """Edge case: distinguish 'scanned and clean' from 'scan failed silently'.

    Uses a genuinely clean repo — the seeded fixture contains a real credential
    that the redactor detects deterministically, so it is never 'clean'.
    """
    repo = tmp_path / "clean-app"
    (repo / "src" / "math").mkdir(parents=True)
    (repo / "src" / "__init__.py").write_text("")
    (repo / "src" / "math" / "__init__.py").write_text("")
    (repo / "src" / "math" / "ops.py").write_text(
        '"""Pure arithmetic helpers."""\n\n\n'
        "def add(a, b):\n    return a + b\n\n\n"
        "def mean(values):\n"
        "    if not values:\n        return 0\n"
        "    return sum(values) / len(values)\n"
    )
    (repo / "pyproject.toml").write_text('[project]\nname = "clean-app"\n')
    write_config(repo)

    result = run_mod.run_scan(repo, responder=silent_responder, full=True)
    assert result.reported_findings == []
    assert result.report["coverage"]["clean"] is True
    assert result.report["coverage"]["segments_analyzed"] > 0
    assert "no issues" in result.report_path.read_text().lower()


# --------------------------------------------------------------- SC-001 scale


@pytest.mark.slow
def test_scan_handles_repository_10x_the_context_window(tmp_path: Path) -> None:
    """SC-001: a repo at least 10x a single context window still scans in budget."""
    from tests.fixtures.generate_large_repo import build_for_budget

    context_window = 12000
    repo = build_for_budget(tmp_path, context_window_tokens=context_window, factor=10)
    write_config(repo, {"budgets": {"max_context_tokens": context_window}})

    result = run_mod.run_scan(repo, responder=oracle_responder, full=True)

    assert result.total_source_tokens >= context_window * 10
    for packet in result.context_packets:
        assert packet["estimated_tokens"] <= context_window
    assert result.reported_findings, "seeded flaws at scale should still be found"
