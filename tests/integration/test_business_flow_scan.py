"""T021: full-scan flow-gap detection end to end (feature 015, US1, SC-003/SC-004).

The oracle answers the flow round with the seeded gap for the staff-discount flow
and clean for everything else; the assertions pin what the *pipeline* must do with it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import run as run_mod
from pipeline.state import ArtifactStore
from tests.fixtures.flow_app import GROUND_TRUTH, build, flow_oracle_answer
from tests.integration.conftest import oracle_responder, silent_responder, write_config


def _flow_oracle(request) -> str:
    answer = flow_oracle_answer(request)
    return answer if answer is not None else oracle_responder(request)


@pytest.fixture
def flow_repo(tmp_path: Path) -> Path:
    root = build(tmp_path)
    write_config(root, {"business_flow": {"enabled": True}})
    return root


@pytest.fixture
def result(flow_repo: Path):
    return run_mod.run_scan(flow_repo, responder=_flow_oracle, full=True)


def _flow_findings(result) -> list[dict]:
    return [f for f in result.findings if f.get("flow_category")]


def test_exactly_one_flow_gap_for_seeded_flow(result):
    findings = _flow_findings(result)
    gaps = [f for f in findings if f["flow_category"] == "flow-gap"]
    assert len(gaps) == 1, gaps


def test_finding_names_flow_check_and_compromise(result):
    gap = _flow_findings(result)[0]
    narrative = gap["flow_narrative"]
    assert GROUND_TRUTH["flow_gaps"][0]["flow_contains"] in json.dumps(narrative)
    assert GROUND_TRUTH["flow_gaps"][0]["missing_check"] in narrative["missing_check"]
    assert "staff pricing" in narrative["compromise"]
    assert narrative["steps"]  # the relevant sequence is present (SC-003)


def test_finding_resolves_and_is_verified(result):
    gap = _flow_findings(result)[0]
    flows_doc = ArtifactStore(result.scan_root).read("business-flows.json")
    known = {flow["id"] for flow in flows_doc["flows"]}
    assert gap["flow_ref"] in known  # SC-003: traceable to a flow
    assert gap["verification"]["status"] in ("verified", "plausible")


def test_safe_flows_are_not_flagged(result):
    findings_text = json.dumps(result.findings)
    for route in GROUND_TRUTH["safe_flows_at"]:
        safe_name = route.strip("/")
        assert f"flow gap at {safe_name}" not in findings_text
    flow_findings = _flow_findings(result)
    assert all(
        GROUND_TRUTH["flow_gaps"][0]["flow_contains"] in json.dumps(f["flow_narrative"])
        for f in flow_findings
    )


def test_flows_artifact_and_coverage_exist(result):
    flows_doc = ArtifactStore(result.scan_root).read("business-flows.json")
    assert flows_doc["coverage"]["reconstructed"]
    assert flows_doc["coverage"]["analyzed"] == sorted(
        flows_doc["coverage"]["reconstructed"]
    )

def test_code_level_scan_finds_nothing_for_the_gap(flow_repo: Path):
    result = run_mod.run_scan(flow_repo, responder=silent_responder, full=True)
    text = json.dumps(result.findings)
    assert "apply-staff" not in text


def test_usage_itemizes_business_flow_stage(result):
    assert result.usage["by_stage"]["business_flow_analysis"]["invocations"] >= 3


def test_report_contains_flow_coverage_section(result):
    assert result.report.get("flow_coverage"), "report must declare flow coverage"
