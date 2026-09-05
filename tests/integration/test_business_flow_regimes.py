"""T035: the three applicability modes end to end (feature 015, FR-018..023,
SC-006/SC-007)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from config.loader import ConfigError, load
from pipeline import run as run_mod
from pipeline.state import ArtifactStore
from tests.fixtures.flow_app import GROUND_TRUTH, build, flow_oracle_answer
from tests.integration.conftest import oracle_responder, write_config

CASE = GROUND_TRUTH["regulatory_case"]


def _responder(request) -> str:
    answer = flow_oracle_answer(request)
    return answer if answer is not None else oracle_responder(request)


def _scan(tmp_path: Path, business_flow_cfg: dict, label: str):
    root = build(tmp_path / label)
    write_config(root, {"business_flow": business_flow_cfg})
    return run_mod.run_scan(root, responder=_responder, full=True)


def _violations(result) -> list[dict]:
    return [f for f in result.findings if f.get("flow_category") == "regulatory-violation"]


def test_declared_only_reports_the_consent_breach(tmp_path: Path):
    result = _scan(
        tmp_path,
        {"enabled": True, "applicability_mode": "declared-only",
         "declared_regimes": [CASE["expected_regime"]]},
        "declared",
    )
    violations = _violations(result)
    assert len(violations) == 1
    refs = violations[0]["regulatory_refs"]
    assert [(r["regime"], r["obligation"]) for r in refs] == [
        (CASE["expected_regime"], CASE["expected_obligation"])
    ]
    assert CASE["violation_flow"] in violations[0]["flow_narrative"]["name"]
    narrative = json.dumps(violations[0]["flow_narrative"])
    assert "consent" in narrative


def test_hybrid_suggests_candidates_without_evaluating(tmp_path: Path):
    result = _scan(
        tmp_path, {"enabled": True}, "hybrid"
    )  # nothing declared; signup flow carries personal-data
    assert _violations(result) == []  # candidates are never evaluated (FR-023)
    flows_doc = ArtifactStore(result.scan_root).read("business-flows.json")
    candidates = flows_doc["coverage"]["candidate_regimes"]
    assert CASE["expected_regime"] in {c["regime"] for c in candidates}
    assert all(c["detected_categories"] for c in candidates)
    applicability = flows_doc["coverage"]["applicability"]
    assert applicability["mode"] == "hybrid"
    assert applicability["evaluated_regimes"] == []
    assert applicability.get("skipped_reason")  # declared, not silent

    # Declaring the suggested regime on the next scan evaluates it.
    config_path = result.scan_root / ".secscan" / "config.yaml"
    data = yaml.safe_load(config_path.read_text())
    data["business_flow"]["declared_regimes"] = [CASE["expected_regime"]]
    config_path.write_text(yaml.safe_dump(data, sort_keys=False))
    confirmed = run_mod.run_scan(result.scan_root, responder=_responder, full=True)
    assert len(_violations(confirmed)) == 1


def test_inferred_only_evaluates_with_basis(tmp_path: Path):
    result = _scan(
        tmp_path, {"enabled": True, "applicability_mode": "inferred-only"}, "inferred"
    )
    violations = _violations(result)
    assert len(violations) == 1
    ref = violations[0]["regulatory_refs"][0]
    assert ref["regime"] in ("gdpr", "ccpa")
    assert ref.get("basis"), "FR-023: inferred regimes state the detection basis"
    assert "personal-data" in ref["basis"]


def test_unknown_regime_id_is_a_config_error(tmp_path: Path):
    root = build(tmp_path / "bogus")
    write_config(root, {"business_flow": {"declared_regimes": ["bogus"]}})
    with pytest.raises(ConfigError, match="unknown regime"):
        load(root / ".secscan")


def test_multi_regime_breach_is_one_finding(tmp_path: Path):
    # Both privacy regimes declared: one finding, both refs — never one per regime.
    result = _scan(
        tmp_path,
        {"enabled": True, "applicability_mode": "declared-only",
         "declared_regimes": ["gdpr", "ccpa"]},
        "multi",
    )
    violations = _violations(result)
    assert len(violations) == 1
    assert {r["regime"] for r in violations[0]["regulatory_refs"]} == {"gdpr", "ccpa"}
