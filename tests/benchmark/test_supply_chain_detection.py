"""Spec 007 defect class: supply-chain-detection (cases/supply_chain.json)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from pipeline import run as run_mod
from tests.integration.conftest import silent_responder, write_config

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "llm_workspace"


def _scan(root: Path, tmp_path: Path) -> list[dict]:
    target = tmp_path / root.name
    shutil.copytree(root, target)
    write_config(target)
    run_mod.run_scan(target, responder=silent_responder, full=True)
    correlated = json.loads(
        (target / ".secscan" / "findings" / "correlated.json").read_text()
    )["payload"]
    return correlated["findings"]


def test_confusion_and_mutable_exposure_is_found(tmp_path) -> None:
    findings = _scan(FIXTURES / "us4_supply_chain" / "vulnerable", tmp_path)
    supply = [f for f in findings if str(f.get("tool_ref", "")).startswith("supply-chain:")]
    assert supply, "supply-chain findings missing on the vulnerable fixture"
    refs = {f["tool_ref"] for f in supply}
    assert "supply-chain:npm-scoped-internal-namespace-unprotected" in refs
    assert "supply-chain:npm-mutable-reference" in refs
    for finding in supply:
        assert finding["location"]["file"] == "package.json"
        assert "guard: " in finding["evidence"][0]["reason"]


def test_unguarded_scope_records_guard_as_undetermined(tmp_path) -> None:
    findings = _scan(FIXTURES / "us4_supply_chain" / "vulnerable", tmp_path)
    confusion = [
        f for f in findings
        if f.get("tool_ref") == "supply-chain:npm-scoped-internal-namespace-unprotected"
    ]
    assert confusion
    assert any("guard: undetermined" in e.get("reason", "") for e in confusion[0]["evidence"])


def test_hardened_manifest_produces_zero_supply_chain_findings(tmp_path) -> None:
    findings = _scan(FIXTURES / "us4_supply_chain" / "hardened", tmp_path)
    supply = [f for f in findings if str(f.get("tool_ref", "")).startswith("supply-chain:")]
    assert not supply, f"false positives on the hardened fixture: {[f['id'] for f in supply]}"
