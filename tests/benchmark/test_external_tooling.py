"""Spec 008 defect-class coverage: external tooling (cases/external_tooling.json).

Runs offline against recorded tool output (PATH shims); this is the
release-blocking regression gate for the feature per FR-013.
"""

from __future__ import annotations

import json
from pathlib import Path

from pipeline import run as run_mod
from tests.helpers.tool_shims import copy_fixture, install_shims
from tests.integration.conftest import silent_responder, write_config


def _scan(name: str, tmp_path: Path, monkeypatch, shims: dict[str, str]):
    target = copy_fixture(name, tmp_path)
    bin_dir = install_shims(tmp_path / f"bin-{name}", shims)
    monkeypatch.setenv("PATH", str(bin_dir))
    write_config(target)
    result = run_mod.run_scan(target, responder=silent_responder, full=True)
    return target, result


def test_beyond_snapshot_advisory_surfaces_with_provenance(tmp_path, monkeypatch) -> None:
    target, result = _scan("vuln_dep", tmp_path, monkeypatch, {"npm": "npm_audit.json"})
    flagged = [
        f for f in result.findings
        if "rapid-parse" in str(f.get("description", ""))
    ]
    assert len(flagged) == 1
    assert "npm-audit" in flagged[0].get("sources", [])
    assert flagged[0]["location"]["file"] == "package-lock.json"


def test_crosscheck_suppression_ground_truth(tmp_path, monkeypatch) -> None:
    target, result = _scan(
        "crosscheck",
        tmp_path,
        monkeypatch,
        {"osv-scanner": "osv_crosscheck.json", "semgrep": "semgrep_crosscheck.json"},
    )

    suppressions = json.loads(
        (target / ".secscan" / "tooling" / "suppressions.json").read_text()
    )["suppressions"]
    grounds = {s["disproof_ground"] for s in suppressions}
    assert grounds == {"package-absent", "version-outside-range", "location-unresolvable"}
    assert all(s["evidence"] for s in suppressions)

    descriptions = json.dumps(result.findings)
    for seed in ("ghost-lib", "safe-serial", "missing.py"):
        assert seed not in descriptions, f"suppressed-by-ground-truth seed surfaced: {seed}"

    # zero seeded true findings suppressed
    assert any("left-pad-again" in str(f.get("description", "")) for f in result.findings)
    assert any((f.get("location") or {}).get("file") == "src/app.py" for f in result.findings)
