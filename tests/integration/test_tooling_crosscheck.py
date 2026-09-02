"""Cross-check: structural disproof suppresses, unknowns stay (feature 008, US3).

quickstart.md Scenario 5 / SC-004 / FR-007/FR-008 over the crosscheck fixture
whose README declares the ground truth per seeded finding.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.init_cmd import run_init
from pipeline.run import run_scan
from tests.helpers.tool_shims import copy_fixture, install_shims

EMPTY_ANALYSIS = lambda _request: json.dumps({"findings": []})  # noqa: E731


def _scan(root: Path, monkeypatch: pytest.MonkeyPatch):
    bin_dir = install_shims(
        root.parent,
        {"osv-scanner": "osv_crosscheck.json", "semgrep": "semgrep_crosscheck.json"},
    )
    monkeypatch.setenv("PATH", str(bin_dir))
    run_init(root, environ={}, no_input=True)
    return run_scan(root, responder=EMPTY_ANALYSIS, full=True)


def _suppressions(root: Path) -> list[dict]:
    path = root / ".secscan" / "tooling" / "suppressions.json"
    assert path.exists(), "suppressions artifact must exist when any finding is suppressed"
    return json.loads(path.read_text())["suppressions"]


def test_disproven_findings_suppressed_with_audit_trail(tmp_path, monkeypatch) -> None:
    root = copy_fixture("crosscheck", tmp_path)
    result = _scan(root, monkeypatch)

    suppressions = _suppressions(root)
    by_ground = {s["disproof_ground"]: s for s in suppressions}
    assert set(by_ground) == {"package-absent", "version-outside-range", "location-unresolvable"}
    for record in suppressions:
        assert record["evidence"], "every suppression carries deterministic evidence (FR-007)"
        assert record["tool_id"] in {"osv-scanner", "semgrep"}

    assert "ghost-lib" in by_ground["package-absent"]["finding"]["description"]
    assert "safe-serial" in by_ground["version-outside-range"]["finding"]["description"]
    assert "src/missing.py" in by_ground["location-unresolvable"]["finding"]["location"]["file"]

    # suppressed findings never reach the published findings; identity is the
    # suppressed location (code findings) or suppressed package (advisories),
    # since descriptions may share a template across distinct findings
    suppressed_locations = {
        json.dumps(s["finding"]["location"], sort_keys=True) for s in suppressions
    }
    suppressed_packages = {
        s["finding"]["description"].split(" ", 1)[0]
        for s in suppressions
        if s["disproof_ground"] in ("package-absent", "version-outside-range")
    }
    for finding in result.findings:
        location = json.dumps(finding.get("location") or {}, sort_keys=True)
        assert location not in suppressed_locations, f"suppressed finding survived: {location}"
        assert not any(pkg in finding.get("description", "") for pkg in suppressed_packages)


def test_true_and_undetermined_findings_are_retained(tmp_path, monkeypatch) -> None:
    root = copy_fixture("crosscheck", tmp_path)
    result = _scan(root, monkeypatch)

    # SC-004: zero true positives suppressed
    suppressions = _suppressions(root)
    assert not any("left-pad-again" in s["finding"]["description"] for s in suppressions)

    surviving = [f for f in result.findings if "left-pad-again" in str(f.get("description", ""))]
    assert len(surviving) == 1
    assert "osv-scanner" in surviving[0].get("sources", [])

    # the reachable-looking SAST finding at src/app.py is retained; reachability
    # doubt is a verification gap, never a suppression ground
    sast = [
        f for f in result.findings
        if (f.get("location") or {}).get("file") == "src/app.py"
    ]
    assert sast, "the src/app.py semgrep finding must survive"
    verdict = sast[0].get("verification") or {}
    if verdict:
        assert verdict.get("status") in {"verified", "plausible"}
