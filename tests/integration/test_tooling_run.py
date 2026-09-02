"""External tool execution and merge during analysis (feature 008, US2).

quickstart.md Scenarios 4 and 6: a seeded advisory beyond the bundled
snapshot surfaces exactly once with provenance; crashing/missing tools degrade
to declared limitations; the zero-tool path is unchanged (FR-010).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.init_cmd import run_init
from pipeline.run import run_scan
from pipeline.state import ArtifactStore
from tests.helpers.tool_shims import copy_fixture, install_shims

EMPTY_ANALYSIS = lambda _request: json.dumps({"findings": []})  # noqa: E731


def _scan(root: Path, monkeypatch: pytest.MonkeyPatch, shim_tools: dict[str, str], *, env=None):
    bin_dir = install_shims(root.parent, shim_tools)
    monkeypatch.setenv("PATH", str(bin_dir))
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)
    run_init(root, environ={}, no_input=True)
    result = run_scan(root, responder=EMPTY_ANALYSIS, full=True)
    return result


def _runs(root: Path) -> dict[str, dict]:
    payload = json.loads(
        (root / ".secscan" / "tooling" / "runs.json").read_text()
    )
    return {r["tool_id"]: r for r in payload["runs"]}


def test_seeded_advisory_surfaces_once_with_provenance(tmp_path, monkeypatch) -> None:
    """quickstart Scenario 4 / SC-003 / FR-005, FR-006."""
    root = copy_fixture("vuln_dep", tmp_path)
    result = _scan(root, monkeypatch, {"npm": "npm_audit.json"})

    flagged = [
        f for f in result.findings
        if "rapid-parse" in (f.get("dependency") or {}).get("package", "")
        or "rapid-parse" in f.get("description", "")
    ]
    assert len(flagged) == 1, "the external advisory merges exactly once"
    finding = flagged[0]
    assert "npm-audit" in finding.get("sources", []), "provenance records the tool"

    runs = _runs(root)
    assert runs["npm-audit"]["status"] == "ran"
    assert runs["npm-audit"]["read_only_guard"] == "passed"
    assert runs["npm-audit"]["finding_count"] == 1
    # every other applicable tool is a declared limitation, never silence (FR-009)
    assert result.report["coverage"]["tool_limitations"], "missing tools must be declared"
    markdown = result.report_path.read_text()
    assert "External tool:" in markdown


def test_crashing_tool_degrades_to_declared_failure(tmp_path, monkeypatch) -> None:
    """quickstart Scenario 6 / SC-006 / FR-009."""
    root = copy_fixture("crash_tool", tmp_path)
    result = _scan(
        root,
        monkeypatch,
        {"npm": "npm_audit.json"},
        env={"SECSCAN_SHIM_CRASH": "1"},
    )

    assert result.report_path.exists(), "a failing tool never fails the scan"
    runs = _runs(root)
    assert runs["npm-audit"]["status"] == "failed"
    assert runs["npm-audit"]["reason"]
    assert runs["npm-audit"]["finding_count"] == 0

    limitation = [
        t for t in result.report["coverage"]["tool_limitations"]
        if t["tool_id"] == "npm-audit"
    ]
    assert limitation and limitation[0]["status"] == "failed"


def test_format_drift_is_rejected_as_tool_failure(tmp_path, monkeypatch) -> None:
    """Spec edge case: valid JSON but wrong schema version → failed, zero merges."""
    root = copy_fixture("vuln_dep", tmp_path)
    result = _scan(root, monkeypatch, {"npm": "npm_audit_wrong_schema.json"})

    runs = _runs(root)
    assert runs["npm-audit"]["status"] == "failed"
    assert "unsupported" in runs["npm-audit"]["reason"]
    assert not any(
        "rapid-parse" in str(f.get("description", "")) for f in result.findings
    ), "no partial merges from a drifted report"


def test_zero_tool_run_matches_builtin_output(tmp_path, monkeypatch) -> None:
    """SC-005 / FR-010: with no external tools the scan is unchanged + declared."""
    root = copy_fixture("vuln_dep", tmp_path)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    run_init(root, environ={}, no_input=True)
    result = run_scan(root, responder=EMPTY_ANALYSIS, full=True)

    store = ArtifactStore(root)
    assert store.glob("findings/external/*.json") == []
    assert not any(f.get("source") == "external-tool" for f in result.findings)
    assert _runs(root) == {}, "missing tools produce limitations, not run records"
    missing = [
        t for t in result.report["coverage"]["tool_limitations"] if t["status"] == "missing"
    ]
    assert any(t["tool_id"] == "npm-audit" for t in missing), (
        "npm audit absence must be declared, never read as clean"
    )
