"""Feature 014 T007: integration evidence for misconfiguration findings (FR-004).

Pinned contract: every misconfig finding gets one of three states —
`integrated` (evidence listed), `no-integration-found` (declared, remediation
shifts to removal), `undetermined` (rule class carries no markers). Neither of
the latter two suppresses or inflates the finding.
"""

from __future__ import annotations

from pathlib import Path

from pipeline import misconfig


def _finding(rule_id: str = "django-debug-enabled", repo: str = "api") -> dict:
    return {
        "cwe": "CWE-489",
        "severity_score": 4.0,
        "confidence": 0.9,
        "detection": "format",
        "location": {"repo": repo, "file": "app/settings.py", "line_start": 3},
        "description": "Django DEBUG enabled",
        "evidence": [{"repo": repo, "file": "app/settings.py", "reason": "matched"}],
        "recommendation": "Set DEBUG = False.",
        "tool_ref": f"misconfig:{rule_id}",
    }


def _member(tmp_path: Path, requirements: str = "") -> dict[str, Path]:
    root = tmp_path / "api"
    root.mkdir()
    if requirements:
        (root / "requirements.txt").write_text(requirements)
    return {"api": root}


def test_integrated_state_with_evidence(tmp_path: Path) -> None:
    roots = _member(tmp_path, "django==4.2.0\n")
    finding = _finding()
    misconfig.attach_integration([finding], roots)
    block = finding["integration"]
    assert block["state"] == "integrated"
    assert block["evidence"], "integrated state must list evidence"
    assert any("requirements.txt" in e["file"] for e in block["evidence"])


def test_no_integration_found(tmp_path: Path) -> None:
    roots = _member(tmp_path, "flask==3.0.0\n")
    finding = _finding()
    misconfig.attach_integration([finding], roots)
    block = finding["integration"]
    assert block["state"] == "no-integration-found"
    assert finding["severity_score"] == 4.0, "integration evidence must not adjust severity"
    assert "remove" in finding["recommendation"].lower() or "unused" in (
        finding["recommendation"].lower()
    ), "remediation should lead with removal of the unused configuration"


def test_undetermined_when_rule_carries_no_markers(tmp_path: Path) -> None:
    rule = {
        "id": "contract-sentinel",
        "stacks": ["python"],
        "file_globs": ["**/*.py"],
        "pattern": "DEBUG = True",
        "cwe": "CWE-489",
        "title": "t",
        "description": "d",
        "recommendation": "r",
        "severity_score": 4.0,
    }
    roots = _member(tmp_path)
    finding = _finding(rule_id="contract-sentinel")
    misconfig.attach_integration([finding], roots, rules=[rule])
    block = finding["integration"]
    assert block["state"] == "undetermined"
    assert block["reason"]


def test_unknown_tool_ref_rule_is_undetermined(tmp_path: Path) -> None:
    roots = _member(tmp_path)
    finding = _finding(rule_id="no-such-rule")
    misconfig.attach_integration([finding], roots)
    assert finding["integration"]["state"] == "undetermined"


def test_non_misconfig_findings_are_untouched(tmp_path: Path) -> None:
    finding = {"id": "SEC-1", "location": {"repo": "api"}}
    misconfig.attach_integration([finding], _member(tmp_path))
    assert "integration" not in finding


def test_integration_never_suppresses(tmp_path: Path) -> None:
    roots = _member(tmp_path)
    finding = _finding()
    misconfig.attach_integration([finding], roots)
    assert finding["integration"]["state"] == "no-integration-found"
    assert finding.get("status") not in ("rejected", "suppressed")
