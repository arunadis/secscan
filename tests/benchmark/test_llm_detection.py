"""Spec 007 defect class: llm-detection (cases/llm_scan.json).

Runs full scans over the seeded LLM fixtures and asserts detection quality per
variant — recall on vulnerable fixtures, silence on deliberate false positives.
A regression in this class fails the build alone (FR-043b).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import run as run_mod
from tests.integration.conftest import silent_responder, write_config

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "llm_workspace"


def _scan(root: Path, tmp_path: Path) -> list[dict]:
    """Full scan over a fixture copy; returns correlated findings."""
    target = tmp_path / root.name
    import shutil

    shutil.copytree(root, target)
    write_config(target)
    run_mod.run_scan(target, responder=silent_responder, full=True)
    correlated = json.loads(
        (target / ".secscan" / "findings" / "correlated.json").read_text()
    )["payload"]
    return correlated["findings"]


def _llm(findings: list[dict], category: str) -> list[dict]:
    return [f for f in findings if str(f.get("tool_ref", "")) == f"llm:{category}"]


def test_direct_prompt_injection_is_found(tmp_path) -> None:
    findings = _scan(FIXTURES / "us1_direct" / "vulnerable", tmp_path)
    matched = _llm(findings, "direct")
    assert matched, "direct prompt injection missed on the vulnerable fixture"
    finding = matched[0]
    assert finding["cwe"] == "CWE-1427"
    assert finding["location"]["file"] == "app/server.py"
    assert "chat" == finding["location"].get("symbol")
    assert finding["verification"]["status"] in ("verified", "plausible")
    assert finding["mitigation"]["state"] == "undetermined"
    assert finding["mitigation"].get("reason")


def test_structured_separation_produces_no_finding(tmp_path) -> None:
    findings = _scan(FIXTURES / "us1_direct" / "safe", tmp_path)
    flagged = [
        f["id"] for f in findings if str(f.get("tool_ref", "")).startswith("llm:")
    ]
    assert not flagged, f"false positives on the safe fixture: {flagged}"


def test_sensitive_data_in_context_is_found(tmp_path) -> None:
    findings = _scan(FIXTURES / "us1_direct" / "sensitive", tmp_path)
    matched = _llm(findings, "sensitive-context")
    assert matched, "sensitive data entering model context missed"
    assert matched[0]["cwe"] == "CWE-200"


def test_insecure_output_handling_is_found(tmp_path) -> None:
    findings = _scan(FIXTURES / "us1_direct" / "output", tmp_path)
    matched = _llm(findings, "output-handling")
    assert matched, "model output reaching an interpreter missed"
    assert matched[0]["cwe"] == "CWE-116"


def test_indirect_injection_is_found_with_capability_reach(tmp_path) -> None:
    findings = _scan(FIXTURES / "us2_indirect" / "unbounded", tmp_path)
    matched = _llm(findings, "indirect")
    assert matched, "indirect exposure missed on the unbounded fixture"
    finding = matched[0]
    assert finding["cwe"] == "CWE-1427"
    assert finding["location"]["file"] == "app/agent.py"
    assert any(
        "send_email" in entry.get("reason", "") for entry in finding["evidence"]
    ), "reachable capability not recorded as evidence"


def test_bounded_ingestion_produces_no_indirect_finding(tmp_path) -> None:
    findings = _scan(FIXTURES / "us2_indirect" / "bounded", tmp_path)
    assert not _llm(findings, "indirect"), (
        f"false positive on the bounded fixture: "
        f"{[f['id'] for f in _llm(findings, 'indirect')]}"
    )


def test_overprivileged_agent_config_is_flagged(tmp_path) -> None:
    findings = _scan(FIXTURES / "us3_agent_config" / "overprivileged", tmp_path)
    rule_ids = {str(f.get("tool_ref", "")) for f in findings}
    for expected in (
        "agent-config:mcp-shell-arbitrary-command",
        "agent-config:mcp-auto-approve-all-tools",
        "agent-config:agent-rules-auto-approve-everything",
        "agent-config:agent-rules-unrestricted-filesystem-write",
    ):
        assert expected in rule_ids, f"{expected} missing from {sorted(rule_ids)}"


def test_scoped_agent_config_is_silent(tmp_path) -> None:
    findings = _scan(FIXTURES / "us3_agent_config" / "scoped", tmp_path)
    flagged = [f["id"] for f in findings if str(f.get("tool_ref", "")).startswith("agent-config:")]
    assert not flagged, f"false positives on scoped config: {flagged}"


def test_embedded_credential_in_prompt_artifact_is_never_serialized(tmp_path) -> None:
    root = tmp_path / "overprivileged"
    import shutil

    shutil.copytree(FIXTURES / "us3_agent_config" / "overprivileged", root)
    write_config(root)
    result = run_mod.run_scan(root, responder=silent_responder, full=True)
    correlated = json.loads(
        (root / ".secscan" / "findings" / "correlated.json").read_text()
    )["payload"]
    secrets = [f for f in correlated["findings"] if f["location"]["file"] == "system_prompt.txt"]
    assert secrets, "embedded credential in prompt artifact not reported"
    secret_value = "AKIAIOSFODNN7EXAMPLE"
    checked = 0
    for artifact in (root / ".secscan").rglob("*.json"):
        checked += 1
        assert secret_value not in artifact.read_text(), f"secret value leaked into {artifact.name}"
    for rendered in (result.report_path, result.report_json_path, result.report_html_path):
        assert secret_value not in Path(rendered).read_text()


@pytest.mark.parametrize("variant", ["vulnerable", "safe", "sensitive", "output"])
def test_llm_findings_declare_mitigation_honestly(variant, tmp_path) -> None:
    """SC-004: every finding in the category records a mitigation state."""
    findings = _scan(FIXTURES / "us1_direct" / variant, tmp_path)
    for finding in findings:
        if not str(finding.get("tool_ref", "")).startswith("llm:"):
            continue
        assert finding["mitigation"]["state"] in ("demonstrated", "undetermined")
        if finding["mitigation"]["state"] == "undetermined":
            assert finding["mitigation"]["reason"]
