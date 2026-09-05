"""T019: flow findings relate to code-level findings, never double-count (FR-011)."""

from __future__ import annotations

from pipeline.correlate_findings import _link_flow_findings, correlate


def _code_finding(**over) -> dict:
    finding = {
        "id": "SEC-0001",
        "cwe": "CWE-862",
        "confidence": 0.8,
        "location": {"repo": "shop", "file": "src/app.py", "symbol": "handler"},
        "evidence": [{"file": "src/app.py", "reason": "missing authorization"}],
        "status": "local",
    }
    finding.update(over)
    return finding


def _flow_finding(**over) -> dict:
    finding = _code_finding(id="SEC-0007")
    finding["flow_ref"] = "flow:ws:abc"
    finding.update(over)
    return finding


class TestFlowLinks:
    def test_same_cwe_same_location_links_both_ways(self):
        flow_finding, code_finding = _flow_finding(), _code_finding()
        findings = [flow_finding, code_finding]
        _link_flow_findings(findings)
        assert any(
            rel["target_id"] == code_finding["id"] and rel["type"] == "related"
            for rel in flow_finding["relationships"]
        )
        assert any(
            rel["target_id"] == flow_finding["id"] and rel["type"] == "related"
            for rel in code_finding["relationships"]
        )

    def test_different_cwe_not_linked(self):
        flow_finding, code_finding = _flow_finding(), _code_finding(cwe="CWE-89")
        findings = [flow_finding, code_finding]
        _link_flow_findings(findings)
        assert not flow_finding.get("relationships")
        assert not code_finding.get("relationships")

    def test_different_file_not_linked(self):
        flow_finding, code_finding = _flow_finding(), _code_finding()
        code_finding["location"]["file"] = "src/other.py"
        findings = [flow_finding, code_finding]
        _link_flow_findings(findings)
        assert not flow_finding.get("relationships")

    def test_both_findings_survive_correlation(self):
        # Flow findings get no symbol matching the code finding's, so they are
        # NOT collapsed as duplicates — related, not merged (FR-011).
        flow_finding = _flow_finding(symbol="order_start_flow")
        flow_finding["location"]["symbol"] = "order_apply_staff_discount"
        code_finding = _code_finding(id="SEC-0002")
        code_finding["location"]["symbol"] = "order_apply_staff_discount"
        correlated = correlate([flow_finding, code_finding])
        ids = {f["id"] for f in correlated if f.get("status") != "rejected"}
        assert ids == {"SEC-0002", "SEC-0007"}
