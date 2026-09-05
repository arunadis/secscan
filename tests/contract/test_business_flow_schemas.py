"""T016: contract tests for the feature-015 schemas and additive finding fields.

Golden documents pass; every deliberate BREAK is rejected. Additive change rule:
finding.json/report internals keep schema_version "1" (contracts §4-5).
"""

from __future__ import annotations

import pytest

from pipeline.schemas import SchemaError, is_valid, validate
from tests.contract.test_schemas import valid_finding


def valid_business_flow() -> dict:
    return {
        "flows": [
            {
                "id": "flow:ws-demo:0123456789ab",
                "name": "/order/start",
                "actor": {"kind": "anonymous", "determination": "undetermined"},
                "steps": [
                    {
                        "node_id": "shop:src/app.py#@/order/start",
                        "operation": "entry",
                        "annotations": ["user_controlled_input"],
                        "data_categories": [],
                    },
                    {
                        "node_id": "shop:src/app.py#order_apply_staff_discount",
                        "operation": "mutation",
                        "annotations": [],
                        "data_categories": [],
                    },
                ],
                "related_data_flows": [],
                "partial": False,
            }
        ],
        "coverage": {
            "reconstructed": ["flow:ws-demo:0123456789ab"],
            "analyzed": [],
            "partial": [],
            "unanalyzed": [],
            "candidate_regimes": [],
            "applicability": {"mode": "hybrid", "evaluated_regimes": []},
        },
    }


def valid_flow_answer() -> dict:
    return {
        "flow_id": "flow:ws-demo:0123456789ab",
        "assessment": "gap",
        "findings": [
            {
                "cwe": "CWE-862",
                "severity_score": 8.5,
                "confidence": 0.85,
                "location": {"repo": "shop", "file": "src/app.py"},
                "description": "flow gap",
                "missing_check": "staff role",
                "compromise": "shopper obtains staff pricing",
            }
        ],
    }


def valid_flow_finding() -> dict:
    finding = valid_finding()
    finding["flow_category"] = "flow-gap"
    finding["flow_ref"] = "flow:ws-demo:0123456789ab"
    finding["flow_narrative"] = {
        "name": "/order/start",
        "steps": [{"node_id": "shop:src/app.py#@/order/start"}],
        "missing_check": "staff role",
        "compromise": "shopper obtains staff pricing",
    }
    return finding


class TestBusinessFlowSchema:
    def test_golden_document_passes(self):
        validate("business_flow", valid_business_flow())

    def test_partial_flow_carries_reasons(self):
        doc = valid_business_flow()
        doc["flows"][0]["partial"] = True
        doc["flows"][0]["gap_reasons"] = ["integration-undeclared"]
        doc["coverage"]["partial"] = [
            {"flow_id": doc["flows"][0]["id"], "gap_reasons": ["integration-undeclared"]}
        ]
        validate("business_flow", doc)

    def test_unknown_step_operation_rejected(self):
        doc = valid_business_flow()
        doc["flows"][0]["steps"][0]["operation"] = "leap"
        with pytest.raises(SchemaError):
            validate("business_flow", doc)

    def test_unknown_extra_key_rejected(self):
        doc = valid_business_flow()
        doc["flows"][0]["mood"] = "happy"
        with pytest.raises(SchemaError):
            validate("business_flow", doc)


class TestFlowAnswerSchema:
    def test_golden_answer_passes(self):
        validate("flow_answer", valid_flow_answer())

    def test_undetermined_requires_assessment_only(self):
        answer = valid_flow_answer()
        answer["assessment"] = "undetermined"
        answer["undetermined_reasons"] = ["reachability of step 3 unknown"]
        del answer["findings"]
        validate("flow_answer", answer)

    def test_closed_assessment_vocabulary(self):
        answer = valid_flow_answer()
        answer["assessment"] = "definitely-fine"
        with pytest.raises(SchemaError):
            validate("flow_answer", answer)

    def test_missing_flow_id_rejected(self):
        answer = valid_flow_answer()
        del answer["flow_id"]
        with pytest.raises(SchemaError):
            validate("flow_answer", answer)


class TestFindingFlowExtensions:
    def test_additive_fields_pass(self):
        validate("finding", valid_flow_finding())

    def test_plain_finding_still_valid(self):
        validate("finding", valid_finding())

    def test_unknown_flow_category_rejected(self):
        finding = valid_flow_finding()
        finding["flow_category"] = "vibes"
        with pytest.raises(SchemaError):
            validate("finding", finding)

    def test_regulatory_refs_bind_regime_and_obligation(self):
        finding = valid_flow_finding()
        finding["flow_category"] = "regulatory-violation"
        finding["regulatory_refs"] = [{"regime": "gdpr", "obligation": "consent"}]
        validate("finding", finding)

    def test_unexpected_property_still_rejected(self):
        finding = valid_flow_finding()
        finding["surprise"] = True
        assert not is_valid("finding", finding)
