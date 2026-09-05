"""T034: regime applicability modes and candidate regimes (feature 015, FR-022/023)."""

from __future__ import annotations

from dataclasses import dataclass, field

from pipeline import business_flow


@dataclass
class FakeConfig:
    mode: str = "hybrid"
    declared: list[str] = field(default_factory=list)

    @property
    def business_flow_applicability_mode(self) -> str:
        return self.mode

    @property
    def business_flow_declared_regimes(self) -> list[str]:
        return self.declared


def _flows_doc(categories: list[str]) -> dict:
    step = {
        "node_id": "shop:src/app.py#signup",
        "operation": "mutation",
        "annotations": [],
        "data_categories": categories,
    }
    return {
        "flows": [
            {
                "id": "flow:ws:person1",
                "name": "/signup",
                "actor": {"kind": "authenticated", "determination": "declared"},
                "steps": [step],
                "partial": False,
            }
        ],
        "coverage": {},
    }


class TestModes:
    def test_hybrid_evaluates_declared_and_suggests_detected(self):
        resolution = business_flow.resolve_applicability(
            FakeConfig(mode="hybrid", declared=["hipaa"]), _flows_doc(["personal-data"])
        )
        assert resolution["evaluated_regimes"] == ["hipaa"]
        # personal-data maps to gdpr+ccpa: suggested, NOT evaluated.
        candidates = {c["regime"] for c in resolution["candidate_regimes"]}
        assert {"gdpr", "ccpa"} <= candidates
        assert "hipaa" not in candidates
        assert resolution["skipped_reason"] is None

    def test_hybrid_with_nothing_declared_or_detected_declares_skip(self):
        resolution = business_flow.resolve_applicability(
            FakeConfig(mode="hybrid"), _flows_doc([])
        )
        assert resolution["evaluated_regimes"] == []
        assert resolution["candidate_regimes"] == []
        assert resolution["skipped_reason"]  # declared, never silent (FR-010)

    def test_declared_only_never_infers(self):
        resolution = business_flow.resolve_applicability(
            FakeConfig(mode="declared-only"), _flows_doc(["personal-data"])
        )
        assert resolution["evaluated_regimes"] == []
        assert resolution["candidate_regimes"] == []

    def test_inferred_only_evaluates_detected_with_basis(self):
        resolution = business_flow.resolve_applicability(
            FakeConfig(mode="inferred-only"), _flows_doc(["personal-data"])
        )
        assert {"gdpr", "ccpa"} <= set(resolution["evaluated_regimes"])
        assert resolution["basis"]["gdpr"].startswith("detected personal-data")
        assert resolution["obligations"]

    def test_inferred_only_without_signals_declares_skip(self):
        resolution = business_flow.resolve_applicability(
            FakeConfig(mode="inferred-only"), _flows_doc([])
        )
        assert resolution["evaluated_regimes"] == []
        assert resolution["skipped_reason"]

    def test_obligations_reach_the_round_only_for_evaluated(self):
        resolution = business_flow.resolve_applicability(
            FakeConfig(mode="hybrid", declared=["gdpr"]), _flows_doc(["personal-data"])
        )
        assert [o["regime"] for o in resolution["obligations"]] == ["gdpr"]
