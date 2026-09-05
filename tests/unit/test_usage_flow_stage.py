"""T041: business_flow_analysis usage attribution (feature 015, FR-013).

Test-only over the recording T013 performs: the stage shows up itemized, cached
answers are never counted in a run's usage, and fallbacks are logged.
"""

from __future__ import annotations

from pipeline.budget import TokenBudget
from pipeline.business_flow import STAGE_ANALYSIS, FlowRound
from pipeline.llm_client import AnalysisResponse
from pipeline.usage import UsageTracker


class StubClient:
    """Answers flow requests deterministically; counts invocations."""

    def __init__(self, cached: bool = False, fell_back: bool = False) -> None:
        self.cached = cached
        self.fell_back = fell_back
        self.calls = 0

    def run(self, request):
        self.calls += 1
        import json

        return AnalysisResponse(
            request_id=request.id,
            content=json.dumps(
                {
                    "flow_id": request.payload["flow"]["id"],
                    "assessment": "clean",
                    "findings": [],
                }
            ),
            input_tokens=100,
            output_tokens=20,
            model_tier="agent",
            batch=False,
            fell_back=self.fell_back,
            fallback_reason="batch item re-executed" if self.fell_back else None,
            cached=self.cached,
        )


FLOW = {
    "id": "flow:ws:stub1",
    "name": "/x",
    "actor": {"kind": "anonymous", "determination": "inferred"},
    "partial": False,
    "steps": [
        {
            "node_id": "shop:src/app.py#@/x",
            "operation": "entry",
            "annotations": [],
            "data_categories": [],
        }
    ],
}


def _budget() -> TokenBudget:
    return TokenBudget(
        max_context_tokens=100000, max_output_tokens=5000, escalation_threshold=0.75
    )


def test_stage_is_itemized():
    usage = UsageTracker()
    second = dict(FLOW, id="flow:ws:stub2")
    FlowRound(client=StubClient(), usage=usage, budget=_budget()).run([FLOW, second])
    stage = usage.to_dict()["by_stage"][STAGE_ANALYSIS]
    assert stage["invocations"] == 2
    assert stage["input_tokens"] == 200


def test_cached_answers_are_never_counted():
    usage = UsageTracker()
    FlowRound(client=StubClient(cached=True), usage=usage, budget=_budget()).run([FLOW])
    assert STAGE_ANALYSIS not in usage.to_dict()["by_stage"]


def test_fallbacks_are_recorded():
    usage = UsageTracker()
    FlowRound(
        client=StubClient(fell_back=True), usage=usage, budget=_budget()
    ).run([FLOW])
    summary = usage.to_dict()
    assert summary["batch_share"]["fallbacks"] == 1
    assert summary["by_stage"][STAGE_ANALYSIS]["invocations"] == 1
