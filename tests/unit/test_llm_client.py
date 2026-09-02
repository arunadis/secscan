"""T016/T017: analysis clients — agent-mediated default, batch abstraction, fallback."""

from __future__ import annotations

from datetime import datetime

import pytest

from config.mode import ExecutionMode, Resolution
from pipeline.budget import BudgetExceeded, TokenBudget
from pipeline.llm_client import (
    AgentMediatedClient,
    AnalysisRequest,
    EndpointClient,
    build_client,
    in_window,
)
from pipeline.usage import UsageTracker

BUDGET = TokenBudget(12000, 3000, 0.75)


def make_request(request_id: str = "req-1", level: str = "segment") -> AnalysisRequest:
    return AnalysisRequest(
        id=request_id,
        stage="segment_analysis",
        prompt="Analyze this segment for injection flaws.",
        payload={"segment_id": "seg-orders", "source": {"a.py": "def f(): pass"}},
        budget=BUDGET,
        level=level,
    )


# ----------------------------------------------------------- agent-mediated


def test_agent_client_queues_requests_without_responder() -> None:
    """FR-027: the scanner never sends anything itself in agent-mediated mode."""
    client = AgentMediatedClient()
    response = client.run(make_request())
    assert response.pending
    assert response.content == ""
    assert client.pending and client.pending[0].id == "req-1"
    assert not client.supports_batch()


def test_agent_client_uses_responder_when_provided() -> None:
    client = AgentMediatedClient(responder=lambda req: f"answer for {req.id}")
    response = client.run(make_request())
    assert not response.pending
    assert response.content == "answer for req-1"
    assert response.model_tier == "agent"
    assert response.input_tokens > 0


def test_agent_client_enforces_budget() -> None:
    tight = TokenBudget(5, 100, 0.75)
    request = make_request()
    request.budget = tight
    with pytest.raises(BudgetExceeded):
        AgentMediatedClient(responder=lambda r: "x").run(request)


# ------------------------------------------------------------------ endpoint


def endpoint_resolution(batch: bool = False) -> Resolution:
    return Resolution(
        mode=ExecutionMode.ENDPOINT_BATCH if batch else ExecutionMode.ENDPOINT_INTERACTIVE,
        reason="test",
        model_map={"local": "haiku", "segment": "sonnet", "system": "opus"},
        api_key_env="TEST_KEY",
    )


def fake_transport(**kwargs) -> str:
    return f"result from {kwargs['model']}"


def test_endpoint_client_uses_model_tier_for_level() -> None:
    """FR-008a: cheaper tier locally, stronger tier for system review."""
    client = EndpointClient(endpoint_resolution(), "key", transport=fake_transport)
    assert client.run(make_request(level="local")).model_tier == "haiku"
    assert client.run(make_request(level="segment")).model_tier == "sonnet"
    assert client.run(make_request(level="system")).model_tier == "opus"


def test_batch_submission_returns_job_handle() -> None:
    client = EndpointClient(endpoint_resolution(batch=True), "key", transport=fake_transport)
    job = client.submit_batch([make_request("a"), make_request("b")])
    assert job.request_ids == ["a", "b"]
    assert job.expires_at > job.submitted_at
    assert client.supports_batch()


def test_expired_batch_falls_back_to_interactive_and_is_recorded() -> None:
    """FR-016b: no silent skips or stalls; every fallback is recorded."""
    client = EndpointClient(
        endpoint_resolution(batch=True), "key", transport=fake_transport, batch_window_seconds=-1
    )
    usage = UsageTracker()
    responses = client.run_batch_with_fallback(
        [make_request("a"), make_request("b")],
        on_fallback=usage.record_fallback,
    )
    assert len(responses) == 2
    assert all(r.fell_back for r in responses)
    assert all(r.content for r in responses)  # actually analyzed, not skipped
    assert usage.fallbacks == 2
    assert "expired" in usage.fallback_log[0]["reason"]


def test_pending_batch_still_completes_every_item() -> None:
    client = EndpointClient(endpoint_resolution(batch=True), "key", transport=fake_transport)
    responses = client.run_batch_with_fallback([make_request("a")])
    assert len(responses) == 1
    assert responses[0].content


def test_build_client_selects_backend() -> None:
    agent = build_client(
        Resolution(mode=ExecutionMode.AGENT_MEDIATED, reason="default"), api_key=None
    )
    assert isinstance(agent, AgentMediatedClient)

    endpoint = build_client(endpoint_resolution(), api_key="key", transport=fake_transport)
    assert isinstance(endpoint, EndpointClient)


def test_build_client_requires_key_for_endpoint() -> None:
    with pytest.raises(RuntimeError):
        build_client(endpoint_resolution(), api_key=None)


# --------------------------------------------------------------- off-peak


@pytest.mark.parametrize(
    ("window", "now", "expected"),
    [
        ("02:00-06:00", datetime(2026, 8, 30, 3, 0), True),
        ("02:00-06:00", datetime(2026, 8, 30, 7, 0), False),
        ("22:00-04:00", datetime(2026, 8, 30, 23, 30), True),  # crosses midnight
        ("22:00-04:00", datetime(2026, 8, 30, 2, 30), True),
        ("22:00-04:00", datetime(2026, 8, 30, 12, 0), False),
    ],
)
def test_offpeak_window_detection(window: str, now: datetime, expected: bool) -> None:
    assert in_window(window, now) is expected


# ----------------------------------------------------------------- usage


def test_usage_tracker_reports_savings_and_spread() -> None:
    """FR-019 + SC-004: savings vs maximal-context baseline is measurable."""
    usage = UsageTracker()
    for _ in range(8):
        usage.record("segment_analysis", 500, 100, escalation_level=1, baseline_input_tokens=10000)
    usage.record("segment_analysis", 5000, 400, escalation_level=3, baseline_input_tokens=10000)

    doc = usage.to_dict()
    assert doc["invocations"] == 9
    assert doc["baseline_comparison"]["savings_factor"] > 5.0
    assert doc["by_escalation_level"]["1"] == 8
    assert "Savings vs maximal-context baseline" in usage.render_markdown()


def test_usage_roundtrip() -> None:
    usage = UsageTracker()
    usage.record("x", 10, 5, model_tier="haiku", batch=True)
    usage.record_fallback("req-1", "expired")
    restored = UsageTracker.from_dict(usage.to_dict())
    assert restored.to_dict() == usage.to_dict()
