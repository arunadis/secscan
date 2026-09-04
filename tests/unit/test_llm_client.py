"""T016/T017: analysis clients — agent-mediated default, batch abstraction, fallback."""

from __future__ import annotations

from datetime import datetime

import pytest

from config.mode import ExecutionMode, Resolution, resolve
from pipeline.answers import AnswerStore
from pipeline.budget import BudgetExceeded, TokenBudget
from pipeline.llm_client import (
    AgentMediatedClient,
    AnalysisRequest,
    EndpointClient,
    RetryPolicy,
    build_client,
    build_endpoint_request,
    in_window,
    parse_endpoint_response,
)
from pipeline.providers import EndpointError
from pipeline.usage import UsageTracker
from tests.helpers.fake_provider import FakeProvider, Scenario, legacy_adapter

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


def _legacy(**kwargs) -> str:
    return f"result from {kwargs['model']}"


fake_transport = legacy_adapter(_legacy)


def test_endpoint_client_uses_model_tier_for_level() -> None:
    """FR-008a: cheaper tier locally, stronger tier for system review."""
    client = EndpointClient(endpoint_resolution(), "key", transport=fake_transport)
    assert client.run(make_request(level="local")).model_tier == "haiku"
    assert client.run(make_request(level="segment")).model_tier == "sonnet"
    assert client.run(make_request(level="system")).model_tier == "opus"
    assert client.supports_batch() is False
    assert EndpointClient(endpoint_resolution(batch=True), "key",
                          transport=fake_transport).supports_batch()


def test_endpoint_client_passes_provider_and_base_url_to_transport() -> None:
    """Regression: the configured provider/base_url must reach the transport."""
    seen: dict = {}

    def capture(**kwargs) -> str:
        seen.update(kwargs)
        return "ok"

    resolution = Resolution(
        mode=ExecutionMode.ENDPOINT_INTERACTIVE,
        reason="test",
        model_map={"segment": "gpt-x"},
        provider="openai-compatible",
        base_url="https://gateway.example/v1",
    )
    EndpointClient(resolution, "key", transport=legacy_adapter(capture)).run(make_request())
    assert seen["provider"] == "openai-compatible"
    assert seen["base_url"] == "https://gateway.example/v1"
    assert seen["model"] == "gpt-x"


def test_terminal_http_error_is_typed_and_leaks_nothing() -> None:
    """FR-016/FR-017: a 401 is not retried and the message carries metadata only."""
    provider = FakeProvider("anthropic", Scenario(interactive={"seg-orders": [401]}))
    client = EndpointClient(endpoint_resolution(), "sk-very-secret", transport=provider,
                            retry=RetryPolicy(attempts=5, sleep=lambda s: None))
    with pytest.raises(EndpointError) as info:
        client.run(make_request())
    exc = info.value
    assert exc.transient is False and exc.attempts == 1 and exc.status == 401
    assert exc.request_id == "req-1"
    text = str(exc)
    assert "sk-very-secret" not in text and "def f(): pass" not in text
    assert "HTTP 401" in text
    assert provider.interactive_calls == 1


def test_answers_are_persisted_and_reused_without_a_second_call(tmp_path) -> None:
    """FR-005/FR-008: a matching persisted answer short-circuits the transport."""
    provider = FakeProvider("anthropic", answer=lambda cid, payload: '{"findings": []}')
    answers = AnswerStore(tmp_path / "answers")
    client = EndpointClient(endpoint_resolution(), "key", transport=provider, answers=answers)
    first = client.run(make_request())
    assert first.content == '{"findings": []}' and first.cached is False
    assert provider.interactive_calls == 1
    second = client.run(make_request())
    assert second.cached is True and second.content == first.content
    assert second.model_tier == "sonnet"
    assert provider.interactive_calls == 1
    assert client.run(make_request(level="local")).cached is False  # different tier -> miss


def test_resolve_threads_provider_and_base_url_from_config() -> None:
    from config import loader

    config = loader.Config(
        path=None,
        raw={
            "version": 1,
            "llm": {
                "mode": "endpoint",
                "endpoint": {
                    "provider": "openai-compatible",
                    "api_key_env": "OPENAI_API_KEY",
                    "base_url": "https://gateway.example/v1/",
                    "model_map": {"segment": "gpt-x"},
                },
            },
        },
    )
    resolution = resolve(config, {"OPENAI_API_KEY": "set"})
    assert resolution.provider == "openai-compatible"
    assert resolution.base_url == "https://gateway.example/v1"

    default = resolve(
        loader.Config(
            path=None, raw={"version": 1, "llm": {"endpoint": {"api_key_env": "ANTHROPIC_API_KEY"}}}
        ),
        {"ANTHROPIC_API_KEY": "set"},
    )
    assert default.provider == "anthropic"
    assert default.base_url is None


COMMON = dict(model="m", api_key="sk-test", prompt="p", payload={"a": 1}, max_output_tokens=50)


def test_anthropic_request_shape() -> None:
    url, headers, body = build_endpoint_request(provider="anthropic", **COMMON)
    assert url == "https://api.anthropic.com/v1/messages"
    assert headers["x-api-key"] == "sk-test"
    assert "authorization" not in headers
    assert body["max_tokens"] == 50
    assert body["messages"][0]["content"].endswith('{"a": 1}')


def test_openai_compatible_request_shape_uses_bearer_and_chat_completions() -> None:
    """Regression: an OpenAI key must never be posted to the Anthropic endpoint (401)."""
    url, headers, body = build_endpoint_request(provider="openai-compatible", **COMMON)
    assert url == "https://api.openai.com/v1/chat/completions"
    assert headers["authorization"] == "Bearer sk-test"
    assert "x-api-key" not in headers
    assert body["max_completion_tokens"] == 50

    url, _, _ = build_endpoint_request(
        provider="openai-compatible", base_url="https://gw.example/v1/", **COMMON
    )
    assert url == "https://gw.example/v1/chat/completions"


def test_base_url_overrides_anthropic_host() -> None:
    url, _, _ = build_endpoint_request(
        provider="anthropic", base_url="https://proxy.example", **COMMON
    )
    assert url == "https://proxy.example/v1/messages"


def test_unknown_provider_is_rejected() -> None:
    with pytest.raises(RuntimeError):
        build_endpoint_request(provider="mystery", **COMMON)


def test_parse_endpoint_response_per_provider() -> None:
    assert (
        parse_endpoint_response("anthropic", {"content": [{"type": "text", "text": "hi"}]}) == "hi"
    )
    openai_doc = {"choices": [{"message": {"role": "assistant", "content": "hello"}}]}
    assert parse_endpoint_response("openai-compatible", openai_doc) == "hello"
    parts_doc = {"choices": [{"message": {"content": [{"type": "text", "text": "x"}]}}]}
    assert parse_endpoint_response("openai-compatible", parts_doc) == "x"
    assert parse_endpoint_response("openai-compatible", {}) == ""


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
