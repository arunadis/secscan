"""Feature 012 T005: provider adapters (contracts/provider-batch-adapters.md)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import pytest

from pipeline.providers import (
    AnthropicAdapter,
    BatchItemSpec,
    BatchUnsupported,
    EndpointError,
    OpenAICompatibleAdapter,
    adapter_for,
    build_endpoint_request,
    classify_status,
    custom_id_for,
    parse_retry_after,
)
from tests.helpers.fake_provider import FakeProvider, Scenario

COMMON = dict(model="m", prompt="analyse", payload={"segment_id": "seg-a", "source": {}},
              max_output_tokens=50)


def _item(custom_id: str, model: str = "m") -> BatchItemSpec:
    return BatchItemSpec(custom_id=custom_id, model=model, prompt="analyse",
                         payload={"segment_id": custom_id, "source": {}}, max_output_tokens=50)


# ------------------------------------------------------------ interactive


@pytest.mark.parametrize("provider", ["anthropic", "openai-compatible"])
def test_interactive_body_is_byte_identical_to_build_endpoint_request(provider: str) -> None:
    """Principle III: the adapter adds no new content path."""
    adapter = adapter_for(provider, "sk-test")
    url, headers, body = adapter.interactive(**COMMON)
    ref_url, ref_headers, ref_body = build_endpoint_request(
        provider=provider, api_key="sk-test", **COMMON
    )
    assert url == ref_url and headers == ref_headers
    assert json.loads(body) == ref_body


def test_parse_interactive_handles_both_shapes() -> None:
    anth = adapter_for("anthropic", "k")
    anth_body = json.dumps({"content": [{"type": "text", "text": "hi"}]}).encode()
    assert anth.parse_interactive(anth_body) == "hi"
    oai = adapter_for("openai-compatible", "k")
    oai_body = json.dumps({"choices": [{"message": {"content": "x"}}]}).encode()
    assert oai.parse_interactive(oai_body) == "x"
    parts = {"choices": [{"message": {"content": [{"type": "text", "text": "y"}]}}]}
    assert oai.parse_interactive(json.dumps(parts).encode()) == "y"
    assert oai.parse_interactive(b"not json") == ""


# -------------------------------------------------------------- classify


@pytest.mark.parametrize("status", [408, 409, 429, 500, 502, 503, 504, 529])
def test_transient_statuses(status: int) -> None:
    assert classify_status(status) == "transient"
    assert classify_status(status, batch_create=True) == "transient"


@pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 413, 422, 501])
def test_terminal_statuses_on_interactive_path(status: int) -> None:
    assert classify_status(status) == "terminal"


@pytest.mark.parametrize("status", [404, 405, 501])
def test_unsupported_only_on_batch_create_path(status: int) -> None:
    assert classify_status(status, batch_create=True) == "unsupported"
    anth = adapter_for("anthropic", "k")
    assert anth.classify(status, path="/v1/messages/batches") == "unsupported"
    assert anth.classify(status, path="/v1/messages/batches/abc") == "terminal"
    oai = adapter_for("openai-compatible", "k")
    assert oai.classify(status, path="https://api.openai.com/v1/batches") == "unsupported"
    assert oai.classify(status, path="https://api.openai.com/v1/files") == "unsupported"
    assert oai.classify(status, path="https://api.openai.com/v1/files/f1/content") == "terminal"


def test_error_objects_carry_metadata_only() -> None:
    adapter = adapter_for("anthropic", "sk-secret")
    body = json.dumps(
        {"error": {"type": "rate_limit_error", "message": "slow down " * 50}}
    ).encode()
    exc = adapter.error(429, {"Retry-After": "7"}, body, path="https://api.anthropic.com/v1/messages")
    assert isinstance(exc, EndpointError) and not isinstance(exc, BatchUnsupported)
    assert exc.transient and exc.status == 429 and exc.retry_after_s == 7.0
    assert exc.error_type == "rate_limit_error"
    assert exc.path == "/v1/messages"
    text = str(exc)
    assert "sk-secret" not in text and "HTTP 429 rate_limit_error" in text
    assert len(exc.detail or "") <= 200

    unsupported = adapter.error(501, {}, b"", path="https://x/v1/messages/batches")
    assert isinstance(unsupported, BatchUnsupported)
    assert not unsupported.transient

    terminal = adapter.error(401, {}, b'{"error":{"type":"authentication_error"}}',
                             path="/v1/messages")
    assert not terminal.transient and terminal.error_type == "authentication_error"


def test_parse_retry_after_seconds_and_http_date() -> None:
    assert parse_retry_after({"retry-after": "12"}) == 12.0
    assert parse_retry_after({"Retry-After": " 3 "}) == 3.0
    assert parse_retry_after({}) is None
    future = format_datetime(datetime.now(UTC) + timedelta(seconds=90))
    value = parse_retry_after({"Retry-After": future})
    assert value is not None and 80 <= value <= 91
    assert parse_retry_after({"retry-after": "garbage"}) is None


def test_custom_id_grammar() -> None:
    assert custom_id_for("seg-shop-p1-l1") == "seg-shop-p1-l1"
    hashed = custom_id_for("seg with spaces/and:colons" * 3)
    assert len(hashed) == 32 and hashed.isalnum()


# ------------------------------------------------------------- anthropic


def test_anthropic_submit_batch_shape_and_handle() -> None:
    seen: dict = {}

    def transport(method, url, headers, body, *, timeout):
        seen.update(method=method, url=url, headers=headers, body=json.loads(body))
        response = {"id": "msgbatch_01", "processing_status": "in_progress"}
        return 200, {}, json.dumps(response).encode()

    adapter = AnthropicAdapter("sk-a", None)
    handle = adapter.submit_batch(transport, [_item("seg-a-l1"), _item("seg-b-l1")], model="m")
    assert handle == "msgbatch_01"
    assert seen["method"] == "POST" and seen["url"] == "https://api.anthropic.com/v1/messages/batches"
    assert seen["headers"]["x-api-key"] == "sk-a" and "anthropic-beta" not in seen["headers"]
    requests = seen["body"]["requests"]
    assert [r["custom_id"] for r in requests] == ["seg-a-l1", "seg-b-l1"]
    params = requests[0]["params"]
    assert set(params) == {"model", "max_tokens", "messages"}
    _, _, ref = build_endpoint_request(provider="anthropic", api_key="sk-a", model="m",
                                       prompt="analyse",
                                       payload={"segment_id": "seg-a-l1", "source": {}},
                                       max_output_tokens=50)
    assert params == ref


def test_anthropic_submit_unsupported_raises_batch_unsupported() -> None:
    adapter = AnthropicAdapter("k", None)
    with pytest.raises(BatchUnsupported):
        adapter.submit_batch(lambda *a, **k: (501, {}, b""), [_item("a")], model="m")


def test_anthropic_status_and_results() -> None:
    provider = FakeProvider(
        "anthropic",
        Scenario(polls_until_ended=2, items={"seg-b-l1": "error", "seg-c-l1": "expire"}),
        answer=lambda cid, payload: f"answer {cid}",
    )
    adapter = AnthropicAdapter("k", None)
    handle = adapter.submit_batch(
        provider, [_item("seg-a-l1"), _item("seg-b-l1"), _item("seg-c-l1")], model="m"
    )
    first = adapter.batch_status(provider, handle)
    assert first.state == "in_progress" and first.total == 3
    second = adapter.batch_status(provider, handle)
    assert second.state == "ended" and second.completed == 3
    results = {r.custom_id: r for r in adapter.batch_results(provider, handle)}
    assert results["seg-a-l1"].outcome == "succeeded"
    assert results["seg-a-l1"].content == "answer seg-a-l1"
    assert results["seg-b-l1"].outcome == "errored"
    assert results["seg-b-l1"].reason.startswith("errored: invalid_request_error")
    assert results["seg-c-l1"].outcome == "expired"
    assert adapter.batch_status(provider, "msgbatch_missing").state == "not_found"


def test_anthropic_limits() -> None:
    limits = AnthropicAdapter("k", None).batch_limits()
    assert limits.max_items == 100_000 and limits.max_bytes == int(256 * 1024 * 1024 * 0.9)


# ---------------------------------------------------------------- openai


def test_openai_submit_is_two_steps_with_multipart_and_single_model() -> None:
    calls: list = []

    def transport(method, url, headers, body, *, timeout):
        calls.append((method, url, headers, body))
        if url.endswith("/files"):
            return 200, {}, json.dumps({"id": "file-1"}).encode()
        return 200, {}, json.dumps({"id": "batch_1", "status": "validating"}).encode()

    adapter = OpenAICompatibleAdapter("sk-o", "https://gw.example/v1/")
    handle = adapter.submit_batch(transport, [_item("seg-a-l1"), _item("seg-b-l1")], model="m")
    assert handle == "batch_1"
    (m1, u1, h1, b1), (m2, u2, h2, b2) = calls
    assert (m1, u1) == ("POST", "https://gw.example/v1/files")
    assert h1["authorization"] == "Bearer sk-o"
    assert h1["content-type"].startswith("multipart/form-data; boundary=")
    assert b'name="purpose"\r\n\r\nbatch' in b1 and b'name="file"; filename="input.jsonl"' in b1
    assert b1.count(b'Content-Disposition') == 2
    jsonl_part = b1.split(b"\r\n\r\n")[2].split(b"\r\n--")[0]
    lines = [json.loads(line) for line in jsonl_part.splitlines() if line.strip()]
    assert [line["custom_id"] for line in lines] == ["seg-a-l1", "seg-b-l1"]
    assert all(line["method"] == "POST" and line["url"] == "/v1/chat/completions" for line in lines)
    assert set(lines[0]["body"]) == {"model", "messages", "max_completion_tokens"}
    assert (m2, u2) == ("POST", "https://gw.example/v1/batches")
    assert json.loads(b2) == {"input_file_id": "file-1", "endpoint": "/v1/chat/completions",
                              "completion_window": "24h"}

    with pytest.raises(ValueError):
        adapter.jsonl_for([_item("a", model="m1"), _item("b", model="m2")], model="m1")


def test_openai_status_mapping_and_results() -> None:
    provider = FakeProvider(
        "openai-compatible",
        Scenario(polls_until_ended=1,
                 items={"seg-b-l1": "error", "seg-c-l1": "expire", "seg-d-l1": "omit"}),
        answer=lambda cid, payload: f"answer {cid}",
    )
    adapter = OpenAICompatibleAdapter("k", None)
    items = [_item(f"seg-{x}-l1") for x in "abcd"]
    handle = adapter.submit_batch(provider, items, model="m")
    status = adapter.batch_status(provider, handle)
    assert status.state == "ended" and status.total == 4
    results = {r.custom_id: r for r in adapter.batch_results(provider, handle)}
    assert set(results) == {"seg-a-l1", "seg-b-l1", "seg-c-l1"}  # omitted item absent
    assert results["seg-a-l1"].content == "answer seg-a-l1"
    assert results["seg-b-l1"].outcome == "errored"
    assert results["seg-b-l1"].reason.startswith("errored: invalid_request")
    assert results["seg-c-l1"].outcome == "expired"


def test_openai_failed_batch_joins_error_messages() -> None:
    provider = FakeProvider("openai-compatible", Scenario(submit="validation_failed"))
    adapter = OpenAICompatibleAdapter("k", None)
    handle = adapter.submit_batch(provider, [_item("seg-a-l1")], model="m")
    status = adapter.batch_status(provider, handle)
    assert status.state == "failed" and "enqueued token limit" in (status.reason or "")
    assert adapter.batch_status(provider, "batch_nope").state == "not_found"


def test_openai_gateway_without_batch_support() -> None:
    provider = FakeProvider("openai-compatible", Scenario(submit="unsupported"))
    with pytest.raises(BatchUnsupported):
        OpenAICompatibleAdapter("k", None).submit_batch(provider, [_item("a")], model="m")


def test_openai_limits() -> None:
    limits = OpenAICompatibleAdapter("k", None).batch_limits()
    assert limits.max_items == 50_000 and limits.max_bytes == int(200 * 1024 * 1024 * 0.9)


def test_unknown_provider_rejected() -> None:
    with pytest.raises(RuntimeError):
        adapter_for("mystery", "k")
