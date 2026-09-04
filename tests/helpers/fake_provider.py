"""In-process stand-in for an analysis endpoint (feature 012, research R12).

Implements :class:`pipeline.providers.HttpTransport` for both wire shapes — the
Anthropic Messages / Message Batches API and the OpenAI-compatible Chat Completions /
Files + Batches API — driven by a small :class:`Scenario`. No socket is ever opened.

Answers are produced by ``answer(custom_id, payload)``; by default the integration
oracle responder is used so a batch scan yields the same findings as an interactive one.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

#: Interactive responses keyed by *segment id* (interactive calls carry no custom id;
#: the steps are consumed across escalation levels): an ``int`` is an HTTP status to
#: return, ``(429, seconds)`` adds a ``Retry-After`` header, a ``str`` is a 200 answer.
Step = int | tuple[int, int] | str


@dataclass
class Scenario:
    interactive: dict[str, list[Step]] = field(default_factory=dict)
    submit: str = "ok"  # ok | unsupported | validation_failed
    polls_until_ended: int = 1
    items: dict[str, str] = field(default_factory=dict)  # succeed | error | expire | omit
    status_after_resume: str = "same"  # same | not_found
    interactive_error_body: dict[str, Any] | None = None


class _Request:
    """Minimal duck-type for responders that read ``request.payload``/``request.id``."""

    def __init__(self, request_id: str, payload: dict[str, Any]) -> None:
        self.id = request_id
        self.payload = payload


_PAYLOAD_SPLIT = re.compile(r"\n\n(\{\")")


def payload_of(message_content: str) -> dict[str, Any]:
    """Recover the context-packet JSON appended to the prompt by ``build_endpoint_request``."""
    matches = list(_PAYLOAD_SPLIT.finditer(message_content))
    match = matches[-1] if matches else None
    if match is None:
        return {}
    try:
        return json.loads(message_content[match.start(1):])
    except ValueError:
        return {}


class FakeProvider:
    def __init__(
        self,
        family: str = "anthropic",
        scenario: Scenario | None = None,
        *,
        answer: Callable[[str, dict[str, Any]], str] | None = None,
    ) -> None:
        assert family in ("anthropic", "openai-compatible")
        self.family = family
        self.scenario = scenario or Scenario()
        self.answer = answer or _default_answer
        self.calls: list[tuple[str, str]] = []
        self.batch_submissions = 0
        self.interactive_calls = 0
        self.polls = 0
        self._batches: dict[str, dict[str, Any]] = {}
        self._files: dict[str, bytes] = {}
        self._steps: dict[str, list[Step]] = {
            k: list(v) for k, v in self.scenario.interactive.items()
        }
        self._resumed = False
        self._counter = 0

    # ------------------------------------------------------------ transport

    def __call__(self, method, url, headers, body, *, timeout):
        path = "/" + url.split("://", 1)[1].split("/", 1)[1]
        self.calls.append((method, path))
        if self.family == "anthropic":
            return self._anthropic(method, path, headers, body)
        return self._openai(method, path, headers, body)

    def mark_resumed(self) -> None:
        """Simulate a new process observing provider state (e.g. handle retention)."""
        self._resumed = True

    # ------------------------------------------------------------- helpers

    @staticmethod
    def _ok(doc: Any) -> tuple[int, dict[str, str], bytes]:
        return 200, {"content-type": "application/json"}, json.dumps(doc).encode()

    @staticmethod
    def _err(status: int, kind: str, message: str, headers=None):
        return status, dict(headers or {}), json.dumps(
            {"error": {"type": kind, "code": kind, "message": message}}
        ).encode()

    def _interactive_answer(self, custom_id: str, payload: dict[str, Any]):
        """A ``str`` answer, or a ``(status, headers, body)`` error response."""
        self.interactive_calls += 1
        steps = self._steps.get(custom_id)
        if steps:
            step = steps.pop(0)
            if isinstance(step, tuple):
                return self._err(step[0], "rate_limit_error", "slow down",
                                 {"retry-after": str(step[1])})
            if isinstance(step, int):
                kinds = {429: "rate_limit_error", 401: "authentication_error",
                         529: "overloaded_error"}
                if self.scenario.interactive_error_body is not None:
                    return step, {}, json.dumps(self.scenario.interactive_error_body).encode()
                return self._err(step, kinds.get(step, "api_error"), f"status {step}")
            return step
        return self.answer(custom_id, payload)

    def _new_batch(self, entries: list[tuple[str, dict[str, Any]]], model: str) -> str:
        self.batch_submissions += 1
        self._counter += 1
        handle = f"batch_{self._counter:04d}"
        self._batches[handle] = {"entries": entries, "polls": 0, "model": model}
        return handle

    def _results(self, handle: str) -> list[tuple[str, str, str | None]]:
        """``(custom_id, outcome, content)`` in reverse order to prove ordering independence."""
        batch = self._batches[handle]
        out = []
        for custom_id, payload in reversed(batch["entries"]):
            outcome = self.scenario.items.get(custom_id, "succeed")
            if outcome == "omit":
                continue
            if outcome == "succeed":
                out.append((custom_id, "succeeded", self.answer(custom_id, payload)))
            elif outcome == "error":
                out.append((custom_id, "errored", None))
            else:
                out.append((custom_id, "expired", None))
        return out

    def _ended(self, handle: str) -> bool:
        return self._batches[handle]["polls"] >= self.scenario.polls_until_ended

    # ------------------------------------------------------------ anthropic

    def _anthropic(self, method, path, headers, body):
        if path == "/v1/messages" and method == "POST":
            doc = json.loads(body)
            content = doc["messages"][0]["content"]
            payload = payload_of(content)
            answer = self._interactive_answer(_request_id_of(doc, payload), payload)
            if isinstance(answer, tuple):
                return answer
            return self._ok({"content": [{"type": "text", "text": answer}]})
        if path == "/v1/messages/batches" and method == "POST":
            if self.scenario.submit == "unsupported":
                return 501, {}, b"not implemented"
            doc = json.loads(body)
            entries = []
            model = None
            for req in doc["requests"]:
                params = req["params"]
                model = params["model"]
                entries.append((req["custom_id"], payload_of(params["messages"][0]["content"])))
            handle = self._new_batch(entries, model or "")
            if self.scenario.submit == "validation_failed":
                self._batches[handle]["failed"] = True
            return self._ok({"id": handle, "processing_status": "in_progress"})
        m = re.match(r"^/v1/messages/batches/([^/]+)(/results)?$", path)
        if m and method == "GET":
            handle = m.group(1)
            if handle not in self._batches or (self._resumed and
                                               self.scenario.status_after_resume == "not_found"):
                return self._err(404, "not_found_error", "no such batch")
            batch = self._batches[handle]
            if m.group(2):
                lines = []
                for custom_id, outcome, content in self._results(handle):
                    if outcome == "succeeded":
                        result = {"type": "succeeded",
                                  "message": {"content": [{"type": "text", "text": content}]}}
                    elif outcome == "errored":
                        result = {"type": "errored",
                                  "error": {"type": "invalid_request_error", "message": "bad"}}
                    else:
                        result = {"type": outcome}
                    lines.append(json.dumps({"custom_id": custom_id, "result": result}))
                return 200, {}, ("\n".join(lines) + "\n").encode()
            batch["polls"] += 1
            self.polls += 1
            total = len(batch["entries"])
            if batch.get("failed"):
                # Anthropic has no whole-batch failure state: every item errors.
                counts = {"processing": 0, "succeeded": 0, "errored": total, "canceled": 0,
                          "expired": 0}
                return self._ok({"id": handle, "processing_status": "ended",
                                 "request_counts": counts})
            if self._ended(handle):
                results = self._results(handle)
                counts = {
                    "processing": total - len(results),
                    "succeeded": sum(1 for r in results if r[1] == "succeeded"),
                    "errored": sum(1 for r in results if r[1] == "errored"),
                    "canceled": 0,
                    "expired": sum(1 for r in results if r[1] == "expired"),
                }
                return self._ok({"id": handle, "processing_status": "ended",
                                 "request_counts": counts})
            done = min(total, batch["polls"] * max(1, total // 2))
            counts = {"processing": total - done, "succeeded": done, "errored": 0,
                      "canceled": 0, "expired": 0}
            return self._ok({"id": handle, "processing_status": "in_progress",
                             "request_counts": counts})
        return 404, {}, b"not found"

    # --------------------------------------------------------------- openai

    def _openai(self, method, path, headers, body):
        if path.endswith("/chat/completions") and method == "POST":
            doc = json.loads(body)
            payload = payload_of(doc["messages"][0]["content"])
            answer = self._interactive_answer(_request_id_of(doc, payload), payload)
            if isinstance(answer, tuple):
                return answer
            return self._ok({"choices": [{"message": {"role": "assistant", "content": answer}}]})
        if path.endswith("/files") and method == "POST":
            if self.scenario.submit == "unsupported":
                return 404, {}, b"<html>not found</html>"
            self._counter += 1
            file_id = f"file-{self._counter:04d}"
            self._files[file_id] = _multipart_file(body)
            return self._ok({"id": file_id, "purpose": "batch"})
        if path.endswith("/batches") and method == "POST":
            if self.scenario.submit == "unsupported":
                return 501, {}, b"not implemented"
            doc = json.loads(body)
            jsonl = self._files[doc["input_file_id"]]
            entries = []
            model = None
            for line in jsonl.decode().splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                model = item["body"]["model"]
                entries.append(
                    (item["custom_id"], payload_of(item["body"]["messages"][0]["content"]))
                )
            handle = self._new_batch(entries, model or "")
            if self.scenario.submit == "validation_failed":
                self._batches[handle]["failed"] = True
            return self._ok({"id": handle, "status": "validating"})
        m = re.match(r"^.*/batches/([^/]+)$", path)
        if m and method == "GET":
            handle = m.group(1)
            if handle not in self._batches or (self._resumed and
                                               self.scenario.status_after_resume == "not_found"):
                return self._err(404, "not_found", "no such batch")
            batch = self._batches[handle]
            batch["polls"] += 1
            self.polls += 1
            total = len(batch["entries"])
            if batch.get("failed"):
                return self._ok({"id": handle, "status": "failed",
                                 "request_counts": {"total": total, "completed": 0, "failed": 0},
                                 "errors": {"data": [{"code": "token_limit_exceeded",
                                                      "message": "enqueued token limit"}]}})
            if self._ended(handle):
                results = self._results(handle)
                ok = [r for r in results if r[1] == "succeeded"]
                bad = [r for r in results if r[1] != "succeeded"]
                out_id, err_id = f"{handle}-out", f"{handle}-err"
                self._files[out_id] = ("\n".join(
                    json.dumps({"id": f"req-{c}", "custom_id": c,
                                "response": {"status_code": 200, "request_id": "r",
                                             "body": {"choices": [{"message": {
                                                 "role": "assistant", "content": content}}]}},
                                "error": None})
                    for c, _, content in ok) + "\n").encode()
                self._files[err_id] = ("\n".join(
                    json.dumps({"id": f"req-{c}", "custom_id": c, "response": None,
                                "error": {"code": "batch_expired" if outcome == "expired"
                                          else "invalid_request",
                                          "message": "expired" if outcome == "expired"
                                          else "bad"}})
                    for c, outcome, _ in bad) + "\n").encode()
                return self._ok({"id": handle, "status": "completed",
                                 "request_counts": {"total": total, "completed": len(ok),
                                                    "failed": len(bad)},
                                 "output_file_id": out_id if ok else None,
                                 "error_file_id": err_id if bad else None})
            done = min(total, batch["polls"] * max(1, total // 2))
            return self._ok({"id": handle, "status": "in_progress",
                             "request_counts": {"total": total, "completed": done, "failed": 0}})
        m = re.match(r"^.*/files/([^/]+)/content$", path)
        if m and method == "GET":
            data = self._files.get(m.group(1))
            if data is None:
                return 404, {}, b"no such file"
            return 200, {}, data
        return 404, {}, b"not found"


def _request_id_of(doc: dict[str, Any], payload: dict[str, Any]) -> str:
    """Interactive calls carry no custom id; scenarios key them by segment id."""
    return str(payload.get("segment_id") or doc.get("model") or "?")


def _multipart_file(body: bytes) -> bytes:
    """Extract the ``file`` part of a multipart/form-data body (purpose must be ``batch``)."""
    boundary = body.split(b"\r\n", 1)[0]
    parts = body.split(boundary)
    purpose = None
    file_data = None
    for part in parts:
        if b'name="purpose"' in part:
            purpose = part.split(b"\r\n\r\n", 1)[1].strip(b"\r\n-")
        elif b'name="file"' in part:
            file_data = part.split(b"\r\n\r\n", 1)[1]
            if file_data.endswith(b"\r\n"):
                file_data = file_data[:-2]
    assert purpose == b"batch", f"unexpected purpose {purpose!r}"
    assert file_data is not None, "multipart body has no file part"
    return file_data


def _default_answer(custom_id: str, payload: dict[str, Any]) -> str:
    from tests.integration.conftest import oracle_responder

    return oracle_responder(_Request(custom_id, payload))


def legacy_adapter(fn: Callable[..., str]) -> Callable[..., tuple[int, dict[str, str], bytes]]:
    """Wrap the pre-012 ``**kwargs -> str`` fake transport shape as an ``HttpTransport``.

    Reconstructs ``provider``/``model``/``base_url`` from the request so older unit
    tests that inspect those keyword arguments keep working.
    """

    def transport(method, url, headers, body, *, timeout):
        doc = json.loads(body or b"{}")
        is_anthropic = "x-api-key" in {k.lower() for k in headers}
        provider = "anthropic" if is_anthropic else "openai-compatible"
        base_url = url.rsplit("/v1/messages", 1)[0] if provider == "anthropic" else url.rsplit(
            "/chat/completions", 1)[0]
        api_key = headers.get("x-api-key") or headers.get("authorization", "").removeprefix(
            "Bearer ")
        content = doc["messages"][0]["content"]
        text = fn(
            provider=provider,
            model=doc["model"],
            api_key=api_key,
            prompt=content,
            payload=payload_of(content),
            max_output_tokens=doc.get("max_tokens") or doc.get("max_completion_tokens"),
            base_url=base_url,
        )
        if provider == "anthropic":
            return FakeProvider._ok({"content": [{"type": "text", "text": text}]})
        return FakeProvider._ok({"choices": [{"message": {"content": text}}]})

    return transport
