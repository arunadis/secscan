"""Analysis-endpoint provider adapters (feature 012, contracts/provider-batch-adapters.md).

Every byte that leaves the scanner for the analysis endpoint is produced here. Two
adapters implement one protocol: the Anthropic Messages / Message Batches shape and
the OpenAI-compatible Chat Completions / Files + Batches shape. ``llm_client`` and
``batch_runner`` never build a URL or parse a provider document themselves.

The per-item batch body is built by the same function as the interactive body
(:func:`build_endpoint_request`), so batching never changes what content reaches
the provider (Principle III).
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import UTC
from email.utils import parsedate_to_datetime
from typing import Any, Literal, Protocol

DEFAULT_TIMEOUT_S = 120.0

DEFAULT_BASE_URLS = {
    "anthropic": "https://api.anthropic.com",
    "openai-compatible": "https://api.openai.com/v1",
}

#: HTTP statuses retried on interactive calls (research R2).
TRANSIENT_STATUSES = frozenset({408, 409, 429, 500, 502, 503, 504, 529})
#: On the batch-create path these mean "the gateway does not implement batching".
UNSUPPORTED_STATUSES = frozenset({404, 405, 501})

_CUSTOM_ID = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_REASON_LIMIT = 200

Classification = Literal["transient", "terminal", "unsupported"]


class HttpTransport(Protocol):
    """The adapters' only I/O seam; the fake provider in tests implements it."""

    def __call__(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        *,
        timeout: float,
    ) -> tuple[int, dict[str, str], bytes]: ...


@dataclass(frozen=True)
class BatchLimits:
    max_items: int
    max_bytes: int


@dataclass(frozen=True)
class BatchStatus:
    state: Literal["in_progress", "ended", "failed", "not_found"]
    completed: int
    total: int
    reason: str | None = None


@dataclass(frozen=True)
class ItemResult:
    custom_id: str
    outcome: Literal["succeeded", "errored", "canceled", "expired"]
    content: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class BatchItemSpec:
    custom_id: str
    model: str
    prompt: str
    payload: dict[str, Any]
    max_output_tokens: int


class EndpointError(RuntimeError):
    """A provider call failed. Carries only status/type metadata — never request content."""

    def __init__(
        self,
        *,
        provider: str,
        path: str,
        status: int | None,
        error_type: str | None = None,
        transient: bool,
        retry_after_s: float | None = None,
        attempts: int = 1,
        request_id: str | None = None,
        detail: str | None = None,
    ) -> None:
        self.provider = provider
        self.path = path
        self.status = status
        self.error_type = error_type
        self.transient = transient
        self.retry_after_s = retry_after_s
        self.attempts = attempts
        self.request_id = request_id
        self.detail = detail
        super().__init__(self._describe())

    def _describe(self) -> str:
        what = f"HTTP {self.status}" if self.status is not None else "connection error"
        if self.error_type:
            what += f" {self.error_type}"
        plural = "s" if self.attempts != 1 else ""
        text = (
            f"analysis endpoint request failed ({self.provider} {self.path}): {what} "
            f"after {self.attempts} attempt{plural}"
        )
        if self.detail:
            text += f" - {self.detail}"
        return text

    def with_attempts(self, attempts: int, request_id: str | None = None) -> EndpointError:
        return type(self)(
            provider=self.provider,
            path=self.path,
            status=self.status,
            error_type=self.error_type,
            transient=self.transient,
            retry_after_s=self.retry_after_s,
            attempts=attempts,
            request_id=request_id if request_id is not None else self.request_id,
            detail=self.detail,
        )


class BatchUnsupported(EndpointError):
    """The endpoint answered the batch-create path with 404/405/501 (FR-010)."""


# ------------------------------------------------------------- shared helpers


def parse_retry_after(headers: dict[str, str]) -> float | None:
    """``Retry-After`` as seconds (integer form or HTTP-date), else ``None``."""
    value = None
    for key, candidate in headers.items():
        if key.lower() == "retry-after":
            value = candidate.strip()
            break
    if not value:
        return None
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    from datetime import datetime

    delta = (when - datetime.now(UTC)).total_seconds()
    return max(0.0, delta)


def classify_status(status: int, *, batch_create: bool = False) -> Classification:
    if batch_create and status in UNSUPPORTED_STATUSES:
        return "unsupported"
    if status in TRANSIENT_STATUSES:
        return "transient"
    return "terminal"


def custom_id_for(request_id: str) -> str:
    """The provider-facing item id: the request id when it fits the grammar, else a hash."""
    if _CUSTOM_ID.match(request_id):
        return request_id
    return hashlib.sha256(request_id.encode("utf-8")).hexdigest()[:32]


def _truncate(text: str) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= _REASON_LIMIT else text[: _REASON_LIMIT - 3] + "..."


def _error_fields(body: bytes) -> tuple[str | None, str | None]:
    """``(error_type, message)`` from a provider error document, when parseable."""
    try:
        doc = json.loads(body or b"")
    except (ValueError, UnicodeDecodeError):
        return None, None
    if not isinstance(doc, dict):
        return None, None
    error = doc.get("error")
    if isinstance(error, dict):
        kind = error.get("type") or error.get("code")
        return (str(kind) if kind else None), (
            _truncate(error["message"]) if error.get("message") else None
        )
    if isinstance(error, str):
        return None, _truncate(error)
    return None, None


def path_of(url: str) -> str:
    split = url.split("://", 1)
    return "/" + split[1].split("/", 1)[1] if len(split) == 2 and "/" in split[1] else url


def _parse_jsonl(body: bytes) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in body.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        if isinstance(doc, dict):
            out.append(doc)
    return out


def build_endpoint_request(
    *,
    provider: str,
    model: str,
    api_key: str,
    prompt: str,
    payload: dict[str, Any],
    max_output_tokens: int,
    base_url: str | None = None,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """Return ``(url, headers, body)`` shaped for the configured provider.

    ``anthropic`` speaks the Messages API; ``openai-compatible`` speaks Chat
    Completions and covers OpenAI itself plus any gateway exposing that shape
    (``base_url`` selects the gateway).
    """
    root = (base_url or DEFAULT_BASE_URLS.get(provider) or "").rstrip("/")
    if not root:
        raise RuntimeError(f"unsupported analysis endpoint provider: {provider!r}")
    content = prompt + "\n\n" + json.dumps(payload, sort_keys=True)
    messages = [{"role": "user", "content": content}]
    if provider == "anthropic":
        url = f"{root}/v1/messages"
        headers = {
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }
        body: dict[str, Any] = {
            "model": model,
            "max_tokens": max_output_tokens,
            "messages": messages,
        }
    else:
        url = f"{root}/chat/completions"
        headers = {
            "content-type": "application/json",
            "authorization": f"Bearer {api_key}",
        }
        body = {"model": model, "max_completion_tokens": max_output_tokens, "messages": messages}
    return url, headers, body


def parse_endpoint_response(provider: str, doc: dict[str, Any]) -> str:
    """Extract the assistant text from a provider response document."""
    if provider == "anthropic":
        blocks = doc.get("content") or []
        return "".join(b.get("text", "") for b in blocks if isinstance(b, dict))
    choices = doc.get("choices") or []
    if not choices or not isinstance(choices[0], dict):
        return ""
    content = (choices[0].get("message") or {}).get("content")
    if isinstance(content, list):  # some gateways return content parts
        return "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return content or ""


# ------------------------------------------------------------------ protocol


class ProviderAdapter(Protocol):
    name: str

    def interactive(
        self, *, model: str, prompt: str, payload: dict[str, Any], max_output_tokens: int
    ) -> tuple[str, dict[str, str], bytes]: ...

    def parse_interactive(self, body: bytes) -> str: ...

    def error(
        self, status: int, headers: dict[str, str], body: bytes, *, path: str,
        batch_create: bool = False,
    ) -> EndpointError: ...

    def classify(self, status: int, *, path: str) -> Classification: ...

    def batch_limits(self) -> BatchLimits: ...

    def item_bytes(self, item: BatchItemSpec) -> int: ...

    def submit_batch(
        self, transport: HttpTransport, items: list[BatchItemSpec], *, model: str
    ) -> str: ...

    def batch_status(self, transport: HttpTransport, handle: str) -> BatchStatus: ...

    def batch_results(self, transport: HttpTransport, handle: str) -> list[ItemResult]: ...


class _BaseAdapter:
    name = ""
    batch_create_path = ""

    def __init__(self, api_key: str, base_url: str | None, *, timeout: float = DEFAULT_TIMEOUT_S):
        self.api_key = api_key
        self.root = (base_url or DEFAULT_BASE_URLS[self.name]).rstrip("/")
        self.timeout = timeout

    # ----------------------------------------------------------- interactive

    def interactive(
        self, *, model: str, prompt: str, payload: dict[str, Any], max_output_tokens: int
    ) -> tuple[str, dict[str, str], bytes]:
        url, headers, body = build_endpoint_request(
            provider=self.name,
            model=model,
            api_key=self.api_key,
            prompt=prompt,
            payload=payload,
            max_output_tokens=max_output_tokens,
            base_url=self.root,
        )
        return url, headers, json.dumps(body).encode()

    def parse_interactive(self, body: bytes) -> str:
        try:
            doc = json.loads(body)
        except ValueError:
            return ""
        return parse_endpoint_response(self.name, doc) if isinstance(doc, dict) else ""

    # ---------------------------------------------------------------- errors

    def classify(self, status: int, *, path: str) -> Classification:
        return classify_status(status, batch_create=self._is_batch_create(path))

    def _is_batch_create(self, path: str) -> bool:
        return path.rstrip("/").endswith(self.batch_create_path)

    def error(
        self,
        status: int,
        headers: dict[str, str],
        body: bytes,
        *,
        path: str,
        batch_create: bool = False,
    ) -> EndpointError:
        kind = classify_status(status, batch_create=batch_create or self._is_batch_create(path))
        error_type, message = _error_fields(body)
        cls = BatchUnsupported if kind == "unsupported" else EndpointError
        return cls(
            provider=self.name,
            path=path_of(path),
            status=status,
            error_type=error_type,
            transient=kind == "transient",
            retry_after_s=parse_retry_after(headers),
            detail=message,
        )

    def _call(
        self,
        transport: HttpTransport,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        *,
        batch_create: bool = False,
    ) -> tuple[dict[str, str], bytes]:
        try:
            status, resp_headers, resp_body = transport(
                method, url, headers, body, timeout=self.timeout
            )
        except (ConnectionError, TimeoutError) as exc:
            raise EndpointError(
                provider=self.name,
                path=path_of(url),
                status=None,
                transient=True,
                detail=_truncate(str(exc)) or type(exc).__name__,
            ) from exc
        if status >= 300:
            raise self.error(status, resp_headers, resp_body, path=url, batch_create=batch_create)
        return resp_headers, resp_body

    def _json(self, transport: HttpTransport, method: str, url: str, body: dict | None = None,
              *, batch_create: bool = False) -> dict[str, Any]:
        headers = dict(self._headers())
        data = None
        if body is not None:
            headers["content-type"] = "application/json"
            data = json.dumps(body).encode()
        _, raw = self._call(transport, method, url, headers, data, batch_create=batch_create)
        try:
            doc = json.loads(raw)
        except ValueError:
            doc = {}
        return doc if isinstance(doc, dict) else {}

    def _headers(self) -> dict[str, str]:  # pragma: no cover - overridden
        raise NotImplementedError

    # ----------------------------------------------------------------- batch

    def item_body(self, item: BatchItemSpec) -> dict[str, Any]:
        _, _, body = build_endpoint_request(
            provider=self.name,
            model=item.model,
            api_key=self.api_key,
            prompt=item.prompt,
            payload=item.payload,
            max_output_tokens=item.max_output_tokens,
            base_url=self.root,
        )
        return body

    def item_bytes(self, item: BatchItemSpec) -> int:
        return len(json.dumps(self.item_body(item)).encode()) + len(item.custom_id) + 64


class AnthropicAdapter(_BaseAdapter):
    name = "anthropic"
    batch_create_path = "/v1/messages/batches"

    def _headers(self) -> dict[str, str]:
        return {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"}

    def batch_limits(self) -> BatchLimits:
        return BatchLimits(max_items=100_000, max_bytes=int(256 * 1024 * 1024 * 0.9))

    def submit_batch(
        self, transport: HttpTransport, items: list[BatchItemSpec], *, model: str
    ) -> str:
        requests = [
            {"custom_id": item.custom_id, "params": self.item_body(item)} for item in items
        ]
        doc = self._json(
            transport, "POST", f"{self.root}/v1/messages/batches", {"requests": requests},
            batch_create=True,
        )
        handle = doc.get("id")
        if not handle:
            raise EndpointError(
                provider=self.name, path="/v1/messages/batches", status=None,
                transient=False, detail="batch submission returned no id",
            )
        return str(handle)

    def batch_status(self, transport: HttpTransport, handle: str) -> BatchStatus:
        try:
            doc = self._json(transport, "GET", f"{self.root}/v1/messages/batches/{handle}")
        except EndpointError as exc:
            if exc.status == 404:
                return BatchStatus(state="not_found", completed=0, total=0, reason=str(exc))
            raise
        counts = doc.get("request_counts") or {}
        done = sum(int(counts.get(k, 0)) for k in ("succeeded", "errored", "canceled", "expired"))
        total = done + int(counts.get("processing", 0))
        state = "ended" if doc.get("processing_status") == "ended" else "in_progress"
        return BatchStatus(state=state, completed=done, total=total)

    def batch_results(self, transport: HttpTransport, handle: str) -> list[ItemResult]:
        headers = dict(self._headers())
        _, raw = self._call(
            transport, "GET", f"{self.root}/v1/messages/batches/{handle}/results", headers, None
        )
        out: list[ItemResult] = []
        for line in _parse_jsonl(raw):
            custom_id = str(line.get("custom_id", ""))
            result = line.get("result") or {}
            kind = result.get("type")
            if kind == "succeeded":
                message = result.get("message") or {}
                out.append(
                    ItemResult(custom_id, "succeeded", content=parse_endpoint_response(
                        self.name, message if isinstance(message, dict) else {}
                    ))
                )
            elif kind in ("canceled", "expired"):
                out.append(ItemResult(custom_id, kind, reason=kind))
            else:
                error = result.get("error") or {}
                etype = error.get("type") or "error"
                msg = error.get("message") or ""
                reason = _truncate(f"errored: {etype}" + (f": {msg}" if msg else ""))
                out.append(ItemResult(custom_id, "errored", reason=reason))
        return out


class OpenAICompatibleAdapter(_BaseAdapter):
    name = "openai-compatible"
    batch_create_path = "/batches"

    def _headers(self) -> dict[str, str]:
        return {"authorization": f"Bearer {self.api_key}"}

    def batch_limits(self) -> BatchLimits:
        return BatchLimits(max_items=50_000, max_bytes=int(200 * 1024 * 1024 * 0.9))

    def _is_batch_create(self, path: str) -> bool:
        stripped = path.rstrip("/")
        return stripped.endswith("/batches") or stripped.endswith("/files")

    def jsonl_for(self, items: list[BatchItemSpec], *, model: str) -> bytes:
        lines = []
        for item in items:
            if item.model != model:
                raise ValueError("an OpenAI batch must contain a single model")
            lines.append(
                json.dumps(
                    {
                        "custom_id": item.custom_id,
                        "method": "POST",
                        "url": "/v1/chat/completions",
                        "body": self.item_body(item),
                    }
                )
            )
        return ("\n".join(lines) + "\n").encode()

    @staticmethod
    def multipart(jsonl: bytes) -> tuple[str, bytes]:
        boundary = uuid.uuid4().hex
        head = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="purpose"\r\n\r\nbatch\r\n'
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="input.jsonl"\r\n'
            "Content-Type: application/jsonl\r\n\r\n"
        ).encode()
        tail = f"\r\n--{boundary}--\r\n".encode()
        return f"multipart/form-data; boundary={boundary}", head + jsonl + tail

    def submit_batch(
        self, transport: HttpTransport, items: list[BatchItemSpec], *, model: str
    ) -> str:
        jsonl = self.jsonl_for(items, model=model)
        content_type, body = self.multipart(jsonl)
        headers = {**self._headers(), "content-type": content_type}
        _, raw = self._call(transport, "POST", f"{self.root}/files", headers, body,
                            batch_create=True)
        try:
            file_id = json.loads(raw).get("id")
        except (ValueError, AttributeError):
            file_id = None
        if not file_id:
            raise EndpointError(provider=self.name, path="/files", status=None, transient=False,
                                detail="file upload returned no id")
        doc = self._json(
            transport,
            "POST",
            f"{self.root}/batches",
            {
                "input_file_id": file_id,
                "endpoint": "/v1/chat/completions",
                "completion_window": "24h",
            },
            batch_create=True,
        )
        handle = doc.get("id")
        if not handle:
            raise EndpointError(provider=self.name, path="/batches", status=None,
                                transient=False, detail="batch submission returned no id")
        return str(handle)

    def _status_doc(self, transport: HttpTransport, handle: str) -> dict[str, Any] | None:
        try:
            return self._json(transport, "GET", f"{self.root}/batches/{handle}")
        except EndpointError as exc:
            if exc.status == 404:
                return None
            raise

    def batch_status(self, transport: HttpTransport, handle: str) -> BatchStatus:
        doc = self._status_doc(transport, handle)
        if doc is None:
            return BatchStatus(state="not_found", completed=0, total=0,
                               reason="batch reference not found")
        counts = doc.get("request_counts") or {}
        completed = int(counts.get("completed", 0)) + int(counts.get("failed", 0))
        total = int(counts.get("total", 0))
        status = doc.get("status")
        if status in ("completed", "expired", "cancelled"):
            return BatchStatus(state="ended", completed=completed, total=total)
        if status == "failed":
            errors = ((doc.get("errors") or {}).get("data") or [])
            reason = "; ".join(
                str(e.get("message")) for e in errors if isinstance(e, dict) and e.get("message")
            ) or "batch failed"
            return BatchStatus(state="failed", completed=completed, total=total,
                               reason=_truncate(reason))
        return BatchStatus(state="in_progress", completed=completed, total=total)

    def batch_results(self, transport: HttpTransport, handle: str) -> list[ItemResult]:
        doc = self._status_doc(transport, handle) or {}
        out: list[ItemResult] = []
        for key in ("output_file_id", "error_file_id"):
            file_id = doc.get(key)
            if not file_id:
                continue
            _, raw = self._call(
                transport, "GET", f"{self.root}/files/{file_id}/content",
                dict(self._headers()), None,
            )
            for line in _parse_jsonl(raw):
                custom_id = str(line.get("custom_id", ""))
                error = line.get("error")
                response = line.get("response") or {}
                if error:
                    code = str(error.get("code") or error.get("type") or "error")
                    msg = error.get("message") or ""
                    if code == "batch_expired":
                        out.append(ItemResult(custom_id, "expired", reason="expired"))
                    else:
                        out.append(ItemResult(custom_id, "errored", reason=_truncate(
                            f"errored: {code}" + (f": {msg}" if msg else ""))))
                    continue
                status = int(response.get("status_code") or 0)
                body = response.get("body") or {}
                if 200 <= status < 300 and isinstance(body, dict):
                    out.append(ItemResult(custom_id, "succeeded",
                                          content=parse_endpoint_response(self.name, body)))
                else:
                    etype, msg = _error_fields(json.dumps(body).encode())
                    out.append(ItemResult(custom_id, "errored", reason=_truncate(
                        f"errored: HTTP {status}" + (f" {etype}" if etype else ""))))
        return out


def adapter_for(provider: str, api_key: str, base_url: str | None = None) -> ProviderAdapter:
    if provider == "anthropic":
        return AnthropicAdapter(api_key, base_url)
    if provider == "openai-compatible":
        return OpenAICompatibleAdapter(api_key, base_url)
    raise RuntimeError(f"unsupported analysis endpoint provider: {provider!r}")


def urllib_transport(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    *,
    timeout: float,
) -> tuple[int, dict[str, str], bytes]:  # pragma: no cover - exercised only against a live endpoint
    """Stdlib :class:`HttpTransport`; non-2xx responses are returned, not raised."""
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read() if exc.fp else b""
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            raise TimeoutError(str(exc.reason)) from exc
        raise ConnectionError(str(exc.reason)) from exc
    except TimeoutError as exc:
        raise TimeoutError(str(exc)) from exc
