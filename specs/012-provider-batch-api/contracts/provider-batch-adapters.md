# Contract: Provider Adapters

**Feature**: 012-provider-batch-api | **Status**: Draft | **Module**: `src/pipeline/providers.py`

Every byte that leaves the scanner for the analysis endpoint is produced by one of the two
adapters below. Both implement the same protocol; `llm_client.py` and `batch_runner.py` never
build a URL or parse a provider document themselves.

The protocol has nine members: `interactive`, `parse_interactive`, `error`, `classify`,
`batch_limits`, `item_bytes`, `submit_batch`, `batch_status`, `batch_results` (`error` builds
the typed exception for a non-2xx response; `item_bytes` sizes a prospective batch item so the
round runner can split under `batch_limits`).

## Protocol

```python
class HttpTransport(Protocol):
    def __call__(self, method: str, url: str, headers: dict[str, str],
                 body: bytes | None, *, timeout: float) -> tuple[int, dict[str, str], bytes]: ...

@dataclass(frozen=True)
class BatchLimits:
    max_items: int
    max_bytes: int            # applied to the serialized submission body / input file

@dataclass(frozen=True)
class BatchStatus:
    state: Literal["in_progress", "ended", "failed", "not_found"]
    completed: int            # items in a terminal state at the provider
    total: int
    reason: str | None        # provider message for failed

@dataclass(frozen=True)
class ItemResult:
    custom_id: str
    outcome: Literal["succeeded", "errored", "canceled", "expired"]
    content: str | None       # assistant text when succeeded
    reason: str | None        # "<error type>: <message>" when not succeeded (message truncated to 200 chars)

class ProviderAdapter(Protocol):
    name: str
    def interactive(self, *, model: str, prompt: str, payload: dict, max_output_tokens: int) -> tuple[str, dict[str, str], bytes]: ...   # (url, headers, body)
    def parse_interactive(self, body: bytes) -> str: ...
    def batch_limits(self) -> BatchLimits: ...
    def submit_batch(self, transport, items: list[BatchItemSpec], *, model: str) -> str: ...        # returns handle; raises BatchUnsupported / EndpointError
    def batch_status(self, transport, handle: str) -> BatchStatus: ...
    def batch_results(self, transport, handle: str) -> list[ItemResult]: ...
    def classify(self, status: int, *, path: str) -> Literal["transient", "terminal", "unsupported"]: ...
```

`BatchItemSpec = (custom_id, model, prompt, payload, max_output_tokens)`. The per-item body is
built by the **same** function as the interactive body (`build_endpoint_request`), so batch
and interactive requests are byte-identical for the same input (Principle III).

`custom_id` = analysis request id. If it does not match `^[a-zA-Z0-9_-]{1,64}$`, the adapter
substitutes `sha256(request_id)[:32]` and returns the mapping alongside the handle for the
ledger. Current segment ids (`seg-<slug>-p<n>-l<level>`) satisfy the grammar.

## Error classification (shared)

| Condition | Class |
|---|---|
| connection refused/reset, DNS failure, socket timeout | transient |
| 408, 409, 429, 500, 502, 503, 504, 529 | transient |
| 404, 405, 501 **on the batch-create path** | unsupported → `BatchUnsupported` |
| any other 4xx/5xx (400, 401, 403, 404 elsewhere, 413, 422, …) | terminal |

`Retry-After` is parsed from the response headers as integer seconds or an HTTP-date; when
present it is the minimum wait for the next attempt. Provider error `type`/`code` is extracted
from the JSON body when present (`error.type` for Anthropic, `error.type`/`error.code` for
OpenAI) and placed in `EndpointError.error_type`; the message is **not** echoed to the terminal
beyond 200 chars and never includes request content.

## Anthropic adapter (`provider: anthropic`)

Root: `base_url` or `https://api.anthropic.com`. Headers on every call:
`x-api-key: <key>`, `anthropic-version: 2023-06-01`, `content-type: application/json`.
No beta header.

| Operation | Method / path | Body / notes |
|---|---|---|
| interactive | `POST /v1/messages` | `{model, max_tokens, messages:[{role:user, content}]}` (unchanged) |
| submit_batch | `POST /v1/messages/batches` | `{"requests":[{"custom_id", "params":{model, max_tokens, messages}}]}`; handle = `id` |
| batch_status | `GET /v1/messages/batches/{id}` | `processing_status`: `in_progress`/`canceling` → `in_progress`; `ended` → `ended`; `completed = succeeded+errored+canceled+expired`; 404 → `not_found` |
| batch_results | `GET /v1/messages/batches/{id}/results` (or `results_url`) | JSONL lines `{custom_id, result:{type, message?, error?}}`; `content` = concatenated `message.content[*].text`; unordered |
| limits | — | `max_items=100_000`, `max_bytes=int(256 MB × 0.9)` |

Item outcomes map 1:1 (`succeeded`, `errored`, `canceled`, `expired`). Mixed models are
allowed by the provider but the runner still submits one model per batch (uniform behaviour).

## OpenAI-compatible adapter (`provider: openai-compatible`)

Root: `base_url` or `https://api.openai.com/v1`. Headers: `authorization: Bearer <key>`,
`content-type` as appropriate.

| Operation | Method / path | Body / notes |
|---|---|---|
| interactive | `POST {root}/chat/completions` | `{model, max_completion_tokens, messages}` (unchanged) |
| submit_batch step 1 | `POST {root}/files` | `multipart/form-data` with fields `purpose=batch` and `file=@input.jsonl`; body built by hand (boundary from `uuid4().hex`); response `id` → `input_file_id` |
| submit_batch step 2 | `POST {root}/batches` | `{"input_file_id", "endpoint":"/v1/chat/completions", "completion_window":"24h"}`; handle = `id`. The uploaded file id is not surfaced to the runner — the batch handle is the only reference the ledger needs |
| batch_status | `GET {root}/batches/{id}` | `validating`/`in_progress`/`finalizing`/`cancelling` → `in_progress`; `completed`/`expired`/`cancelled` → `ended`; `failed` → `failed` with `errors.data[*].message` joined as reason; 404 → `not_found`; `completed = request_counts.completed + request_counts.failed` |
| batch_results | `GET {root}/files/{output_file_id}/content` and, if present, `GET {root}/files/{error_file_id}/content` | JSONL `{custom_id, response:{status_code, body}, error}`; `content` = `choices[0].message.content` (string or text parts); error lines → `errored` with `error.code: error.message`; `batch_expired` code → `expired`; items present in neither file → reported by the runner as `missing from results` |
| limits | — | `max_items=50_000`, `max_bytes=int(200 MB × 0.9)` measured on the JSONL |

Input JSONL line: `{"custom_id", "method":"POST", "url":"/v1/chat/completions", "body":{model,
messages, max_completion_tokens}}`. **All lines carry the same `model`** — enforced by the
runner's grouping; the adapter asserts it and raises `ValueError` otherwise (programming
error, not a provider error).

Gateway behaviour: a gateway that does not implement batching answers `POST {root}/batches`
(or the preceding `POST {root}/files`) with 404/405/501 → `BatchUnsupported`. Known: OpenRouter
404; vLLM 501 unless `--enable-batch-api`; LiteLLM and Azure OpenAI proxy the real API.
Azure's `api-key` header and `api-version` query are **not** handled in this feature
(documented limitation; `openai-compatible` targets the `Bearer` shape).

## Non-goals

- Cancel endpoints are never called (paid work is preserved for resume).
- List endpoints are not used; the ledger is the source of truth for handles.
- Streaming, tools, system prompts, prompt caching: unchanged from today (none used).
