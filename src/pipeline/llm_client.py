"""Analysis execution clients (FR-007a, FR-016b, FR-027; research.md R4; feature 012).

Two backends satisfy one interface:

* :class:`AgentMediatedClient` — the default. The host coding agent performs the
  reasoning, so the pipeline *externalises* the request: it writes the prompt and
  context packet to an artifact and expects the agent to write findings back.
  Nothing is sent anywhere by the scanner itself.
* :class:`EndpointClient` — an operator-configured provider, spoken to through a
  :mod:`pipeline.providers` adapter. Interactive calls retry transient failures
  (:class:`RetryPolicy`) and every answer is persisted in an
  :class:`~pipeline.answers.AnswerStore` so a resumed scan never repeats a request.
  Batch submission lives in :mod:`pipeline.batch_runner` and reuses the same adapter.
"""

from __future__ import annotations

import json
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from datetime import time as dtime
from pathlib import Path
from typing import Any, Protocol, TypeVar

from config.mode import ExecutionMode, Resolution
from pipeline.answers import AnswerStore
from pipeline.budget import TokenBudget, estimate_tokens
from pipeline.providers import (
    DEFAULT_BASE_URLS,
    EndpointError,
    HttpTransport,
    ProviderAdapter,
    adapter_for,
    build_endpoint_request,
    parse_endpoint_response,
    path_of,
    urllib_transport,
)

__all__ = [
    "DEFAULT_BASE_URLS",
    "AgentHandoff",
    "AgentMediatedClient",
    "AnalysisClient",
    "AnalysisRequest",
    "AnalysisResponse",
    "EndpointClient",
    "RetryPolicy",
    "build_client",
    "build_endpoint_request",
    "in_window",
    "parse_endpoint_response",
    "parse_window",
]

T = TypeVar("T")


@dataclass
class AnalysisRequest:
    """One bounded analysis invocation."""

    id: str
    stage: str
    prompt: str
    payload: dict[str, Any]
    budget: TokenBudget
    level: str = "segment"  # local | segment | system
    escalation_level: int = 1

    @property
    def context_text(self) -> str:
        return self.prompt + "\n" + json.dumps(self.payload, sort_keys=True)

    def estimated_tokens(self) -> int:
        return estimate_tokens(self.context_text)


@dataclass
class AnalysisResponse:
    request_id: str
    content: str
    input_tokens: int
    output_tokens: int
    model_tier: str
    batch: bool = False
    fell_back: bool = False
    fallback_reason: str | None = None
    pending: bool = False
    #: True when the content came from a persisted answer rather than a request made
    #: in this run; such a response is never counted in this run's usage (feature 012).
    cached: bool = False


class AnalysisClient(Protocol):
    """Interface shared by both execution modes."""

    mode: ExecutionMode

    def run(self, request: AnalysisRequest) -> AnalysisResponse: ...

    def supports_batch(self) -> bool: ...


# ------------------------------------------------------------ agent-mediated


class AgentHandoff(Exception):
    """Raised when the pipeline needs the host agent to perform reasoning.

    The orchestrator (SKILL.md) catches this at the driver level: the pending
    requests are on disk, the agent answers them, and re-invoking the scan
    resumes from the checkpoint (FR-027 cross-session resume).
    """

    request_dir: Path | None = None
    response_dir: Path | None = None

    def __init__(self, pending: list[str]) -> None:
        self.pending = pending
        super().__init__(
            f"{len(pending)} analysis request(s) await agent reasoning: "
            f"{', '.join(pending[:3])}{' ...' if len(pending) > 3 else ''}"
        )

    def instructions(self) -> str:
        lines = [str(self)]
        if self.request_dir and self.response_dir:
            lines += [
                "",
                f"Requests (prompt + bounded context packet): {self.request_dir}",
                "Write one findings JSON per request to:",
                f"  {self.response_dir}/<request-id>.json",
                "",
                "Then re-run the scan command; completed stages are skipped and the scan",
                "continues from this checkpoint.",
            ]
        return "\n".join(lines)


@dataclass
class AgentMediatedClient:
    """Externalises reasoning to the host agent (default mode, FR-027).

    Three ways an answer arrives, in priority order:

    1. ``responder`` — an in-process callable (used by tests and any future
       in-agent bridge);
    2. a response file the agent already wrote to ``response_dir`` (this is how
       a scan resumes across agent sessions);
    3. otherwise the request is written to ``request_dir`` and queued, and the
       driver raises :class:`AgentHandoff` so the agent can answer it.
    """

    mode: ExecutionMode = ExecutionMode.AGENT_MEDIATED
    responder: Any | None = None
    request_dir: Path | None = None
    response_dir: Path | None = None
    pending: list[AnalysisRequest] = field(default_factory=list)

    def supports_batch(self) -> bool:
        return False

    def run(self, request: AnalysisRequest) -> AnalysisResponse:
        request.budget.check(request.estimated_tokens(), f"{request.stage}/{request.id}")

        if self.responder is not None:
            content = self.responder(request)
            return self._answered(request, content)

        existing = self._read_response(request)
        if existing is not None:
            return self._answered(request, existing)

        self._write_request(request)
        self.pending.append(request)
        return AnalysisResponse(
            request_id=request.id,
            content="",
            input_tokens=request.estimated_tokens(),
            output_tokens=0,
            model_tier="agent",
            pending=True,
        )

    # ----------------------------------------------------------- handoff io

    def _answered(self, request: AnalysisRequest, content: str) -> AnalysisResponse:
        return AnalysisResponse(
            request_id=request.id,
            content=content,
            input_tokens=request.estimated_tokens(),
            output_tokens=estimate_tokens(content),
            model_tier="agent",
        )

    def response_path(self, request_id: str) -> Path | None:
        if self.response_dir is None:
            return None
        return self.response_dir / f"{request_id}.json"

    def _read_response(self, request: AnalysisRequest) -> str | None:
        path = self.response_path(request.id)
        if path is None or not path.exists():
            return None
        try:
            text = path.read_text()
        except OSError:
            return None
        return text if text.strip() else None

    def _write_request(self, request: AnalysisRequest) -> None:
        if self.request_dir is None:
            return
        self.request_dir.mkdir(parents=True, exist_ok=True)
        if request.stage == "finding_triage":
            # Feature 013: triage requests answer with the verdict vocabulary,
            # not the findings shape.
            instructions = (
                "Answer this request by writing the triage verdict JSON described "
                "in prompts/triage_finding.md (schema: schemas/triage_answer.json) to "
                f"../responses/{request.id}.json, then re-run the scan command."
            )
        else:
            instructions = (
                "Answer this request by writing the findings JSON described in "
                "prompts/segment_scan.md to "
                f"../responses/{request.id}.json, then re-run the scan command."
            )
        document = {
            "request_id": request.id,
            "stage": request.stage,
            "escalation_level": request.escalation_level,
            "estimated_tokens": request.estimated_tokens(),
            "budget": request.budget.to_dict(),
            "instructions": instructions,
            "prompt": request.prompt,
            "context_packet": request.payload,
        }
        path = self.request_dir / f"{request.id}.json"
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


# --------------------------------------------------------------------- retry


@dataclass
class RetryPolicy:
    """Bounded, jittered backoff for transient endpoint failures (FR-014, research R3).

    ``attempts`` counts the initial try. Waits double from ``base_wait_s`` up to
    ``max_wait_s`` (times a U(0.5, 1) jitter), a provider ``Retry-After`` is a
    minimum, and the sum of waits never exceeds ``total_wait_s``.
    """

    attempts: int = 5
    base_wait_s: float = 2.0
    max_wait_s: float = 60.0
    total_wait_s: float = 180.0
    rng: random.Random = field(default_factory=random.Random)
    sleep: Callable[[float], None] = time.sleep

    def wait_for(self, attempt: int, retry_after_s: float | None) -> float:
        """Wait before attempt ``attempt + 1`` (``attempt`` is 1-based)."""
        base = min(self.max_wait_s, self.base_wait_s * (2 ** (attempt - 1)))
        wait = base * self.rng.uniform(0.5, 1.0)
        if retry_after_s is not None:
            wait = max(wait, float(retry_after_s))
        return wait

    def execute(
        self,
        fn: Callable[[], T],
        *,
        request_id: str | None = None,
        on_retry: Callable[[str | None, int, float, int | None], None] | None = None,
    ) -> T:
        waited = 0.0
        attempt = 0
        while True:
            attempt += 1
            try:
                return fn()
            except EndpointError as exc:
                if not exc.transient or attempt >= max(1, self.attempts):
                    raise exc.with_attempts(attempt, request_id) from None
                wait = self.wait_for(attempt, exc.retry_after_s)
                if waited + wait > self.total_wait_s:
                    raise exc.with_attempts(attempt, request_id) from None
                if on_retry is not None:
                    on_retry(request_id, attempt + 1, wait, exc.status)
                self.sleep(wait)
                waited += wait


# ------------------------------------------------------------------ endpoint


class EndpointClient:
    """Provider-backed interactive client; persists answers and retries transients."""

    def __init__(
        self,
        resolution: Resolution,
        api_key: str,
        *,
        transport: HttpTransport | None = None,
        answers: AnswerStore | None = None,
        retry: RetryPolicy | None = None,
        on_retry: Callable[[str | None, int, float, int | None], None] | None = None,
        timeout: float = 120.0,
    ) -> None:
        self.mode = resolution.mode
        self.resolution = resolution
        self.api_key = api_key
        self.adapter: ProviderAdapter = adapter_for(
            resolution.provider, api_key, resolution.base_url
        )
        self.transport: HttpTransport = transport or urllib_transport
        self.answers = answers
        self.retry = retry or RetryPolicy(
            attempts=resolution.retry_attempts, max_wait_s=float(resolution.retry_max_wait_s)
        )
        self.on_retry = on_retry
        self.timeout = timeout

    def supports_batch(self) -> bool:
        return self.mode is ExecutionMode.ENDPOINT_BATCH

    def run(self, request: AnalysisRequest) -> AnalysisResponse:
        request.budget.check(request.estimated_tokens(), f"{request.stage}/{request.id}")
        tier = self.resolution.tier_for(request.level)

        cached = self.answers.get(request, tier) if self.answers is not None else None
        if cached is not None:
            return self._response(request, cached, tier, cached=True)

        url, headers, body = self.adapter.interactive(
            model=tier,
            prompt=request.prompt,
            payload=request.payload,
            max_output_tokens=request.budget.max_output_tokens,
        )

        def attempt() -> str:
            try:
                status, resp_headers, resp_body = self.transport(
                    "POST", url, headers, body, timeout=self.timeout
                )
            except (ConnectionError, TimeoutError) as exc:
                raise EndpointError(
                    provider=self.adapter.name,
                    path=path_of(url),
                    status=None,
                    transient=True,
                    detail=type(exc).__name__,
                ) from exc
            if status >= 300:
                raise self.adapter.error(status, resp_headers, resp_body, path=url)
            return self.adapter.parse_interactive(resp_body)

        content = self.retry.execute(attempt, request_id=request.id, on_retry=self.on_retry)
        if self.answers is not None:
            self.answers.put(request, tier, content)
        return self._response(request, content, tier)

    @staticmethod
    def _response(
        request: AnalysisRequest, content: str, tier: str, *, cached: bool = False
    ) -> AnalysisResponse:
        return AnalysisResponse(
            request_id=request.id,
            content=content,
            input_tokens=request.estimated_tokens(),
            output_tokens=estimate_tokens(content),
            model_tier=tier,
            cached=cached,
        )


# ------------------------------------------------------------ off-peak window


def parse_window(window: str) -> tuple[dtime, dtime]:
    start_raw, end_raw = window.split("-")
    start_h, start_m = (int(p) for p in start_raw.strip().split(":"))
    end_h, end_m = (int(p) for p in end_raw.strip().split(":"))
    return dtime(start_h, start_m), dtime(end_h, end_m)


def in_window(window: str, now: datetime | None = None) -> bool:
    """True when ``now`` falls inside the configured off-peak window."""
    start, end = parse_window(window)
    current = (now or datetime.now()).time()
    if start <= end:
        return start <= current <= end
    return current >= start or current <= end  # window crosses midnight


def build_client(
    resolution: Resolution,
    api_key: str | None,
    *,
    responder: Any | None = None,
    transport: HttpTransport | None = None,
    handoff_dir: Path | None = None,
    answers: AnswerStore | None = None,
    retry: RetryPolicy | None = None,
    on_retry: Callable[[str | None, int, float, int | None], None] | None = None,
) -> AnalysisClient:
    """Construct the client for the resolved execution mode."""
    if not resolution.mode.uses_endpoint:
        return AgentMediatedClient(
            responder=responder,
            request_dir=(handoff_dir / "requests") if handoff_dir else None,
            response_dir=(handoff_dir / "responses") if handoff_dir else None,
        )
    if not api_key:
        raise RuntimeError("endpoint mode requires an API key")
    return EndpointClient(
        resolution, api_key, transport=transport, answers=answers, retry=retry, on_retry=on_retry
    )
