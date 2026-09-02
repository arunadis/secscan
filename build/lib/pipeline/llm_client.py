"""Analysis execution clients (FR-007a, FR-016b, FR-027; research.md R4).

Two backends satisfy one interface:

* :class:`AgentMediatedClient` — the default. The host coding agent performs the
  reasoning, so the pipeline *externalises* the request: it writes the prompt and
  context packet to an artifact and expects the agent to write findings back.
  Nothing is sent anywhere by the scanner itself.
* :class:`EndpointClient` — an operator-configured provider. Supports interactive
  calls and a provider-agnostic batch abstraction (``submit_batch``/``poll``);
  failed or expired batch items fall back to interactive execution and every
  fallback is recorded (FR-016b).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from datetime import time as dtime
from pathlib import Path
from typing import Any, Protocol

from config.mode import ExecutionMode, Resolution
from pipeline.budget import TokenBudget, estimate_tokens


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
        document = {
            "request_id": request.id,
            "stage": request.stage,
            "escalation_level": request.escalation_level,
            "estimated_tokens": request.estimated_tokens(),
            "budget": request.budget.to_dict(),
            "instructions": (
                "Answer this request by writing the findings JSON described in "
                "prompts/segment_scan.md to "
                f"../responses/{request.id}.json, then re-run the scan command."
            ),
            "prompt": request.prompt,
            "context_packet": request.payload,
        }
        path = self.request_dir / f"{request.id}.json"
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


# ------------------------------------------------------------------ endpoint


@dataclass
class BatchJob:
    handle: str
    request_ids: list[str]
    submitted_at: float
    expires_at: float


class EndpointClient:
    """Provider-backed client with interactive and batch execution."""

    def __init__(
        self,
        resolution: Resolution,
        api_key: str,
        *,
        transport: Any | None = None,
        batch_window_seconds: int = 24 * 3600,
    ) -> None:
        self.mode = resolution.mode
        self.resolution = resolution
        self.api_key = api_key
        self.transport = transport or _http_transport
        self.batch_window_seconds = batch_window_seconds
        self._jobs: dict[str, BatchJob] = {}

    def supports_batch(self) -> bool:
        return self.mode is ExecutionMode.ENDPOINT_BATCH

    # ------------------------------------------------------------ interactive

    def run(self, request: AnalysisRequest) -> AnalysisResponse:
        request.budget.check(request.estimated_tokens(), f"{request.stage}/{request.id}")
        tier = self.resolution.tier_for(request.level)
        content = self.transport(
            provider=str(self.resolution.model_map and "configured" or "configured"),
            model=tier,
            api_key=self.api_key,
            prompt=request.prompt,
            payload=request.payload,
            max_output_tokens=request.budget.max_output_tokens,
        )
        return AnalysisResponse(
            request_id=request.id,
            content=content,
            input_tokens=request.estimated_tokens(),
            output_tokens=estimate_tokens(content),
            model_tier=tier,
        )

    # ----------------------------------------------------------------- batch

    def submit_batch(self, requests: list[AnalysisRequest]) -> BatchJob:
        for request in requests:
            request.budget.check(request.estimated_tokens(), f"{request.stage}/{request.id}")
        now = time.time()
        handle = f"batch-{int(now)}-{len(requests)}"
        job = BatchJob(
            handle=handle,
            request_ids=[r.id for r in requests],
            submitted_at=now,
            expires_at=now + self.batch_window_seconds,
        )
        self._jobs[handle] = job
        return job

    def poll(self, job: BatchJob) -> dict[str, Any]:
        """Return ``{status, results}`` where status is done | pending | failed."""
        if time.time() > job.expires_at:
            return {"status": "failed", "results": {}, "reason": "batch window expired"}
        return {"status": "pending", "results": {}}

    def run_batch_with_fallback(
        self,
        requests: list[AnalysisRequest],
        on_fallback: Any | None = None,
    ) -> list[AnalysisResponse]:
        """Submit as a batch; re-execute failed/expired items interactively (FR-016b)."""
        if not requests:
            return []
        job = self.submit_batch(requests)
        outcome = self.poll(job)
        by_id = {r.id: r for r in requests}
        responses: list[AnalysisResponse] = []

        completed: dict[str, str] = outcome.get("results") or {}
        for request_id, content in sorted(completed.items()):
            request = by_id[request_id]
            responses.append(
                AnalysisResponse(
                    request_id=request_id,
                    content=content,
                    input_tokens=request.estimated_tokens(),
                    output_tokens=estimate_tokens(content),
                    model_tier=self.resolution.tier_for(request.level),
                    batch=True,
                )
            )

        reason = outcome.get("reason") or f"batch status={outcome.get('status')}"
        for request_id in sorted(set(by_id) - set(completed)):
            request = by_id[request_id]
            if on_fallback:
                on_fallback(request_id, reason)
            response = self.run(request)
            response.fell_back = True
            response.fallback_reason = reason
            responses.append(response)
        return responses


def _http_transport(
    *,
    provider: str,
    model: str,
    api_key: str,
    prompt: str,
    payload: dict[str, Any],
    max_output_tokens: int,
) -> str:  # pragma: no cover - exercised only against a live endpoint
    """Minimal Anthropic-shaped request. Replaced by tests via ``transport``."""
    body = json.dumps(
        {
            "model": model,
            "max_tokens": max_output_tokens,
            "messages": [
                {
                    "role": "user",
                    "content": prompt + "\n\n" + json.dumps(payload, sort_keys=True),
                }
            ],
        }
    ).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            doc = json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"analysis endpoint request failed: {exc}") from exc
    blocks = doc.get("content") or []
    return "".join(b.get("text", "") for b in blocks if isinstance(b, dict))


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
    transport: Any | None = None,
    handoff_dir: Path | None = None,
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
    return EndpointClient(resolution, api_key, transport=transport)
