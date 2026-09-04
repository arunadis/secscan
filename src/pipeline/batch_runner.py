"""Round-based batch execution of segment analysis (feature 012, research R5–R9).

The escalation ladder is re-expressed as rounds: level 1 for every segment, then
level 2 for the segments whose answer asked for more evidence, and so on. Each
round's requests are grouped by model, split under the provider's limits, submitted
as batches, recorded in a ledger inside ``state.json`` *before* waiting, polled
with a backing-off interval, and absorbed through the same ``EscalationRunner``
methods the interactive ladder uses. Items the batch could not answer fall back to
the retrying interactive client and every fallback is recorded (FR-007).

Nothing here builds a URL or parses a provider document: that is the adapter's job.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pipeline.answers import AnswerStore, answer_key
from pipeline.budget import estimate_tokens
from pipeline.escalate import EscalationRunner, SegmentOutcome
from pipeline.llm_client import (
    AnalysisRequest,
    AnalysisResponse,
    EndpointClient,
    in_window,
    parse_window,
)
from pipeline.providers import (
    BatchItemSpec,
    BatchLimits,
    BatchStatus,
    BatchUnsupported,
    EndpointError,
    ItemResult,
    custom_id_for,
)
from pipeline.state import BATCH_LEDGER_META, ArtifactStore
from pipeline.usage import UsageTracker

POLL_START_S = 30.0
POLL_FACTOR = 1.5
POLL_CAP_S = 300.0
OFFPEAK_WAIT_CAP_S = 300.0

TERMINAL_STATES = frozenset({"ended", "expired", "not_found", "failed", "abandoned"})

UNSUPPORTED_NOTE = (
    "batch execution requested but the endpoint does not support batch submission "
    "(HTTP {status}); all analysis ran interactively"
)


# ------------------------------------------------------------------ ledger


@dataclass
class BatchRecord:
    handle: str
    provider: str
    base_url: str | None
    model: str
    level: int
    items: dict[str, str]  # request_id -> answer_key recorded at submission
    submitted_at: float
    expires_at: float
    status: str = "submitted"
    reason: str | None = None
    polls: int = 0
    custom_id_map: dict[str, str] | None = None  # custom_id -> request_id, when hashed

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_STATES

    def to_dict(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "handle": self.handle,
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "level": self.level,
            "items": dict(sorted(self.items.items())),
            "submitted_at": self.submitted_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "polls": self.polls,
        }
        if self.reason is not None:
            doc["reason"] = self.reason
        if self.custom_id_map:
            doc["custom_id_map"] = dict(sorted(self.custom_id_map.items()))
        return doc

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> BatchRecord:
        return cls(
            handle=str(raw["handle"]),
            provider=str(raw.get("provider", "")),
            base_url=raw.get("base_url"),
            model=str(raw.get("model", "")),
            level=int(raw.get("level", 1)),
            items=dict(raw.get("items") or {}),
            submitted_at=float(raw.get("submitted_at", 0.0)),
            expires_at=float(raw.get("expires_at", 0.0)),
            status=str(raw.get("status", "submitted")),
            reason=raw.get("reason"),
            polls=int(raw.get("polls", 0)),
            custom_id_map=dict(raw["custom_id_map"]) if raw.get("custom_id_map") else None,
        )


def round_key(level: int, model: str) -> str:
    return f"{level}:{model}"


class BatchLedger:
    """Batch bookkeeping under ``state.json`` → ``meta.analysis_batches`` (research R7)."""

    def __init__(self, store: ArtifactStore) -> None:
        self.store = store

    def _raw(self) -> dict[str, list[dict[str, Any]]]:
        raw = self.store.get_meta(BATCH_LEDGER_META) or {}
        return {k: list(v) for k, v in raw.items()}

    def load(self) -> dict[str, list[BatchRecord]]:
        return {
            key: [BatchRecord.from_dict(r) for r in records]
            for key, records in sorted(self._raw().items())
        }

    def record(self, key: str, record: BatchRecord) -> None:
        raw = self._raw()
        raw.setdefault(key, []).append(record.to_dict())
        self.store.set_meta(BATCH_LEDGER_META, dict(sorted(raw.items())))

    def update(self, key: str, handle: str, **fields: Any) -> None:
        raw = self._raw()
        for entry in raw.get(key, []):
            if entry.get("handle") == handle:
                entry.update(fields)
        self.store.set_meta(BATCH_LEDGER_META, dict(sorted(raw.items())))

    def open_records(self, key: str) -> list[BatchRecord]:
        return [r for r in self.load().get(key, []) if not r.terminal]

    def open_count(self) -> int:
        return sum(1 for records in self.load().values() for r in records if not r.terminal)


# ------------------------------------------------------------- pure helpers


def group_and_split(
    requests: list[tuple[AnalysisRequest, str]],
    limits: BatchLimits,
    *,
    size_of: Callable[[AnalysisRequest], int],
) -> list[tuple[str, list[AnalysisRequest]]]:
    """Group by model (first-seen order), then greedy-fill chunks under the limits.

    Deterministic for a given input order; never drops an item (a single oversized
    item becomes its own chunk and the provider decides).
    """
    by_model: dict[str, list[AnalysisRequest]] = {}
    for request, model in requests:
        by_model.setdefault(model, []).append(request)
    chunks: list[tuple[str, list[AnalysisRequest]]] = []
    for model, items in by_model.items():
        current: list[AnalysisRequest] = []
        current_bytes = 0
        for request in items:
            size = size_of(request)
            if current and (
                len(current) >= limits.max_items or current_bytes + size > limits.max_bytes
            ):
                chunks.append((model, current))
                current, current_bytes = [], 0
            current.append(request)
            current_bytes += size
        if current:
            chunks.append((model, current))
    return chunks


def poll_schedule() -> Iterator[float]:
    wait = POLL_START_S
    while True:
        yield min(POLL_CAP_S, wait)
        wait = min(POLL_CAP_S, wait * POLL_FACTOR)


def plan_round(
    level: int, segments: list[dict[str, Any]], needs_more: dict[str, bool]
) -> list[dict[str, Any]]:
    if level == 1:
        return list(segments)
    return [s for s in segments if needs_more.get(s["id"], False)]


def check_budgets(requests: list[AnalysisRequest], stage: str) -> None:
    """FR-011: every batch item is budget-checked exactly like an interactive request."""
    for request in requests:
        request.budget.check(request.estimated_tokens(), f"{stage}/{request.id}")


@dataclass
class ItemOutcome:
    request_id: str
    outcome: str  # answered | failed
    content: str | None = None
    reason: str | None = None


def classify_items(
    record: BatchRecord, status: BatchStatus | None, results: list[ItemResult]
) -> list[ItemOutcome]:
    """Every item of ``record`` ends ``answered`` or ``failed(reason)`` (FR-007)."""
    if record.status == "expired" or status is None:
        return [ItemOutcome(rid, "failed", reason="expired") for rid in sorted(record.items)]
    if status.state == "not_found":
        return [
            ItemOutcome(rid, "failed", reason="batch reference not found")
            for rid in sorted(record.items)
        ]
    if status.state == "failed":
        reason = f"batch failed: {status.reason or 'provider rejected the batch'}"
        return [ItemOutcome(rid, "failed", reason=reason) for rid in sorted(record.items)]
    translate = record.custom_id_map or {}
    seen: dict[str, ItemResult] = {}
    for result in results:
        seen[translate.get(result.custom_id, result.custom_id)] = result
    outcomes: list[ItemOutcome] = []
    for rid in sorted(record.items):
        result = seen.get(rid)
        if result is None:
            outcomes.append(ItemOutcome(rid, "failed", reason="missing from results"))
        elif result.outcome == "succeeded":
            outcomes.append(ItemOutcome(rid, "answered", content=result.content or ""))
        else:
            outcomes.append(ItemOutcome(rid, "failed", reason=result.reason or result.outcome))
    return outcomes


def resume_check(record: BatchRecord, current_keys: dict[str, str]) -> str:
    """``resume`` when every still-requested item has the key recorded at submission."""
    for rid, key in record.items.items():
        if rid in current_keys and current_keys[rid] != key:
            return "abandon"
    return "resume"


# ------------------------------------------------------------------ runner


@dataclass
class _Pending:
    record: BatchRecord
    key: str
    index: int
    total: int
    status: BatchStatus | None = None
    waited_s: float = 0.0


class BatchRoundRunner:
    """Drives segment analysis through provider batches, one escalation level per round."""

    def __init__(
        self,
        client: EndpointClient,
        escalation: EscalationRunner,
        ledger: BatchLedger,
        answers: AnswerStore,
        usage: UsageTracker,
        reporter: Any,
        *,
        window_hours: float,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
        offpeak_window: str | None = None,
        stage: str = "segment_analysis",
    ) -> None:
        self.client = client
        self.adapter = client.adapter
        self.transport = client.transport
        self.escalation = escalation
        self.ledger = ledger
        self.answers = answers
        self.usage = usage
        self.reporter = reporter
        self.window_hours = float(window_hours)
        self.clock = clock or time.time
        self.sleep = sleep or time.sleep
        self.offpeak_window = offpeak_window
        self.stage = stage
        self.batch_available = True
        #: Coverage notes raised by the runner (already reported live); run.py merges
        #: them into the report so terminal and report cannot disagree.
        self.warnings: list[str] = []
        self.fallbacks: list[tuple[str, str]] = []
        self._outcomes: dict[str, SegmentOutcome] = {}
        self._segments: dict[str, dict[str, Any]] = {}
        self._requests: dict[str, tuple[AnalysisRequest, dict[str, Any]]] = {}

    # ------------------------------------------------------------------ run

    def run(
        self,
        segments: list[dict[str, Any]],
        flows_for: Callable[[dict[str, Any]], Any],
        on_packet: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, SegmentOutcome]:
        self._segments = {s["id"]: s for s in segments}
        self._outcomes = {
            s["id"]: SegmentOutcome(segment_id=s["id"], content="", escalation_level=1)
            for s in segments
        }
        needs_more: dict[str, bool] = {}
        for level in range(1, self.escalation.max_level + 1):
            active = plan_round(level, segments, needs_more)
            if not active:
                break
            needs_more = self._run_round(level, active, flows_for, on_packet)
        return self._outcomes

    def _run_round(
        self,
        level: int,
        active: list[dict[str, Any]],
        flows_for: Callable[[dict[str, Any]], Any],
        on_packet: Callable[[dict[str, Any]], None] | None,
    ) -> dict[str, bool]:
        needs_more: dict[str, bool] = {}
        to_send: list[tuple[AnalysisRequest, str]] = []
        for segment in active:
            request, packet = self.escalation.prepare(segment, level, flows_for(segment), on_packet)
            tier = self.client.resolution.tier_for(request.level)
            self._requests[request.id] = (request, packet)
            cached = self.answers.get(request, tier)
            if cached is not None:
                response = AnalysisResponse(
                    request.id, cached, request.estimated_tokens(), 0, tier, cached=True
                )
                needs_more[segment["id"]] = self._absorb(segment, request, response, packet)
                continue
            to_send.append((request, tier))

        if to_send:
            check_budgets([r for r, _ in to_send], self.stage)
            answered = self._execute(level, to_send)
            for request_id, response in answered.items():
                request, packet = self._requests[request_id]
                segment = self._segments[request.payload["segment_id"]]
                needs_more[segment["id"]] = self._absorb(segment, request, response, packet)
        return needs_more

    def _absorb(self, segment, request, response, packet) -> bool:
        outcome = self._outcomes[segment["id"]]
        more = self.escalation.absorb(segment, outcome, request, response, packet)
        index = list(self._segments).index(segment["id"]) + 1
        self.reporter.segment_done(
            self.stage, segment["id"], index, len(self._segments),
            escalation_level=request.escalation_level,
            estimated_tokens=packet.get("estimated_tokens", 0),
        )
        return more

    # -------------------------------------------------------------- execute

    def _execute(
        self, level: int, to_send: list[tuple[AnalysisRequest, str]]
    ) -> dict[str, AnalysisResponse]:
        """Answer every request in ``to_send`` — by batch where possible, else live."""
        answered: dict[str, AnalysisResponse] = {}
        if not self.batch_available:
            for request, _tier in to_send:
                answered[request.id] = self.client.run(request)
            return answered

        by_id = {r.id: (r, tier) for r, tier in to_send}
        keys = {r.id: answer_key(r, tier) for r, tier in to_send}
        pending: list[_Pending] = []
        remaining = dict(by_id)

        # Resume batches recorded by an earlier run whose items are unchanged (FR-006).
        # Every open record of this level is visited, whatever model it was submitted
        # for, so a model change abandons the old batch instead of leaking it.
        for key in sorted(self.ledger.load()):
            if not key.startswith(f"{level}:"):
                continue
            for record in self.ledger.open_records(key):
                if resume_check(record, keys) == "abandon":
                    self.ledger.update(key, record.handle, status="abandoned",
                                       reason="request changed")
                    continue
                covered = [rid for rid in record.items if rid in remaining]
                if not covered:
                    self.ledger.update(key, record.handle, status="abandoned",
                                       reason="no longer requested")
                    continue
                pending.append(_Pending(record, key, 0, 0))
                for rid in covered:
                    remaining.pop(rid)

        chunks = group_and_split(
            [(r, tier) for r, tier in remaining.values()],
            self.adapter.batch_limits(),
            size_of=lambda r: self.adapter.item_bytes(self._spec(r, by_id[r.id][1])),
        )
        self._wait_for_window()
        # The round's batch count is known before the first submission, so each batch is
        # announced as it is submitted rather than after the whole round is away.
        total = len(pending) + len(chunks)
        for offset, (model, items) in enumerate(chunks):
            key = round_key(level, model)
            index = len(pending) + 1
            try:
                record = self._submit(level, model, items, keys)
            except BatchUnsupported as exc:
                # Batches already outstanding at the provider still resolve normally;
                # everything not yet submitted runs live for the rest of the scan.
                self._disable_batch(exc)
                for request, _tier in remaining.values():
                    if request.id not in answered:
                        answered[request.id] = self.client.run(request)
                return self._finish(pending, answered, by_id, total=total - len(chunks) + offset)
            self.ledger.record(key, record)
            pending.append(_Pending(record, key, index, total))
            self.reporter.batch_submitted(
                self.stage, index, total, items=len(record.items),
                model=record.model, handle=record.handle,
            )

        return self._finish(pending, answered, by_id, total=total)

    def _finish(
        self,
        pending: list[_Pending],
        answered: dict[str, AnalysisResponse],
        by_id: dict[str, tuple[AnalysisRequest, str]],
        *,
        total: int,
    ) -> dict[str, AnalysisResponse]:
        # Resumed records were not announced (they were submitted by an earlier run);
        # they still need their position for the status and completion lines.
        for index, pend in enumerate(pending, start=1):
            pend.index, pend.total = index, max(total, len(pending))
        self._wait(pending)
        for pend in pending:
            for outcome in self._collect(pend):
                request, tier = by_id.get(outcome.request_id, (None, None))
                if request is None:
                    continue  # answered earlier or no longer requested this run
                if outcome.outcome == "answered":
                    self.answers.put(request, tier, outcome.content or "")
                    answered[request.id] = AnalysisResponse(
                        request.id, outcome.content or "", request.estimated_tokens(),
                        estimate_tokens(outcome.content or ""), tier, batch=True,
                    )
                else:
                    answered[request.id] = self._fallback(request, outcome.reason or "failed")
        return answered

    # --------------------------------------------------------------- submit

    def _spec(self, request: AnalysisRequest, model: str) -> BatchItemSpec:
        return BatchItemSpec(
            custom_id=custom_id_for(request.id),
            model=model,
            prompt=request.prompt,
            payload=request.payload,
            max_output_tokens=request.budget.max_output_tokens,
        )

    def _submit(
        self, level: int, model: str, items: list[AnalysisRequest], keys: dict[str, str]
    ) -> BatchRecord:
        specs = [self._spec(r, model) for r in items]
        handle = self.adapter.submit_batch(self.transport, specs, model=model)
        now = self.clock()
        custom_map = {s.custom_id: r.id for s, r in zip(specs, items, strict=True)
                      if s.custom_id != r.id}
        return BatchRecord(
            handle=handle,
            provider=self.adapter.name,
            base_url=self.client.resolution.base_url,
            model=model,
            level=level,
            items={r.id: keys[r.id] for r in items},
            submitted_at=now,
            expires_at=now + self.window_hours * 3600.0,
            custom_id_map=custom_map or None,
        )

    def _disable_batch(self, exc: BatchUnsupported) -> None:
        self.batch_available = False
        reason = f"provider does not support batch submission (HTTP {exc.status})"
        self.usage.record_fallback(self.stage, reason)
        note = UNSUPPORTED_NOTE.format(status=exc.status)
        self.warnings.append(note)
        self.reporter.warning(note, stage=self.stage)

    # ----------------------------------------------------------------- wait

    def _wait_for_window(self) -> None:
        if not self.offpeak_window:
            return
        while True:
            now = datetime.fromtimestamp(self.clock())
            if in_window(self.offpeak_window, now):
                return
            start, _ = parse_window(self.offpeak_window)
            start_at = now.replace(hour=start.hour, minute=start.minute, second=0, microsecond=0)
            seconds = (start_at - now).total_seconds()
            if seconds <= 0:
                seconds += 86400
            self.reporter.batch_status(
                self.stage, 0, 0, completed=0, item_total=0, waited_s=0, next_poll_s=0,
                waiting_for_window=self.offpeak_window, starts_in_s=seconds,
            )
            self.sleep(min(OFFPEAK_WAIT_CAP_S, seconds))

    def _wait(self, pending: list[_Pending]) -> None:
        schedule = poll_schedule()
        while any(not p.record.terminal for p in pending):
            interval = next(schedule)
            for pend in pending:
                if pend.record.terminal:
                    continue
                self._poll(pend, interval)
            if any(not p.record.terminal for p in pending):
                self.sleep(interval)
                for pend in pending:
                    if not pend.record.terminal:
                        pend.waited_s += interval

    def _poll(self, pend: _Pending, next_poll_s: float) -> None:
        record = pend.record
        if self.clock() >= record.expires_at:
            record.status = "expired"
            self.ledger.update(pend.key, record.handle, status="expired", reason="window expired")
            return
        status = self.adapter.batch_status(self.transport, record.handle)
        record.polls += 1
        pend.status = status
        if status.state == "in_progress":
            self.ledger.update(pend.key, record.handle, status="in_progress", polls=record.polls)
            record.status = "in_progress"
            self.reporter.batch_status(
                self.stage, pend.index, pend.total, completed=status.completed,
                item_total=status.total or len(record.items), waited_s=pend.waited_s,
                next_poll_s=next_poll_s,
            )
            return
        record.status = status.state
        self.ledger.update(pend.key, record.handle, status=status.state, polls=record.polls,
                           reason=status.reason)

    def _collect(self, pend: _Pending) -> list[ItemOutcome]:
        record = pend.record
        results: list[ItemResult] = []
        if record.status == "ended":
            try:
                results = self.adapter.batch_results(self.transport, record.handle)
            except EndpointError as exc:
                if exc.status != 404:
                    raise
                record.status = "not_found"
                pend.status = BatchStatus("not_found", 0, 0, reason=str(exc))
                self.ledger.update(pend.key, record.handle, status="not_found")
        outcomes = classify_items(record, pend.status, results)
        answered = [o for o in outcomes if o.outcome == "answered"]
        failed = [o for o in outcomes if o.outcome == "failed"]
        expired = [o for o in failed if o.reason == "expired"]
        self.reporter.batch_done(
            self.stage, pend.index, pend.total, succeeded=len(answered),
            failed=len(failed) - len(expired), expired=len(expired), fallbacks=len(failed),
        )
        return outcomes

    # ------------------------------------------------------------- fallback

    def _fallback(self, request: AnalysisRequest, reason: str) -> AnalysisResponse:
        self.fallbacks.append((request.id, reason))
        note = f"{request.id}: batch item fell back to interactive: {reason}"
        self.warnings.append(note)
        self.reporter.warning(note, stage=self.stage, subject=request.id)
        response = self.client.run(request)
        response.fell_back = True
        response.fallback_reason = reason
        return response
