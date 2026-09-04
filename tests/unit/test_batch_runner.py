"""Feature 012 T017/T030: pure parts of the batch round runner (data-model.md)."""

from __future__ import annotations

import itertools
from pathlib import Path

import pytest

from pipeline.batch_runner import (
    BatchLedger,
    BatchRecord,
    check_budgets,
    classify_items,
    group_and_split,
    plan_round,
    poll_schedule,
    resume_check,
    round_key,
)
from pipeline.budget import BudgetExceeded, TokenBudget
from pipeline.llm_client import AnalysisRequest
from pipeline.providers import BatchLimits, BatchStatus, ItemResult
from pipeline.state import BATCH_LEDGER_META, ArtifactStore

BUDGET = TokenBudget(12000, 3000, 0.75)


def _req(request_id: str, size: int = 10, level: int = 1) -> AnalysisRequest:
    return AnalysisRequest(
        id=request_id, stage="segment_analysis", prompt="p",
        payload={"segment_id": request_id.rsplit("-l", 1)[0], "source": {"a.py": "x" * size}},
        budget=BUDGET, level="local" if level == 1 else "segment", escalation_level=level,
    )


# --------------------------------------------------------------- splitting


def test_group_and_split_groups_by_model_preserves_order_and_is_deterministic() -> None:
    requests = [(_req("seg-c-l1"), "m1"), (_req("seg-a-l1"), "m1"), (_req("seg-b-l1"), "m2")]
    limits = BatchLimits(max_items=10, max_bytes=10_000)
    chunks = group_and_split(requests, limits, size_of=lambda r: 10)
    assert [(model, [r.id for r in items]) for model, items in chunks] == [
        ("m1", ["seg-c-l1", "seg-a-l1"]),
        ("m2", ["seg-b-l1"]),
    ]
    again = group_and_split(list(requests), limits, size_of=lambda r: 10)
    assert [(m, [r.id for r in items]) for m, items in again] == [
        (m, [r.id for r in items]) for m, items in chunks
    ]


def test_group_and_split_honours_item_and_byte_limits() -> None:
    requests = [(_req(f"seg-{i:02d}-l1"), "m") for i in range(5)]
    by_items = group_and_split(requests, BatchLimits(max_items=2, max_bytes=10**9),
                               size_of=lambda r: 1)
    assert [len(items) for _, items in by_items] == [2, 2, 1]
    by_bytes = group_and_split(requests, BatchLimits(max_items=100, max_bytes=25),
                               size_of=lambda r: 10)
    assert [len(items) for _, items in by_bytes] == [2, 2, 1]
    oversized = group_and_split(requests[:1], BatchLimits(max_items=100, max_bytes=5),
                                size_of=lambda r: 10)
    assert [len(items) for _, items in oversized] == [1]  # never drops an item


# ---------------------------------------------------------------- polling


def test_poll_schedule_backs_off_from_30s_to_5min() -> None:
    waits = list(itertools.islice(poll_schedule(), 8))
    assert waits[:3] == [30.0, 45.0, 67.5]
    assert waits[-1] == 300.0 and all(w <= 300.0 for w in waits)
    assert waits == sorted(waits)


# ----------------------------------------------------------------- rounds


def test_plan_round_selects_all_at_level_one_then_only_escalating_segments() -> None:
    segments = [{"id": "seg-a"}, {"id": "seg-b"}, {"id": "seg-c"}]
    assert [s["id"] for s in plan_round(1, segments, {})] == ["seg-a", "seg-b", "seg-c"]
    more = {"seg-a": False, "seg-b": True, "seg-c": True}
    assert [s["id"] for s in plan_round(2, segments, more)] == ["seg-b", "seg-c"]
    assert plan_round(3, segments, {"seg-b": False, "seg-c": False}) == []


def test_check_budgets_raises_before_any_submission() -> None:
    tight = TokenBudget(5, 100, 0.75)
    request = _req("seg-a-l1")
    request.budget = tight
    with pytest.raises(BudgetExceeded):
        check_budgets([request], "segment_analysis")
    check_budgets([_req("seg-b-l1")], "segment_analysis")  # within budget: no error


# ----------------------------------------------------------------- ledger


def _record(handle: str = "batch_1", status: str = "submitted", **items: str) -> BatchRecord:
    return BatchRecord(
        handle=handle, provider="anthropic", base_url=None, model="m", level=1,
        items=dict(items or {"seg-a-l1": "k1", "seg-b-l1": "k2"}),
        submitted_at=1000.0, expires_at=1000.0 + 86400, status=status,
    )


def test_ledger_round_trips_through_state_meta(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    ledger = BatchLedger(store)
    key = round_key(1, "m")
    assert key == "1:m"
    ledger.record(key, _record(**{"seg-b-l1": "k2", "seg-a-l1": "k1"}))
    raw = store.get_meta(BATCH_LEDGER_META)
    assert list(raw) == ["1:m"] and list(raw["1:m"][0]["items"]) == ["seg-a-l1", "seg-b-l1"]
    reloaded = BatchLedger(ArtifactStore(tmp_path)).load()
    record = reloaded["1:m"][0]
    assert record.handle == "batch_1" and record.status == "submitted"
    assert record.expires_at == 1000.0 + 86400
    ledger.update(key, "batch_1", status="ended", polls=3)
    assert BatchLedger(ArtifactStore(tmp_path)).load()["1:m"][0].status == "ended"


def test_open_records_ignore_terminal_states(tmp_path: Path) -> None:
    ledger = BatchLedger(ArtifactStore(tmp_path))
    key = round_key(1, "m")
    for handle, status in [("b1", "submitted"), ("b2", "in_progress"), ("b3", "ended"),
                           ("b4", "expired"), ("b5", "failed"), ("b6", "abandoned"),
                           ("b7", "not_found")]:
        ledger.record(key, _record(handle, status))
    assert [r.handle for r in ledger.open_records(key)] == ["b1", "b2"]
    assert ledger.open_records("2:m") == []


def test_invalidate_segment_analysis_clears_ledger_and_answers(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    BatchLedger(store).record("1:m", _record())
    answers = store.dir / "analysis" / "answers"
    answers.mkdir(parents=True)
    (answers / "seg-a-l1.json").write_text("{}")
    store.invalidate("segment_analysis")
    assert store.get_meta(BATCH_LEDGER_META) is None
    assert list(answers.iterdir()) == []


# ------------------------------------------------------------ item outcomes


def test_classify_items_covers_every_outcome() -> None:
    record = _record(**{"seg-a-l1": "k", "seg-b-l1": "k", "seg-c-l1": "k", "seg-d-l1": "k",
                        "seg-e-l1": "k"})
    results = [
        ItemResult("seg-e-l1", "expired", reason="expired"),
        ItemResult("seg-c-l1", "canceled", reason="canceled"),
        ItemResult("seg-b-l1", "errored", reason="errored: invalid_request_error"),
        ItemResult("seg-a-l1", "succeeded", content="{}"),
    ]
    ended = BatchStatus(state="ended", completed=5, total=5)
    outcomes = {o.request_id: o for o in classify_items(record, ended, results)}
    assert outcomes["seg-a-l1"].outcome == "answered" and outcomes["seg-a-l1"].content == "{}"
    assert outcomes["seg-b-l1"].reason == "errored: invalid_request_error"
    assert outcomes["seg-c-l1"].reason == "canceled"
    assert outcomes["seg-d-l1"].reason == "missing from results"
    assert outcomes["seg-e-l1"].reason == "expired"
    assert all(o.outcome == "failed" for rid, o in outcomes.items() if rid != "seg-a-l1")

    failed = BatchStatus(state="failed", completed=0, total=2, reason="enqueued token limit")
    reasons = {o.reason for o in classify_items(_record(), failed, [])}
    assert reasons == {"batch failed: enqueued token limit"}
    missing = BatchStatus(state="not_found", completed=0, total=0)
    assert {o.reason for o in classify_items(_record(), missing, [])} == {
        "batch reference not found"
    }
    expired = _record(status="expired")
    assert {o.reason for o in classify_items(expired, None, [])} == {"expired"}


def test_classify_items_translates_custom_ids() -> None:
    record = _record(**{"seg a-l1": "k"})
    record.custom_id_map = {"abc123": "seg a-l1"}
    ended = BatchStatus(state="ended", completed=1, total=1)
    (outcome,) = classify_items(record, ended, [ItemResult("abc123", "succeeded", content="x")])
    assert outcome.request_id == "seg a-l1" and outcome.outcome == "answered"


def test_offpeak_wait_sleeps_until_the_window_opens() -> None:
    """Feature 012 T042 (research R8): submission waits for the off-peak window."""
    from datetime import datetime

    from pipeline.batch_runner import BatchRoundRunner

    class Clock:
        def __init__(self) -> None:
            self.now = datetime(2026, 9, 3, 1, 50).timestamp()  # window opens at 02:00
            self.sleeps: list[float] = []

        def clock(self) -> float:
            return self.now

        def sleep(self, seconds: float) -> None:
            self.sleeps.append(seconds)
            self.now += seconds

    class Reporter:
        def __init__(self) -> None:
            self.events: list[dict] = []

        def batch_status(self, stage, index, total, **detail):
            self.events.append(detail)

    class FakeClient:
        adapter = None
        transport = None

    clock, reporter = Clock(), Reporter()
    runner = BatchRoundRunner.__new__(BatchRoundRunner)
    runner.offpeak_window = "02:00-06:00"
    runner.clock, runner.sleep, runner.reporter, runner.stage = (
        clock.clock, clock.sleep, reporter, "segment_analysis",
    )
    runner._wait_for_window()
    assert clock.sleeps == [300.0, 300.0]  # 10 minutes, capped at 5-minute steps
    assert reporter.events[0]["waiting_for_window"] == "02:00-06:00"
    assert reporter.events[0]["starts_in_s"] == 600.0
    clock.sleeps.clear()
    runner._wait_for_window()  # already inside the window: returns at once
    assert clock.sleeps == []


def test_resume_check_abandons_on_any_key_change() -> None:
    record = _record(**{"seg-a-l1": "k1", "seg-b-l1": "k2"})
    assert resume_check(record, {"seg-a-l1": "k1", "seg-b-l1": "k2"}) == "resume"
    assert resume_check(record, {"seg-a-l1": "k1", "seg-b-l1": "changed"}) == "abandon"
    # An item no longer requested is harmless; only a changed key invalidates the batch.
    assert resume_check(record, {"seg-a-l1": "k1"}) == "resume"
