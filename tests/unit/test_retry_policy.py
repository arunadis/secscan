"""Feature 012 T035: bounded, jittered retries for transient endpoint failures (FR-014)."""

from __future__ import annotations

import random

import pytest

from pipeline.llm_client import RetryPolicy
from pipeline.providers import EndpointError


def _policy(**kwargs) -> tuple[RetryPolicy, list[float]]:
    sleeps: list[float] = []
    defaults = dict(attempts=5, base_wait_s=2.0, max_wait_s=60.0, total_wait_s=180.0,
                    rng=random.Random(0), sleep=sleeps.append)
    defaults.update(kwargs)
    return RetryPolicy(**defaults), sleeps


def _error(status: int | None = 429, *, transient: bool = True, retry_after: float | None = None):
    return EndpointError(provider="anthropic", path="/v1/messages", status=status,
                         transient=transient, retry_after_s=retry_after)


def _flaky(sequence: list):
    """A callable that raises the errors in ``sequence`` then returns ``"ok"``."""
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        step = sequence[calls["n"] - 1] if calls["n"] <= len(sequence) else "ok"
        if isinstance(step, EndpointError):
            raise step
        return step

    return fn, calls


def test_wait_grows_with_jitter_and_respects_cap() -> None:
    policy, _ = _policy()
    waits = [policy.wait_for(n, None) for n in range(1, 5)]
    for n, wait in enumerate(waits, start=1):
        base = min(60.0, 2.0 * 2 ** (n - 1))
        assert 0.5 * base <= wait <= base
    assert policy.wait_for(20, None) <= 60.0


def test_retry_after_is_a_minimum_even_beyond_the_cap() -> None:
    policy, _ = _policy()
    assert policy.wait_for(1, 7.0) >= 7.0
    assert policy.wait_for(1, 90.0) >= 90.0


def test_transient_failures_are_retried_until_success_and_reported() -> None:
    policy, sleeps = _policy()
    fn, calls = _flaky([_error(retry_after=7), _error(), "ok"])
    seen: list[tuple] = []
    assert policy.execute(fn, request_id="seg-a-l1", on_retry=lambda *a: seen.append(a)) == "ok"
    assert calls["n"] == 3 and len(sleeps) == 2
    assert sleeps[0] >= 7.0
    assert [(rid, attempt, status) for rid, attempt, _wait, status in seen] == [
        ("seg-a-l1", 2, 429), ("seg-a-l1", 3, 429)
    ]
    assert all(wait > 0 for _, _, wait, _ in seen)


def test_exhausted_attempts_raise_with_count() -> None:
    policy, sleeps = _policy()
    fn, calls = _flaky([_error()] * 10)
    with pytest.raises(EndpointError) as info:
        policy.execute(fn, request_id="seg-a-l1")
    assert calls["n"] == 5 and len(sleeps) == 4
    assert info.value.attempts == 5 and info.value.request_id == "seg-a-l1"
    assert info.value.transient is True
    # Doubling with U(0.5, 1) jitter is non-decreasing: min(next) == max(current).
    assert sorted(sleeps) == sleeps


def test_total_wait_bound_stops_early() -> None:
    policy, sleeps = _policy()
    fn, calls = _flaky([_error(retry_after=100), _error(retry_after=100), _error(retry_after=100)])
    with pytest.raises(EndpointError) as info:
        policy.execute(fn)
    assert sleeps == [100.0]  # a second 100 s wait would exceed the 180 s bound
    assert calls["n"] == 2 and info.value.attempts == 2


def test_terminal_failures_and_single_attempt_policies_do_not_retry() -> None:
    policy, sleeps = _policy()
    fn, calls = _flaky([_error(401, transient=False)])
    with pytest.raises(EndpointError) as info:
        policy.execute(fn)
    assert calls["n"] == 1 and sleeps == [] and info.value.attempts == 1

    once, sleeps = _policy(attempts=1)
    fn, calls = _flaky([_error(), "ok"])
    with pytest.raises(EndpointError):
        once.execute(fn)
    assert calls["n"] == 1 and sleeps == []


def test_connection_errors_count_as_transient() -> None:
    policy, sleeps = _policy()
    fn, calls = _flaky([_error(None), _error(None), "ok"])
    assert policy.execute(fn) == "ok"
    assert calls["n"] == 3 and len(sleeps) == 2
