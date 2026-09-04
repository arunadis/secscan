"""Provider batch execution end to end (feature 012, contracts/batch-execution.md).

Every scenario runs against :class:`tests.helpers.fake_provider.FakeProvider` — no
socket is opened — with injected clock/sleep so waits take no wall time.
"""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pytest

from pipeline import progress
from pipeline import run as run_mod
from pipeline.batch_runner import BatchLedger
from pipeline.progress import OutputLevel
from pipeline.state import ANSWERS_DIR, BATCH_LEDGER_META, ArtifactStore
from tests.fixtures.single_repo_shop import build as build_shop
from tests.helpers.fake_provider import FakeProvider, Scenario
from tests.integration.conftest import oracle_responder, write_config

FAKE_KEY = "FAKE_ENDPOINT_KEY"
_TAGS = "start|done |reuse|skip |fail |warn |wait |pause|stop |info "
_LINE = re.compile(rf"^\d{{2}}:\d{{2}}:\d{{2}} \+\d{{2}}:\d{{2}} ({_TAGS}) (.+)$")


class FakeTime:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _batch_config(root: Path, family: str = "anthropic", mode: str | None = None,
                  local_model: str = "m-local", triage_on: bool = False, **extra):
    policy: dict = {}
    if mode is not None:
        policy["mode"] = mode
    overrides = {
        "llm": {
            "endpoint": {
                "provider": family,
                "api_key_env": FAKE_KEY,
                "model_map": {"local": local_model, "segment": "m-segment"},
            }
        },
        # These tests pin feature 012's batch machinery; the triage round
        # (feature 013) is covered by its own suites.
        "triage": {"enabled": "on" if triage_on else "off"},
    }
    if policy:
        overrides["execution_policy"] = policy
    overrides.update(extra)
    write_config(root, overrides)


@pytest.fixture
def endpoint_shop(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv(FAKE_KEY, "sk-fake")
    root = build_shop(tmp_path / "shop")
    _batch_config(root)
    return root


def _run(root: Path, provider, *, time: FakeTime | None = None, level=OutputLevel.DEFAULT,
         **kwargs):
    time = time or FakeTime()
    stream = io.StringIO()
    reporter = progress.build_reporter(level, stream=stream, log_path=None)
    try:
        result = run_mod.run_scan(
            root, transport=provider, progress=reporter, clock=time.clock, sleep=time.sleep,
            **kwargs,
        )
    finally:
        reporter.close()
    return result, stream.getvalue()


def _events(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        m = _LINE.match(line)
        assert m, f"malformed progress line: {line!r}"
        out.append((m.group(1).strip(), m.group(2)))
    return out


def _findings_artifacts(root: Path) -> dict[str, str]:
    """Findings-bearing artifacts, normalised for cross-policy comparison (SC-003)."""
    out: dict[str, str] = {}
    for path in sorted((root / ".secscan").rglob("*.json")):
        rel = str(path.relative_to(root / ".secscan"))
        if rel in ("state.json", "usage.json") or rel.startswith("reports/"):
            continue
        doc = json.loads(path.read_text())
        if isinstance(doc, dict):
            doc.pop("scan_id", None)
        out[rel] = json.dumps(doc, sort_keys=True).replace(str(root), "<root>")
    report = next((root / ".secscan" / "reports").glob("*.json"))
    doc = json.loads(report.read_text())
    payload = doc.get("payload", doc)
    out["report.findings_by_band"] = json.dumps(payload["findings_by_band"], sort_keys=True)
    return out


# =================================================================== US1


@pytest.mark.parametrize("family", ["anthropic", "openai-compatible"])
def test_happy_path_submits_one_batch_per_round(endpoint_shop: Path, family: str) -> None:
    """FR-001/FR-004/FR-012, SC-001: one submission, zero interactive calls."""
    _batch_config(endpoint_shop, family)
    provider = FakeProvider(family, Scenario(polls_until_ended=2))
    result, err = _run(endpoint_shop, provider, full=True)
    assert provider.batch_submissions == 1
    assert provider.interactive_calls == 0
    events = _events(err)
    assert any(tag == "info" and "batch 1/1 submitted:" in text for tag, text in events)
    assert sum(1 for tag, text in events if tag == "wait" and "processing" in text) >= 1
    assert any(tag == "done" and "batch 1/1 ended:" in text and "(0 fallback)" in text
               for tag, text in events)
    segment_done = [t for tag, t in events if tag == "done" and " segment " in t]
    assert len(segment_done) == len(result.segments)
    assert result.reported_findings, "batch answers must produce findings"
    assert (endpoint_shop / ".secscan" / ANSWERS_DIR).is_dir()
    assert len(list((endpoint_shop / ".secscan" / ANSWERS_DIR).glob("*.json"))) == len(
        result.segments
    )
    ledger = ArtifactStore(endpoint_shop).get_meta(BATCH_LEDGER_META)
    (record,) = ledger["1:m-local"]
    assert record["status"] == "ended" and record["handle"].startswith("batch_")


def test_escalation_round_is_batched_separately(endpoint_shop: Path) -> None:
    """FR-002: segments asking for more evidence form the next round's single batch."""
    first_segment: dict = {}

    def answer(custom_id: str, payload: dict) -> str:
        first_segment.setdefault("id", payload["segment_id"])
        if custom_id.endswith("-l1") and payload["segment_id"] == first_segment["id"]:
            return json.dumps({"needs_escalation": True, "findings": []})
        from tests.helpers.fake_provider import _Request

        return oracle_responder(_Request(custom_id, payload))

    provider = FakeProvider("anthropic", answer=answer)
    result, err = _run(endpoint_shop, provider, full=True)
    assert provider.batch_submissions == 2
    assert provider.interactive_calls == 0
    ledger = ArtifactStore(endpoint_shop).get_meta(BATCH_LEDGER_META)
    assert set(ledger) == {"1:m-local", "2:m-segment"}
    assert list(ledger["2:m-segment"][0]["items"]) == [f"{first_segment['id']}-l2"]
    assert "batch 1/1 submitted: 1 items, model m-segment" in err
    assert result.usage["batch_share"]["batch_invocations"] == len(result.segments) + 1


def test_batch_findings_identical_to_interactive(tmp_path: Path, monkeypatch) -> None:
    """SC-003 / FR-012: policy changes when requests go out, never what comes back.

    Runs with the triage round enabled so the parity guarantee covers it too:
    the triage requests are built once and sent either way, so persisted triage
    artifacts must be byte-identical across policies.
    """
    monkeypatch.setenv(FAKE_KEY, "sk-fake")
    batch_root = build_shop(tmp_path / "a")
    live_root = build_shop(tmp_path / "b")
    _batch_config(batch_root, mode="auto", triage_on=True)
    _batch_config(live_root, mode="interactive", triage_on=True)
    _run(batch_root, FakeProvider("anthropic"), full=True)
    _run(live_root, FakeProvider("anthropic"), full=True)
    batch_artifacts = _findings_artifacts(batch_root)
    live_artifacts = _findings_artifacts(live_root)
    assert set(batch_artifacts) == set(live_artifacts)
    for name in sorted(batch_artifacts):
        assert batch_artifacts[name] == live_artifacts[name], f"{name} differs across policies"
    assert any(name.startswith("analysis/answers/") for name in batch_artifacts)


def test_usage_summary_reports_batch_share(endpoint_shop: Path) -> None:
    """FR-013: the report states what ran in batch and the labelled estimated saving."""
    result, _ = _run(endpoint_shop, FakeProvider("anthropic"), full=True)
    share = result.usage["batch_share"]
    assert share["batch_invocations"] == result.usage["invocations"] > 0
    assert share["interactive_invocations"] == 0 and share["fallbacks"] == 0
    assert share["estimated_saving_percent"] == 50.0
    assert share["assumption"] == "provider's published 50% batch discount"
    markdown = result.report_path.read_text()
    assert "Estimated saving vs interactive pricing | 50.0%" in markdown
    assert "endpoint-batch (default policy)" in markdown


def test_resumed_run_does_not_count_cached_answers(endpoint_shop: Path) -> None:
    """Principle IV: the usage summary describes only what this run sent."""
    _run(endpoint_shop, FakeProvider("anthropic"), full=True)
    # Segment analysis always re-runs; every answer is already persisted, so nothing
    # is sent and nothing may be counted.
    provider = FakeProvider("anthropic")
    result, err = _run(endpoint_shop, provider)
    assert provider.batch_submissions == 0 and provider.interactive_calls == 0
    assert result.usage["invocations"] == 0
    assert "submitted:" not in err
    assert result.reported_findings


def test_scan_header_states_default_policy(endpoint_shop: Path) -> None:
    _, err = _run(endpoint_shop, FakeProvider("anthropic"), full=True)
    events = _events(err)
    assert events[0][0] == "start" and "endpoint-batch (default policy)" in events[0][1]
    _batch_config(endpoint_shop, mode="batch")
    _, err = _run(endpoint_shop, FakeProvider("anthropic"), full=True)
    assert "(default policy)" not in _events(err)[0][1]


# =================================================================== US2


def _segment_ids(root: Path) -> list[str]:
    result, _ = _run(root, FakeProvider("anthropic"), full=True)
    return [s["id"] for s in result.segments]


class InterruptingTime(FakeTime):
    """Raises ``KeyboardInterrupt`` on the n-th sleep, like an operator pressing Ctrl-C."""

    def __init__(self, on_sleep: int) -> None:
        super().__init__()
        self.on_sleep = on_sleep

    def sleep(self, seconds: float) -> None:
        if len(self.sleeps) + 1 == self.on_sleep:
            raise KeyboardInterrupt
        super().sleep(seconds)


def test_partial_failure_falls_back_only_failed_items(endpoint_shop: Path) -> None:
    """FR-007, SC-005: exactly the failed items fall back, each with its reason."""
    ids = _segment_ids(endpoint_shop)
    assert len(ids) >= 2
    items = {f"{ids[0]}-l1": "error", f"{ids[1]}-l1": "omit"}
    provider = FakeProvider("anthropic", Scenario(items=items))
    result, err = _run(endpoint_shop, provider, full=True)
    log = {entry["item"]: entry["reason"] for entry in result.usage["fallback_log"]}
    assert log == {
        f"{ids[0]}-l1": "errored: invalid_request_error: bad",
        f"{ids[1]}-l1": "missing from results",
    }
    assert provider.interactive_calls == 2
    assert result.usage["batch_share"]["fallbacks"] == 2
    assert result.usage["batch_share"]["interactive_invocations"] == 2
    answers = {p.stem for p in (endpoint_shop / ".secscan" / ANSWERS_DIR).glob("*.json")}
    assert answers == {f"{sid}-l1" for sid in ids}
    warnings = [t for tag, t in _events(err) if tag == "warn"]
    assert any(f"{ids[0]}-l1: batch item fell back to interactive: errored" in w
               for w in warnings)
    assert any(f"{ids[1]}-l1: batch item fell back to interactive: missing from results" in w
               for w in warnings)
    assert "(2 fallback)" in err
    assert any("fell back to interactive" in note for note in result.warnings)


def test_expiry_falls_back_all_outstanding(endpoint_shop: Path) -> None:
    """FR-009: local expiry from submission; the scan never waits indefinitely."""
    _batch_config(endpoint_shop, execution_policy={"batch": {"window_hours": 0.001}})
    provider = FakeProvider("anthropic", Scenario(polls_until_ended=50))
    time = FakeTime()
    result, err = _run(endpoint_shop, provider, time=time, full=True)
    assert provider.polls == 1  # one status check, then the local window expired
    assert {e["reason"] for e in result.usage["fallback_log"]} == {"expired"}
    assert len(result.usage["fallback_log"]) == len(result.segments)
    assert provider.interactive_calls == len(result.segments)
    ledger = ArtifactStore(endpoint_shop).get_meta(BATCH_LEDGER_META)
    assert ledger["1:m-local"][0]["status"] == "expired"
    assert result.reported_findings


def test_interrupt_during_wait_then_resume_polls_same_batch(endpoint_shop: Path) -> None:
    """FR-003/FR-006/FR-022, SC-004: Ctrl-C keeps the batch; re-run resumes it."""
    provider = FakeProvider("anthropic", Scenario(polls_until_ended=3))
    with pytest.raises(KeyboardInterrupt):
        _run(endpoint_shop, provider, time=InterruptingTime(on_sleep=2), full=True)
    assert provider.batch_submissions == 1
    ledger = ArtifactStore(endpoint_shop).get_meta(BATCH_LEDGER_META)
    (record,) = ledger["1:m-local"]
    assert record["status"] == "in_progress" and record["polls"] >= 1
    assert BatchLedger(ArtifactStore(endpoint_shop)).open_count() == 1

    result, err = _run(endpoint_shop, provider)
    assert provider.batch_submissions == 1  # no resubmission
    assert provider.interactive_calls == 0
    assert "submitted:" not in err  # resumed, not submitted
    assert result.reported_findings
    ledger = ArtifactStore(endpoint_shop).get_meta(BATCH_LEDGER_META)
    assert ledger["1:m-local"][0]["status"] == "ended"

    reference = build_shop(endpoint_shop.parent / "reference")
    _batch_config(reference)
    _run(reference, FakeProvider("anthropic"), full=True)
    ours = {p.name: p.read_text() for p in (endpoint_shop / ".secscan" / ANSWERS_DIR).iterdir()}
    theirs = {p.name: p.read_text() for p in (reference / ".secscan" / ANSWERS_DIR).iterdir()}
    assert ours == theirs


def test_stale_handle_falls_back(endpoint_shop: Path) -> None:
    provider = FakeProvider("anthropic", Scenario(polls_until_ended=3,
                                                  status_after_resume="not_found"))
    with pytest.raises(KeyboardInterrupt):
        _run(endpoint_shop, provider, time=InterruptingTime(on_sleep=2), full=True)
    provider.mark_resumed()
    result, _ = _run(endpoint_shop, provider)
    assert provider.batch_submissions == 1
    assert {e["reason"] for e in result.usage["fallback_log"]} == {"batch reference not found"}
    assert provider.interactive_calls == len(result.segments)
    assert ArtifactStore(endpoint_shop).get_meta(BATCH_LEDGER_META)["1:m-local"][0][
        "status"
    ] == "not_found"


@pytest.mark.parametrize("family", ["anthropic", "openai-compatible"])
def test_unsupported_gateway_runs_interactively(endpoint_shop: Path, family: str) -> None:
    """FR-010: one declared fallback for the stage, no further batch attempts."""
    _batch_config(endpoint_shop, family)
    provider = FakeProvider(family, Scenario(submit="unsupported"))
    result, err = _run(endpoint_shop, provider, full=True)
    assert provider.batch_submissions == 0
    submit_paths = {"/v1/messages/batches", "/v1/files", "/v1/batches"}
    assert sum(1 for m, p in provider.calls if m == "POST" and p in submit_paths) == 1
    assert provider.interactive_calls == result.usage["invocations"] > 0
    share = result.usage["batch_share"]
    assert share["batch_invocations"] == 0 and share["fallbacks"] == 1
    status = 501 if family == "anthropic" else 404
    note = (
        "batch execution requested but the endpoint does not support batch submission "
        f"(HTTP {status}); all analysis ran interactively"
    )
    assert note in result.warnings
    assert note in err
    assert result.usage["fallback_log"] == [
        {"item": "segment_analysis",
         "reason": f"provider does not support batch submission (HTTP {status})"}
    ]


def test_changed_prompt_abandons_batch_and_requests_afresh(endpoint_shop: Path) -> None:
    """FR-008: a persisted batch whose items changed is abandoned, never reused."""
    provider = FakeProvider("anthropic", Scenario(polls_until_ended=3))
    with pytest.raises(KeyboardInterrupt):
        _run(endpoint_shop, provider, time=InterruptingTime(on_sleep=2), full=True)
    _batch_config(endpoint_shop, local_model="m-other")
    result, _ = _run(endpoint_shop, provider)
    assert provider.batch_submissions == 2
    assert result.usage["fallback_log"] == []
    ledger = ArtifactStore(endpoint_shop).get_meta(BATCH_LEDGER_META)
    assert ledger["1:m-local"][0]["status"] == "abandoned"
    assert ledger["1:m-local"][0]["reason"] == "request changed"
    assert ledger["1:m-other"][0]["status"] == "ended"


def test_validation_failed_batch_falls_back_with_provider_reason(endpoint_shop: Path) -> None:
    _batch_config(endpoint_shop, "openai-compatible")
    provider = FakeProvider("openai-compatible", Scenario(submit="validation_failed"))
    result, _ = _run(endpoint_shop, provider, full=True)
    assert {e["reason"] for e in result.usage["fallback_log"]} == {
        "batch failed: enqueued token limit"
    }
    assert provider.interactive_calls == len(result.segments)
    assert ArtifactStore(endpoint_shop).get_meta(BATCH_LEDGER_META)["1:m-local"][0][
        "status"
    ] == "failed"


def test_full_rerun_clears_answers_and_ledger(endpoint_shop: Path) -> None:
    _run(endpoint_shop, FakeProvider("anthropic"), full=True)
    store = ArtifactStore(endpoint_shop)
    assert store.get_meta(BATCH_LEDGER_META)
    provider = FakeProvider("anthropic")
    _run(endpoint_shop, provider, full=True)
    assert provider.batch_submissions == 1  # answers were cleared, so a fresh batch went out
    ledger = ArtifactStore(endpoint_shop).get_meta(BATCH_LEDGER_META)
    assert len(ledger["1:m-local"]) == 1  # the old record is gone


def test_cli_interrupt_mentions_outstanding_batches(endpoint_shop: Path, monkeypatch) -> None:
    """FR-022: the interrupt line says the batch is still processing and resumable."""
    import argparse
    import sys

    from pipeline import scan_cli

    provider = FakeProvider("anthropic", Scenario(polls_until_ended=3))
    real_run = run_mod.run_scan

    def run_and_interrupt(root, **kwargs):
        kwargs.update(transport=provider, clock=FakeTime().clock,
                      sleep=InterruptingTime(on_sleep=2).sleep)
        return real_run(root, **kwargs)

    monkeypatch.setattr(run_mod, "run_scan", run_and_interrupt)
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    args = argparse.Namespace(workdir=endpoint_shop, profile=None, overrides=[], full=True,
                              segment=None, policy=None, tool_timeout=None, output=None)
    code = scan_cli.cmd_run(args)
    assert code == scan_cli.EXIT_INTERRUPTED
    assert "re-run to resume; 1 batch(es) still processing at the provider" in err.getvalue()


# =================================================================== US3


def test_rate_limit_then_success_retries_and_counts_once(endpoint_shop: Path) -> None:
    """FR-014/FR-015, SC-006: two refusals, then success — two warnings, one invocation."""
    _batch_config(endpoint_shop, mode="interactive")
    ids = _segment_ids(endpoint_shop)
    provider = FakeProvider("anthropic", Scenario(interactive={ids[0]: [(429, 7), 429]}))
    time = FakeTime()
    result, err = _run(endpoint_shop, provider, time=time, full=True)
    warnings = [t for tag, t in _events(err) if tag == "warn"]
    retries = [w for w in warnings if re.search(
        rf"{re.escape(ids[0])}-l1: rate limited \(HTTP 429\), attempt [23]/5, waiting \d+s", w)]
    assert len(retries) == 2
    assert time.sleeps[0] >= 7.0 and len(time.sleeps) == 2
    assert result.usage["invocations"] == len(result.segments)
    assert result.usage["batch_share"]["interactive_invocations"] == len(result.segments)
    assert not any("rate limited" in note for note in result.warnings)  # progress only


def test_rate_limit_exhausted_stops_cleanly_and_resumes(endpoint_shop: Path) -> None:
    """FR-017/FR-018, SC-007: prior segments are kept; the re-run starts at the failure."""
    from pipeline.providers import EndpointError

    _batch_config(endpoint_shop, mode="interactive")
    ids = _segment_ids(endpoint_shop)
    assert len(ids) >= 2
    target = ids[-1]
    provider = FakeProvider("anthropic", Scenario(interactive={target: [429] * 10}))
    time = FakeTime()
    with pytest.raises(EndpointError) as info:
        _run(endpoint_shop, provider, time=time, full=True)
    assert info.value.attempts == 5 and info.value.request_id == f"{target}-l1"
    assert len(time.sleeps) == 4
    store = ArtifactStore(endpoint_shop)
    record = store.stage("segment_analysis")
    assert record.status == "failed" and "HTTP 429" in (record.error or "")
    answers = {p.stem for p in (store.dir / ANSWERS_DIR).glob("*.json")}
    assert answers == {f"{sid}-l1" for sid in ids[:-1]}
    for sid in ids[:-1]:
        assert store.exists(f"findings/local/{sid}.json")

    healthy = FakeProvider("anthropic")
    result, _ = _run(endpoint_shop, healthy)
    assert healthy.interactive_calls == 1  # only the failed segment is requested again
    assert result.usage["invocations"] == 1
    assert result.reported_findings


def test_terminal_error_not_retried(endpoint_shop: Path) -> None:
    from pipeline.providers import EndpointError

    _batch_config(endpoint_shop, mode="interactive")
    ids = _segment_ids(endpoint_shop)
    provider = FakeProvider("anthropic", Scenario(interactive={sid: [401] for sid in ids}))
    time = FakeTime()
    with pytest.raises(EndpointError) as info:
        _run(endpoint_shop, provider, time=time, full=True)
    assert info.value.attempts == 1 and info.value.status == 401
    assert time.sleeps == []


def test_cli_reports_exhausted_retries_without_traceback(endpoint_shop: Path, monkeypatch,
                                                         capsys) -> None:
    import argparse
    import sys

    from pipeline import scan_cli
    from pipeline.providers import EndpointError

    def boom(root, **kwargs):
        raise EndpointError(provider="anthropic", path="/v1/messages", status=429,
                            error_type="rate_limit_error", transient=True, attempts=5,
                            request_id="seg-shop-p3-l1")

    monkeypatch.setattr(run_mod, "run_scan", boom)
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    args = argparse.Namespace(workdir=endpoint_shop, profile=None, overrides=[], full=True,
                              segment=None, policy=None, tool_timeout=None, output=None)
    code = scan_cli.cmd_run(args)
    text = err.getvalue()
    assert code == scan_cli.EXIT_ERROR
    assert "segment_analysis" in text or "scan failed" in text
    assert "seg-shop-p3-l1" in text and "HTTP 429" in text and "5 attempts" in text
    assert "re-run to resume" in text
    assert "Traceback" not in text
    assert capsys.readouterr().out == ""


def test_interactive_policy_persists_answers_per_segment(endpoint_shop: Path) -> None:
    """FR-018: an interrupted interactive scan keeps the segments already answered."""
    _batch_config(endpoint_shop, mode="interactive")
    ids = _segment_ids(endpoint_shop)
    assert len(ids) >= 3
    provider = FakeProvider("anthropic")
    calls = {"n": 0}
    original = provider.answer

    def interrupt_at_third(custom_id, payload):
        calls["n"] += 1
        if calls["n"] == 3:
            raise KeyboardInterrupt
        return original(custom_id, payload)

    provider.answer = interrupt_at_third
    with pytest.raises(KeyboardInterrupt):
        _run(endpoint_shop, provider, full=True)
    answers = {p.stem for p in (endpoint_shop / ".secscan" / ANSWERS_DIR).glob("*.json")}
    assert answers == {f"{sid}-l1" for sid in ids[:2]}
    resumed = FakeProvider("anthropic")
    _run(endpoint_shop, resumed)
    assert resumed.interactive_calls == len(ids) - 2


def test_single_segment_run_submits_one_item_batch(endpoint_shop: Path) -> None:
    first, _ = _run(endpoint_shop, FakeProvider("anthropic"), full=True)
    target = first.segments[0]["id"]
    provider = FakeProvider("anthropic")
    ArtifactStore(endpoint_shop).invalidate("segment_analysis")
    _, err = _run(endpoint_shop, provider, only_segment=target)
    assert provider.batch_submissions == 1
    assert "batch 1/1 submitted: 1 items" in err
