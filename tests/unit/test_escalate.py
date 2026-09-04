"""Feature 012 T018: the escalation ladder split into ``prepare`` and ``absorb``.

A fake context builder stands in for :class:`pipeline.build_context.ContextBuilder`
so the ladder's decisions can be asserted without a repository.
"""

from __future__ import annotations

import json
from typing import Any

from pipeline.budget import TokenBudget
from pipeline.escalate import EscalationRunner, SegmentOutcome
from pipeline.llm_client import AnalysisRequest, AnalysisResponse
from pipeline.usage import UsageTracker

SEGMENT = {"id": "seg-a", "repos": ["shop"], "files": ["a.py", "b.py"], "domains": []}


class FakeBuilder:
    def __init__(self, full_at_level: int = 3) -> None:
        self.budget = TokenBudget(12000, 3000, 0.75)
        self.warnings: list[str] = []
        self.roots: dict[str, Any] = {}
        self.written: list[dict] = []
        self.full_at_level = full_at_level

    def build(self, segment, level, flows):
        source = {"a.py": "x"} if level < self.full_at_level else {"a.py": "x", "b.py": "y"}
        return {
            "segment_id": segment["id"], "purpose": "p", "domains": [], "entrypoints": [],
            "call_graph_summary": {}, "data_flows": [], "security_relevant_symbols": [],
            "source": source, "level": level,
        }

    def write(self, packet):
        self.written.append(packet)


class ScriptedClient:
    mode = None

    def __init__(self, answers: dict[str, str]) -> None:
        self.answers = answers
        self.calls: list[str] = []

    def supports_batch(self) -> bool:
        return False

    def run(self, request: AnalysisRequest) -> AnalysisResponse:
        self.calls.append(request.id)
        content = self.answers.get(request.id, json.dumps({"findings": []}))
        return AnalysisResponse(request.id, content, 10, 5, "tier")


def _runner(client, builder=None, max_level=4) -> EscalationRunner:
    return EscalationRunner(
        client=client, builder=builder or FakeBuilder(), usage=UsageTracker(),
        prompt="analyse", max_level=max_level,
    )


def test_prepare_builds_fits_writes_and_notifies() -> None:
    builder = FakeBuilder()
    seen: list[dict] = []
    runner = _runner(ScriptedClient({}), builder)
    request, packet = runner.prepare(SEGMENT, 2, None, on_packet=seen.append)
    assert request.id == "seg-a-l2" and request.escalation_level == 2
    assert request.level == "segment"
    assert builder.written == [packet] and seen == [packet]
    assert packet["estimated_tokens"] == request.estimated_tokens()


def test_absorb_records_usage_and_decides_continuation() -> None:
    runner = _runner(ScriptedClient({}))
    outcome = SegmentOutcome(segment_id="seg-a", content="", escalation_level=1)
    request, packet = runner.prepare(SEGMENT, 1, None)
    confident = AnalysisResponse("seg-a-l1", json.dumps({"findings": []}), 10, 5, "tier",
                                 batch=True)
    assert runner.absorb(SEGMENT, outcome, request, confident, packet) is False
    assert outcome.content == confident.content and outcome.escalation_level == 1
    assert runner.usage.invocations == 1 and runner.usage.batch_invocations == 1

    request, packet = runner.prepare(SEGMENT, 2, None)
    wants_more = AnalysisResponse("seg-a-l2", json.dumps({"needs_escalation": True}), 10, 5,
                                  "tier", fell_back=True, fallback_reason="expired")
    assert runner.absorb(SEGMENT, outcome, request, wants_more, packet) is True
    assert outcome.escalated is True and outcome.escalation_level == 2
    assert runner.usage.fallbacks == 1 and runner.usage.fallback_log[0]["item"] == "seg-a-l2"

    # Level >= 3 with the whole segment already in the packet: nothing more to add.
    request, packet = runner.prepare(SEGMENT, 3, None)
    assert runner.absorb(SEGMENT, outcome, request, wants_more, packet) is False


def test_absorb_records_nothing_for_cached_answers() -> None:
    """Principle IV: a resumed run reports only what it actually sent."""
    runner = _runner(ScriptedClient({}))
    outcome = SegmentOutcome(segment_id="seg-a", content="", escalation_level=1)
    request, packet = runner.prepare(SEGMENT, 1, None)
    cached = AnalysisResponse("seg-a-l1", json.dumps({"findings": []}), 10, 5, "tier",
                              cached=True)
    assert runner.absorb(SEGMENT, outcome, request, cached, packet) is False
    assert runner.usage.invocations == 0 and runner.usage.total_input_tokens == 0
    assert outcome.content == cached.content


def test_run_still_walks_the_ladder_like_before() -> None:
    client = ScriptedClient({
        "seg-a-l1": json.dumps({"needs_escalation": True}),
        "seg-a-l2": json.dumps({"findings": [{"cwe": "CWE-89"}]}),
    })
    outcome = _runner(client).run(SEGMENT, None)
    assert client.calls == ["seg-a-l1", "seg-a-l2"]
    assert outcome.escalation_level == 2 and outcome.escalated is True
    assert "CWE-89" in outcome.content and len(outcome.packets) == 2
    assert outcome.pending is False
