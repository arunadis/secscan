"""Agent-mediated handoff across sessions (FR-027).

Without a responder the scanner does not call anything itself: it writes requests
to disk, stops, and resumes when the agent has written responses. This is what
makes a large scan able to span several agent sessions.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import run as run_mod
from pipeline.llm_client import AgentHandoff
from tests.integration.conftest import oracle_responder


def _answer(requests_dir: Path, responses_dir: Path, limit: int | None = None) -> int:
    """Act as the agent: answer request files using the oracle logic."""
    responses_dir.mkdir(parents=True, exist_ok=True)
    answered = 0
    for path in sorted(requests_dir.glob("*.json")):
        if limit is not None and answered >= limit:
            break
        request = json.loads(path.read_text())
        target = responses_dir / f"{request['request_id']}.json"
        if target.exists():
            continue

        if request.get("stage") == "finding_triage":
            # Feature 013: triage requests answer with the closed verdict
            # vocabulary, not the findings shape segment requests use.
            fid = request["context_packet"]["finding_id"]
            target.write_text(json.dumps({"finding_id": fid, "verdict": "confirmed"}))
            answered += 1
            continue

        class _Shim:
            payload = request["context_packet"]

        target.write_text(oracle_responder(_Shim()))
        answered += 1
    return answered


def _answer_until_done(root: Path) -> object:
    """Run the handoff/answer loop to completion (feature 013 added a second,
    post-analysis handoff round: triage questions follow segment questions)."""
    handoff_dir = root / ".secscan" / "handoff"
    for _ in range(4):
        try:
            return run_mod.run_scan(root)
        except AgentHandoff:
            answered = _answer(handoff_dir / "requests", handoff_dir / "responses")
            assert answered > 0, "the loop must make progress"
    raise AssertionError("scan did not complete after four answer rounds")


def test_scan_without_responder_hands_off_and_writes_requests(configured_shop: Path) -> None:
    with pytest.raises(AgentHandoff) as exc:
        run_mod.run_scan(configured_shop, full=True)

    handoff = exc.value
    assert handoff.pending
    requests_dir = configured_shop / ".secscan" / "handoff" / "requests"
    assert requests_dir.is_dir()

    files = sorted(requests_dir.glob("*.json"))
    assert files, "each pending request must be persisted for the agent"

    request = json.loads(files[0].read_text())
    assert request["prompt"].strip(), "the agent needs the analysis instructions"
    assert request["context_packet"]["source"], "and the bounded context"
    assert request["estimated_tokens"] <= request["budget"]["max_context_tokens"]
    assert "responses" in request["instructions"]

    # Guidance must tell the operator exactly what to do next.
    text = handoff.instructions()
    assert "handoff/requests" in text.replace("\\", "/")
    assert "responses" in text
    assert "re-run" in text.lower()


def test_scan_resumes_from_agent_written_responses(configured_shop: Path) -> None:
    """The full loop: handoff -> agent answers on disk -> re-run completes."""
    handoff_dir = configured_shop / ".secscan" / "handoff"

    with pytest.raises(AgentHandoff):
        run_mod.run_scan(configured_shop, full=True)

    answered = _answer(handoff_dir / "requests", handoff_dir / "responses")
    assert answered > 0

    # Re-run: no responder, answers come from disk (and any triage round the
    # full-profile scan adds is answered through the same loop).
    result = _answer_until_done(configured_shop)
    assert result.reported_findings
    assert result.report["execution_mode"] == "agent-mediated"
    assert result.report_path.exists()


def test_partial_answers_keep_asking_for_the_rest(configured_shop: Path) -> None:
    """A session that answers only some requests makes progress, not a reset."""
    handoff_dir = configured_shop / ".secscan" / "handoff"

    with pytest.raises(AgentHandoff) as first:
        run_mod.run_scan(configured_shop, full=True)
    total = len(first.value.pending)
    assert total >= 2

    _answer(handoff_dir / "requests", handoff_dir / "responses", limit=1)

    with pytest.raises(AgentHandoff) as second:
        run_mod.run_scan(configured_shop)
    assert len(second.value.pending) < total

    _answer(handoff_dir / "requests", handoff_dir / "responses")
    assert _answer_until_done(configured_shop).reported_findings


def test_responder_bypasses_the_handoff(configured_shop: Path) -> None:
    """An in-process responder (test double or in-agent bridge) needs no files."""
    result = run_mod.run_scan(configured_shop, responder=oracle_responder, full=True)
    assert result.reported_findings
    assert not (configured_shop / ".secscan" / "handoff" / "requests").exists()
