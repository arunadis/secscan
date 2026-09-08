"""Business-flow handoff pause/resume (feature 015, FR-018 cross-session resume).

Regression: a paused business_flow_analysis stage was checkpointed "done"
*before* the handoff was raised, so the reuse branch re-pended every
originally-unanswered flow on the next run without ever consulting the agent's
response files — an infinite pause loop the operator could only escape by
manually invalidating the stage. The stage must not be marked done while any
flow request is pending (the finding_triage round's precedent), and resuming
must consume answers written to ``.secscan/handoff/responses/``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import business_flow
from pipeline import run as run_mod
from pipeline.llm_client import AgentHandoff
from pipeline.state import ArtifactStore
from tests.fixtures.flow_app import build, flow_oracle_answer
from tests.integration.conftest import oracle_responder, write_config


@pytest.fixture
def flow_repo(tmp_path: Path) -> Path:
    root = build(tmp_path)
    write_config(root, {"business_flow": {"enabled": True}})
    return root


class _Shim:
    def __init__(self, payload: dict) -> None:
        self.payload = payload


def _answer_requests(
    requests_dir: Path, responses_dir: Path, *, flow_limit: int | None = None
) -> int:
    """Act as the agent: answer on-disk requests, at most ``flow_limit`` flow ones."""
    responses_dir.mkdir(parents=True, exist_ok=True)
    answered = flow_answered = 0
    for path in sorted(requests_dir.glob("*.json")):
        request = json.loads(path.read_text())
        target = responses_dir / f"{request['request_id']}.json"
        if target.exists():
            continue
        if request.get("stage") == "finding_triage":
            fid = request["context_packet"]["finding_id"]
            target.write_text(json.dumps({"finding_id": fid, "verdict": "confirmed"}))
        elif request.get("stage") == business_flow.STAGE_ANALYSIS:
            if flow_limit is not None and flow_answered >= flow_limit:
                continue
            answer = flow_oracle_answer(_Shim(request["context_packet"]))
            assert answer is not None, "flow packets must be answerable by the flow oracle"
            target.write_text(answer)
            flow_answered += 1
        else:
            target.write_text(oracle_responder(_Shim(request["context_packet"])))
        answered += 1
    return answered


def _run_handoff_loop(root: Path, max_rounds: int = 6):
    """Answer whatever hands off until the scan completes."""
    handoff_dir = root / ".secscan" / "handoff"
    for _ in range(max_rounds):
        try:
            return run_mod.run_scan(root)
        except AgentHandoff:
            answered = _answer_requests(
                handoff_dir / "requests", handoff_dir / "responses"
            )
            assert answered > 0, "the loop must make progress"
    raise AssertionError(f"scan did not complete after {max_rounds} answer rounds")


def _flow_pendings(handoff: AgentHandoff) -> list[str]:
    return [p for p in handoff.pending if p.startswith("flow:")]


def test_paused_flow_stage_is_not_checkpointed_done(flow_repo: Path) -> None:
    """The regression pin: pending flows ⇒ the stage is not 'done' (run-finding-
    triage precedent); previously it was, trapping resume in the reuse branch."""
    with pytest.raises(AgentHandoff) as exc:
        run_mod.run_scan(flow_repo, full=True)
    assert _flow_pendings(exc.value), "the flow fixture must pause on flow requests"

    status = ArtifactStore(flow_repo).stage(business_flow.STAGE_ANALYSIS).status
    assert status != "done", "a paused stage must never checkpoint as done"


def test_answered_flow_requests_resume_to_completion(flow_repo: Path) -> None:
    """Handoff → agent answers on disk → re-run completes; no manual invalidation."""
    result = _run_handoff_loop(flow_repo)

    store = ArtifactStore(flow_repo)
    assert store.stage(business_flow.STAGE_ANALYSIS).status == "done"
    coverage = store.read("business-flows.json")["coverage"]
    assert coverage["analyzed"] == sorted(coverage["reconstructed"])
    assert coverage["unanalyzed"] == []

    # The flow round drew from the scan-wide id sequence: no duplicate ids can
    # have reached correlation or triage verdict binding.
    ids = [f["id"] for f in result.findings]
    assert len(ids) == len(set(ids))


def test_partial_flow_answers_make_progress(flow_repo: Path) -> None:
    """Answering one flow request reduces the pending set on the next run —
    the answered request is consumed from responses/, never re-asked."""
    handoff_dir = flow_repo / ".secscan" / "handoff"

    with pytest.raises(AgentHandoff) as first:
        run_mod.run_scan(flow_repo, full=True)
    total = len(_flow_pendings(first.value))
    assert total >= 2

    _answer_requests(handoff_dir / "requests", handoff_dir / "responses", flow_limit=1)
    with pytest.raises(AgentHandoff) as second:
        run_mod.run_scan(flow_repo)
    assert len(_flow_pendings(second.value)) == total - 1
