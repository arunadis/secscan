"""Feature 012 T006: persisted answers and their key (data-model.md "Segment Answer")."""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.answers import AnswerStore, answer_key
from pipeline.budget import TokenBudget
from pipeline.llm_client import AnalysisRequest

BUDGET = TokenBudget(12000, 3000, 0.75)


def _request(request_id="seg-a-l1", prompt="p", payload=None) -> AnalysisRequest:
    return AnalysisRequest(
        id=request_id, stage="segment_analysis", prompt=prompt,
        payload=(payload if payload is not None
                 else {"segment_id": "seg-a", "source": {"a.py": "x"}}),
        budget=BUDGET, level="local", escalation_level=1,
    )


def test_answer_key_tracks_prompt_payload_and_tier() -> None:
    base = answer_key(_request(), "haiku")
    assert base == answer_key(_request(), "haiku")
    assert base != answer_key(_request(prompt="q"), "haiku")
    changed_payload = {"segment_id": "seg-a", "source": {"a.py": "y"}}
    assert base != answer_key(_request(payload=changed_payload), "haiku")
    assert base != answer_key(_request(), "sonnet")


def test_put_then_get_round_trips_and_tier_mismatch_is_a_miss(tmp_path: Path) -> None:
    store = AnswerStore(tmp_path / "answers")
    assert store.get(_request(), "haiku") is None
    store.put(_request(), "haiku", '{"findings": []}')
    assert store.get(_request(), "haiku") == '{"findings": []}'
    assert store.get(_request(), "sonnet") is None
    assert store.get(_request(prompt="changed"), "haiku") is None


def test_file_holds_exactly_three_sorted_keys_and_is_written_atomically(tmp_path: Path) -> None:
    store = AnswerStore(tmp_path / "answers")
    path = store.put(_request(), "haiku", "content")
    text = path.read_text()
    assert list(json.loads(text)) == ["answer_key", "content", "request_id"]
    assert text.endswith("\n") and json.loads(text)["request_id"] == "seg-a-l1"
    assert not list((tmp_path / "answers").glob("*.tmp"))


def test_clear_empties_and_missing_directory_behaves_as_empty(tmp_path: Path) -> None:
    store = AnswerStore(tmp_path / "nope")
    assert store.get(_request(), "haiku") is None
    store.clear()  # no error
    store.put(_request(), "haiku", "c")
    store.put(_request("seg-b-l1"), "haiku", "d")
    assert len(list(store.root.iterdir())) == 2
    store.clear()
    assert list(store.root.iterdir()) == []
