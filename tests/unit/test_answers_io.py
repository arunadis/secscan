"""Answer validation and response writing shared by the plugin form (feature 018,
FR-006, FR-022; research R12). The acceptance test is exactly the one the resume
path applies, so the plugin never accepts less or more than the skill path."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import answers_io
from pipeline.state import canonical_json


def _handoff(tmp_path: Path, *requests: dict) -> Path:
    handoff = tmp_path / ".secscan" / "handoff"
    (handoff / "requests").mkdir(parents=True)
    for doc in requests:
        (handoff / "requests" / f"{doc['request_id']}.json").write_text(
            json.dumps(doc, indent=2, sort_keys=True) + "\n"
        )
    return handoff


SEGMENT = {"request_id": "shop:api-l1", "stage": "segment_analysis", "context_packet": {}}
FLOW = {"request_id": "flow-abc123-l1", "stage": "business_flow_analysis",
        "context_packet": {"flow": {"id": "abc123"}}}
TRIAGE = {"request_id": "triage-SEC-0007", "stage": "finding_triage",
          "context_packet": {"finding_id": "SEC-0007"}}


# ------------------------------------------------------------- answer kinds


def test_answer_kind_by_stage() -> None:
    assert answers_io.answer_kind(SEGMENT) == "finding"
    assert answers_io.answer_kind(FLOW) == "flow_answer"
    assert answers_io.answer_kind(TRIAGE) == "triage_answer"


def test_guidance_by_kind() -> None:
    assert answers_io.guidance_for("finding") == "prompts/segment_scan.md"
    assert answers_io.guidance_for("flow_answer") == "prompts/business_flow.md"
    assert answers_io.guidance_for("triage_answer") == "prompts/triage_finding.md"


# -------------------------------------------------------------- validation


def test_segment_prose_is_rejected() -> None:
    errors = answers_io.validate_answer(SEGMENT, "I think there is a SQL injection here.")
    assert errors and errors[0]["path"] == ""
    assert "structured findings JSON" in errors[0]["message"]


def test_segment_findings_and_escalation_accepted() -> None:
    assert answers_io.validate_answer(SEGMENT, json.dumps({"findings": []})) == []
    assert answers_io.validate_answer(SEGMENT, {"findings": [], "needs_escalation": True}) == []
    fenced = "```json\n{\"findings\": []}\n```"
    assert answers_io.validate_answer(SEGMENT, fenced) == []


def test_segment_findings_must_be_a_list() -> None:
    errors = answers_io.validate_answer(SEGMENT, json.dumps({"findings": {"cwe": "CWE-89"}}))
    assert errors and "list" in errors[0]["message"]


def test_flow_answer_schema_errors_name_path_not_instance() -> None:
    bad = {"flow_id": "abc123", "assessment": "maybe", "secret": "AKIAIOSFODNN7EXAMPLE"}
    errors = answers_io.validate_answer(FLOW, bad)
    assert errors
    assert any(e["path"] == "assessment" for e in errors)
    joined = json.dumps(errors)
    assert "AKIAIOSFODNN7EXAMPLE" not in joined, "rejection reasons never echo the instance"
    assert set(errors[0]) == {"path", "message"}


def test_flow_answer_valid() -> None:
    assert answers_io.validate_answer(FLOW, {"flow_id": "abc123", "assessment": "clean"}) == []


def test_triage_answer_validation() -> None:
    assert answers_io.validate_answer(
        TRIAGE, {"finding_id": "SEC-0007", "verdict": "confirmed"}
    ) == []
    errors = answers_io.validate_answer(TRIAGE, {"finding_id": "SEC-0007", "verdict": "meh"})
    assert errors and errors[0]["path"] == "verdict"


def test_non_json_string_for_schema_kinds_is_rejected() -> None:
    errors = answers_io.validate_answer(TRIAGE, "confirmed")
    assert errors and "JSON" in errors[0]["message"]


# ------------------------------------------------------------- resolution


def test_resolve_request_matches_listing_only(tmp_path: Path) -> None:
    handoff = _handoff(tmp_path, SEGMENT)
    doc = answers_io.resolve_request(handoff, "shop:api-l1")
    assert doc["request_id"] == "shop:api-l1"
    with pytest.raises(answers_io.UnknownRequest):
        answers_io.resolve_request(handoff, "../../config")
    with pytest.raises(answers_io.UnknownRequest):
        answers_io.resolve_request(handoff, "shop:api-l1.json")  # stems only
    with pytest.raises(answers_io.UnknownRequest):
        answers_io.resolve_request(handoff, "nope")


def test_list_requests_reports_answered_flag(tmp_path: Path) -> None:
    handoff = _handoff(tmp_path, SEGMENT, TRIAGE)
    (handoff / "responses").mkdir()
    (handoff / "responses" / "triage-SEC-0007.json").write_text("{}")
    listing = answers_io.list_requests(handoff)
    assert [r["request_id"] for r in listing] == ["shop:api-l1", "triage-SEC-0007"]
    assert [r["answered"] for r in listing] == [False, True]
    assert set(listing[0]) >= {"request_id", "stage", "answered"}
    assert "context_packet" not in listing[0]


# ------------------------------------------------------------------ writes


def test_write_response_string_verbatim_and_object_canonical(tmp_path: Path) -> None:
    handoff = _handoff(tmp_path, SEGMENT, TRIAGE)
    text = '{"findings": []}\n'
    path = answers_io.write_response(handoff, "shop:api-l1", text)
    assert path == handoff / "responses" / "shop:api-l1.json"
    assert path.read_text() == text, "a string answer is written exactly as given"

    doc = {"verdict": "confirmed", "finding_id": "SEC-0007"}
    path = answers_io.write_response(handoff, "triage-SEC-0007", doc)
    assert path.read_text() == canonical_json(doc)


def test_write_response_refuses_overwrite_unless_asked(tmp_path: Path) -> None:
    handoff = _handoff(tmp_path, SEGMENT)
    answers_io.write_response(handoff, "shop:api-l1", "{}")
    with pytest.raises(answers_io.AlreadyAnswered):
        answers_io.write_response(handoff, "shop:api-l1", '{"findings": []}')
    answers_io.write_response(handoff, "shop:api-l1", '{"findings": []}', overwrite=True)
    assert (handoff / "responses" / "shop:api-l1.json").read_text() == '{"findings": []}'


def test_write_response_unknown_request_writes_nothing(tmp_path: Path) -> None:
    handoff = _handoff(tmp_path, SEGMENT)
    with pytest.raises(answers_io.UnknownRequest):
        answers_io.write_response(handoff, "ghost", "{}")
    assert not (handoff / "responses").exists()


def test_submit_rejected_leaves_no_file(tmp_path: Path) -> None:
    """`submit` = validate then write; a rejection must leave the directory untouched."""
    handoff = _handoff(tmp_path, TRIAGE)
    outcome = answers_io.submit(handoff, "triage-SEC-0007", {"finding_id": "x", "verdict": "?"})
    assert outcome.errors and outcome.path is None
    assert not (handoff / "responses").exists()
    outcome = answers_io.submit(
        handoff, "triage-SEC-0007",
        {"finding_id": "SEC-0007", "verdict": "flagged", "user_question": "Is X reachable?"},
    )
    assert outcome.errors == [] and outcome.path is not None and outcome.path.exists()
