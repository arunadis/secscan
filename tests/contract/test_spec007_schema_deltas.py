"""Spec 007, T006: additive schema extensions for the modern-exploit category.

Every delta is additive: new documents validate and documents captured before
this feature must keep validating (additive-schema rule).
"""

from __future__ import annotations

import copy

import pytest

from pipeline.schemas import SchemaError, is_valid, validate


def _node(**overrides) -> dict:
    node = {
        "id": "svc:app/llm.py",
        "repo": "svc",
        "type": "file",
        "path": "app/llm.py",
        "language": "python",
    }
    node.update(overrides)
    return node


def _finding() -> dict:
    return {
        "id": "SEC-0007",
        "cwe": "CWE-1427",
        "severity_score": 9.1,
        "severity_band": "Critical",
        "confidence": 0.9,
        "location": {
            "repo": "svc",
            "file": "app/llm.py",
            "symbol": "chat",
            "line_start": 12,
            "line_end": 16,
        },
        "description": "User input reaches instruction-bearing model context.",
        "evidence": [
            {
                "repo": "svc",
                "file": "app/llm.py",
                "symbol": "chat",
                "reason": "user input interpolated into the system prompt",
            }
        ],
        "attack_scenario": "An attacker overrides the application's instructions.",
        "impact": "Model behaviour is hijacked; tool calls and data follow.",
        "recommendation": "Separate instruction and data channels.",
        "source": "scanner-ingest",
        "status": "local",
    }


@pytest.mark.parametrize(
    "file_class",
    ["ai-agent-config", "ai-mcp-config", "prompt-artifact"],
)
def test_code_graph_accepts_ai_file_classes(file_class: str) -> None:
    validate(
        "code_graph",
        {
            "nodes": [_node(type="config", parsed=False, file_class=file_class)],
            "edges": [],
        },
    )


@pytest.mark.parametrize(
    "annotation",
    [
        "llm_invocation",
        "llm_prompt_sink",
        "tool_declaration",
        "external_content_source",
        "ai_config",
        "llm_undetermined",
    ],
)
def test_code_graph_accepts_llm_annotations(annotation: str) -> None:
    validate(
        "code_graph",
        {"nodes": [_node(annotations=[annotation])], "edges": []},
    )


def test_pre_007_code_graph_still_validates() -> None:
    """A graph written before this feature carries none of the new values."""
    validate(
        "code_graph",
        {
            "nodes": [_node(file_class="source", annotations=["security_sink"])],
            "edges": [],
        },
    )


def test_finding_accepts_mitigation_block() -> None:
    doc = _finding()
    doc["mitigation"] = {
        "control": "isolation-boundary",
        "state": "demonstrated",
    }
    validate("finding", doc)


def test_finding_undetermined_mitigation_requires_a_reason() -> None:
    """Honest uncertainty: undetermined must say why, never empty (spec FR-004)."""
    doc = _finding()
    doc["mitigation"] = {"control": "validation", "state": "undetermined"}
    with pytest.raises(SchemaError):
        validate("finding", doc)

    doc["mitigation"]["reason"] = "no isolation or validation control was traced"
    validate("finding", doc)


def test_pre_007_finding_without_mitigation_still_validates() -> None:
    validate("finding", _finding())


def test_mitigation_rejects_unknown_control_and_state() -> None:
    doc = _finding()
    doc["mitigation"] = {"control": "magic", "state": "demonstrated"}
    assert not is_valid("finding", doc)

    doc = copy.deepcopy(_finding())
    doc["mitigation"] = {
        "control": "human-approval",
        "state": "assumed",
    }
    assert not is_valid("finding", doc)
