"""Tool result envelopes conform to contracts/mcp-tools.md §5 (feature 018, FR-010)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from pipeline import mcp_server
from tests.fixtures.single_repo_shop import build as build_shop
from tests.integration.conftest import oracle_responder, write_config

SCHEMA_DIR = Path(__file__).parent / "schemas_018"


def _registry() -> Registry:
    registry = Registry()
    for path in sorted(SCHEMA_DIR.glob("*.json")):
        doc = json.loads(path.read_text())
        registry = registry.with_resource(doc["$id"], Resource.from_contents(doc))
    return registry


def _validator(name: str) -> Draft202012Validator:
    doc = json.loads((SCHEMA_DIR / f"{name}.json").read_text())
    return Draft202012Validator(doc, registry=_registry())


def _assert_valid(name: str, document: dict) -> None:
    errors = sorted(_validator(name).iter_errors(document), key=lambda e: list(e.path))
    assert not errors, [e.message for e in errors]


@pytest.fixture
def shop(tmp_path: Path) -> Path:
    root = build_shop(tmp_path / "shop")
    write_config(root, {"triage": {"enabled": "off"}})
    return root


def test_state_enum_is_closed() -> None:
    schema = json.loads((SCHEMA_DIR / "result-envelope.json").read_text())
    assert tuple(schema["properties"]["state"]["enum"]) == mcp_server.STATES


def test_lifecycle_results_validate(shop: Path) -> None:
    w = str(shop)
    _assert_valid("result-envelope", mcp_server.call_tool("status", {"workdir": w}))
    _assert_valid("result-envelope", mcp_server.call_tool("init", {"workdir": w}))
    res = mcp_server.call_tool("run", {"workdir": w, "time_budget_s": 3600})
    _assert_valid("run-result", res)
    assert res["state"] == "awaiting_reasoning"
    for row in mcp_server.call_tool("list_requests", {"workdir": w})["requests"]:
        got = mcp_server.call_tool("get_request", {"workdir": w, "request_id": row["request_id"]})
        _assert_valid("result-envelope", got)

        class _Shim:
            payload = got["request"]["context_packet"]

        bad = mcp_server.call_tool(
            "submit_answer", {"workdir": w, "request_id": row["request_id"], "content": "prose"}
        )
        _assert_valid("submit-answer-result", bad)
        assert bad["state"] == "rejected"
        good = mcp_server.call_tool(
            "submit_answer",
            {"workdir": w, "request_id": row["request_id"], "content": oracle_responder(_Shim())},
        )
        _assert_valid("submit-answer-result", good)
    res = mcp_server.call_tool("run", {"workdir": w, "time_budget_s": 3600})
    _assert_valid("run-result", res)
    assert res["state"] in ("ok", "report_defect", "awaiting_reasoning")
    _assert_valid("result-envelope", mcp_server.call_tool("report", {"workdir": w}))


def test_in_progress_and_error_results_validate(shop: Path) -> None:
    w = str(shop)
    ticks = iter(range(0, 10**6, 100))
    paused = mcp_server.tool_run({"workdir": w, "time_budget_s": 5}, clock=lambda: next(ticks))
    _assert_valid("run-result", paused)
    assert paused["state"] == "in_progress"
    _assert_valid("run-result", mcp_server.call_tool("run", {"workdir": w, "time_budget_s": 1}))
    _assert_valid("result-envelope", mcp_server.call_tool("status", {}))
