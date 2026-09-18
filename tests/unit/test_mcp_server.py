"""Plugin tool-provider handlers, called in-process (feature 018, US2).

Covers FR-004..FR-012, FR-021, FR-022: result states, id resolution, answer
validation, redaction of error text, prompt/resource surfaces.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from installer.agents.base import render_skill, split_frontmatter
from pipeline import mcp_app, mcp_server
from pipeline.state import RUN_LOCK_NAME
from tests.fixtures.single_repo_shop import build as build_shop
from tests.integration.conftest import oracle_responder, write_config


@pytest.fixture
def shop(tmp_path: Path) -> Path:
    root = build_shop(tmp_path / "shop")
    write_config(root, {"triage": {"enabled": "off"}})
    return root


def _call(name: str, **args):
    return mcp_server.call_tool(name, args)


def _answer_all(root: Path) -> int:
    """Act as the agent through the tool surface."""
    listing = _call("list_requests", workdir=str(root))["requests"]
    answered = 0
    for row in listing:
        if row["answered"]:
            continue
        got = _call("get_request", workdir=str(root), request_id=row["request_id"])
        assert got["state"] == "ok"

        class _Shim:
            payload = got["request"]["context_packet"]

        content = oracle_responder(_Shim())
        res = _call("submit_answer", workdir=str(root), request_id=row["request_id"],
                    content=content)
        assert res["state"] == "ok", res
        answered += 1
    return answered


# ------------------------------------------------------------------ envelope


def test_every_result_carries_the_envelope(shop: Path) -> None:
    res = _call("status", workdir=str(shop))
    assert set(res) >= {"state", "tool_version", "driver"}
    assert res["state"] in mcp_server.STATES
    assert res["driver"] == {"form": "plugin", "tool_version": mcp_server.TOOL_VERSION,
                             "plugin_version": mcp_server.TOOL_VERSION, "delegated": False}


def test_missing_workdir_is_an_error_state() -> None:
    res = _call("status")
    assert res["state"] == "error" and "workdir" in res["message"]


# ---------------------------------------------------------------------- init


def test_init_unconfigured_project(tmp_path: Path) -> None:
    root = build_shop(tmp_path / "shop")
    res = _call("init", workdir=str(root))
    assert res["state"] in ("ok", "not_ready")
    assert (root / ".secscan" / "config.yaml").exists()
    assert res["config_schema_changed"] is False
    assert "report" in res


def test_init_flags_config_schema_change(shop: Path) -> None:
    config = shop / ".secscan" / "config.yaml"
    config.write_text(config.read_text().replace("version: 1", "version: 0", 1))
    res = _call("init", workdir=str(shop))
    assert res["config_schema_changed"] is True
    assert "configuration schema changed" in res["message"]


# ----------------------------------------------------------------------- run


def test_run_without_answers_awaits_reasoning(shop: Path) -> None:
    res = _call("run", workdir=str(shop), time_budget_s=3600)
    assert res["state"] == "awaiting_reasoning"
    assert res["pending"] == sorted(res["pending"]) and res["pending"]
    assert res["requests_dir"].endswith("handoff/requests")
    assert "secscan_run" in res["next"]
    # progress never appears in the result
    assert "progress" not in res and "log" not in res


def test_full_lifecycle_through_tools(shop: Path) -> None:
    res = _call("run", workdir=str(shop), time_budget_s=3600)
    rounds = 0
    while res["state"] == "awaiting_reasoning" and rounds < 4:
        assert _answer_all(shop) > 0
        res = _call("run", workdir=str(shop), time_budget_s=3600)
        rounds += 1
    assert res["state"] == "ok", res
    assert res["summary"][0].startswith("scan ") and res["summary"][1].startswith("report: ")
    assert Path(res["report_path"]).exists()
    assert res["findings_reported"] >= 1
    report = _call("report", workdir=str(shop), format="json")
    assert report["state"] == "ok" and json.loads(report["content"])["findings_by_band"]
    status = _call("status", workdir=str(shop))
    assert status["stages"]["generate_report"] == "done"
    assert status["lock"] is None


def test_run_pauses_in_progress_and_leaves_no_lock(shop: Path) -> None:
    clock = {"now": 0.0}

    def tick() -> float:
        clock["now"] += 100.0  # every read overruns a 5 s bound
        return clock["now"]

    res = mcp_server.tool_run({"workdir": str(shop), "time_budget_s": 5}, clock=tick)
    assert res["state"] == "in_progress"
    assert res["checkpoint"]["stage"]
    assert res["next"] == "call secscan_run again"
    assert isinstance(res["overran_bound"], bool)
    assert not (shop / ".secscan" / RUN_LOCK_NAME).exists()


def test_run_bad_time_budget_is_error(shop: Path) -> None:
    assert _call("run", workdir=str(shop), time_budget_s=1)["state"] == "error"
    assert _call("run", workdir=str(shop), time_budget_s="5")["state"] == "error"


def test_run_refuses_when_locked(shop: Path) -> None:
    lock = {"pid": os.getpid(), "started_at": 1.0, "scan_id": "x", "driver": "cli",
            "tool_version": "0.1.0"}
    (shop / ".secscan" / RUN_LOCK_NAME).write_text(json.dumps(lock))
    res = _call("run", workdir=str(shop))
    assert res["state"] == "locked" and res["lock"]["driver"] == "cli"


def test_run_unconfigured_is_error_not_traceback(tmp_path: Path) -> None:
    root = build_shop(tmp_path / "shop")
    res = _call("run", workdir=str(root))
    assert res["state"] == "error" and "message" in res


def test_error_messages_are_redacted(shop: Path, monkeypatch) -> None:
    from pipeline import run as run_mod

    def boom(*a, **k):
        raise RuntimeError("leak AKIAIOSFODNN7EXAMPLE token")

    monkeypatch.setattr(run_mod, "run_scan", boom)
    res = _call("run", workdir=str(shop))
    assert res["state"] == "error"
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(res)


# ------------------------------------------------------------------ requests


def test_get_request_returns_document_verbatim(shop: Path) -> None:
    _call("run", workdir=str(shop), time_budget_s=3600)
    rows = _call("list_requests", workdir=str(shop))["requests"]
    assert rows and all(not r["answered"] for r in rows)
    assert "context_packet" not in rows[0]
    rid = rows[0]["request_id"]
    got = _call("get_request", workdir=str(shop), request_id=rid)
    on_disk = json.loads((shop / ".secscan" / "handoff" / "requests" / f"{rid}.json").read_text())
    assert got["request"] == on_disk
    assert got["answer_schema"] == "finding"
    assert got["guidance"] == "prompts/segment_scan.md"
    assert got["answered"] is False


def test_get_request_rejects_traversal_and_unknown(shop: Path) -> None:
    _call("run", workdir=str(shop), time_budget_s=3600)
    for bad in ("../config", "/etc/passwd", "nope", ""):
        res = _call("get_request", workdir=str(shop), request_id=bad)
        assert res["state"] == "error", bad


def test_submit_answer_rejected_writes_nothing(shop: Path) -> None:
    _call("run", workdir=str(shop), time_budget_s=3600)
    rid = _call("list_requests", workdir=str(shop))["requests"][0]["request_id"]
    res = _call("submit_answer", workdir=str(shop), request_id=rid, content="just prose")
    assert res["state"] == "rejected" and res["errors"]
    assert not (shop / ".secscan" / "handoff" / "responses").exists()
    res = _call("submit_answer", workdir=str(shop), request_id=rid, content={"findings": []})
    assert res["state"] == "ok"
    assert Path(res["response_path"]).exists()
    again = _call("submit_answer", workdir=str(shop), request_id=rid, content={"findings": []})
    assert again["state"] == "error" and "overwrite" in again["message"]


# ------------------------------------------------------------------- report


def test_report_before_any_scan_is_error(shop: Path) -> None:
    res = _call("report", workdir=str(shop))
    assert res["state"] == "error"
    assert _call("report", workdir=str(shop), format="pdf")["state"] == "error"


# ---------------------------------------------------------- prompt/resources


def test_prompt_text_is_the_plugin_skill_body() -> None:
    _front, body = split_frontmatter(render_skill("tools"))
    assert mcp_app.prompt_text() == body.rstrip() + "\n"
    assert "secscan_submit_answer" in mcp_app.prompt_text()
    assert "python -m pipeline.scan_cli" not in mcp_app.prompt_text()


def test_handler_module_does_not_import_mcp() -> None:
    import subprocess
    import sys

    code = (
        "import sys; sys.path.insert(0, 'src'); import pipeline.mcp_server; "
        "print('mcp' in sys.modules)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"


def test_oneshot_prints_one_envelope(shop: Path, capsys) -> None:
    code = mcp_server.main(["--oneshot", "status", json.dumps({"workdir": str(shop)})])
    out, _err = capsys.readouterr()
    assert code == 0
    doc = json.loads(out.strip().splitlines()[-1])
    assert doc["state"] == "ok" and doc["driver"]["form"] == "plugin"
