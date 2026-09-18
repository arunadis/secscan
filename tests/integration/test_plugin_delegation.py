"""Precedence: a project skill install drives the scan, the plugin only delegates
(feature 018, FR-015; research R9). Also the corrupt-install and file-only tool cases."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from installer import core as installer
from pipeline import mcp_server
from pipeline import run as run_mod
from pipeline.state import TOOL_VERSION
from tests.fixtures.single_repo_shop import build as build_shop
from tests.integration.conftest import oracle_responder, write_config


@pytest.fixture
def pinned_shop(tmp_path: Path) -> tuple[Path, Path]:
    root = build_shop(tmp_path / "shop")
    write_config(root, {"triage": {"enabled": "off"}})
    result = installer.install(root, "cursor")
    return root, result.skill_dir


def _never_run(*a, **k):
    raise AssertionError("the plugin's own engine must never run against a pinned project")


def test_status_reports_the_pinned_skill_install(pinned_shop) -> None:
    root, _skill_dir = pinned_shop
    res = mcp_server.call_tool("status", {"workdir": str(root)})
    assert res["driver"]["form"] == "skill"
    assert res["driver"]["delegated"] is True
    assert res["driver"]["tool_version"] == TOOL_VERSION
    assert res["driver"]["plugin_version"] == TOOL_VERSION
    assert res["driver"]["installs"] == [{"agent": "cursor", "tool_version": TOOL_VERSION}]
    assert res["state"] == "ok"


def test_current_payload_is_driven_through_oneshot_and_honours_the_bound(
    pinned_shop, monkeypatch
) -> None:
    root, skill_dir = pinned_shop
    assert (skill_dir / "scripts" / "pipeline" / "mcp_server.py").is_file()
    monkeypatch.setattr(run_mod, "run_scan", _never_run)
    lines: list[str] = []

    res = mcp_server.call_tool(
        "run", {"workdir": str(root), "time_budget_s": 3600},
        notify=lambda level, text: lines.append(text),
    )
    assert res["state"] == "awaiting_reasoning", res
    assert res["driver"]["form"] == "skill" and res["driver"]["delegated"] is True
    assert "bound" not in res, "a current payload honours the bound itself"
    assert lines and any("segment" in line for line in lines), "subprocess progress forwarded"
    assert (root / ".secscan" / "handoff" / "requests").is_dir()

    # Bound is honoured by the pinned engine: an expired-looking tiny bound pauses.
    res = mcp_server.call_tool("run", {"workdir": str(root), "time_budget_s": 5})
    assert res["state"] in ("awaiting_reasoning", "in_progress")


def test_pre_feature_payload_is_driven_through_scan_cli(pinned_shop, monkeypatch) -> None:
    root, skill_dir = pinned_shop
    (skill_dir / "scripts" / "pipeline" / "mcp_server.py").unlink()  # simulate an older pin
    monkeypatch.setattr(run_mod, "run_scan", _never_run)

    res = mcp_server.call_tool("run", {"workdir": str(root), "time_budget_s": 3600})
    assert res["state"] == "awaiting_reasoning", res
    assert res["bound"] == f"unsupported by pinned payload v{TOOL_VERSION}"
    assert res["pending"] and res["requests_dir"].endswith("handoff/requests")

    # Answer through the file-only tools (identical with or without a skill install),
    # then the legacy path completes and maps exit 0 -> ok with the summary lines.
    w = str(root)
    for row in mcp_server.call_tool("list_requests", {"workdir": w})["requests"]:
        got = mcp_server.call_tool("get_request", {"workdir": w, "request_id": row["request_id"]})

        class _Shim:
            payload = got["request"]["context_packet"]

        sub = mcp_server.call_tool(
            "submit_answer",
            {"workdir": w, "request_id": row["request_id"], "content": oracle_responder(_Shim())},
        )
        assert sub["state"] == "ok"
    res = mcp_server.call_tool("run", {"workdir": w, "time_budget_s": 3600})
    assert res["state"] in ("ok", "report_defect", "awaiting_reasoning"), res
    if res["state"] == "ok":
        assert res["summary"][0].startswith("scan ")
    status = mcp_server.call_tool("status", {"workdir": w})
    assert status["state"] == "ok" and "text" in status

    report = mcp_server.call_tool("report", {"workdir": w, "format": "json"})
    assert report["state"] in ("ok", "error")


def test_corrupt_install_is_reported_never_bypassed(pinned_shop, monkeypatch) -> None:
    root, skill_dir = pinned_shop
    shutil.rmtree(skill_dir / "scripts")
    monkeypatch.setattr(run_mod, "run_scan", _never_run)
    res = mcp_server.call_tool("run", {"workdir": str(root)})
    assert res["state"] == "error"
    assert res["reason"] == "corrupt skill install"
    assert res["repair"] == f"secscan init {root.resolve()} --ai cursor"
    assert "scripts" in res["message"]


def test_newest_of_several_installs_drives(pinned_shop) -> None:
    root, _ = pinned_shop
    other = installer.install(root, "claude")
    manifest_path = other.skill_dir / installer.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    manifest["tool_version"] = "0.0.1"
    manifest_path.write_text(json.dumps(manifest))
    driver, chosen = mcp_server._detect_driver(root)
    assert chosen["agent"] == "cursor", "the newest pinned version drives"
    assert [i["agent"] for i in driver["installs"]] == ["claude", "cursor"]


def test_missing_entrypoint_is_corrupt(pinned_shop) -> None:
    root, skill_dir = pinned_shop
    (skill_dir / "SKILL.md").unlink()
    res = mcp_server.call_tool("status", {"workdir": str(root)})
    assert res["state"] == "error" and res["reason"] == "corrupt skill install"


def test_file_only_tools_do_not_depend_on_delegation(pinned_shop, monkeypatch) -> None:
    root, _ = pinned_shop
    mcp_server.call_tool("run", {"workdir": str(root), "time_budget_s": 3600})
    listing = mcp_server.call_tool("list_requests", {"workdir": str(root)})
    assert listing["state"] == "ok" and listing["requests"]
    assert listing["driver"]["form"] == "skill"
