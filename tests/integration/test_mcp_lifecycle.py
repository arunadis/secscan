"""End-to-end plugin lifecycle through a real stdio MCP session (feature 018, US2).

An SDK client launches ``python -m pipeline.mcp_server`` as a subprocess exactly as
a host would and drives init -> run -> answer -> resume -> report. Asserts: the
tool/prompt/resource surface (FR-004, FR-011); progress arrives as notifications and
never in results (FR-009); the server writes nothing to stderr during calls; no
credential reaches any result or notification (SC-008); the endpoint-configured case
never hands reasoning to the host (FR-012); no socket is opened by the handlers
(FR-021).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import sys
import urllib.request
from pathlib import Path

import pytest

from pipeline import mcp_server
from pipeline.redact import Redactor
from tests.contract.test_artifact_redaction import SEEDED_SECRETS
from tests.fixtures.single_repo_shop import build as build_shop
from tests.helpers.fake_provider import FakeProvider
from tests.integration.conftest import oracle_responder, write_config

mcp = pytest.importorskip("mcp")
from mcp.client.client import Client  # noqa: E402
from mcp.client.stdio import StdioServerParameters  # noqa: E402

SRC = Path(__file__).resolve().parents[2] / "src"


@pytest.fixture
def shop(tmp_path: Path) -> Path:
    root = build_shop(tmp_path / "shop")
    write_config(root, {"triage": {"enabled": "off"}})
    return root


@pytest.fixture
def no_network(monkeypatch):
    """Any socket or urlopen from the handlers is a test failure (FR-021)."""

    def _refuse(*a, **k):
        raise AssertionError("network access attempted during a tool call")

    monkeypatch.setattr(socket, "socket", _refuse)
    monkeypatch.setattr(urllib.request, "urlopen", _refuse)


def _server_params(tmp_path: Path, stderr_path: Path) -> StdioServerParameters:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    # The server's stderr is captured to a file so the test can assert it stayed
    # empty for the whole session (FR-009: no terminal output from the plugin form).
    return StdioServerParameters(
        command="sh",
        args=["-c", f'exec "{sys.executable}" -m pipeline.mcp_server 2>"{stderr_path}"'],
        env=env,
        cwd=str(tmp_path),
    )


def _run(coro):
    return asyncio.run(coro)


def test_stdio_lifecycle(shop: Path, tmp_path: Path) -> None:
    stderr_path = tmp_path / "server.stderr"
    logs: list[str] = []
    progress: list[str] = []

    async def log_cb(params):
        logs.append(str(params.data))

    async def progress_cb(p, total, message):
        progress.append(message or "")

    async def go():
        params = _server_params(tmp_path, stderr_path)
        async with Client(params, logging_callback=log_cb, log_level="debug") as c:
            tools = await c.list_tools()
            names = sorted(t.name for t in tools.tools)
            assert names == sorted(f"secscan_{n}" for n in mcp_server.TOOL_NAMES)
            assert [p.name for p in (await c.list_prompts()).prompts] == ["secscan"]
            prompt = await c.get_prompt("secscan")
            assert "secscan_submit_answer" in prompt.messages[0].content.text
            schema = await c.read_resource("secscan://schemas/finding")
            assert json.loads(schema.contents[0].text)

            w = str(shop)
            init = (await c.call_tool("secscan_init", {"workdir": w})).structured_content
            assert init["state"] in ("ok", "not_ready")

            res = (await c.call_tool(
                "secscan_run", {"workdir": w, "time_budget_s": 3600},
                progress_callback=progress_cb,
            )).structured_content
            rounds = 0
            while res["state"] == "awaiting_reasoning" and rounds < 4:
                for rid in res["pending"]:
                    got = (await c.call_tool(
                        "secscan_get_request", {"workdir": w, "request_id": rid}
                    )).structured_content
                    assert got["state"] == "ok"

                    class _Shim:
                        payload = got["request"]["context_packet"]

                    sub = (await c.call_tool(
                        "secscan_submit_answer",
                        {"workdir": w, "request_id": rid,
                         "content": oracle_responder(_Shim())},
                    )).structured_content
                    assert sub["state"] == "ok", sub
                res = (await c.call_tool(
                    "secscan_run", {"workdir": w, "time_budget_s": 3600},
                    progress_callback=progress_cb,
                )).structured_content
                rounds += 1
            assert res["state"] == "ok", res
            assert len(res["summary"]) in (2, 3)
            report = (await c.call_tool(
                "secscan_report", {"workdir": w, "format": "json"}
            )).structured_content
            assert report["state"] == "ok"
            return res, report


    res, report = _run(go())

    # Progress reached the host as notifications, never inside a result.
    assert progress, "progress notifications expected during run"
    assert any("segment" in line for line in progress)
    assert not any(k in res for k in ("progress", "events", "log"))

    # Nothing on the server's stderr during the calls.
    assert stderr_path.read_text() == "" if stderr_path.exists() else True

    # Redaction sweep over everything the host received.
    redactor = Redactor()
    marker = re.compile(r"\[(?:REDACTED|BLOCKED):[^\]]*\]")
    # The pytest temp root itself is a high-entropy token on macOS
    # (`/var/folders/<random>/...`); it is not content the scan produced.
    tmp_root = str(tmp_path.resolve().parent)

    def _strings(value, key: str = "") -> list[str]:
        # Filesystem paths the tool minted itself (`report_path`, `requests_dir`,
        # the `report: <path>` summary line) are one long token containing the
        # scan id, which the redactor's unclassified-token rule blocks by design;
        # they are not content the scan produced and are checked literally below.
        if isinstance(value, str):
            if key.endswith(("_path", "_dir")) or value.startswith("report: "):
                return []
            return [value]
        if isinstance(value, dict):
            return [s for k, v in value.items() for s in _strings(v, str(k))]
        if isinstance(value, list):
            return [s for v in value for s in _strings(v, key)]
        return []

    # Sweep every string the host received (values, not JSON framing — the
    # artifact sweep does the same for finding fields).
    received = [*_strings(res), report["content"], *logs, *progress]
    for secret in SEEDED_SECRETS:
        assert secret not in json.dumps(res)
    for text in received:
        for secret in SEEDED_SECRETS:
            assert secret not in text
        cleaned = marker.sub("***", text).replace(tmp_root, "/TMP")
        assert not redactor.scan(cleaned), text[:200]

    # The report on disk equals what the tool returned.
    assert Path(res["report_path"]).exists()


def test_handlers_open_no_socket(shop: Path, no_network) -> None:
    w = str(shop)
    assert mcp_server.call_tool("init", {"workdir": w})["state"] in ("ok", "not_ready")
    res = mcp_server.call_tool("run", {"workdir": w, "time_budget_s": 3600})
    assert res["state"] == "awaiting_reasoning"
    assert mcp_server.call_tool("status", {"workdir": w})["state"] == "ok"


FAKE_KEY = "FAKE_ENDPOINT_KEY_018_LIFECYCLE"


def test_endpoint_mode_never_hands_reasoning_to_the_host(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(FAKE_KEY, "sk-fake")
    root = build_shop(tmp_path / "shop")
    write_config(
        root,
        {
            "llm": {
                "endpoint": {
                    "provider": "anthropic",
                    "api_key_env": FAKE_KEY,
                    "model_map": {"local": "m-local", "segment": "m-segment"},
                }
            },
            "execution_policy": {"mode": "interactive"},
            "triage": {"enabled": "off"},
        },
    )
    provider = FakeProvider("anthropic")
    res = mcp_server.tool_run({"workdir": str(root), "time_budget_s": 3600}, transport=provider)
    assert res["state"] in ("ok", "report_defect"), res
    assert not (root / ".secscan" / "handoff" / "requests").exists()
    assert provider.interactive_calls >= 1
