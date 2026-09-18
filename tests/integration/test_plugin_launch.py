"""The committed launch reference actually starts the server (feature 018, FR-019,
research R11). Reads mcp.json, substitutes the host placeholders, spawns exactly
that argv over stdio and completes the handshake + tool listing."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from pathlib import Path

import pytest

from pipeline import mcp_server

mcp = pytest.importorskip("mcp")
from mcp.client.client import Client  # noqa: E402
from mcp.client.stdio import StdioServerParameters  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is not on PATH")
def test_mcp_json_launch_reference_starts_the_server(tmp_path: Path) -> None:
    entry = json.loads((REPO / "mcp.json").read_text())["mcpServers"]["secscan"]
    data_dir = tmp_path / "plugin-data"
    data_dir.mkdir()

    def expand(value: str) -> str:
        return value.replace("${PLUGIN_ROOT}", str(REPO)).replace("${PLUGIN_DATA}", str(data_dir))

    env = dict(os.environ)
    env.update({k: expand(v) for k, v in entry.get("env", {}).items()})
    # Reuse the checkout's already-synced environment rather than resolving a fresh
    # one into ${PLUGIN_DATA} (that is what a host does on first launch; here it
    # would just download the same wheels again).
    env["UV_PROJECT_ENVIRONMENT"] = str(REPO / ".venv")
    params = StdioServerParameters(
        command=entry["command"],
        args=[expand(a) for a in entry["args"]],
        env=env,
        cwd=expand(entry.get("cwd", "${PLUGIN_ROOT}")),
    )

    async def go():
        async with Client(params) as c:
            tools = await c.list_tools()
            return sorted(t.name for t in tools.tools)

    names = asyncio.run(go())
    assert names == sorted(f"secscan_{n}" for n in mcp_server.TOOL_NAMES)
