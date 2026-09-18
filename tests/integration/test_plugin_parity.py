"""Artifacts are byte-identical whether the scan is driven by the skill path (CLI +
response files) or by the plugin tool handlers, including across bounded pauses
(feature 018, FR-020, SC-003, SC-005)."""

from __future__ import annotations

import json
from pathlib import Path

from pipeline import mcp_server
from pipeline import run as run_mod
from pipeline.llm_client import AgentHandoff
from tests.fixtures.single_repo_shop import build as build_shop
from tests.integration.conftest import oracle_responder, write_config


def _skill_driven(root: Path) -> None:
    """The skill path: run, answer the request files by hand, re-run."""
    handoff = root / ".secscan" / "handoff"
    for _ in range(4):
        try:
            run_mod.run_scan(root)
            return
        except AgentHandoff:
            (handoff / "responses").mkdir(parents=True, exist_ok=True)
            for path in sorted((handoff / "requests").glob("*.json")):
                request = json.loads(path.read_text())
                target = handoff / "responses" / f"{request['request_id']}.json"
                if target.exists():
                    continue

                class _Shim:
                    payload = request["context_packet"]

                target.write_text(oracle_responder(_Shim()))
    raise AssertionError("skill-driven scan did not settle")


def _tool_driven(root: Path, *, time_budget_s: int) -> None:
    """The plugin path: tool calls only, possibly many `in_progress` rounds."""
    w = str(root)
    for _ in range(60):
        res = mcp_server.call_tool("run", {"workdir": w, "time_budget_s": time_budget_s})
        if res["state"] in ("ok", "report_defect"):
            return
        if res["state"] == "in_progress":
            continue
        assert res["state"] == "awaiting_reasoning", res
        for row in mcp_server.call_tool("list_requests", {"workdir": w})["requests"]:
            if row["answered"]:
                continue
            got = mcp_server.call_tool(
                "get_request", {"workdir": w, "request_id": row["request_id"]}
            )

            class _Shim:
                payload = got["request"]["context_packet"]

            sub = mcp_server.call_tool(
                "submit_answer",
                {"workdir": w, "request_id": row["request_id"],
                 "content": oracle_responder(_Shim())},
            )
            assert sub["state"] == "ok", sub
    raise AssertionError("tool-driven scan did not settle")


def _artifacts(root: Path) -> dict[str, str]:
    """Canonical artifact contents with per-run values (scan id, absolute root) removed."""
    out: dict[str, str] = {}
    base = root / ".secscan"
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.suffix not in (".json", ".md", ".html"):
            continue
        if path.name == "state.json" or path.parent.name == "responses":
            continue
        text = path.read_text()
        for prefix in (str(root.resolve()), str(root)):
            text = text.replace(prefix, "<ROOT>")
        if path.suffix == ".json":
            doc = json.loads(text)
            if isinstance(doc, dict):
                doc.pop("scan_id", None)
                if isinstance(doc.get("payload"), dict):
                    doc["payload"].pop("scan_id", None)
            text = json.dumps(doc, sort_keys=True)
        else:
            import re

            text = re.sub(r"\d{8}T\d{6}Z-[0-9a-f]{6}", "<SCAN-ID>", text)
        rel = path.relative_to(base).as_posix()
        rel = rel.replace(path.stem, "<SCAN-ID>") if path.parent.name == "reports" else rel
        out[rel] = text
    return out


def test_skill_and_plugin_forms_produce_identical_artifacts(tmp_path: Path) -> None:
    skill_root = build_shop(tmp_path / "skill")
    plugin_root = build_shop(tmp_path / "plugin")
    for root in (skill_root, plugin_root):
        write_config(root, {"triage": {"enabled": "off"}})

    _skill_driven(skill_root)
    _tool_driven(plugin_root, time_budget_s=3600)

    left, right = _artifacts(skill_root), _artifacts(plugin_root)
    assert set(left) == set(right)
    for key in sorted(left):
        assert left[key] == right[key], f"{key} differs between skill and plugin forms"


def test_bounded_pauses_do_not_change_artifacts(tmp_path: Path, monkeypatch) -> None:
    """Many `in_progress` rounds (a tiny bound with an accelerated clock) settle to
    the same artifacts as an uninterrupted tool-driven run (SC-005)."""
    steady = build_shop(tmp_path / "steady")
    paused = build_shop(tmp_path / "paused")
    for root in (steady, paused):
        write_config(root, {"triage": {"enabled": "off"}})

    _tool_driven(steady, time_budget_s=3600)

    import time as _time

    real = _time.monotonic
    state = {"offset": 0.0}

    def fast_clock() -> float:
        state["offset"] += 3.0  # every boundary check advances 3 s: a 5 s bound trips often
        return real() + state["offset"]

    monkeypatch.setattr(_time, "monotonic", fast_clock)
    _tool_driven(paused, time_budget_s=5)

    left, right = _artifacts(steady), _artifacts(paused)
    assert set(left) == set(right)
    for key in sorted(left):
        assert left[key] == right[key], f"{key} differs after bounded pauses"
