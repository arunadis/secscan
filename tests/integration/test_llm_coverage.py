"""Spec 007, T047: coverage honesty for the modern-exploit category.

- Undetermined LLM integration postures are declared (never silent exclusion).
- The new AI file classes appear in the per-file-class coverage statement.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from pipeline import run as run_mod
from tests.integration.conftest import silent_responder, write_config

FIXTURES = Path("tests/fixtures/llm_workspace")


def _scan(fixture: str | Path, tmp_path: Path) -> tuple[Path, dict]:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURES / fixture, root)
    write_config(root)
    result = run_mod.run_scan(root, responder=silent_responder, full=True)
    report = json.loads(Path(result.report_json_path).read_text())["payload"]
    return root, report


def test_undetermined_integration_posture_is_declared(tmp_path) -> None:
    _, report = _scan(Path("undetermined"), tmp_path)
    gaps = report["coverage"]["gaps"]
    assert any("undetermined" in gap and "triage.py" in gap for gap in gaps), (
        f"undetermined posture not declared: {gaps}"
    )


def test_ai_file_classes_appear_in_the_coverage_statement(tmp_path) -> None:
    _, report = _scan(Path("us3_agent_config") / "scoped", tmp_path)
    classes = {entry["file_class"] for entry in report["coverage"]["file_classes"]}
    assert {"ai-agent-config", "ai-mcp-config", "prompt-artifact"} <= classes
    represented = {
        entry["file_class"]: entry["represented"]
        for entry in report["coverage"]["file_classes"]
    }
    assert represented["ai-agent-config"] >= 1
    assert represented["ai-mcp-config"] >= 1


def test_clean_repo_emits_no_undetermined_posture(tmp_path) -> None:
    _, report = _scan(Path("us1_direct") / "safe", tmp_path)
    assert not any("undetermined" in gap for gap in report["coverage"].get("gaps", []))
