"""T030: the skill's business-flow ask/remember contract (feature 015, FR-003).

A true interactive conversation belongs to the host agent, so this tests the two
things the pipeline owns: the installed SKILL.md instructs the ask/remember
behavior exactly, and the config round-trip from "remember" (writing
``business_flow.enabled`` into `.secscan/config.yaml`) flips the scan between
skipped and running.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from installer import core as installer
from tests.fixtures.flow_app import build
from tests.integration.conftest import write_config


@pytest.fixture
def installed_flow_app(tmp_path: Path) -> tuple[Path, Path]:
    repo = build(tmp_path)
    result = installer.install(repo, "devin")
    write_config(repo)
    return result.skill_dir, repo / ".secscan" / "config.yaml"


def _run(skill_dir: Path, repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pipeline.scan_cli", "run", "--workdir", str(repo)],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(skill_dir / "scripts")},
        timeout=300,
    )


def test_skill_instructs_ask_and_remember(installed_flow_app):
    skill_dir, _ = installed_flow_app
    text = (skill_dir / "SKILL.md").read_text()
    # The ask fires only when no preference exists, and remembering is opt-in.
    assert "business_flow.enabled" in text
    assert "ask the user" in text
    assert "remember this choice" in text
    assert "off by default" in text
    # Non-interactive runs never block on the question (FR-004).
    assert "never" in text.lower() and "block" in text.lower()
    assert "prompts/business_flow.md" in text
    assert "schemas/flow_answer.json" in text


def test_unset_preference_runs_skip_flow_analysis(installed_flow_app):
    skill_dir, config_path = installed_flow_app
    repo = config_path.parent.parent
    assert "business_flow" not in config_path.read_text() or "enabled" not in yaml.safe_load(
        config_path.read_text()
    ).get("business_flow", {})
    proc = _run(skill_dir, repo)
    # Exit 3 = reasoning handoff awaited; the flow stages must NOT have run.
    assert proc.returncode == 3
    assert not (repo / ".secscan" / "business-flows.json").exists()


def test_remembered_preference_enables_the_round(installed_flow_app):
    skill_dir, config_path = installed_flow_app
    repo = config_path.parent.parent
    # Simulate the agent honoring an explicit "remember: yes".
    data = yaml.safe_load(config_path.read_text()) or {}
    data["business_flow"] = {"enabled": True}
    config_path.write_text(yaml.safe_dump(data, sort_keys=False))

    proc = _run(skill_dir, repo)
    assert proc.returncode == 3
    flows_doc = json.loads((repo / ".secscan" / "business-flows.json").read_text())
    assert flows_doc["payload"]["flows"], "model stage must reconstruct flows"
    # Handoff must include the flow requests, one per flow.
    pending = list((repo / ".secscan" / "handoff" / "requests").glob("flow-*.json"))
    assert len(pending) == len(flows_doc["payload"]["flows"])
