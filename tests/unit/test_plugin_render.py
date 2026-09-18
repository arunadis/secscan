"""Committed plugin files are renders of the single skill source (feature 018,
FR-018, FR-019, SC-007; contracts/plugin-manifests.md §6)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from installer import plugin
from installer.agents import ADAPTERS
from installer.agents.base import (
    DRIVER_MARKER,
    driver_text,
    render_skill,
    skill_source_text,
    split_frontmatter,
    strip_driver,
)
from installer.core import SKILL_NAME
from pipeline.state import TOOL_VERSION

REPO = Path(__file__).resolve().parents[2]


def test_render_produces_exactly_the_contract_files() -> None:
    assert tuple(sorted(plugin.render_all(REPO))) == tuple(sorted(plugin.RENDERED_FILES))


def test_committed_files_match_their_render() -> None:
    stale = plugin.check(REPO)
    assert stale == [], f"stale plugin files: {stale} — run `secscan plugin render`"


def test_versions_and_descriptions_are_single_sourced() -> None:
    front, _ = split_frontmatter(skill_source_text())
    description = " ".join(str(front["description"]).split())
    for relative in ("plugin.json", ".claude-plugin/plugin.json", "gemini-extension.json"):
        doc = json.loads((REPO / relative).read_text())
        assert doc["version"] == TOOL_VERSION, relative
        assert doc["description"] == description, relative
        assert doc["name"] == SKILL_NAME
    skill_front, _ = split_frontmatter((REPO / "skills/secscan/SKILL.md").read_text())
    assert skill_front["metadata"]["version"] == TOOL_VERSION
    assert "description = " in (REPO / "commands/secscan.toml").read_text()


def test_plugin_skill_shares_the_core_body_with_every_skill_render() -> None:
    plugin_body = strip_driver((REPO / "skills/secscan/SKILL.md").read_text())
    assert DRIVER_MARKER in plugin_body, "the tools driver must be recognised and stripped"
    assert "secscan_submit_answer" not in plugin_body, "driver text fully stripped"
    core = skill_source_text()
    for key, adapter in sorted(ADAPTERS.items()):
        if key == "gemini":
            continue  # TOML translation, compared via test_install_matrix golden
        skill_body = strip_driver(adapter.render_entrypoint(core, SKILL_NAME))
        _, plugin_text = split_frontmatter(plugin_body)
        _, skill_text = split_frontmatter(skill_body)
        assert plugin_text == skill_text, f"{key}: body differs from the plugin skill"


def test_drivers_differ_only_in_how_the_pipeline_is_invoked() -> None:
    shell = render_skill("shell")
    tools = render_skill("tools")
    assert shell.replace(driver_text("shell").rstrip("\n"), DRIVER_MARKER) == tools.replace(
        driver_text("tools").rstrip("\n"), DRIVER_MARKER
    )
    assert "python -m pipeline.scan_cli" in shell and "python -m pipeline.scan_cli" not in tools
    assert "secscan_run" in tools and "secscan_run" not in shell


def test_check_reports_drift_when_source_changes(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "plugin"
    root.mkdir()
    plugin.write_all(root)
    assert plugin.check(root) == []

    # Mutate the single source (in a copy) and re-render: the derived files drift.
    core_copy = tmp_path / "SKILL.md"
    shutil.copy(REPO / "src" / "skill_core" / "SKILL.md", core_copy)
    mutated = core_copy.read_text().replace("## Objective", "## Objective (edited)")
    monkeypatch.setattr("installer.agents.base.skill_source_text", lambda: mutated)
    stale = plugin.check(root)
    assert "skills/secscan/SKILL.md" in stale
    assert "commands/secscan.toml" in stale
    # metadata files did not change (description/version untouched)
    assert "plugin.json" not in stale


def test_write_all_is_idempotent(tmp_path: Path) -> None:
    root = tmp_path / "plugin"
    root.mkdir()
    first = plugin.write_all(root)
    assert sorted(first) == sorted(plugin.RENDERED_FILES)
    assert plugin.write_all(root) == []


def test_find_plugin_root_from_checkout_and_failure(tmp_path: Path) -> None:
    assert plugin.find_plugin_root() == REPO
    with pytest.raises(plugin.PluginError):
        plugin.find_plugin_root(tmp_path / "nowhere" / "deep")
