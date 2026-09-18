"""User-level plugin registration (feature 018, FR-013, FR-014, FR-016; research R2)."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from installer import plugin
from installer.agents import ADAPTERS
from installer.upgrade import DowngradeRefused
from pipeline.state import TOOL_VERSION

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def home(tmp_path: Path) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    return h


def _env(home: Path, path_dir: Path | None = None) -> dict[str, str]:
    env = {"HOME": str(home), "PATH": str(path_dir) if path_dir else "/nonexistent"}
    return env


def _fake_cli(bin_dir: Path, name: str, exit_code: int = 0) -> Path:
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / name
    script.write_text(f'#!/bin/sh\necho "$@" > "{bin_dir}/{name}.argv"\nexit {exit_code}\n')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


class _NoRun:
    """subprocess.run stand-in that records but never executes (provisioning off)."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))

        class _P:
            returncode = 0
            stdout = ""
            stderr = ""

        return _P()


def test_every_adapter_declares_a_coherent_plugin_descriptor() -> None:
    for key, adapter in ADAPTERS.items():
        if adapter.plugin_layout == "none":
            assert key == "agents"
            continue
        assert adapter.user_mcp_config or adapter.register_command, key
        assert adapter.plugin_layout in ("agent-plugins", "claude", "gemini", "mcp-only"), key
        if adapter.register_command:
            assert adapter.register_command[0] in ("claude", "gemini")


@pytest.mark.parametrize("agent", ["cursor", "copilot", "windsurf", "devin"])
def test_json_merge_hosts(home: Path, agent: str) -> None:
    adapter = ADAPTERS[agent]
    target = Path(adapter.user_mcp_config.replace("~", str(home), 1))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}, "theme": "dark"}))

    result = plugin.register(agent, REPO, environ=_env(home), skip_provision=True)
    doc = json.loads(target.read_text())
    assert doc["theme"] == "dark" and doc["mcpServers"]["other"] == {"command": "x"}
    entry = doc["mcpServers"]["secscan"]
    assert entry["command"] == "uv"
    assert entry["args"] == ["run", "--project", str(REPO), "--extra", "plugin", "secscan", "mcp"]
    assert "${PLUGIN_ROOT}" not in json.dumps(entry), "absolute root substituted"
    assert result.registered_via == "json-merge" and result.registered_in == str(target)

    # idempotent
    plugin.register(agent, REPO, environ=_env(home), skip_provision=True)
    assert json.loads(target.read_text()) == doc

    record = plugin.read_record(_env(home))
    assert record["installs"][agent]["form"] == "plugin"
    assert record["installs"][agent]["tool_version"] == TOOL_VERSION
    assert record["installs"][agent]["registered_in"] == str(target)
    expected = home / ".config" / "secscan" / "plugin-installs.json"
    assert plugin.user_record_path(_env(home)) == expected


def test_claude_uses_host_cli_and_fails_without_it(home: Path, tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    _fake_cli(bin_dir, "claude")
    result = plugin.register("claude", REPO, environ=_env(home, bin_dir), skip_provision=True)
    assert result.registered_via == "host-cli"
    argv = (bin_dir / "claude.argv").read_text()
    assert argv.startswith("mcp add-json --scope user secscan ")
    assert '"command": "uv"' in argv
    assert result.install_hint == f"claude --plugin-dir {REPO}"

    with pytest.raises(plugin.PluginError) as exc:
        plugin.register("claude", REPO, environ=_env(home), skip_provision=True)
    assert "claude" in str(exc.value) and "PATH" in str(exc.value)
    assert not (home / ".claude.json").exists(), "never edits the host-owned file"


def test_gemini_prefers_cli_and_falls_back_to_settings(home: Path, tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    _fake_cli(bin_dir, "gemini")
    result = plugin.register("gemini", REPO, environ=_env(home, bin_dir), skip_provision=True)
    assert result.registered_via == "host-cli"
    assert (bin_dir / "gemini.argv").read_text().strip() == f"extensions install {REPO}"

    result = plugin.register("gemini", REPO, environ=_env(home), skip_provision=True)
    assert result.registered_via == "json-merge"
    settings = json.loads((home / ".gemini" / "settings.json").read_text())
    assert "secscan" in settings["mcpServers"]
    assert any("gemini not found" in n for n in result.notes)


def test_host_cli_failure_is_reported(home: Path, tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    _fake_cli(bin_dir, "claude", exit_code=3)
    with pytest.raises(plugin.PluginError) as exc:
        plugin.register("claude", REPO, environ=_env(home, bin_dir), skip_provision=True)
    assert "failed (3)" in str(exc.value)


def test_unwritable_target_names_the_path_and_writes_nothing(home: Path) -> None:
    target_dir = home / ".cursor"
    target_dir.mkdir()
    target_dir.chmod(0o500)
    try:
        with pytest.raises(plugin.PluginError) as exc:
            plugin.register("cursor", REPO, environ=_env(home), skip_provision=True)
        assert str(target_dir / "mcp.json") in str(exc.value)
        assert not plugin.user_record_path(_env(home)).exists()
    finally:
        target_dir.chmod(0o700)


def test_agents_target_has_no_plugin_form(home: Path) -> None:
    with pytest.raises(plugin.PluginError) as exc:
        plugin.register("agents", REPO, environ=_env(home), skip_provision=True)
    assert "no plugin form" in str(exc.value)


def test_not_a_plugin_root(home: Path, tmp_path: Path) -> None:
    with pytest.raises(plugin.PluginError):
        plugin.register("cursor", tmp_path, environ=_env(home), skip_provision=True)


def test_downgrade_refused_unless_forced(home: Path, monkeypatch) -> None:
    record = {"record_version": 1, "installs": {"cursor": {
        "form": "plugin", "tool_version": "9.9.9", "plugin_root": str(REPO),
        "registered_in": "x", "registered_via": "json-merge", "installed_at": "t"}}}
    plugin.write_record(record, _env(home))
    with pytest.raises(DowngradeRefused):
        plugin.register("cursor", REPO, environ=_env(home), skip_provision=True)
    result = plugin.register("cursor", REPO, environ=_env(home), skip_provision=True, force=True)
    assert result.previous_version == "9.9.9"
    assert plugin.read_record(_env(home))["installs"]["cursor"]["tool_version"] == TOOL_VERSION


def test_provision_uses_uv_when_present(home: Path, tmp_path: Path) -> None:
    runner = _NoRun()
    bin_dir = tmp_path / "bin"
    _fake_cli(bin_dir, "uv")
    note = plugin.provision(REPO, run=runner, environ=_env(home, bin_dir))
    assert note is None
    assert runner.calls and runner.calls[0][1:] == ["sync", "--extra", "plugin"]
    note = plugin.provision(REPO, run=runner, environ=_env(home))
    assert note and "uv not found" in note and "pip install" in note


def test_windows_devin_path_uses_appdata(home: Path) -> None:
    env = {"HOME": str(home), "APPDATA": str(home / "AppData")}
    path = plugin._expand_user_path(ADAPTERS["devin"].user_mcp_config, "devin", env, windows=True)
    assert path == home / "AppData" / "devin" / "mcp_config.json"
