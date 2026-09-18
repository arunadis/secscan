"""Committed plugin manifests conform to Agent Plugins 1.0.0 and the vendor layouts
(feature 018, FR-002, FR-003; contracts/plugin-manifests.md §6). Schemas are vendored
in tests/fixtures/agent_plugins/ — tests never fetch."""

from __future__ import annotations

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator

from installer import plugin

REPO = Path(__file__).resolve().parents[2]
SCHEMAS = REPO / "tests" / "fixtures" / "agent_plugins"
NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


def _load(relative: str) -> dict:
    return json.loads((REPO / relative).read_text())


def _validate(schema_name: str, document: dict) -> None:
    schema = json.loads((SCHEMAS / f"{schema_name}.schema.json").read_text())
    errors = sorted(Draft202012Validator(schema).iter_errors(document), key=lambda e: list(e.path))
    assert not errors, [f"{'/'.join(map(str, e.path))}: {e.message}" for e in errors]


def test_plugin_json_validates_against_agent_plugins_schema() -> None:
    doc = _load("plugin.json")
    _validate("plugin", doc)
    assert doc["$schema"] == plugin.AGENT_PLUGINS_SCHEMA
    assert NAME_RE.match(doc["name"]) and "--" not in doc["name"] and ".." not in doc["name"]


def test_mcp_json_validates_and_has_only_the_two_top_level_keys() -> None:
    doc = _load("mcp.json")
    _validate("mcp", doc)
    assert set(doc) == {"$schema", "mcpServers"}
    server = doc["mcpServers"]["secscan"]
    assert server["type"] == "stdio"
    assert server["command"] == "uv" and "/" not in server["command"], "bare executable token"
    assert server["cwd"] == "${PLUGIN_ROOT}"
    assert "${PLUGIN_ROOT}" in server["args"]
    assert server["env"] == {"UV_PROJECT_ENVIRONMENT": "${PLUGIN_DATA}/venv"}


def test_vendor_entries_differ_only_in_the_root_placeholder() -> None:
    base = _load("mcp.json")["mcpServers"]["secscan"]
    claude = _load(".mcp.json")["mcpServers"]["secscan"]
    gemini = _load("gemini-extension.json")["mcpServers"]["secscan"]
    normalise = lambda args, ph: [a.replace(ph, "<ROOT>") for a in args]  # noqa: E731
    assert normalise(base["args"], "${PLUGIN_ROOT}") == normalise(
        claude["args"], "${CLAUDE_PLUGIN_ROOT}"
    ) == normalise(gemini["args"], "${extensionPath}")
    assert base["command"] == claude["command"] == gemini["command"] == "uv"
    assert gemini["cwd"] == "${extensionPath}"


def test_claude_manifest_shape() -> None:
    doc = _load(".claude-plugin/plugin.json")
    assert NAME_RE.match(doc["name"])
    assert set(doc) >= {"name", "version", "description"}
    assert not (REPO / ".claude-plugin" / "skills").exists(), "skills live at the plugin root"
    assert (REPO / "skills" / "secscan" / "SKILL.md").is_file()


def test_gemini_extension_shape() -> None:
    doc = _load("gemini-extension.json")
    assert set(doc) >= {"name", "version", "mcpServers"}
    assert (REPO / "commands" / "secscan.toml").is_file()
    toml = (REPO / "commands" / "secscan.toml").read_text()
    assert toml.startswith("# secscan") and 'prompt = """' in toml


def test_no_committed_plugin_file_contains_an_absolute_path() -> None:
    for relative in plugin.RENDERED_FILES:
        text = (REPO / relative).read_text()
        assert "/Users/" not in text and "/home/" not in text, relative
