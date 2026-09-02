"""Spec 007, T032: agent/tool configuration review unit tests."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from pipeline import agent_config
from pipeline.agent_config import InvalidRuleData
from pipeline.redact import Redactor

OVERPRIVILEGED_MCP = json.dumps(
    {
        "mcpServers": {
            "shell": {
                "command": "bash",
                "args": ["-c"],
                "alwaysAllow": ["*"],
            }
        }
    }
)

SCOPED_MCP = json.dumps(
    {
        "mcpServers": {
            "fs": {
                "command": "uvx",
                "args": ["mcp-server-fs", "/workspace/docs"],
                "requireApproval": True,
            }
        }
    }
)

AUTO_APPROVE_MD = "# Agent rules\n\nauto-approve: all\n"

UNRESTRICTED_WRITE_MD = (
    "# Agent rules\n\ngrant full filesystem write access to the agent\n"
)

SCOPED_MD = (
    "# Agent rules\n\nAllow reads in ./docs. Require approval for writes.\n"
)


def _root(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return root


def test_shell_with_arbitrary_command_channel_is_flagged() -> None:
    root = _root({"mcp.json": OVERPRIVILEGED_MCP})
    review = agent_config.run({"svc": root})
    shell = [
        f
        for f in review.findings
        if f["tool_ref"] == "agent-config:mcp-shell-arbitrary-command"
    ]
    assert shell
    assert shell[0]["cwe"] == "CWE-250"
    assert shell[0]["mitigation"]["control"] == "human-approval"


def test_wildcard_auto_approval_is_flagged() -> None:
    root = _root({"mcp.json": OVERPRIVILEGED_MCP})
    review = agent_config.run({"svc": root})
    assert any(
        f["tool_ref"] == "agent-config:mcp-auto-approve-all-tools" for f in review.findings
    )


def test_scoped_config_is_silent() -> None:
    root = _root({"mcp.json": SCOPED_MCP, "AGENTS.md": SCOPED_MD})
    review = agent_config.run({"svc": root})
    assert review.findings == [], f"false positives: {[f['tool_ref'] for f in review.findings]}"
    assert not review.secret_hits


@pytest.mark.parametrize(
    ("content", "rule_id"),
    [
        (AUTO_APPROVE_MD, "agent-config:agent-rules-auto-approve-everything"),
        (UNRESTRICTED_WRITE_MD, "agent-config:agent-rules-unrestricted-filesystem-write"),
    ],
)
def test_anchor_patterns_over_agent_rule_files(content: str, rule_id: str) -> None:
    root = _root({"CLAUDE.md": content})
    review = agent_config.run({"svc": root})
    matched = [f for f in review.findings if f["tool_ref"] == rule_id]
    assert matched, f"{rule_id} missed"
    assert matched[0]["location"]["file"] == "CLAUDE.md"


def test_matched_values_never_enter_a_finding() -> None:
    """Value-free: findings carry rule id and location, never matched text."""
    root = _root({"CLAUDE.md": AUTO_APPROVE_MD})
    review = agent_config.run({"svc": root})
    rendered = json.dumps(review.findings)
    assert "auto-approve: all" not in rendered  # the matched line itself


def test_embedded_credentials_become_secret_hits_never_values() -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"
    root = _root({"system_prompt.txt": f"You are helpful. Key: {secret}"})
    review = agent_config.run({"svc": root}, redactor=Redactor())
    matching = [h for h in review.secret_hits if h.origin == "system_prompt.txt"]
    assert matching, "embedded credential not detected in prompt artifact"
    assert all(secret not in json.dumps(f) for f in review.findings)


def test_invalid_rule_data_fails_the_build(tmp_path, monkeypatch) -> None:
    bad = {
        "id": "bad-rule",
        "form": "anchored-pattern",
        "file_classes": ["ai-agent-config"],
        "grant": "shell-exec",
        "pattern": "(unclosed",
        "cwe": "CWE-250",
        "title": "t",
        "description": "d",
        "recommendation": "r",
    }
    payload = tmp_path / "agent_config_rules.json"
    payload.write_text(json.dumps({"version": "9", "dataset_date": "x", "rules": [bad]}))
    monkeypatch.setattr(agent_config.resources, "data_path", lambda _name: payload)
    with pytest.raises(InvalidRuleData):
        agent_config.load_rules()
