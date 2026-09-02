"""Deterministic review of shipped AI configuration artifacts (spec 007, FR-005, R8).

Two evaluation forms, declared per rule in ``agent_config_rules.json``:

- ``structural`` — MCP-style tool configurations are parsed as JSON; grants are
  asserted from structure (shell delegation, wildcard auto-approval), so no
  wording trick dodges the rule.
- ``anchored-pattern`` — markdown agent rule files are matched over **redacted**
  text (the redactor runs first), so credentials embedded in the artifacts can
  neither influence classification nor leak into a finding.

Findings are value-free (file, line, rule id, granted capability — never the
matched text), like misconfig. Embedded credentials additionally surface as
secret findings via the redactor, whose labels are reportable while values stay
nowhere.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pipeline import cwe, resources, stacks
from pipeline.redact import Redactor, SecretHit
from pipeline.state import iter_source_files

DATA_FILE = "agent_config_rules.json"

#: deterministic rule match, not a model judgement (misconfig precedent)
_CONFIDENCE = 0.9

#: shell interpreters whose ``-c`` channel accepts arbitrary command strings
_SHELLS = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}

#: config keys that gate actions behind human approval
_APPROVAL_KEYS = ("requireApproval", "requiresApproval", "confirm", "confirmation")

#: auto-approval key variants and the wildcard grant value
_AUTO_APPROVE_KEYS = ("autoApprove", "alwaysAllow", "auto-approve")


class InvalidRuleData(RuntimeError):
    """Rule data that fails validation fails the build, not the scan."""


def load_rules() -> list[dict[str, Any]]:
    """The validated rule pack (misconfig load-time validation precedent)."""
    document = json.loads(resources.data_path(DATA_FILE).read_text())
    rules = document["rules"]
    ids: set[str] = set()
    for rule in rules:
        if rule["id"] in ids:
            raise InvalidRuleData(f"duplicate rule id: {rule['id']}")
        ids.add(rule["id"])
        required = (
            "id",
            "form",
            "file_classes",
            "grant",
            "cwe",
            "title",
            "description",
            "recommendation",
        )
        for field_name in required:
            if not rule.get(field_name):
                raise InvalidRuleData(f"{rule['id']}: missing {field_name}")
        if rule["form"] == "anchored-pattern":
            try:
                re.compile(rule["pattern"])
            except re.error as exc:
                raise InvalidRuleData(
                    f"{rule['id']}: pattern does not compile: {exc}"
                ) from exc
        elif rule["form"] == "structural":
            if "ai-mcp-config" not in rule["file_classes"]:
                raise InvalidRuleData(
                    f"{rule['id']}: structural rules evaluate MCP configuration "
                    "(file_classes must include ai-mcp-config)"
                )
        else:
            raise InvalidRuleData(f"{rule['id']}: unknown form {rule['form']}")
        cwe.validate_cwe(rule["cwe"])
    return rules


@dataclass
class ConfigReview:
    findings: list[dict[str, Any]] = field(default_factory=list)
    secret_hits: list[SecretHit] = field(default_factory=list)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _finding(rule: dict[str, Any], repo: str, path: str, line: int) -> dict[str, Any]:
    return {
        "cwe": rule["cwe"],
        "confidence": _CONFIDENCE,
        "location": {"repo": repo, "file": path, "line_start": line},
        "description": f"{rule['title']} (grant: {rule['grant']})",
        "evidence": [
            {
                "repo": repo,
                "file": path,
                "reason": (
                    f"rule {rule['id']}: grants {rule['grant']} without a "
                    "demonstrated approval gate"
                ),
            }
        ],
        "attack_scenario": (
            "An injected instruction reaches the agent and exercises the "
            "over-privileged grant without human review."
        ),
        "impact": "The agent performs consequential actions outside its intended authority.",
        "recommendation": rule["recommendation"],
        "mitigation": {
            "control": "human-approval",
            "state": "undetermined",
            "reason": "no approval gate is demonstrated in the shipped configuration",
        },
        "tool_ref": f"agent-config:{rule['id']}",
    }


def _evaluate_structural(
    rule: dict[str, Any], repo: str, path: str, text: str
) -> list[dict[str, Any]]:
    """Assert grants from parsed MCP-style JSON configuration."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return []
    servers = document.get("mcpServers") or document.get("servers") or {}
    if not isinstance(servers, dict):
        return []
    findings: list[dict[str, Any]] = []
    for name in sorted(servers):
        server = servers[name]
        if not isinstance(server, dict):
            continue
        command = str(server.get("command", "")).rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        args = server.get("args") or []
        gated = any(key in server for key in _APPROVAL_KEYS)
        line = _line_of(text, text.find(f'"{name}"')) if f'"{name}"' in text else 1
        hit = False
        if rule["grant"] == "shell-exec":
            hit = command in _SHELLS and "-c" in [str(a) for a in args] and not gated
        elif rule["grant"] == "tool-auto-approve":
            for key in _AUTO_APPROVE_KEYS:
                grants = server.get(key)
                if isinstance(grants, list) and "*" in grants and not gated:
                    hit = True
        if hit:
            findings.append(_finding(rule, repo, path, line))
    return findings


def _evaluate_pattern(
    rule: dict[str, Any], repo: str, path: str, redacted_text: str
) -> list[dict[str, Any]]:
    pattern = re.compile(rule["pattern"])
    return [
        _finding(rule, repo, path, _line_of(redacted_text, match.start()))
        for match in pattern.finditer(redacted_text)
    ]


def run(
    roots: dict[str, Path],
    redactor: Redactor | None = None,
    rules: list[dict[str, Any]] | None = None,
) -> ConfigReview:
    """Evaluate the rule pack over every workspace member's AI artifacts."""
    rules = rules if rules is not None else load_rules()
    redactor = redactor or Redactor()
    review = ConfigReview()
    for repo in sorted(roots):
        for path in iter_source_files(roots[repo]):
            relative = str(path.relative_to(roots[repo]))
            file_class = stacks.file_class_for(path.name)
            if file_class not in ("ai-agent-config", "ai-mcp-config", "prompt-artifact"):
                continue
            try:
                raw_text = path.read_text(errors="replace")
            except OSError:
                continue
            # Redact before any evaluation or serialization (FR-009): matches
            # run over the redacted view, and credential hits become findings
            # whose values appear nowhere.
            result = redactor.redact(raw_text, origin=relative)
            review.secret_hits.extend(result.hits)
            for rule in rules:
                if file_class not in rule["file_classes"]:
                    continue
                if rule["form"] == "structural":
                    review.findings.extend(
                        _evaluate_structural(rule, repo, relative, result.text)
                    )
                else:
                    review.findings.extend(
                        _evaluate_pattern(rule, repo, relative, result.text)
                    )
    review.findings.sort(
        key=lambda f: (
            f["location"]["repo"],
            f["location"]["file"],
            f["location"]["line_start"],
            f["tool_ref"],
        )
    )
    review.secret_hits.sort(key=lambda h: (h.origin, h.line, h.label))
    return review
