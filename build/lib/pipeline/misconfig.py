"""Deterministic security-misconfiguration detection (feature 004, FR-001).

A versioned rule pack (`misconfig_rules.json`) of anchored patterns over the raw
text of glob-selected files. Three properties matter (research.md R1):

- **Redaction-independent** (FR-002): evaluation reads raw source and matches
  call/configuration *shape*, never values — a blocked secret elsewhere in the
  file cannot change the outcome.
- **Value-free findings**: findings carry file, line, and rule id; matched text
  is never copied into a finding or artifact (Principle III).
- **Data-driven** (FR-003): adding a rule is a data-only change.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from pipeline import cwe, resources
from pipeline.state import iter_source_files

DATA_FILE = "misconfig_rules.json"

#: deterministic rule match, not a model judgement
_CONFIDENCE = 0.9


class InvalidRuleData(RuntimeError):
    """Rule data that fails validation fails the build, not the scan."""


def load_rules() -> list[dict[str, Any]]:
    """The validated rule pack (controls.py load-time validation precedent)."""
    document = json.loads(resources.data_path(DATA_FILE).read_text())
    rules = document["rules"]
    ids: set[str] = set()
    for rule in rules:
        if rule["id"] in ids:
            raise InvalidRuleData(f"duplicate rule id: {rule['id']}")
        ids.add(rule["id"])
        required = (
            "stacks", "file_globs", "pattern", "cwe", "title", "description", "recommendation"
        )
        for field in required:
            if not rule.get(field):
                raise InvalidRuleData(f"{rule['id']}: missing {field}")
        try:
            re.compile(rule["pattern"])
        except re.error as exc:
            raise InvalidRuleData(f"{rule['id']}: pattern does not compile: {exc}") from exc
        cwe.validate_cwe(rule["cwe"])
    return rules


@dataclass(frozen=True)
class _Compiled:
    rule: dict[str, Any]
    pattern: re.Pattern[str]


def _matches(path: str, globs: list[str]) -> bool:
    # fnmatch is not path-aware ('*' crosses separators), but a glob containing a
    # literal '/' still requires one — so '**/*.go' misses a root-level main.go.
    # Try each glob with and without a leading '**/'.
    lowered = path.lower()
    for glob in globs:
        glob = glob.lower()
        if fnmatch(lowered, glob):
            return True
        if glob.startswith("**/") and fnmatch(lowered, glob[3:]):
            return True
    return False


def evaluate_files(
    files: dict[str, str], repo: str, rules: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """Evaluate rules over ``{repo-relative path: raw text}``."""
    compiled = [_Compiled(rule, re.compile(rule["pattern"])) for rule in (rules or load_rules())]
    findings: list[dict[str, Any]] = []
    for entry in compiled:
        rule = entry.rule
        for path in sorted(files):
            if not _matches(path, rule["file_globs"]):
                continue
            for match in entry.pattern.finditer(files[path]):
                line = files[path].count("\n", 0, match.start()) + 1
                findings.append(_finding(rule, repo, path, line))
    return findings


def run(roots: dict[str, Path]) -> list[dict[str, Any]]:
    """Evaluate the rule pack over every workspace member's enumerated files."""
    findings: list[dict[str, Any]] = []
    for repo in sorted(roots):
        files: dict[str, str] = {}
        for path in iter_source_files(roots[repo]):
            relative = str(path.relative_to(roots[repo]))
            files[relative] = path.read_text(errors="replace")
        findings.extend(evaluate_files(files, repo))
    return findings


def _finding(rule: dict[str, Any], repo: str, path: str, line: int) -> dict[str, Any]:
    return {
        "cwe": rule["cwe"],
        "severity_score": float(rule["severity_score"]),
        "confidence": _CONFIDENCE,
        # A deterministic rule match is a presence finding: the dangerous state
        # is visible at the location, which is itself the finding.
        "detection": "format",
        "location": {"repo": repo, "file": path, "line_start": line, "line_end": line},
        "description": f"{rule['title']}: {rule['description']}",
        "evidence": [
            {
                "repo": repo,
                "file": path,
                "reason": f"misconfiguration rule '{rule['id']}' matched at line {line}",
            }
        ],
        "recommendation": rule["recommendation"],
        "tool_ref": f"misconfig:{rule['id']}",
    }
