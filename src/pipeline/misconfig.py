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


# ----------------------------------------------------- integration evidence (014)


#: Manifest files scanned for `packages` markers, per member root.
_MANIFEST_NAMES = (
    "package.json", "requirements.txt", "pyproject.toml", "pom.xml", "build.gradle", "go.mod"
)

STATE_INTEGRATED = "integrated"
STATE_NO_INTEGRATION = "no-integration-found"
STATE_UNDETERMINED_INTEGRATION = "undetermined"


def _manifest_texts(root: Path) -> dict[str, str]:
    texts: dict[str, str] = {}
    for name in _MANIFEST_NAMES:
        path = root / name
        if path.exists():
            try:
                texts[name] = path.read_text(errors="replace")
            except OSError:
                continue
    return texts


def attach_integration(
    findings: list[dict[str, Any]],
    roots: dict[str, Path],
    rules: list[dict[str, Any]] | None = None,
) -> None:
    """Attach an ``integration`` block to every misconfig finding (FR-004).

    Three states, mirroring the usage-evidence contract: `integrated` (markers
    hit, evidence listed), `no-integration-found` (rule carries markers, all
    evaluated, zero hits — remediation shifts to removal), and `undetermined`
    (rule lacks markers, or evidence could not be read). Neither of the latter
    two suppresses the finding, and undetermined never inflates it.
    """
    index = {rule["id"]: rule for rule in (rules if rules is not None else load_rules())}
    file_cache: dict[str, list[tuple[str, str]]] = {}
    for finding in findings:
        tool_ref = str(finding.get("tool_ref") or "")
        if not tool_ref.startswith("misconfig:"):
            continue
        rule_id = tool_ref.split(":", 1)[1]
        rule = index.get(rule_id)
        repo = str((finding.get("location") or {}).get("repo") or "")
        root = roots.get(repo)
        if rule is None:
            finding["integration"] = {
                "state": STATE_UNDETERMINED_INTEGRATION,
                "reason": f"no rule '{rule_id}' in the shipped pack",
            }
            continue
        markers = rule.get("integration_markers")
        if not markers:
            finding["integration"] = {
                "state": STATE_UNDETERMINED_INTEGRATION,
                "reason": f"rule '{rule_id}' carries no integration markers",
            }
            continue
        if root is None or not Path(root).exists():
            finding["integration"] = {
                "state": STATE_UNDETERMINED_INTEGRATION,
                "reason": f"member '{repo}' root unavailable; markers not evaluable",
            }
            continue

        evidence: list[dict[str, Any]] = []
        packages = [str(p) for p in markers.get("packages") or ()]
        if packages:
            manifests = _manifest_texts(Path(root))
            for name in sorted(manifests):
                for package in sorted(packages):
                    if package in manifests[name]:
                        evidence.append(
                            {
                                "repo": repo,
                                "file": name,
                                "reason": f"manifest references '{package}'",
                            }
                        )
        import_markers = [str(i) for i in markers.get("imports") or ()]
        if import_markers:
            if repo not in file_cache:
                file_cache[repo] = []
                for path in iter_source_files(Path(root)):
                    try:
                        file_cache[repo].append(
                            (
                                path.relative_to(Path(root)).as_posix(),
                                path.read_text(errors="replace"),
                            )
                        )
                    except OSError:
                        continue
            for relative, text in sorted(file_cache[repo]):
                for marker in sorted(import_markers):
                    if marker in text:
                        evidence.append(
                            {
                                "repo": repo,
                                "file": relative,
                                "reason": f"source references '{marker}'",
                            }
                        )
        for glob in sorted(str(g) for g in markers.get("config_presence") or ()):
            if repo not in file_cache:
                file_cache[repo] = []
                for path in iter_source_files(Path(root)):
                    file_cache[repo].append((path.relative_to(Path(root)).as_posix(), ""))
            for relative, _ in sorted(file_cache[repo]):
                if fnmatch(relative, glob) or fnmatch(Path(relative).name, glob):
                    evidence.append(
                        {"repo": repo, "file": relative, "reason": f"matches '{glob}'"}
                    )

        if evidence:
            unique = [dict(t) for t in {tuple(sorted(e.items())) for e in evidence}]
            finding["integration"] = {
                "state": STATE_INTEGRATED,
                "evidence": sorted(unique, key=lambda e: (e["repo"], e["file"], e["reason"])),
            }
        else:
            finding["integration"] = {"state": STATE_NO_INTEGRATION}
            finding["recommendation"] = (
                f"No integration with the technology this rule configures was found "
                f"(no marker for '{rule_id}' in manifests, imports, or config); if this "
                "configuration is unused, remove it. "
                + str(finding.get("recommendation", ""))
            )
