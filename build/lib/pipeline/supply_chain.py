"""Deterministic supply-chain / dependency-confusion detection (spec 007, FR-008, R7).

Manifests are parsed structurally (JSON / requirement lines), never by raw
regex, and everything is offline: guard evidence comes only from what the repo
demonstrates (committed lockfile, private-registry mapping). Guards that live in
external infrastructure are recorded as ``undetermined`` — honest uncertainty,
never assumed present or absent (constitution V).

Findings are value-free in the rule-data sense (no dataset values copied); a
finding does name the project's own declared dependency — actionable evidence,
as in dependency-audit findings.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pipeline import cwe, resources

DATA_FILE = "supply_chain_rules.json"

_CONFIDENCE = 0.9

#: lockfiles that demonstrate a pinned resolution, per ecosystem
_LOCKFILES = {
    "npm": ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"),
    "pypi": ("uv.lock", "pylock.toml", "Pipfile.lock"),
}


class InvalidRuleData(RuntimeError):
    """Rule data that fails validation fails the build, not the scan."""


def load_rules() -> list[dict[str, Any]]:
    document = json.loads(resources.data_path(DATA_FILE).read_text())
    rules = document["rules"]
    ids: set[str] = set()
    kinds = {"internal-namespace-unprotected", "mutable-reference", "suspicious-package"}
    for rule in rules:
        if rule["id"] in ids:
            raise InvalidRuleData(f"duplicate rule id: {rule['id']}")
        ids.add(rule["id"])
        required = ("id", "kind", "ecosystems", "cwe", "title", "description", "recommendation")
        for field in required:
            if not rule.get(field):
                raise InvalidRuleData(f"{rule['id']}: missing {field}")
        if rule["kind"] not in kinds:
            raise InvalidRuleData(f"{rule['id']}: unknown kind {rule['kind']}")
        if rule["kind"] == "internal-namespace-unprotected":
            try:
                re.compile(rule["pattern"])
            except re.error as exc:
                raise InvalidRuleData(
                    f"{rule['id']}: pattern does not compile: {exc}"
                ) from exc
        if rule["kind"] == "suspicious-package" and not rule.get("names"):
            raise InvalidRuleData(f"{rule['id']}: suspicious-package needs a names map")
        cwe.validate_cwe(rule["cwe"])
    return rules


@dataclass(frozen=True)
class Dependency:
    name: str
    spec: str
    line: int


def _npm_deps(manifest: dict[str, Any], text: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for section in ("dependencies", "devDependencies"):
        entries = manifest.get(section) or {}
        if not isinstance(entries, dict):
            continue
        for name in sorted(entries):
            marker = f'"{name}"'
            line = text.count("\n", 0, text.find(marker)) + 1 if marker in text else 1
            deps.append(Dependency(name=name, spec=str(entries[name]), line=line))
    return deps


def _pypi_deps(text: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.split("#")[0].strip()
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.*)$", stripped)
        if not match or stripped.startswith(("-", "git+")):
            continue
        deps.append(Dependency(name=match.group(1), spec=match.group(2).strip(), line=number))
    return deps


def _has_lockfile(root: Path, ecosystem: str) -> bool:
    return any((root / name).exists() for name in _LOCKFILES[ecosystem])


def _npm_scope_mapped(root: Path, name: str) -> bool:
    """True when .npmrc maps the dependency's scope to a (private) registry."""
    if not name.startswith("@"):
        return False
    npmrc = root / ".npmrc"
    if not npmrc.exists():
        return False
    scope_reg = re.escape(f"{name.split('/')[0]}:registry")
    try:
        return bool(re.search(rf"(?im)^{scope_reg}\s*=", npmrc.read_text(errors="replace")))
    except OSError:
        return False


def _mutable(spec: str, ecosystem: str) -> bool:
    if "==" in spec:
        return False
    if ecosystem == "npm" and re.match(r"^\d+\.\d+\.\d+$", spec):
        return False
    return True  # "", "*", "latest", ^/~ ranges, >=, ...


def _finding(
    rule: dict[str, Any],
    repo: str,
    path: str,
    line: int,
    dep: Dependency,
    guard: str,
    guard_reason: str,
) -> dict[str, Any]:
    return {
        "cwe": rule["cwe"],
        "confidence": _CONFIDENCE,
        "location": {"repo": repo, "file": path, "line_start": line},
        "description": f"{rule['title']} (package: {dep.name})",
        "evidence": [
            {
                "repo": repo,
                "file": path,
                "reason": (
                    f"rule {rule['id']}: dependency '{dep.name}' "
                    f"('{dep.spec or 'unpinned'}'); guard: {guard} — {guard_reason}"
                ),
            }
        ],
        "attack_scenario": (
            "An attacker publishes a malicious package whose resolution replaces "
            "the intended dependency during install."
        ),
        "impact": "Substituted package content executes in the build or at runtime.",
        "recommendation": rule["recommendation"],
        "tool_ref": f"supply-chain:{rule['id']}",
    }


def evaluate_repo(
    root: Path, repo: str, rules: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    rules = rules if rules is not None else load_rules()
    findings: list[dict[str, Any]] = []
    # Manifests are enumerated by shipped file class, not by source suffix:
    # requirements.txt has no "source" suffix yet is exactly what we evaluate.
    from pipeline import stacks
    from pipeline.state import is_skipped_dir

    manifests = [
        path
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and stacks.file_class_for(path.name) == "dependency-manifest"
        and not any(
            is_skipped_dir(part) for part in path.relative_to(root).parts[:-1]
        )
    ]
    for path in manifests:
        relative = path.name
        ecosystem: str | None = None
        deps: list[Dependency] = []
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if relative == "package.json":
            ecosystem = "npm"
            try:
                deps = _npm_deps(json.loads(text), text)
            except json.JSONDecodeError:
                continue
        elif relative == "requirements.txt":
            ecosystem = "pypi"
            deps = _pypi_deps(text)
        if ecosystem is None:
            continue

        has_lock = _has_lockfile(root, ecosystem)
        for rule in rules:
            if ecosystem not in rule["ecosystems"]:
                continue
            pattern = None
            if rule["kind"] == "internal-namespace-unprotected":
                pattern = re.compile(rule["pattern"])
            suspicious = (rule.get("names") or {}).get(ecosystem) or []
            suspicious_lower = {n.lower() for n in suspicious}
            for dep in deps:
                if rule["kind"] == "mutable-reference":
                    if not _mutable(dep.spec, ecosystem):
                        continue
                    if has_lock:
                        # A committed lockfile pins the resolved artifact.
                        continue
                    findings.append(
                        _finding(
                            rule, repo, str(path.relative_to(root)), dep.line, dep,
                            "undetermined",
                            "no committed lockfile pins the resolution; pinning must "
                            "be demonstrated by the repository or it is unknown",
                        )
                    )
                elif rule["kind"] == "internal-namespace-unprotected":
                    if not pattern.match(dep.name):  # type: ignore[union-attr]
                        continue
                    mapped = ecosystem == "npm" and _npm_scope_mapped(root, dep.name)
                    if mapped and has_lock:
                        # demonstrated guard (scope mapping + committed lockfile):
                        # no exposure to report
                        continue
                    guard = "undetermined"
                    reason = (
                        "no in-repo evidence of a private-registry mapping or pinned "
                        "lockfile; resolution guards in external infrastructure "
                        "cannot be established from here"
                    )
                    findings.append(
                        _finding(
                            rule, repo, str(path.relative_to(root)), dep.line, dep,
                            guard, reason,
                        )
                    )
                else:  # suspicious-package
                    if dep.name.lower() in suspicious_lower:
                        findings.append(
                            _finding(
                                rule, repo, str(path.relative_to(root)), dep.line, dep,
                                "undetermined",
                                "name matches the offline suspicious-name dataset",
                            )
                        )
    findings.sort(
        key=lambda f: (
            f["location"]["repo"],
            f["location"]["file"],
            f["location"]["line_start"],
            f["tool_ref"],
        )
    )
    return findings


def run(roots: dict[str, Path]) -> list[dict[str, Any]]:
    rules = load_rules()
    findings: list[dict[str, Any]] = []
    for repo in sorted(roots):
        findings.extend(evaluate_repo(roots[repo], repo, rules))
    return findings
