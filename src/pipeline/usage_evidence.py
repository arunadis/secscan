"""Deterministic usage evidence for dependency findings (feature 014, FR-001).

For every finding carrying a ``dependency`` block this pass answers one
question: does the member's scanned source reference the package at all? The
answer is three-state, because both directional errors are disqualifying
(Principle V):

- ``found``        — import configuration, or literal dynamic references exist
                     (locations listed, sorted);
- ``none-found``   — every applicable detection form ran and matched nothing.
                     It is *not* a suppression ground, ever;
- ``undetermined`` — some form could not run (unmapped ecosystem, unparsed
                     member, non-literal dynamic call). Carries a reason and
                     must never read as clean.

Detection is driven entirely by the shipped ``usage_patterns.json`` (T001):
module maps, config-reference rules, dynamic literal forms, and dev markers are
data. Supporting another ecosystem is a data change, never a code change.
"""

from __future__ import annotations

import functools
import json
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from pipeline import resources
from pipeline.state import iter_source_files

DATA_FILE = "usage_patterns.json"

STATE_FOUND = "found"
STATE_NONE_FOUND = "none-found"
STATE_UNDETERMINED = "undetermined"
STATES = (STATE_FOUND, STATE_NONE_FOUND, STATE_UNDETERMINED)

#: Graph-node language -> ecosystem whose packages those imports can name.
_LANGUAGE_ECOSYSTEM = {
    "javascript": "npm",
    "typescript": "npm",
    "tsx": "npm",
    "python": "pypi",
    "go": "go",
    "java": "maven",
}


class InvalidUsageData(RuntimeError):
    """Rule data that fails validation fails the build, not the scan."""


@functools.lru_cache(maxsize=1)
def load_patterns() -> dict[str, Any]:
    """The validated rule pack (controls.py load-time validation precedent)."""
    document = json.loads(resources.data_path(DATA_FILE).read_text())
    if not document.get("version") or not document.get("dataset_date"):
        raise InvalidUsageData(f"{DATA_FILE}: missing version/dataset_date")
    for ecosystem, block in document.get("ecosystems", {}).items():
        for entry in block.get("module_map", []):
            if not entry.get("module") or not entry.get("package"):
                raise InvalidUsageData(f"{ecosystem}: module_map entry needs module+package")
        for rule in block.get("config_files", []):
            extract = rule.get("extract") or {}
            kind = extract.get("kind")
            if kind not in ("regex", "json-string-array"):
                raise InvalidUsageData(f"{ecosystem}: unknown config extract kind {kind!r}")
            if kind == "regex":
                pattern = re.compile(extract["pattern"])
                if "pkg" not in pattern.groupindex:
                    raise InvalidUsageData(f"{ecosystem}: config regex must capture (?P<pkg>…)")
            elif not extract.get("path"):
                raise InvalidUsageData(f"{ecosystem}: json-string-array needs a path")
        for form in block.get("dynamic_forms", []):
            if form.get("kind") != "regex":
                raise InvalidUsageData(f"{ecosystem}: unknown dynamic form kind")
            pattern = re.compile(form["pattern"])
            if "pkg" not in pattern.groupindex:
                raise InvalidUsageData(f"{ecosystem}: dynamic form must capture (?P<pkg>…)")
        for marker in block.get("dev_markers", []):
            re.compile(marker)
    return document


# --------------------------------------------------------------- specifier parsing


def _specifier(import_text: str, language: str) -> str | None:
    """The module specifier inside an import statement, or None."""
    quoted = re.search(r"['\"]([^'\"]+)['\"]", import_text)
    if language in ("javascript", "typescript", "tsx"):
        if not quoted:
            return None
        specifier = quoted.group(1)
        # Relative/absolute paths are never package names.
        if specifier.startswith((".", "/")):
            return None
        return specifier
    if language == "python":
        match = re.match(r"\s*(?:from|import)\s+([A-Za-z0-9_.]+)", import_text)
        return match.group(1) if match else None
    if language == "go":
        return quoted.group(1) if quoted else None
    if language == "java":
        match = re.match(r"\s*import\s+(?:static\s+)?([A-Za-z0-9_.]+)", import_text)
        return match.group(1) if match else None
    return None


def _module_matches(specifier: str, package: str, ecosystem: str, rules: dict[str, Any]) -> bool:
    strategy = rules.get("module_strategy", "")
    if strategy == "npm-specifier":
        parts = specifier.split("/")
        module = "/".join(parts[:2]) if specifier.startswith("@") else parts[0]
        return module == package
    if strategy == "first-segment":
        module = specifier.split(".")[0]
        for override in rules.get("module_map", []):
            if override["module"] == module:
                return override["package"].lower() == package.lower()
        return module.lower() == package.lower()
    if strategy == "module-path":
        return specifier == package or specifier.startswith(package + "/")
    # package-prefix (maven) cannot be established without an explicit map.
    for override in rules.get("module_map", []):
        if override["module"] == specifier:
            return override["package"].lower() == package.lower()
    return False


# ------------------------------------------------------------------- file text


def _iter_member_files(root: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for path in iter_source_files(root):
        try:
            out.append((path.relative_to(root).as_posix(), path.read_text(errors="replace")))
        except OSError:
            continue
    return sorted(out)


_NONLITERAL_DYNAMIC = {
    "npm": re.compile(r"\b(?:require|import)\s*\(\s*[^'\"\s)]"),
    "pypi": re.compile(r"\b(?:__import__|importlib\.import_module)\s*\(\s*[^'\"\s)]"),
}


def _json_path_strings(text: str, dotted: str) -> list[str]:
    """Strings at a dotted JSON path (array items or object keys); [] if absent."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return []
    node: Any = document
    for part in dotted.split("."):
        if not isinstance(node, dict):
            return []
        node = node.get(part)
    if isinstance(node, list):
        return [str(item) for item in node]
    if isinstance(node, dict):
        return [str(key) for key in node]
    return []


# ---------------------------------------------------------------------- core


def _role_for(path: str, dev_markers: list[str]) -> str:
    return "development" if any(re.search(m, path) for m in dev_markers) else "runtime"


def _member_evidence(
    member: str,
    package: str,
    ecosystem: str,
    rules: dict[str, Any],
    graph: dict[str, Any],
    files: list[tuple[str, str]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """(locations, incompleteness reasons) for one member."""
    locations: list[dict[str, Any]] = []
    incomplete: list[str] = []
    dev_markers = rules.get("dev_markers", [])

    nodes = [
        n
        for n in graph.get("nodes") or []
        if n.get("repo") == member
        and n.get("type") == "file"
        and n.get("parsed") is True
        and _LANGUAGE_ECOSYSTEM.get(str(n.get("language", ""))) == ecosystem
    ]
    if not nodes:
        incomplete.append(f"member '{member}' has no parsed {ecosystem} source files")

    # Static imports (from the persisted graph).
    seen_imports: set[str] = set()
    for node in nodes:
        for import_text in node.get("imports") or []:
            specifier = _specifier(import_text, str(node.get("language", "")))
            if specifier and _module_matches(specifier, package, ecosystem, rules):
                seen_imports.add(node["path"])
    for path in sorted(seen_imports):
        locations.append(
            {"repo": member, "file": path, "kind": "import", "role": _role_for(path, dev_markers)}
        )

    if files:
        # Config-file references (rule-covered config classes only).
        for path, text in files:
            for rule in rules.get("config_files", []):
                if not (
                    fnmatch(path, rule["file_glob"])
                    or fnmatch(Path(path).name, rule["file_glob"])
                ):
                    continue
                extract = rule["extract"]
                if extract["kind"] == "regex":
                    for m in re.finditer(extract["pattern"], text):
                        if _module_matches(m.group("pkg"), package, ecosystem, rules):
                            locations.append(
                                {
                                    "repo": member,
                                    "file": path,
                                    "line_start": text.count("\n", 0, m.start()) + 1,
                                    "kind": "config",
                                    "role": _role_for(path, dev_markers),
                                }
                            )
                else:
                    refs = _json_path_strings(text, extract["path"])
                    if any(_module_matches(r, package, ecosystem, rules) for r in refs):
                        locations.append(
                            {
                                "repo": member,
                                "file": path,
                                "kind": "config",
                                "role": _role_for(path, dev_markers),
                            }
                        )

        # Dynamic literal forms + the honest-uncertainty guard: any non-literal
        # dynamic call makes dynamic attribution incomplete for this member.
        ecosystem_key = ecosystem if ecosystem in _NONLITERAL_DYNAMIC else None
        for path, text in files:
            if ecosystem == "npm" and not path.endswith((".js", ".ts", ".tsx", ".mjs", ".cjs")):
                continue
            if ecosystem == "pypi" and not path.endswith(".py"):
                continue
            for form in rules.get("dynamic_forms", []):
                for m in re.finditer(form["pattern"], text):
                    if _module_matches(m.group("pkg"), package, ecosystem, rules):
                        locations.append(
                            {
                                "repo": member,
                                "file": path,
                                "line_start": text.count("\n", 0, m.start()) + 1,
                                "kind": "dynamic",
                                "role": _role_for(path, dev_markers),
                            }
                        )
            if ecosystem_key and _NONLITERAL_DYNAMIC[ecosystem_key].search(text):
                incomplete.append(
                    f"member '{member}' contains a non-literal dynamic import in {path}; "
                    "dynamic attribution could not be completed"
                )
    elif rules.get("config_files") or rules.get("dynamic_forms"):
        incomplete.append(
            f"member '{member}' file contents unavailable; config/dynamic forms not evaluated"
        )

    return locations, sorted(set(incomplete))


def usage_for(
    finding: dict[str, Any], graph: dict[str, Any], roots: dict[str, Path] | None
) -> dict:
    """The ``usage`` block for one dependency finding (data-model.md §2)."""
    dependency = finding.get("dependency") or {}
    package = str(dependency.get("package") or "")
    # A merged currency finding spans several packages (data-model.md §4):
    # usage is found if ANY of them is referenced.
    candidates = [str(p) for p in dependency.get("packages") or ()] or [package]
    ecosystem = str(dependency.get("ecosystem") or "")
    members = [
        str(m)
        for m in (dependency.get("affected_members") or [])
        if str(m)
    ] or [str((finding.get("location") or {}).get("repo") or "")]

    rules = (load_patterns().get("ecosystems") or {}).get(ecosystem)
    if not package or not ecosystem:
        return {"state": STATE_UNDETERMINED, "reason": "finding lacks package or ecosystem"}
    if rules is None:
        return {
            "state": STATE_UNDETERMINED,
            "reason": f"no usage-detection rules ship for ecosystem '{ecosystem}'",
        }
    if rules.get("module_strategy") == "package-prefix" and not rules.get("module_map"):
        # A Java import package cannot be mapped to a groupId:artifactId without
        # an explicit map; concluding "none-found" would be a guess.
        return {
            "state": STATE_UNDETERMINED,
            "reason": (
                f"ecosystem '{ecosystem}' cannot map import packages to artifacts "
                "without a module map and none ships"
            ),
        }

    all_locations: list[dict[str, Any]] = []
    reasons: list[str] = []
    for member in sorted(set(members)):
        root = (roots or {}).get(member)
        files = _iter_member_files(Path(root)) if root is not None else []
        member_locations: list[dict[str, Any]] = []
        member_reasons: list[str] = []
        for candidate in sorted(candidates):
            locations, incomplete = _member_evidence(
                member, candidate, ecosystem, rules, graph, files
            )
            member_locations.extend(locations)
            if locations or incomplete or candidate == candidates[-1]:
                member_reasons.extend(incomplete)
        all_locations.extend(member_locations)
        reasons.extend(member_reasons)

    if all_locations:
        deduped = {
            (loc["repo"], loc["file"], loc.get("line_start") or 0, loc["kind"]): loc
            for loc in all_locations
        }
        ordered = sorted(
            deduped.values(),
            key=lambda loc: (
                loc["repo"], loc["file"], loc.get("line_start") or 0, loc["kind"], loc["role"]
            ),
        )
        role = (
            "development" if all(loc["role"] == "development" for loc in ordered) else "runtime"
        )
        return {"state": STATE_FOUND, "locations": ordered, "role": role}
    if reasons:
        return {"state": STATE_UNDETERMINED, "reason": "; ".join(sorted(set(reasons)))}
    return {"state": STATE_NONE_FOUND}


def attach_usage(
    findings: list[dict[str, Any]],
    graph: dict[str, Any],
    roots: dict[str, Path] | None = None,
) -> None:
    """Attach a ``usage`` block to every finding carrying a dependency block."""
    for finding in findings:
        if not finding.get("dependency"):
            continue
        finding["usage"] = usage_for(finding, graph, roots)
