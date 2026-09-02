"""Bundled-snapshot advisory matching — the offline baseline (feature 004, R4).

The native audit tools (npm audit, pip-audit, govulncheck) need a network or a
populated cache; offline they return could-not-check and known-vulnerable pins
go unreported — which is how marked@1.1.1's ReDoS advisories never became a
finding in the reference scan. This module parses manifests and lockfiles
deterministically and matches them against curated per-ecosystem snapshots under
`skill_core/data/advisories/`, with no subprocess and no network.

Staleness is honest: a snapshot past its threshold yields could-not-check for
that ecosystem, never a clean bill (FR-008).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from pipeline import resources
from pipeline.state import is_skipped_dir

_MANIFEST_NAMES = frozenset({"package.json", "pom.xml", "requirements.txt", "go.mod"})


def _iter_manifests(root: Path):
    """Manifest files anywhere under root (manifest names, not source suffixes —
    requirements.txt is not a source file but is still a dependency manifest)."""
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name not in _MANIFEST_NAMES:
            continue
        if any(is_skipped_dir(part) for part in path.relative_to(root).parts[:-1]):
            continue
        yield path

ADVISORY_DIR = "advisories"

_SEVERITY_SCORE = {"critical": 9.8, "high": 7.5, "medium": 5.3, "low": 3.1}


@dataclass(frozen=True)
class ComponentInstance:
    """A pinned dependency (data-model.md, FR-007)."""

    package: str
    version: str
    ecosystem: str
    manifest: str
    exposure: str = "runtime"


# ------------------------------------------------------------------ snapshots


def _snapshot_age_days(ecosystem: str) -> int:
    """Age of the snapshot in days (seam for the staleness test)."""
    snapshot = _load_snapshot(ecosystem)
    if snapshot is None:
        return 10**9
    return (date.today() - date.fromisoformat(snapshot["dataset_date"])).days


def _load_snapshot(ecosystem: str) -> dict[str, Any] | None:
    try:
        return json.loads(
            resources.data_path(f"{ADVISORY_DIR}/{ecosystem}.json").read_text()
        )
    except (FileNotFoundError, json.JSONDecodeError):
        return None


# ----------------------------------------------------------------- extraction


def extract_components(root: Path) -> list[ComponentInstance]:
    """Pinned dependencies from manifests and lockfiles — no subprocess."""
    out: list[ComponentInstance] = []
    for path in _iter_manifests(root):
        name = path.name
        rel = str(path.relative_to(root))
        if name == "package.json":
            out.extend(_npm(path, rel))
        elif name == "pom.xml":
            out.extend(_maven(path, rel))
        elif name == "requirements.txt":
            out.extend(_pypi(path, rel))
        elif name == "go.mod":
            out.extend(_go(path, rel))
    return out


def _npm(manifest: Path, rel: str) -> list[ComponentInstance]:
    if not manifest.exists():
        return []
    try:
        doc = json.loads(manifest.read_text())
    except json.JSONDecodeError:
        return []
    resolved: dict[str, str] = {}
    lock = manifest.parent / "package-lock.json"
    if lock.exists():
        try:
            packages = json.loads(lock.read_text()).get("packages", {})
            for name, entry in packages.items():
                if name.startswith("node_modules/") and entry.get("version"):
                    resolved[name.removeprefix("node_modules/")] = entry["version"]
        except json.JSONDecodeError:
            pass
    out: list[ComponentInstance] = []
    for section, exposure in (("dependencies", "runtime"), ("devDependencies", "development")):
        for package, range_spec in sorted((doc.get(section) or {}).items()):
            version = resolved.get(package) or re.sub(r"^[\^~>=<\s]+", "", str(range_spec))
            if version:
                out.append(
                    ComponentInstance(package, version, "npm", rel, exposure)
                )
    return out


def _maven(pom: Path, rel: str) -> list[ComponentInstance]:
    if not pom.exists():
        return []
    text = pom.read_text(errors="replace")
    out: list[ComponentInstance] = []
    for block in re.findall(r"<dependency>(.*?)</dependency>", text, re.DOTALL):
        group = re.search(r"<groupId>([^<]+)</groupId>", block)
        artifact = re.search(r"<artifactId>([^<]+)</artifactId>", block)
        version = re.search(r"<version>([^<]+)</version>", block)
        if not (group and artifact and version):
            continue
        if "${" in version.group(1):
            continue  # property-managed version: not resolvable without the model
        out.append(
            ComponentInstance(
                f"{group.group(1)}:{artifact.group(1)}",
                version.group(1),
                "maven",
                rel,
            )
        )
    return out


def _pypi(requirements: Path, rel: str) -> list[ComponentInstance]:
    if not requirements.exists():
        return []
    out: list[ComponentInstance] = []
    for line in requirements.read_text(errors="replace").splitlines():
        match = re.match(r"^\s*([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-+]+)", line)
        if match:
            out.append(
                ComponentInstance(match.group(1), match.group(2), "pypi", rel)
            )
    return out


def _go(gomod: Path, rel: str) -> list[ComponentInstance]:
    if not gomod.exists():
        return []
    text = gomod.read_text(errors="replace")
    out: list[ComponentInstance] = []
    for match in re.finditer(r"^\s*([\w./\-]+)\s+v?(\d+\.\d+\.\d+[^\s]*)", text, re.M):
        module = match.group(1)
        if module in ("module", "go", "require", ")") or module.startswith("//"):
            continue
        out.append(ComponentInstance(module, match.group(2), "go", rel))
    return out


# ------------------------------------------------------------------ matching


def _version_parts(version: str) -> tuple:
    parts: list[Any] = []
    for piece in re.split(r"[.\-+]", version):
        parts.append(int(piece) if piece.isdigit() else piece)
    return tuple(parts)


def _version_affected(version: str, entry: dict[str, Any]) -> bool:
    have = _version_parts(version)
    introduced = entry.get("introduced")
    if introduced and have < _version_parts(str(introduced)):
        return False
    fixed = entry.get("fixed")
    if fixed and have >= _version_parts(str(fixed)):
        return False
    return True


def match(components: list[ComponentInstance]) -> list[tuple[ComponentInstance, dict]]:
    """(component, advisory entry) pairs for every affected pinned version."""
    hits: list[tuple[ComponentInstance, dict]] = []
    for component in components:
        snapshot = _load_snapshot(component.ecosystem)
        if snapshot is None:
            continue
        for entry in snapshot["packages"].get(component.package, []):
            if _version_affected(component.version, entry):
                hits.append((component, entry))
    return hits


# ---------------------------------------------------------------------- entry


def run_offline(roots: dict[str, Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(findings, outcome dicts) for the bundled-snapshot baseline."""
    findings: list[dict[str, Any]] = []
    outcomes: list[dict[str, Any]] = []
    for member in sorted(roots):
        components = extract_components(roots[member])
        ecosystems = sorted({c.ecosystem for c in components})
        if not ecosystems:
            continue
        for ecosystem in ecosystems:
            snapshot = _load_snapshot(ecosystem)
            if snapshot is None:
                outcomes.append(
                    {
                        "member": member,
                        "ecosystem": ecosystem,
                        "status": "could-not-check",
                        "reason": "no bundled advisory snapshot ships for this ecosystem",
                        "tool": "bundled-snapshot",
                    }
                )
                continue
            if _snapshot_age_days(ecosystem) > snapshot["staleness_threshold_days"]:
                outcomes.append(
                    {
                        "member": member,
                        "ecosystem": ecosystem,
                        "status": "could-not-check",
                        "reason": (
                            "the bundled advisory snapshot is stale "
                            f"(dataset_date {snapshot['dataset_date']}); refresh it before "
                            "trusting a clean result"
                        ),
                        "tool": "bundled-snapshot",
                    }
                )
                continue
        ecosystem_components = [c for c in components]
        hits = [(c, e) for c, e in match(ecosystem_components)]
        by_eco: dict[str, int] = {}
        for component, entry in hits:
            findings.append(_finding(member, component, entry))
            by_eco[component.ecosystem] = by_eco.get(component.ecosystem, 0) + 1
        for ecosystem in ecosystems:
            if not any(o["ecosystem"] == ecosystem and o["member"] == member for o in outcomes):
                outcomes.append(
                    {
                        "member": member,
                        "ecosystem": ecosystem,
                        "status": "advisories" if by_eco.get(ecosystem) else "clean",
                        "tool": "bundled-snapshot",
                    }
                )
    return findings, outcomes


def _finding(member: str, component: ComponentInstance, entry: dict[str, Any]) -> dict[str, Any]:
    severity = str(entry.get("severity", "unknown")).lower()
    ids = list(entry.get("ids") or [])
    return {
        "cwe": "CWE-1035",
        "severity_score": _SEVERITY_SCORE.get(severity, 5.0),
        "confidence": 0.95,
        "location": {
            "repo": member,
            "file": component.manifest,
            # the package name keeps distinct vulnerable packages in one
            # manifest distinct under location dedupe (D3)
            "symbol": component.package,
            "line_start": 1,
            "line_end": 1,
            # file-tier location; the symbol is the package name, not a code
            # symbol — resolution must not look for it in the code graph
            "tier": "file",
            "symbol_confirmed": False,
        },
        "description": (
            f"{component.package} {component.version} has a known {severity} advisory"
            f" ({', '.join(ids)}): {entry.get('summary', '')} "
            f"Affected range {entry.get('affected_range', '')}; fixed in "
            f"{entry.get('fixed', 'a later release')}. Declared in {component.manifest}."
        ),
        "evidence": [
            {
                "repo": member,
                "file": component.manifest,
                "symbol": component.package,
                "reason": (
                    f"bundled advisory snapshot match: {component.package} "
                    f"{component.version} within {entry.get('affected_range', '')}"
                ),
            }
        ],
        "attack_scenario": (
            "Exploitation depends on the advisory; the component is reachable as a "
            f"{component.exposure} dependency."
        ),
        "impact": entry.get("summary", "Known vulnerability in a shipped dependency."),
        "recommendation": (
            f"Upgrade {component.package} to {entry.get('fixed', 'a fixed release')} "
            "or later."
        ),
        "source": "dependency-audit",
        "tool_ref": f"advisory-match:{component.ecosystem}",
        "dependency": {
            "package": component.package,
            "ecosystem": component.ecosystem,
            "affected_range": entry.get("affected_range", ""),
            "fixed_version": entry.get("fixed", ""),
            "advisory_ids": ids,
            "exposure": component.exposure,
            "affected_members": [member],
            "attribution": "per-member",
            "audit_source": "bundled-snapshot",
        },
    }
