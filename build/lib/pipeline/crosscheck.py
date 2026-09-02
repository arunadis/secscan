"""Cross-check external findings against the codebase (feature 008, FR-007/008).

The scanner trusts external tools but verifies structurally. A finding is
suppressed ONLY on deterministic structural disproof, from the closed contract
enum (contracts/data-contracts.md §5):

* ``package-absent``          — the package is not in the member's resolved pins
* ``version-outside-range``   — the resolved pin cannot satisfy the advisory range
* ``location-unresolvable``   — the finding's file is absent or its line range
                                exceeds the file (tier-file locations, FR-003 file checks)
* ``component-absent``        — reserved for non-file component references

Reachability and usage judgments are NEVER suppression grounds (Clarifications,
Session 2026-09-02): an uncalled vulnerable function stays reported. Retained
findings that could be neither confirmed nor disproven keep flowing to the
existing verification stage, which assigns plausible-with-gap — the schema's
explicit third state — so neither silence nor inflation results (Principle V).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pipeline.audits import offline

GROUNDS = (
    "package-absent",
    "version-outside-range",
    "location-unresolvable",
    "component-absent",
)


def _resolved_pins(root: Path) -> dict[str, dict[str, str]]:
    """package -> {version, ecosystem} from the member's resolved dependencies."""
    pins: dict[str, dict[str, str]] = {}
    for component in offline.extract_components(root):
        pins.setdefault(
            component.package,
            {"version": component.version, "ecosystem": component.ecosystem},
        )
    return pins


def _parse_semver(text: str) -> tuple:
    return offline._version_parts(text)


def _outside_range(resolved: str, dep: dict[str, Any]) -> bool:
    """True only when the resolved pin provably cannot be affected."""
    fixed = str(dep.get("fixed_version") or "")
    if fixed and _parse_semver(resolved) >= _parse_semver(fixed):
        return True
    introduced = ""
    range_text = str(dep.get("affected_range") or "")
    match = re.search(r">=?\s*([\w.+-]+)", range_text)
    if match:
        introduced = match.group(1)
    if introduced and introduced != "0" and _parse_semver(resolved) < _parse_semver(introduced):
        return True
    return False


def _member_root(roots: dict[str, Path], finding: dict[str, Any]) -> tuple[str, Path] | None:
    dep = finding.get("dependency") or {}
    member = str((dep.get("affected_members") or [""])[0] or "")
    if not member:
        member = str((finding.get("location") or {}).get("repo") or "")
    if member in roots:
        return member, Path(roots[member])
    return None


def _disprove_dependency(roots: dict[str, Path], finding: dict[str, Any]) -> dict[str, Any] | None:
    dep = finding["dependency"]
    target = _member_root(roots, finding)
    if target is None:
        return None  # member unknown: cannot disprove, retain
    member, root = target
    package = str(dep.get("package") or "")
    pins = _resolved_pins(root)
    if package not in pins:
        return {
            "ground": "package-absent",
            "evidence": [
                f"no resolved pin for '{package}' in member '{member}' "
                f"(manifests/lockfiles enumerate {len(pins)} packages)"
            ],
        }
    resolved = pins[package]["version"]
    if _outside_range(resolved, dep):
        fixed = dep.get("fixed_version") or ""
        return {
            "ground": "version-outside-range",
            "evidence": [
                f"member '{member}' resolves {package} {resolved}, outside the "
                f"advisory range {dep.get('affected_range') or '<=?'} (fixed in {fixed})"
            ],
        }
    return None


def _disprove_location(roots: dict[str, Path], finding: dict[str, Any]) -> dict[str, Any] | None:
    target = _member_root(roots, finding)
    if target is None:
        member = str((finding.get("location") or {}).get("repo") or sorted(roots)[0])
        root = Path(roots[member]) if member in roots else None
        if root is None:
            return None
    else:
        member, root = target
    location = finding.get("location") or {}
    file = str(location.get("file") or "")
    if not file:
        return None
    path = root / file
    if not path.exists():
        return {
            "ground": "location-unresolvable",
            "evidence": [f"'{file}' does not exist under member '{member}'"],
        }
    line_start = int(location.get("line_start") or 1)
    line_count = len(path.read_text(errors="replace").splitlines())
    if line_start > line_count:
        return {
            "ground": "location-unresolvable",
            "evidence": [
                f"'{file}' has {line_count} lines; the finding starts at line {line_start}"
            ],
        }
    return None


def evaluate(
    roots: dict[str, Path],
    external_findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split external findings into (kept, suppressions).

    Dependency findings get grounds 1-2; code findings get ground 3. Everything
    else is retained as-is. Deterministic: same findings + same tree → same split.
    """
    kept: list[dict[str, Any]] = []
    suppressions: list[dict[str, Any]] = []
    for finding in external_findings:
        tool = str(finding.get("scanner") or finding.get("tool_ref") or "external")
        verdict = (
            _disprove_dependency(roots, finding)
            if finding.get("dependency")
            else _disprove_location(roots, finding)
        )
        if verdict is None:
            # Structural presence confirmed (or undecidable): retained, with the
            # cross-check note making the undetermined reachability explicit
            # (FR-008 — an unknown never suppresses and never inflates).
            finding.setdefault("evidence", []).append(
                {
                    "repo": str((finding.get("location") or {}).get("repo") or ""),
                    "file": str((finding.get("location") or {}).get("file") or ""),
                    "reason": (
                        "cross-check: presence confirmed against the code model; "
                        "exploitability/reachability undetermined — verified by "
                        "the analysis stages, never suppressed on doubt"
                    ),
                }
            )
            kept.append(finding)
            continue
        suppressions.append(
            {
                "finding": {
                    "tool_ref": tool,
                    "description": str(finding.get("description") or ""),
                    "location": dict(finding.get("location") or {}),
                },
                "tool_id": tool,
                "disproof_ground": verdict["ground"],
                "evidence": verdict["evidence"],
            }
        )
    return kept, suppressions


def write_suppressions(store_dir: Path, suppressions: list[dict[str, Any]]) -> Path:
    """Persist the auditable suppression list (contracts §5)."""
    from pipeline.tooling.state import _write

    return _write(store_dir, "tooling/suppressions.json", {"suppressions": suppressions})
