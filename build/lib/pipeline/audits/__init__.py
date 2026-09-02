"""Native dependency audits, run per workspace member (FR-030–FR-035).

Entry point: :func:`run`. Selects an adapter per member from that member's own
detected ecosystem, so a workspace mixing npm and PyPI is fully assessed rather
than assessed for whichever ecosystem is detected first (FR-030a).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pipeline import cwe, stack_currency, stacks
from pipeline.audits import attribution, go, java, node, python
from pipeline.audits.base import (
    DEFAULT_TIMEOUT_S,
    STATUS_ADVISORIES,
    STATUS_CLEAN,
    STATUS_COULD_NOT_CHECK,
    Advisory,
    AuditOutcome,
)

#: Ecosystem id -> module exposing `for_root(root)`.
SELECTORS = {
    "npm": node.for_root,
    "pypi": python.for_root,
    "go": go.for_root,
    "maven": java.for_root,
}

#: Weakness classes for dependency and stack-currency findings.
CWE_VULNERABLE_COMPONENT = "CWE-1035"
CWE_UNMAINTAINED_COMPONENT = "CWE-1104"


def _shared_lockfile(roots: dict[str, Path]) -> bool:
    """True when members sit under a root that holds the only lockfile.

    A hoisted monorepo lockfile means the audit answers for the whole tree, which
    is what triggers the attribution fallback (FR-030e).
    """
    if len(roots) < 2:
        return False
    parents = {root.parent for root in roots.values()}
    if len(parents) != 1:
        return False
    parent = next(iter(parents))
    lockfiles = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")
    parent_has = any((parent / name).exists() for name in lockfiles)
    members_have = any(
        (root / name).exists() for root in roots.values() for name in lockfiles
    )
    return parent_has and not members_have


def run(
    roots: dict[str, Path],
    timeout_s: int = DEFAULT_TIMEOUT_S,
    skip_ecosystems: set[str] | None = None,
) -> tuple[list[AuditOutcome], list[attribution.GroupedAdvisory]]:
    """Audit every member against its own ecosystem.

    ``skip_ecosystems`` lets a domain already covered by an installed external
    scanner be skipped, so nothing is double-reported.
    """
    skip = skip_ecosystems or set()
    outcomes: list[AuditOutcome] = []
    per_member: dict[str, list[Advisory]] = {}
    ambiguous: dict[str, bool] = {}

    for member, root in sorted(roots.items()):
        for ecosystem, selector in sorted(SELECTORS.items()):
            if ecosystem in skip:
                continue
            adapter = selector(root)
            if adapter is None:
                continue
            outcome = adapter.audit(root, member, timeout_s)
            outcomes.append(outcome)
            if outcome.advisories:
                per_member.setdefault(member, []).extend(outcome.advisories)
            # A manifest with no lockfile leaves the resolved version ambiguous;
            # that is stated on the finding rather than resolved by guessing.
            if adapter.lockfiles and not adapter.has_lockfile(root):
                ambiguous[member] = True

    grouped = attribution.group(
        per_member,
        roots=roots,
        lockfile_shared=_shared_lockfile(roots),
        version_ambiguous=ambiguous,
    )
    return outcomes, grouped


# ------------------------------------------------------------------ findings


def to_findings(
    grouped: list[attribution.GroupedAdvisory], start: int = 1
) -> list[dict[str, Any]]:
    """Turn grouped advisories into schema-conforming findings (FR-030b)."""
    findings: list[dict[str, Any]] = []
    for index, item in enumerate(grouped, start=start):
        advisory = item.advisory
        members = ", ".join(item.members) if item.members else "the workspace"
        attribution_note = (
            ""
            if item.attribution == attribution.ATTRIBUTION_PER_MEMBER
            else (
                " Per-member attribution was not derivable: a single hoisted lockfile "
                "covers several members and no member's own manifest declares this "
                "package."
            )
        )
        ambiguity_note = (
            " The resolved version is ambiguous because the manifest has no lockfile."
            if item.version_ambiguous
            else ""
        )
        findings.append(
            {
                "id": f"SEC-{index:04d}",
                "cwe": CWE_VULNERABLE_COMPONENT,
                "severity_score": advisory.severity_score,
                "severity_band": cwe.band_for(advisory.severity_score),
                "confidence": 0.95,
                "location": {
                    "repo": item.members[0] if item.members else "",
                    "file": _manifest_for(advisory.ecosystem),
                    # the package name keeps distinct vulnerable packages in one
                    # manifest distinct under location dedupe (feature 004, D3)
                    "symbol": advisory.package,
                    "line_start": 1,
                    "line_end": 1,
                    "tier": "file",
                    "symbol_confirmed": False,
                },
                "description": (
                    f"{advisory.package} {advisory.affected_range or '(installed version)'} "
                    f"has a known {advisory.severity} advisory"
                    + (f": {advisory.title}" if advisory.title else ".")
                ),
                "evidence": [
                    {
                        "repo": item.members[0] if item.members else "",
                        "file": _manifest_for(advisory.ecosystem),
                        "reason": (
                            f"{advisory.package} is declared as a {advisory.exposure} "
                            f"dependency; advisory {', '.join(advisory.advisory_ids) or 'reported'}"
                        ),
                    }
                ],
                "attack_scenario": (
                    "An attacker exploits the published vulnerability in "
                    f"{advisory.package}, which is reachable wherever {members} uses it."
                ),
                "impact": (
                    f"Whatever the advisory permits in {advisory.package}. "
                    f"Exposure is {advisory.exposure}." + attribution_note + ambiguity_note
                ),
                "recommendation": (
                    f"Upgrade {advisory.package} to "
                    + (f"{advisory.fixed_version} or later." if advisory.fixed_version
                       else "a release that carries the fix.")
                ),
                "source": "dependency-audit",
                "status": "local",
                "dependency": attribution.to_finding_payload(
                    item, audit_source=f"native:{advisory.ecosystem}"
                ),
            }
        )
    return findings


def _manifest_for(ecosystem: str) -> str:
    try:
        return stacks.ecosystem(ecosystem)["manifests"][0]
    except Exception:  # pragma: no cover - defensive
        return "dependency manifest"


def stack_currency_findings(
    roots: dict[str, Path], start: int = 1
) -> list[dict[str, Any]]:
    """Findings for declared versions past their support window (FR-034)."""
    import json
    import re

    findings: list[dict[str, Any]] = []
    index = start
    for member, root in sorted(roots.items()):
        declared: dict[str, str] = {}
        package_json = root / "package.json"
        if package_json.exists():
            try:
                document = json.loads(package_json.read_text())
            except (OSError, json.JSONDecodeError):
                document = {}
            for key in ("dependencies", "devDependencies"):
                for name, spec in (document.get(key) or {}).items():
                    version = re.sub(r"^[^\d]*", "", str(spec))
                    if version:
                        declared[name] = version
        requirements = root / "requirements.txt"
        if requirements.exists():
            for line in requirements.read_text(errors="replace").splitlines():
                match = re.match(r"\s*([A-Za-z0-9._-]+)\s*==\s*([\d.]+)", line)
                if match:
                    declared[match.group(1).lower()] = match.group(2)

        for name, version in sorted(declared.items()):
            status = stack_currency.status_for(name, version)
            if status.past_eol is not True:
                continue
            findings.append(
                {
                    "id": f"SEC-{index:04d}",
                    "cwe": CWE_UNMAINTAINED_COMPONENT,
                    "severity_score": 5.3,
                    "severity_band": cwe.band_for(5.3),
                    "confidence": 0.9,
                    "location": {
                        "repo": member,
                        "file": "package.json" if package_json.exists() else "requirements.txt",
                        "line_start": 1,
                        "line_end": 1,
                        "tier": "file",
                        "symbol_confirmed": False,
                    },
                    "description": (
                        f"{name} {version} is past its end of support "
                        f"({status.eol_date}), so it receives no security fixes."
                    ),
                    "evidence": [
                        {
                            "repo": member,
                            "file": "package.json" if package_json.exists() else "requirements.txt",
                            "reason": (
                                f"declares {name} {version}; support for the "
                                f"{status.cycle} cycle ended {status.eol_date}"
                            ),
                        }
                    ],
                    "attack_scenario": (
                        f"A vulnerability disclosed in {name} after {status.eol_date} will "
                        "never receive an upstream fix for this version."
                    ),
                    "impact": (
                        "Unpatched vulnerabilities accumulate with no remediation path "
                        "short of a major upgrade."
                    ),
                    "recommendation": f"Move {name} to a supported release cycle.",
                    "source": "dependency-audit",
                    "status": "local",
                }
            )
            index += 1
    return findings


def blocking_gaps(outcomes: list[AuditOutcome]) -> list[str]:
    """Unassessed dependency domains, rendered at the top of the report (FR-033)."""
    gaps: list[str] = []
    for outcome in sorted(outcomes, key=lambda o: (o.member, o.ecosystem)):
        if outcome.status != STATUS_COULD_NOT_CHECK:
            continue
        gaps.append(
            f"Dependency domain UNASSESSED for member '{outcome.member}' "
            f"({outcome.ecosystem}): {outcome.reason}. This is not a clean result — "
            f"run: {outcome.remediation_command}"
        )
    return gaps


__all__ = [
    "STATUS_ADVISORIES",
    "STATUS_CLEAN",
    "STATUS_COULD_NOT_CHECK",
    "AuditOutcome",
    "blocking_gaps",
    "run",
    "stack_currency_findings",
    "to_findings",
]
