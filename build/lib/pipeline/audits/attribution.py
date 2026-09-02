"""Advisory grouping and monorepo attribution (FR-030b, FR-030e, FR-030f).

One advisory yields one finding that names every affected member. Where a single
hoisted lockfile covers several members the audit tool answers for the whole tree,
so attribution follows an ordered fallback:

1. **Native per-member.** `npm audit --workspace=<name>` gives per-workspace
   output even with one hoisted lockfile.
2. **Declaring manifests.** Map the advisory's package back to the members whose
   own manifests declare it.
3. **Workspace-level, stated.** ``workspace-not-derivable``.

Guessing and broadening to every member are both prohibited. Broadening looks
safe — it never misses an affected member — but it overstates blast radius on
every advisory and makes per-member views useless, so it is a precision failure
dressed as caution.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pipeline.audits.base import Advisory

ATTRIBUTION_PER_MEMBER = "per-member"
ATTRIBUTION_NOT_DERIVABLE = "workspace-not-derivable"


@dataclass
class GroupedAdvisory:
    """An advisory with every member it affects."""

    advisory: Advisory
    members: tuple[str, ...]
    attribution: str
    version_ambiguous: bool = False
    sources: tuple[str, ...] = ()


def declared_packages(root: Path) -> set[str]:
    """Package names a member's own manifests declare, for fallback 2."""
    names: set[str] = set()
    package_json = root / "package.json"
    if package_json.exists():
        try:
            document = json.loads(package_json.read_text())
        except (OSError, json.JSONDecodeError):
            document = {}
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            names.update(document.get(key) or {})

    requirements = root / "requirements.txt"
    if requirements.exists():
        for line in requirements.read_text(errors="replace").splitlines():
            token = line.strip().split("=")[0].split("<")[0].split(">")[0].split("[")[0]
            if token and not token.startswith("#"):
                names.add(token.strip())

    go_mod = root / "go.mod"
    if go_mod.exists():
        for line in go_mod.read_text(errors="replace").splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and "." in parts[0] and "/" in parts[0]:
                names.add(parts[0])
    return {n.lower() for n in names}


def group(
    per_member: dict[str, list[Advisory]],
    roots: dict[str, Path] | None = None,
    lockfile_shared: bool = False,
    version_ambiguous: dict[str, bool] | None = None,
) -> list[GroupedAdvisory]:
    """Group advisories by identity and attribute them to members."""
    roots = roots or {}
    version_ambiguous = version_ambiguous or {}

    by_identity: dict[tuple, list[tuple[str, Advisory]]] = {}
    for member, advisories in sorted(per_member.items()):
        for advisory in advisories:
            by_identity.setdefault(advisory.identity, []).append((member, advisory))

    grouped: list[GroupedAdvisory] = []
    for identity in sorted(by_identity, key=lambda k: tuple(str(p) for p in k)):
        entries = by_identity[identity]
        reporters = sorted({member for member, _ in entries})
        # Runtime exposure wins when a package is both: it is the one that ships.
        advisory = sorted(
            (a for _, a in entries), key=lambda a: (a.exposure != "runtime", a.package)
        )[0]

        members, attribution = _attribute(advisory, reporters, roots, lockfile_shared)
        grouped.append(
            GroupedAdvisory(
                advisory=advisory,
                members=members,
                attribution=attribution,
                version_ambiguous=any(version_ambiguous.get(m, False) for m in reporters),
                sources=tuple(sorted({a.ecosystem for _, a in entries})),
            )
        )
    return grouped


def _attribute(
    advisory: Advisory,
    reporters: list[str],
    roots: dict[str, Path],
    lockfile_shared: bool,
) -> tuple[tuple[str, ...], str]:
    if not lockfile_shared:
        # Each member was audited against its own lockfile, so the reporting
        # member *is* the affected member.
        return tuple(reporters), ATTRIBUTION_PER_MEMBER

    declaring = sorted(
        member
        for member, root in roots.items()
        if advisory.package.lower() in declared_packages(root)
    )
    if declaring:
        return tuple(declaring), ATTRIBUTION_PER_MEMBER
    # The package is transitive under a hoisted lockfile and no member declares
    # it. Naming a member would be a guess; naming all of them would overstate.
    return (), ATTRIBUTION_NOT_DERIVABLE


def to_finding_payload(grouped: GroupedAdvisory, audit_source: str) -> dict[str, Any]:
    """The `dependency` block for a finding (contracts/schema-deltas.md)."""
    advisory = grouped.advisory
    payload: dict[str, Any] = {
        "package": advisory.package,
        "ecosystem": advisory.ecosystem,
        "exposure": advisory.exposure,
        "attribution": grouped.attribution,
        "audit_source": audit_source,
    }
    if advisory.affected_range:
        payload["affected_range"] = advisory.affected_range
    if advisory.fixed_version:
        payload["fixed_version"] = advisory.fixed_version
    if advisory.advisory_ids:
        payload["advisory_ids"] = list(advisory.advisory_ids)
    if grouped.members:
        payload["affected_members"] = list(grouped.members)
    if grouped.version_ambiguous:
        payload["version_ambiguous"] = True
    return payload
