"""Java ecosystem adapter — coordinates plus offline advisory match.

Java is the one ecosystem with **no read-only native audit**, and the distinction
matters enough to state plainly. The usual answer, OWASP `dependency-check`, would
have Maven or Gradle resolve and *download* a plugin artifact, which FR-031
forbids outright. Rather than break that guarantee or leave a grammar-backed
language uncovered (FR-030d), this adapter:

1. enumerates resolved coordinates in Maven's **offline** mode, and
2. matches them against a bundled advisory export.

Same output shape, same guarantees. When the offline resolution cannot complete —
typically because the local repository was never populated — the result is
``could-not-check`` with the command an operator should run, exactly like a
missing toolchain (research.md A2).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from pipeline import resources
from pipeline.audits.base import STATUS_COULD_NOT_CHECK, Advisory, AuditAdapter, AuditOutcome

#: `groupId:artifactId:packaging:version:scope`
_COORDINATE = re.compile(
    r"^\[INFO\]\s+([\w.\-]+):([\w.\-]+):[\w.\-]+:([\w.\-]+)(?::(\w+))?\s*$", re.M
)

#: Scopes that are not shipped at runtime (FR-032).
_DEV_SCOPES = frozenset({"test", "provided"})

ADVISORY_FILE = "maven_advisories.json"


class MavenCoordinateAudit(AuditAdapter):
    ecosystem = "maven"
    capability = "coordinates-plus-offline-match"
    tool = "mvn"
    manifests = ("pom.xml",)
    lockfiles = ()

    def _command(self) -> list[str]:
        # `-o` is offline: no plugin download, no artifact resolution over the
        # network, nothing written to the project.
        return ["mvn", "-o", "-q", "dependency:list"]

    def remediation(self) -> str:
        return "osv-scanner --lockfile=pom.xml .   # or: mvn -o dependency:list"

    def _advisories(self) -> dict[str, list[dict]]:
        try:
            return json.loads(resources.data_path(ADVISORY_FILE).read_text())["packages"]
        except (FileNotFoundError, KeyError, json.JSONDecodeError):
            return {}

    def _parse(self, stdout: str, root: Path) -> list[Advisory]:
        known = self._advisories()
        found: list[Advisory] = []
        for group, artifact, version, scope in _COORDINATE.findall(stdout or ""):
            coordinate = f"{group}:{artifact}"
            exposure = "development" if (scope or "").lower() in _DEV_SCOPES else "runtime"
            for entry in known.get(coordinate, []):
                if _version_affected(version, entry):
                    found.append(
                        Advisory(
                            package=coordinate,
                            ecosystem=self.ecosystem,
                            affected_range=str(entry.get("affected_range") or ""),
                            fixed_version=str(entry.get("fixed") or ""),
                            advisory_ids=tuple(sorted(entry.get("ids") or ())),
                            severity=str(entry.get("severity") or "unknown"),
                            exposure=exposure,
                            title=str(entry.get("summary") or "")[:160],
                        )
                    )
        return found

    def audit(self, root: Path, member: str, timeout_s: int = 120) -> AuditOutcome:
        """Adds one honest caveat on top of the base behaviour.

        With no bundled advisory export there is nothing to match against, so a
        successful coordinate enumeration would otherwise report ``clean`` — an
        unknown dressed as a reassurance. That is refused explicitly.
        """
        if not self._advisories():
            return AuditOutcome(
                member=member,
                ecosystem=self.ecosystem,
                status=STATUS_COULD_NOT_CHECK,
                tool=self.tool,
                reason=(
                    "no bundled advisory export is available for Maven coordinates, so "
                    "dependencies could be enumerated but not assessed"
                ),
                remediation_command=self.remediation(),
            )
        return super().audit(root, member, timeout_s)


def _version_affected(version: str, entry: dict) -> bool:
    """Conservative range match: `introduced` <= version < `fixed`.

    Deliberately simple and deliberately inclusive at the boundaries. A false
    positive here costs a reader a moment; a false negative hides a known
    vulnerable component.
    """
    fixed = str(entry.get("fixed") or "")
    introduced = str(entry.get("introduced") or "")

    def parts(value: str) -> tuple[int, ...]:
        return tuple(int(p) for p in re.findall(r"\d+", value)[:4]) or (0,)

    current = parts(version)
    if introduced and current < parts(introduced):
        return False
    return not (fixed and current >= parts(fixed))


def for_root(root: Path) -> AuditAdapter | None:
    adapter = MavenCoordinateAudit()
    return adapter if adapter.detect(root) else None
