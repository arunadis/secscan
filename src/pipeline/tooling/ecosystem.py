"""Ecosystem detection from manifests and build files (feature 008, FR-001).

Detection is deterministic structure-reading — the same manifest set always
yields the same EcosystemDetection list, with evidence paths so every claimed
ecosystem is traceable to the file that established it. Build files count too:
a Gradle project with no pom.xml is still the JVM ecosystem (mapped to the
``maven`` id the audits layer already uses).

Manifests inside skipped directories (node_modules, .secscan, and the
rest of the shared skip set) never count — vendored dependencies and the
scanner's own tooling are not the project's ecosystems.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pipeline.state import is_skipped_dir

#: Manifest / build-file name -> ecosystem id. Gradle build files join pom.xml
#: under the ``maven`` id the audits layer already uses for the JVM.
_MANIFEST_ECOSYSTEMS: dict[str, str] = {
    "package.json": "npm",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "build.gradle.kts": "maven",
    "requirements.txt": "pypi",
    "go.mod": "go",
}


@dataclass(frozen=True)
class EcosystemDetection:
    """One ecosystem present in one workspace member, with its evidence."""

    ecosystem: str
    member: str
    evidence: str  # project-relative manifest/build-file path


def detect_ecosystems(roots: dict[str, Path]) -> list[EcosystemDetection]:
    """One EcosystemDetection per (member, ecosystem, evidence file), sorted."""
    detections: list[EcosystemDetection] = []
    for member in sorted(roots):
        root = Path(roots[member]).resolve()
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            ecosystem = _MANIFEST_ECOSYSTEMS.get(path.name)
            if ecosystem is None:
                continue
            directories = path.relative_to(root).parts[:-1]
            if any(is_skipped_dir(part) for part in directories):
                continue
            detections.append(
                EcosystemDetection(
                    ecosystem=ecosystem,
                    member=member,
                    evidence=path.relative_to(root).as_posix(),
                )
            )
    return detections


def ecosystems_present(roots: dict[str, Path]) -> set[str]:
    """Distinct ecosystems across all members (applicability join input)."""
    return {d.ecosystem for d in detect_ecosystems(roots)}
