"""OWASP Dependency-Check JSON adapter (feature 008).

Both invocation modes (project-declared plugin, standalone CLI) emit the same
report schema. Format drift (reportSchema outside 1.x) raises AdapterError.
"""

from __future__ import annotations

from typing import Any

from pipeline.adapters.common import AdapterError, dependency_finding, parse_json


def _package_coordinates(raw: dict[str, Any]) -> tuple[str, str] | None:
    for package in raw.get("packages") or []:
        purl = str(package.get("id") or "")
        if purl.startswith("pkg:maven/") and "@" in purl:
            name, _, version = purl.removeprefix("pkg:maven/").partition("@")
            return name.replace("/", ":"), version
    return None


def normalize(report_text: str, member: str) -> list[dict[str, Any]]:
    document = parse_json(report_text, tool="dependency-check")
    if not isinstance(document, dict) or not str(document.get("reportSchema", "")).startswith("1."):
        raise AdapterError("unsupported dependency-check report schema")

    findings: list[dict[str, Any]] = []
    for dep in document.get("dependencies") or []:
        coordinates = _package_coordinates(dep)
        if coordinates is None:
            continue
        package, _version = coordinates
        for vuln in dep.get("vulnerabilities") or []:
            cwss = vuln.get("cvssv3") or {}
            summary = str(vuln.get("description") or "")
            findings.append(
                dependency_finding(
                    member,
                    package=package,
                    ecosystem="maven",
                    affected_range="",
                    fixed_version="",
                    advisory_ids=[str(vuln.get("name") or "")],
                    severity=str(
                        vuln.get("severity")
                        or ("high" if cwss.get("baseScore", 0) >= 7 else "unknown")
                    ),
                    summary=summary.splitlines()[0][:200],
                    manifest="pom.xml",
                    cwe_id=None,
                    tool="owasp-dependency-check",
                )
            )
    return findings
