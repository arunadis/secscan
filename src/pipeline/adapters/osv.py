"""OSV-Scanner JSON adapter (feature 008)."""

from __future__ import annotations

from typing import Any

from pipeline.adapters.common import AdapterError, dependency_finding, parse_json

_LOCKFILE_HINTS = {
    "npm": "package-lock.json",
    "pypi": "requirements.txt",
    "maven": "pom.xml",
    "go": "go.mod",
}


def _affected_range(vulnerability: dict[str, Any]) -> tuple[str, str]:
    introduced = fixed = ""
    for affected in vulnerability.get("affected") or []:
        for r in affected.get("ranges") or []:
            for event in r.get("events") or []:
                if "introduced" in event:
                    introduced = str(event["introduced"])
                elif "fixed" in event:
                    fixed = str(event["fixed"])
    range_str = f"<{fixed}" if fixed else (f">={introduced}" if introduced else "")
    return range_str, fixed


def normalize(report_text: str, member: str) -> list[dict[str, Any]]:
    document = parse_json(report_text, tool="osv-scanner")
    if not isinstance(document, dict) or not isinstance(document.get("results"), list):
        raise AdapterError("osv-scanner report is missing the results list")

    findings: list[dict[str, Any]] = []
    for result in document["results"]:
        for package_result in result.get("packages") or []:
            package_info = package_result.get("package") or {}
            package = str(package_info.get("name") or "")
            ecosystem = str(package_info.get("ecosystem") or "").lower()
            if not package or ecosystem not in _LOCKFILE_HINTS:
                continue
            for vulnerability in package_result.get("vulnerabilities") or []:
                if not vulnerability.get("id"):
                    continue
                affected_range, fixed = _affected_range(vulnerability)
                severity = "high" if vulnerability.get("severity") else "unknown"
                findings.append(
                    dependency_finding(
                        member,
                        package=package,
                        ecosystem=ecosystem,
                        affected_range=affected_range,
                        fixed_version=fixed,
                        advisory_ids=[str(vulnerability["id"])],
                        severity=severity,
                        summary=str(vulnerability.get("summary") or ""),
                        manifest=_LOCKFILE_HINTS[ecosystem],
                        cwe_id=None,
                        tool="osv-scanner",
                    )
                )
    return findings
