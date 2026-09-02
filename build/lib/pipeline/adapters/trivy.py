"""Trivy fs --format json adapter (feature 008).

Covers vulnerabilities (dependency advisories) and misconfigurations (IaC);
secret findings from trivy are left to gitleaks to avoid double-reporting.
"""

from __future__ import annotations

from typing import Any

from pipeline.adapters.common import AdapterError, code_finding, dependency_finding, parse_json

_TYPE_ECOSYSTEM = {
    "npm": "npm", "pip": "pypi", "poetry": "pypi",
    "jar": "maven", "pom": "maven", "gomod": "go",
}

_SEVERITY = {
    "CRITICAL": "critical", "HIGH": "high",
    "MEDIUM": "moderate", "LOW": "low", "UNKNOWN": "unknown",
}


def normalize(report_text: str, member: str) -> list[dict[str, Any]]:
    document = parse_json(report_text, tool="trivy")
    if not isinstance(document, dict) or document.get("SchemaVersion") != 2:
        raise AdapterError("unsupported trivy report schema version")

    findings: list[dict[str, Any]] = []
    for result in sorted(document.get("Results") or [], key=lambda r: str(r.get("Target"))):
        ecosystem = _TYPE_ECOSYSTEM.get(str(result.get("Type") or "").lower())
        manifest = str(result.get("Target") or "")
        vulnerabilities = result.get("Vulnerabilities") or []
        for vuln in sorted(vulnerabilities, key=lambda v: str(v.get("VulnerabilityID"))):
            if not ecosystem or not vuln.get("PkgName") or not vuln.get("VulnerabilityID"):
                continue
            findings.append(
                dependency_finding(
                    member,
                    package=str(vuln["PkgName"]),
                    ecosystem=ecosystem,
                    affected_range="",
                    fixed_version=str(vuln.get("FixedVersion") or ""),
                    advisory_ids=[str(vuln["VulnerabilityID"])],
                    severity=_SEVERITY.get(str(vuln.get("Severity") or "").upper(), "unknown"),
                    summary=str(vuln.get("Title") or vuln.get("Description") or ""),
                    manifest=manifest or "package-lock.json",
                    cwe_id=None,
                    tool="trivy",
                )
            )
        misconfigurations = result.get("Misconfigurations") or []
        for misconfig in sorted(misconfigurations, key=lambda m: str(m.get("ID"))):
            if not misconfig.get("ID"):
                continue
            filename = str(misconfig.get("Filename") or manifest or ".")
            findings.append(
                code_finding(
                    member,
                    file=filename,
                    line=1,
                    cwe_id=None,
                    severity=_SEVERITY.get(str(misconfig.get("Severity") or "").upper(), "unknown"),
                    message=str(misconfig.get("Title") or misconfig.get("Message") or ""),
                    tool="trivy",
                    rule=str(misconfig["ID"]),
                )
            )
    return findings
