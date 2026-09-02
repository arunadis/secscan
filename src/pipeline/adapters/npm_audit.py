"""npm audit --json adapter (feature 008).

Field variance note (audits/base.py docstring): ``via``, ``effects``, and
``fixAvailable`` vary between runs in shape; only fields with stable meaning
survive normalization. Format drift (auditReportVersion != 2) raises
AdapterError — never a partial merge.
"""

from __future__ import annotations

from typing import Any

from pipeline.adapters.common import AdapterError, dependency_finding, parse_json

LOCKFILE = "package-lock.json"


def normalize(report_text: str, member: str) -> list[dict[str, Any]]:
    document = parse_json(report_text, tool="npm audit")
    if not isinstance(document, dict) or document.get("auditReportVersion") != 2:
        raise AdapterError("unsupported npm audit report shape (expected auditReportVersion 2)")
    vulnerabilities = document.get("vulnerabilities")
    if not isinstance(vulnerabilities, dict):
        raise AdapterError("npm audit report is missing the vulnerabilities mapping")

    findings: list[dict[str, Any]] = []
    for package in sorted(vulnerabilities):
        vuln = vulnerabilities[package] or {}
        advisory: dict[str, Any] = {}
        for via in vuln.get("via") or []:
            if isinstance(via, dict):
                advisory = via
                break
        url = str(advisory.get("url") or "")
        advisory_ids = [url.rsplit("/", 1)[-1]] if "/" in url else []
        if not advisory_ids and advisory.get("source"):
            advisory_ids = [str(advisory["source"])]
        fixed = vuln.get("fixAvailable")
        fixed_version = str(fixed.get("version")) if isinstance(fixed, dict) else ""
        cwes = advisory.get("cwe") or []
        findings.append(
            dependency_finding(
                member,
                package=package,
                ecosystem="npm",
                affected_range=str(advisory.get("range") or vuln.get("range") or ""),
                fixed_version=fixed_version,
                advisory_ids=advisory_ids,
                severity=str(vuln.get("severity") or "unknown"),
                summary=str(advisory.get("title") or ""),
                manifest=LOCKFILE,
                cwe_id=cwes[0] if cwes else None,
                tool="npm-audit",
            )
        )
    return findings
