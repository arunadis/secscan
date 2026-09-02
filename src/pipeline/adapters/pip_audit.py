"""pip-audit -f json adapter (feature 008)."""

from __future__ import annotations

from typing import Any

from pipeline.adapters.common import AdapterError, dependency_finding, parse_json


def normalize(report_text: str, member: str) -> list[dict[str, Any]]:
    document = parse_json(report_text, tool="pip-audit")
    dependencies = (document or {}).get("dependencies")
    if not isinstance(document, dict) or not isinstance(dependencies, list):
        raise AdapterError("pip-audit report is missing the dependencies list")

    findings: list[dict[str, Any]] = []
    for dep in sorted(dependencies, key=lambda d: str(d.get("name"))):
        package = str(dep.get("name") or "")
        for vuln in sorted(dep.get("vulns") or [], key=lambda v: str(v.get("id"))):
            fixes = [str(v) for v in vuln.get("fix_versions") or []]
            findings.append(
                dependency_finding(
                    member,
                    package=package,
                    ecosystem="pypi",
                    affected_range=str(vuln.get("affected_range") or ""),
                    fixed_version=fixes[0] if fixes else "",
                    advisory_ids=[str(vuln.get("id") or "")],
                    severity="unknown",
                    summary=str(vuln.get("description") or "").splitlines()[0][:200],
                    manifest="requirements.txt",
                    cwe_id=None,
                    tool="pip-audit",
                )
            )
    return findings
