"""Semgrep --json adapter (feature 008)."""

from __future__ import annotations

from typing import Any

from pipeline.adapters.common import AdapterError, code_finding, parse_json

_SEVERITY = {"ERROR": "high", "WARNING": "moderate", "INFO": "low"}


def normalize(report_text: str, member: str) -> list[dict[str, Any]]:
    document = parse_json(report_text, tool="semgrep")
    if not isinstance(document, dict) or not isinstance(document.get("results"), list):
        raise AdapterError("semgrep report is missing the results list")

    findings: list[dict[str, Any]] = []
    for result in sorted(
        document["results"],
        key=lambda r: (str(r.get("path")), int((r.get("start") or {}).get("line") or 0)),
    ):
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        cwes = metadata.get("cwe") or []
        findings.append(
            code_finding(
                member,
                file=str(result.get("path") or ""),
                line=int((result.get("start") or {}).get("line") or 1),
                line_end=int((result.get("end") or {}).get("line") or 0) or None,
                cwe_id=cwes[0] if cwes else None,
                severity=_SEVERITY.get(str(extra.get("severity") or "").upper(), "unknown"),
                message=str(extra.get("message") or ""),
                tool="semgrep",
                rule=str(result.get("check_id") or ""),
            )
        )
    return findings
