"""Gitleaks detect --report-format json adapter (feature 008).

FR-011 carve-out: gitleaks output embeds the matched secret. The report text is
redacted BEFORE it reaches this adapter (runner layer), and this adapter never
copies ``Secret``/``Match`` fields — the finding names the rule and location,
the value appears nowhere (Principle III: the same value is reportable while
never printable).
"""

from __future__ import annotations

from typing import Any

from pipeline.adapters.common import AdapterError, code_finding, parse_json

#: Hard-coded credentials are the redactor's own authoritative class (CWE-798).
_CWE = "CWE-798"


def normalize(report_text: str, member: str) -> list[dict[str, Any]]:
    document = parse_json(report_text, tool="gitleaks")
    if not isinstance(document, list):
        raise AdapterError("gitleaks report must be a JSON list")

    findings: list[dict[str, Any]] = []
    for record in sorted(
        document,
        key=lambda r: (str(r.get("File")), int(r.get("StartLine") or 0)),
    ):
        findings.append(
            code_finding(
                member,
                file=str(record.get("File") or ""),
                line=int(record.get("StartLine") or 1),
                line_end=int(record.get("EndLine") or 0) or None,
                cwe_id=_CWE,
                severity="high",
                message=(
                    f"Hard-coded secret matched by rule "
                    f"'{record.get('RuleID', 'unknown')}' (value redacted)"
                ),
                tool="gitleaks",
                rule=str(record.get("RuleID") or "unknown"),
            )
        )
    return findings
