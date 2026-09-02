"""Shared normalizer helpers for external-tool adapters (feature 008).

Every adapter turns one tool's report into NormalizedExternalFindings with the
offline-audit finding shape (so downstream stages see one shape) plus:

* ``scanner: <tool id>`` and ``tool_ref: <tool id>`` — the ingestion seam keys
  displacement on these (ingest_findings.covered_domains)
* ``sources: [tool id]`` — merged findings accumulate every contributor
* deterministic content only: run-varying fields (timestamps, version stamps,
  absolute paths beyond the project root) never survive normalization

Wrong-shape reports raise ``AdapterError`` — the runner turns that into a
``failed`` run with a stable reason, never a partial merge (spec Edge Cases:
report format drift).
"""

from __future__ import annotations

import json
from typing import Any

from pipeline import cwe

_SEVERITY_SCORE = {
    "critical": 9.1,
    "high": 7.5,
    "moderate": 5.3,
    "medium": 5.3,
    "low": 3.1,
    "info": 1.0,
    "unknown": 5.0,
}

#: Findings whose CWE is outside the shipped weakness map fall back to the
#: generic known-vulnerable-component class rather than being rejected (the
#: advisory is real even when its CWE id exceeds our taxonomy).
_FALLBACK_CWE = "CWE-1035"


class AdapterError(ValueError):
    """The report does not match the schema this adapter expects (drift)."""


def parse_json(report_text: str, *, tool: str) -> Any:
    try:
        return json.loads(report_text)
    except json.JSONDecodeError as exc:
        raise AdapterError(f"{tool} output is not valid JSON") from exc


def safe_cwe(identifier: Any) -> str:
    """Normalize a tool-supplied CWE id, falling back to CWE-1035."""
    text = str(identifier or "").strip().upper()
    text = text.split(":", 1)[0].split(" ", 1)[0]
    if text and not text.startswith("CWE-"):
        text = f"CWE-{text}" if text.lstrip("CWE-").isdigit() else text
    try:
        cwe.validate_cwe(text)
        return text
    except Exception:
        return _FALLBACK_CWE


def severity_score(severity: Any) -> float:
    return _SEVERITY_SCORE.get(str(severity or "unknown").lower(), 5.0)


def dependency_finding(
    member: str,
    *,
    package: str,
    ecosystem: str,
    affected_range: str,
    fixed_version: str,
    advisory_ids: list[str],
    severity: str,
    summary: str,
    manifest: str,
    cwe_id: str | None,
    tool: str,
) -> dict[str, Any]:
    """The shared known-vulnerable-dependency finding shape."""
    score = severity_score(severity)
    ids = sorted(set(str(i) for i in advisory_ids if i))
    identifier = safe_cwe(cwe_id)
    return {
        "cwe": identifier,
        "severity_score": score,
        "confidence": 0.95,
        "location": {
            "repo": member,
            "file": manifest,
            "symbol": package,
            "line_start": 1,
            "line_end": 1,
            "tier": "file",
            "symbol_confirmed": False,
        },
        "description": (
            f"{package} has a known {str(severity or 'unknown').lower()} advisory"
            f" ({', '.join(ids) or 'id not recorded'}): {summary} "
            f"Affected range {affected_range or 'not recorded'}; "
            f"fixed in {fixed_version or 'a later release'}. Reported by {tool}."
        ),
        "evidence": [
            {
                "repo": member,
                "file": manifest,
                "symbol": package,
                "reason": f"{tool} advisory match: {package} within {affected_range or '?'}",
            }
        ],
        "attack_scenario": (
            "Exploitation depends on the advisory; reachability of the affected "
            "code path is undetermined from the tool report."
        ),
        "impact": summary or "Known vulnerability in a shipped dependency.",
        "recommendation": (
            f"Upgrade {package} to {fixed_version or 'a fixed release'} or later."
        ),
        "source": "external-tool",
        "scanner": tool,
        "tool_ref": tool,
        "sources": [tool],
        "dependency": {
            "package": package,
            "ecosystem": ecosystem,
            "affected_range": affected_range,
            "fixed_version": fixed_version,
            "advisory_ids": ids,
            "exposure": "runtime",
            "affected_members": [member],
            "attribution": "per-member",
            "audit_source": tool,
        },
    }


def code_finding(
    member: str,
    *,
    file: str,
    line: int,
    cwe_id: str | None,
    severity: str,
    message: str,
    tool: str,
    rule: str,
    line_end: int | None = None,
) -> dict[str, Any]:
    """The shared code/secret finding shape for SAST/secrets/IaC tools."""
    identifier = safe_cwe(cwe_id)
    return {
        "cwe": identifier,
        "severity_score": severity_score(severity),
        "confidence": 0.8,
        "location": {
            "repo": member,
            "file": file,
            "line_start": int(line),
            "line_end": int(line_end or line),
            "tier": "file",
            "symbol_confirmed": False,
        },
        "description": f"{message} (reported by {tool}, rule {rule})",
        "evidence": [
            {
                "repo": member,
                "file": file,
                "reason": f"{tool} rule {rule} at line {int(line)}",
            }
        ],
        "attack_scenario": (
            "Exploitation depends on the reported weakness; reachability is "
            "undetermined from static tool output."
        ),
        "impact": message or f"{rule} weakness.",
        "recommendation": f"Remediate the {rule} finding at the reported location.",
        "source": "external-tool",
        "scanner": tool,
        "tool_ref": tool,
        "sources": [tool],
    }
