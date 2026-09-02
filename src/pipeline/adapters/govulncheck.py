"""govulncheck -json adapter (feature 008).

govulncheck streams one JSON message per line; ``finding`` messages carry the
advisory id, and ``osv`` messages carry affected package metadata. Matching by
id reconstructs package/affected-range conservatively: anything we cannot
reconstruct is reported with explicit gaps rather than dropped.
"""

from __future__ import annotations

import json
from typing import Any

from pipeline.adapters.common import AdapterError, dependency_finding


def normalize(report_text: str, member: str) -> list[dict[str, Any]]:
    findings: dict[str, dict[str, Any]] = {}
    packages_by_osv: dict[str, str] = {}
    saw_message = False
    for line in report_text.splitlines():
        line = line.strip()
        if not line:
            continue
        saw_message = True
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AdapterError("govulncheck stream contains a non-JSON message") from exc
        piece = message.get("osv")
        if piece:
            affected = piece.get("affected") or [{}]
            package = affected[0].get("package") or {}
            if piece.get("id") and package.get("name"):
                packages_by_osv[str(piece["id"])] = str(package["name"])
        piece = message.get("finding")
        if piece and piece.get("osv"):
            findings.setdefault(str(piece["osv"]), {"osv": str(piece["osv"])})
    if not saw_message and report_text.strip():
        raise AdapterError("govulncheck output is not a JSON message stream")

    out: list[dict[str, Any]] = []
    for osv_id in sorted(findings):
        package = packages_by_osv.get(osv_id, osv_id)
        out.append(
            dependency_finding(
                member,
                package=package,
                ecosystem="go",
                affected_range="",
                fixed_version="",
                advisory_ids=[osv_id],
                severity="unknown",
                summary=f"govulncheck advisory {osv_id}",
                manifest="go.mod",
                cwe_id=None,
                tool="govulncheck",
            )
        )
    return out
