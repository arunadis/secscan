"""Go ecosystem audit adapter (`govulncheck`).

Reachability-aware, which makes its results unusually precise: it reports only
advisories whose vulnerable symbols are actually called.
"""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.audits.base import Advisory, AuditAdapter


class GovulncheckAudit(AuditAdapter):
    ecosystem = "go"
    tool = "govulncheck"
    manifests = ("go.mod",)
    lockfiles = ("go.sum",)

    def _command(self) -> list[str]:
        return ["govulncheck", "-json", "./..."]

    def _parse(self, stdout: str, root: Path) -> list[Advisory]:
        """govulncheck streams JSON objects; only `osv` entries carry advisories."""
        found: list[Advisory] = []
        decoder = json.JSONDecoder()
        text = (stdout or "").strip()
        index = 0
        while index < len(text):
            try:
                entry, offset = decoder.raw_decode(text, index)
            except json.JSONDecodeError:
                break
            index = offset
            while index < len(text) and text[index] in " \r\n\t":
                index += 1
            osv = entry.get("osv") if isinstance(entry, dict) else None
            if not osv:
                continue
            aliases = tuple(sorted({str(osv.get("id") or ""), *(osv.get("aliases") or [])} - {""}))
            for affected in osv.get("affected") or []:
                module = (affected.get("package") or {}).get("name") or ""
                fixed = ""
                for rng in affected.get("ranges") or []:
                    for event in rng.get("events") or []:
                        if event.get("fixed"):
                            fixed = str(event["fixed"])
                found.append(
                    Advisory(
                        package=str(module),
                        ecosystem=self.ecosystem,
                        affected_range="",
                        fixed_version=fixed,
                        advisory_ids=aliases,
                        severity=str(
                            (osv.get("database_specific") or {}).get("severity") or "unknown"
                        ),
                        # Go modules have no runtime/development split.
                        exposure="runtime",
                        title=str(osv.get("summary") or "")[:160],
                    )
                )
        return found


def for_root(root: Path) -> AuditAdapter | None:
    adapter = GovulncheckAudit()
    return adapter if adapter.detect(root) else None
