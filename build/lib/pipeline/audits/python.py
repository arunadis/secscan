"""Python ecosystem audit adapter (`pip-audit`)."""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.audits.base import Advisory, AuditAdapter


class PipAudit(AuditAdapter):
    ecosystem = "pypi"
    tool = "pip-audit"
    manifests = ("requirements.txt", "pyproject.toml", "setup.py", "setup.cfg")
    lockfiles = ("poetry.lock", "uv.lock", "pylock.toml", "Pipfile.lock")

    def _command(self) -> list[str]:
        command = ["pip-audit", "--format", "json", "--progress-spinner", "off"]
        if self._requirements is not None:
            command += ["-r", self._requirements]
        return command

    def __init__(self, requirements: str | None = None) -> None:
        self._requirements = requirements

    def detect(self, root: Path) -> bool:
        found = super().detect(root)
        if found and (root / "requirements.txt").exists():
            self._requirements = "requirements.txt"
        return found

    def _parse(self, stdout: str, root: Path) -> list[Advisory]:
        document = json.loads(stdout or "[]")
        # pip-audit emits either a bare list or {"dependencies": [...]}.
        entries = document if isinstance(document, list) else document.get("dependencies") or []
        found: list[Advisory] = []
        for entry in entries:
            name = str(entry.get("name") or "")
            version = str(entry.get("version") or "")
            for vuln in entry.get("vulns") or []:
                fixes = vuln.get("fix_versions") or []
                found.append(
                    Advisory(
                        package=name,
                        ecosystem=self.ecosystem,
                        affected_range=f"=={version}" if version else "",
                        fixed_version=str(fixes[0]) if fixes else "",
                        advisory_ids=tuple(
                            sorted({str(vuln.get("id") or ""), *(vuln.get("aliases") or [])} - {""})
                        ),
                        severity=str(vuln.get("severity") or "unknown"),
                        exposure="runtime",
                        title=str(vuln.get("description") or "")[:160],
                    )
                )
        return found


def for_root(root: Path) -> AuditAdapter | None:
    adapter = PipAudit()
    return adapter if adapter.detect(root) else None
