"""Node ecosystem audit adapter (npm / pnpm / yarn).

Commands and JSON shapes verified in research.md A2. Only the stable subset of
`npm audit --json` is read: `via`, `effects` and `fixAvailable` are known to vary
between runs (npm/cli#4366), and embedding them would break the byte-identical
artifact guarantee.
"""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.audits.base import Advisory, AuditAdapter


class NpmAudit(AuditAdapter):
    ecosystem = "npm"
    tool = "npm"
    manifests = ("package.json",)
    lockfiles = ("package-lock.json", "npm-shrinkwrap.json")

    def _command(self) -> list[str]:
        # `--package-lock-only` audits the lockfile without touching node_modules;
        # `--omit=dev` restricts to runtime exposure (FR-032). Neither writes.
        return ["npm", "audit", "--json", "--omit=dev", "--package-lock-only"]

    def _parse(self, stdout: str, root: Path) -> list[Advisory]:
        document = json.loads(stdout or "{}")
        found: list[Advisory] = []
        for name, entry in sorted((document.get("vulnerabilities") or {}).items()):
            ids = sorted(
                {
                    str(source.get("url") or source.get("source") or "")
                    for source in entry.get("via") or []
                    if isinstance(source, dict)
                }
                - {""}
            )
            fix = entry.get("fixAvailable")
            found.append(
                Advisory(
                    package=str(entry.get("name") or name),
                    ecosystem=self.ecosystem,
                    affected_range=str(entry.get("range") or ""),
                    # Normalized: npm reports this as either a bool or an object.
                    fixed_version=str(fix.get("version", "")) if isinstance(fix, dict) else "",
                    advisory_ids=tuple(ids),
                    severity=str(entry.get("severity") or "unknown"),
                    exposure="runtime",
                    title=str(entry.get("name") or name),
                )
            )
        return found

    def workspace_command(self, member: str) -> list[str]:
        """Per-workspace invocation, which gives per-member attribution (FR-030e)."""
        return [*self._command(), f"--workspace={member}"]


class PnpmAudit(AuditAdapter):
    ecosystem = "npm"
    tool = "pnpm"
    manifests = ("package.json",)
    lockfiles = ("pnpm-lock.yaml",)

    def _command(self) -> list[str]:
        return ["pnpm", "audit", "--json", "--prod"]

    def _parse(self, stdout: str, root: Path) -> list[Advisory]:
        document = json.loads(stdout or "{}")
        found: list[Advisory] = []
        for _key, entry in sorted((document.get("advisories") or {}).items()):
            found.append(
                Advisory(
                    package=str(entry.get("module_name") or ""),
                    ecosystem=self.ecosystem,
                    affected_range=str(entry.get("vulnerable_versions") or ""),
                    fixed_version=str(entry.get("patched_versions") or "" or ""),
                    advisory_ids=(str(entry.get("id") or ""),),
                    severity=str(entry.get("severity") or "unknown"),
                    exposure="runtime",
                    title=str(entry.get("title") or ""),
                )
            )
        return found


class YarnAudit(AuditAdapter):
    """Yarn Berry emits NDJSON since 4.0.1, not one JSON object (research.md A2)."""

    ecosystem = "npm"
    tool = "yarn"
    manifests = ("package.json",)
    lockfiles = ("yarn.lock",)

    def _command(self) -> list[str]:
        return [
            "yarn", "npm", "audit", "--json",
            "--environment", "production", "--all", "--recursive",
        ]

    def _parse(self, stdout: str, root: Path) -> list[Advisory]:
        found: list[Advisory] = []
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            children = entry.get("children") or {}
            if not children:
                continue
            found.append(
                Advisory(
                    package=str(entry.get("value") or ""),
                    ecosystem=self.ecosystem,
                    affected_range=str(children.get("Vulnerable Versions") or ""),
                    fixed_version="",
                    advisory_ids=(str(children.get("ID") or ""),),
                    severity=str(children.get("Severity") or "unknown"),
                    exposure="runtime",
                    title=str(children.get("Issue") or ""),
                )
            )
        return found


#: Preference order: whichever lockfile the project actually uses.
ADAPTERS = (PnpmAudit, YarnAudit, NpmAudit)


def for_root(root: Path) -> AuditAdapter | None:
    """The Node adapter matching this member's lockfile, if any."""
    for adapter_cls in ADAPTERS:
        adapter = adapter_cls()
        if adapter.detect(root) and adapter.has_lockfile(root):
            return adapter
    npm = NpmAudit()
    return npm if npm.detect(root) else None
