"""Native dependency-audit adapter protocol (FR-030–FR-033).

The reviewed benchmark's largest real exposure — 23 runtime advisories, 15 of them
high, on a stack years past end of life — was invisible because no dedicated
scanner happened to be installed on the machine, and the domain silently produced
nothing.

Every adapter here must satisfy the same guarantees, each of which exists because
its violation would be worse than reporting nothing:

* **Read-only** (FR-031). No install, no upgrade, no manifest or lockfile write.
  A security tool that mutates the thing it measures cannot be run where it is
  most needed.
* **Never raises.** A missing toolchain, a non-zero exit, a timeout, unparseable
  output, or a network failure all become ``could-not-check`` with a reason.
* **``clean`` means audited and clean.** Any uncertainty is ``could-not-check``.
  Conflating the two converts an unknown into a reassurance, which is the single
  worst thing this module could do.
* **Deterministic output.** Adapter output is a normalized projection, never
  verbatim tool output — `npm audit --json` is known to vary between runs in
  `via`, `effects` and `fixAvailable` (research.md A2), and artifacts must stay
  byte-identical for identical input.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Tri-state outcome. The third state is the whole point (FR-033).
STATUS_ADVISORIES = "advisories"
STATUS_CLEAN = "clean"
STATUS_COULD_NOT_CHECK = "could-not-check"

#: Per-member wall-clock ceiling. Expiry is `could-not-check`, never a hang.
DEFAULT_TIMEOUT_S = 120

_SEVERITY_SCORE = {
    "critical": 9.1,
    "high": 7.5,
    "moderate": 5.3,
    "medium": 5.3,
    "low": 3.1,
    "info": 1.0,
    "unknown": 5.0,
}


@dataclass(frozen=True)
class Advisory:
    """One known-vulnerable component, normalized across ecosystems."""

    package: str
    ecosystem: str
    affected_range: str = ""
    fixed_version: str = ""
    advisory_ids: tuple[str, ...] = ()
    severity: str = "unknown"
    #: runtime | development (FR-032)
    exposure: str = "runtime"
    title: str = ""

    @property
    def severity_score(self) -> float:
        return _SEVERITY_SCORE.get(self.severity.lower(), 5.0)

    @property
    def identity(self) -> tuple[str, str, str]:
        """Grouping key: one advisory yields one finding across members (FR-030b)."""
        return (self.ecosystem, self.package, self.affected_range)


@dataclass
class AuditOutcome:
    """Per member and ecosystem, what the audit actually established."""

    member: str
    ecosystem: str
    status: str
    advisories: list[Advisory] = field(default_factory=list)
    reason: str = ""
    remediation_command: str = ""
    tool: str = ""
    tool_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "member": self.member,
            "ecosystem": self.ecosystem,
            "status": self.status,
        }
        for key in ("reason", "remediation_command", "tool", "tool_version"):
            value = getattr(self, key)
            if value:
                out[key] = value
        return out

    @property
    def checked(self) -> bool:
        return self.status != STATUS_COULD_NOT_CHECK


class AuditAdapter:
    """Base adapter. Subclasses implement `_command` and `_parse`."""

    ecosystem = ""
    capability = "native-advisory"
    tool = ""
    manifests: tuple[str, ...] = ()
    lockfiles: tuple[str, ...] = ()

    # ------------------------------------------------------------- detection

    def detect(self, root: Path) -> bool:
        """Manifest presence only — never executes anything."""
        return any((root / name).exists() for name in self.manifests)

    def available(self) -> bool:
        return bool(self.tool) and shutil.which(self.tool) is not None

    def has_lockfile(self, root: Path) -> bool:
        return any((root / name).exists() for name in self.lockfiles)

    def remediation(self) -> str:
        return " ".join(self._command())

    # --------------------------------------------------------------- running

    def _command(self) -> list[str]:  # pragma: no cover - overridden
        raise NotImplementedError

    def _parse(self, stdout: str, root: Path) -> list[Advisory]:  # pragma: no cover
        raise NotImplementedError

    def audit(self, root: Path, member: str, timeout_s: int = DEFAULT_TIMEOUT_S) -> AuditOutcome:
        """Run the audit read-only. Never raises; never mutates the project."""
        outcome = AuditOutcome(
            member=member,
            ecosystem=self.ecosystem,
            status=STATUS_COULD_NOT_CHECK,
            tool=self.tool,
            remediation_command=self.remediation(),
        )

        if not self.available():
            outcome.reason = f"'{self.tool}' is not installed on this machine"
            return outcome

        before = _manifest_fingerprint(root, self.manifests + self.lockfiles)
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                self._command(),
                cwd=root,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            outcome.reason = f"'{self.tool}' did not finish within {timeout_s}s"
            return outcome
        except OSError as exc:
            outcome.reason = f"'{self.tool}' could not be executed: {exc}"
            return outcome

        # Read-only guarantee, checked rather than trusted (FR-031). If a command
        # ever starts writing, its result is discarded rather than used.
        after = _manifest_fingerprint(root, self.manifests + self.lockfiles)
        if before != after:  # pragma: no cover - guard against a future regression
            outcome.reason = (
                "the audit command modified a manifest or lockfile, which FR-031 "
                "forbids; its result is discarded"
            )
            return outcome

        try:
            advisories = self._parse(proc.stdout, root)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            outcome.reason = f"'{self.tool}' output could not be parsed: {exc}"
            return outcome

        # A non-zero exit is normal for these tools when advisories exist, so the
        # exit code alone cannot distinguish failure from findings. Empty output
        # plus a non-zero exit is the ambiguous case, and ambiguity is not clean.
        if not advisories and proc.returncode != 0:
            # Deliberately does NOT embed stderr. Tool diagnostics carry absolute
            # paths and timestamps (npm names a per-run debug log), which would
            # make the artifact differ between identical runs and break SC-013.
            # A stable classification is more useful to a reader anyway.
            outcome.reason = (
                f"'{self.tool}' exited {proc.returncode} without usable output — "
                "most often a missing or unreadable lockfile, or no network access "
                "to the advisory source"
            )
            return outcome

        outcome.advisories = _dedupe(advisories)
        outcome.status = STATUS_ADVISORIES if advisories else STATUS_CLEAN
        return outcome


def _manifest_fingerprint(root: Path, names: tuple[str, ...]) -> dict[str, int]:
    """Size+mtime of every manifest and lockfile, to prove nothing was written."""
    out: dict[str, int] = {}
    for name in names:
        path = root / name
        try:
            stat = path.stat()
            out[name] = hash((stat.st_size, int(stat.st_mtime_ns)))
        except OSError:
            continue
    return out


def _dedupe(advisories: list[Advisory]) -> list[Advisory]:
    """Deterministic, deduplicated ordering (the same package can appear twice)."""
    seen: set[tuple] = set()
    out: list[Advisory] = []
    for advisory in sorted(
        advisories, key=lambda a: (a.ecosystem, a.package, a.affected_range, a.exposure)
    ):
        key = (*advisory.identity, advisory.exposure)
        if key not in seen:
            seen.add(key)
            out.append(advisory)
    return out
