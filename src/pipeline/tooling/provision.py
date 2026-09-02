"""Consent-gated, selective external-tool installation (feature 008, FR-003).

The rules that keep this safe:

* nothing installs before the exact list is presented and confirmed — the
  caller (init) presents; this module only ever installs the *selected* subset
* channels come from the registry (ordered); the first channel whose manager
  is on PATH is used — deterministic across platforms
* installs land in the manager's user-level location; scanner-managed
  downloads/caches live under ``tool_dir()`` — never in the scanned project
* install failures are honest results, never exceptions, and never block
  the scan (FR-003, SC-006 spirit)
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from pipeline.tooling.discover import Availability, probe_version
from pipeline.tooling.registry import ToolEntry

_INSTALL_TIMEOUT_S = 300


@dataclass(frozen=True)
class ProvisionResult:
    tool_id: str
    installed: bool
    detail: str  # channel used, or the failure reason
    version: str | None = None


def resolve_selection(spec: str, missing: list[Availability]) -> set[str]:
    """Selection set from an ``--install`` spec or a prompt answer.

    Accepts ``all``, ``none``/empty, or a comma/space-separated mix of tool ids
    and 1-based positions in the presented (sorted) list. Unknown tokens are
    ignored so a typo cannot widen the install set.
    """
    tokens = [t.strip() for t in spec.replace(",", " ").split() if t.strip()]
    ids = {a.tool_id for a in missing}
    positions = {str(i + 1): a.tool_id for i, a in enumerate(missing)}
    out: set[str] = set()
    for token in tokens:
        if token == "all":
            return ids
        if token in ids:
            out.add(token)
        elif token in positions:
            out.add(positions[token])
    return out


def install_tool(entry: ToolEntry) -> ProvisionResult:
    """Install one tool via its first usable channel. Never raises."""
    for channel in entry.provision_channels:
        manager = str(channel.get("manager") or "")
        if not manager or shutil.which(manager) is None:
            continue
        argv = [str(arg) for arg in channel.get("argv") or []]
        try:
            proc = subprocess.run(  # noqa: S603 - registry-declared fixed argv
                argv,
                capture_output=True,
                text=True,
                timeout=_INSTALL_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ProvisionResult(entry.id, False, f"'{manager}' install timed out")
        except OSError as exc:
            return ProvisionResult(entry.id, False, f"'{manager}' install failed: {exc}")
        if proc.returncode != 0:
            # stderr deliberately not embedded: tool chatter contains absolute
            # paths and timestamps that would make artifacts non-deterministic
            return ProvisionResult(
                entry.id, False, f"'{manager}' install exited {proc.returncode}"
            )
        # verify, don't trust: the tool must now resolve and answer its probe
        if entry.system_executable and shutil.which(entry.system_executable) is None:
            return ProvisionResult(
                entry.id,
                False,
                f"installed via {manager} but '{entry.system_executable}' still not on PATH",
            )
        return ProvisionResult(
            entry.id,
            True,
            f"installed via {manager}",
            version=probe_version(entry.version_probe),
        )
    return ProvisionResult(entry.id, False, "no usable install channel on this machine")


def install_selected(
    missing: list[Availability],
    selection: set[str],
) -> list[ProvisionResult]:
    """Install exactly the confirmed subset, in deterministic order."""
    results: list[ProvisionResult] = []
    for record in sorted(missing, key=lambda a: a.tool_id):
        if record.tool_id not in selection or record.entry is None:
            continue
        results.append(install_tool(record.entry))
    return results
