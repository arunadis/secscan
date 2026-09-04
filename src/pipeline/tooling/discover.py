"""Tool availability discovery (feature 008, FR-002, FR-003a).

For each applicable registry entry, discovery answers three questions without
executing any tool beyond a bounded version probe:

1. does the **project itself** provide the tool (project-local dependencies,
   declared build plugins, wrapper toolchains)? — read-only manifest reads only
2. is it installed **system-wide**? — PATH, then the Go bin directory
   (``locate.resolve_executable``)
3. what version is it? — a bounded probe; a failed probe yields ``None``,
   which callers must render as undetermined, never assumed.

Precedence is project-provided over system-installed: the project-pinned tool
is the reproducible one (spec clarification, research.md R3).

Discovery NEVER mutates the scanned project: manifest reads and existence
checks only (FR-004).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pipeline.tooling.locate import resolve_executable, resolved_argv
from pipeline.tooling.registry import ToolEntry

SOURCE_PROJECT = "project-provided"
SOURCE_SYSTEM = "system-installed"
SOURCE_MISSING = "missing"

_VERSION_PROBE_TIMEOUT_S = 10


@dataclass(frozen=True)
class Availability:
    """What discovery established about one tool against one workspace root."""

    tool_id: str
    display_name: str
    applicable: bool
    source: str  # project-provided | system-installed | missing
    version: str | None
    invocation: str | None
    network: str
    decision: str = ""  # filled by init's provisioning flow
    detail: str = ""
    # the entry, carried so callers need no registry round-trip
    entry: ToolEntry = field(compare=False, default=None)  # type: ignore[assignment]

    def to_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "tool_id": self.tool_id,
            "applicable": self.applicable,
            "source": self.source,
            "decision": self.decision,
            "network": self.network,
        }
        if self.version is not None:
            record["version"] = self.version
        if self.invocation is not None:
            record["invocation"] = self.invocation
        if self.detail:
            record["detail"] = self.detail
        return record


def probe_version(argv: tuple[str, ...]) -> str | None:
    """First line of stdout from a bounded version probe; None on any failure."""
    if not argv:
        return None
    try:
        proc = subprocess.run(  # noqa: S603 - registry-declared fixed argv
            list(argv),
            capture_output=True,
            text=True,
            timeout=_VERSION_PROBE_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    line = proc.stdout.strip().splitlines()
    return line[0] if line and line[0] else None


def _manifest_dep(root: Path, rule: dict[str, Any]) -> str | None:
    """Tool named as a project-local dependency; returns an invocation base."""
    manifest = root / str(rule["manifest"])
    if not manifest.exists():
        return None
    names = set(str(n) for n in rule.get("names") or ())
    if manifest.name == "package.json":
        try:
            doc = json.loads(manifest.read_text())
        except json.JSONDecodeError:
            return None
        for section in rule.get("sections") or ():
            declared = doc.get(section) or {}
            if names & set(declared):
                exe = declared and sorted(names & set(declared))[0]
                local_bin = root / "node_modules" / ".bin" / exe
                if local_bin.exists():
                    return f"./{local_bin.relative_to(root).as_posix()}"
                return exe  # declared; resolvable at run time from the project env
        return None
    # requirements-style manifests: one "name[...] == version" per line
    for line in manifest.read_text(errors="replace").splitlines():
        package = line.split("==")[0].split(">=")[0].strip().lower()
        if package and package in {n.lower() for n in names}:
            return next(iter(names))
    return None


def _manifest_plugin(root: Path, rule: dict[str, Any]) -> str | None:
    """Build plugin declared in pom.xml or a Gradle build file."""
    manifest = root / str(rule["manifest"])
    if not manifest.exists():
        return None
    text = manifest.read_text(errors="replace")
    gav = rule.get("plugin_gav_prefix")
    plugin_id = rule.get("plugin_id")
    if gav:
        group, artifact = str(gav).split(":", 1)
        if f"<groupId>{group}</groupId>" not in text or f"<artifactId>{artifact}" not in text:
            return None
    elif plugin_id:
        if str(plugin_id) not in text:
            return None
    else:
        return None
    # wrapper first (reproducible, project-pinned); system build tool as fallback
    for wrapper in rule.get("wrappers") or ():
        if (root / str(wrapper)).exists():
            return f"./{wrapper}"
    return {
        "pom.xml": "mvn",
        "build.gradle": "gradle",
        "build.gradle.kts": "gradle",
    }.get(manifest.name, "mvn")


def _bin_path(root: Path, rule: dict[str, Any]) -> str | None:
    for relative in rule.get("paths") or ():
        candidate = root / str(relative)
        if candidate.exists():
            return f"./{candidate.relative_to(root).as_posix()}"
    return None


def _wrapper(root: Path, rule: dict[str, Any]) -> str | None:
    for script in rule.get("scripts") or ():
        if (root / str(script)).exists():
            return f"./{script}"
    return None


_PROJECT_LOCAL = {
    "manifest-dep": _manifest_dep,
    "manifest-plugin": _manifest_plugin,
    "bin-path": _bin_path,
    "wrapper": _wrapper,
}


def discover_tool(root: Path, entry: ToolEntry) -> Availability:
    """Establish availability for one tool against one workspace member root."""
    root = Path(root).resolve()
    # project-provided first: project-pinned beats system-wide (FR-003a)
    for rule in entry.project_local:
        mechanism = _PROJECT_LOCAL.get(str(rule.get("mechanism")))
        if mechanism is None:
            continue
        invocation = mechanism(root, rule)
        if invocation:
            probe = entry.version_probe
            # for project-local instances probe the resolved invocation where sane;
            # a failing probe yields None — declared undetermined, never guessed
            argv = (invocation, *probe[1:]) if probe and invocation.startswith("./") else probe
            return Availability(
                tool_id=entry.id,
                display_name=entry.display_name,
                applicable=True,
                source=SOURCE_PROJECT,
                version=probe_version(argv),
                invocation=invocation,
                network=entry.network,
                entry=entry,
            )
    resolved = resolve_executable(entry.system_executable) if entry.system_executable else None
    if resolved:
        # PATH hit: keep the bare name (stable invocation); a Go-bin-only hit
        # records the absolute path so the scan can execute it without PATH
        on_path = shutil.which(entry.system_executable) is not None
        return Availability(
            tool_id=entry.id,
            display_name=entry.display_name,
            applicable=True,
            source=SOURCE_SYSTEM,
            version=probe_version(tuple(resolved_argv(entry.version_probe))),
            invocation=entry.system_executable if on_path else resolved,
            network=entry.network,
            entry=entry,
        )
    return Availability(
        tool_id=entry.id,
        display_name=entry.display_name,
        applicable=True,
        source=SOURCE_MISSING,
        version=None,
        invocation=None,
        network=entry.network,
        entry=entry,
    )


def discover_roots(roots: dict[str, Path] | Path, entries) -> list[Availability]:
    """Availability per registry entry across workspace members, sorted by id.

    Every member is probed; the first member (sorted order) where a tool is
    project-provided wins, then system-installed, then missing — deterministic
    and monorepo-correct (a plugin declared in any member counts).
    """
    if isinstance(roots, Path):
        roots = {roots.name: roots}
    members = [roots[name] for name in sorted(roots)]
    out: list[Availability] = []
    for entry in entries:
        best: Availability | None = None
        for root in members:
            record = discover_tool(root, entry)
            if record.source != SOURCE_MISSING:
                best = record
                break
        out.append(best if best is not None else discover_tool(members[0], entry))
    return sorted(out, key=lambda a: a.tool_id)


#: Backward-compatible alias for the single-root shape.
discover_all = discover_roots
