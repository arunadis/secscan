"""Read-only, timeout-bounded external tool execution (feature 008, T020/T021).

Every run satisfies the same guarantees the native audits layer established
(`audits/base.py`), extended to general findings tools:

* **Read-only, checked not trusted** (FR-004): project files are fingerprinted
  before and after; a run that writes has its output discarded and becomes
  ``failed`` with ``read_only_guard: tripped``.
* **Never raises**: missing tools, timeouts, crashes, and unparseable output
  all degrade to ``failed``/``skipped`` with a stable, deterministic reason —
  stderr is deliberately never embedded (it carries per-run paths/timestamps).
* **Declared network**: the entry's network requirement is recorded, not hidden.

Artifacts land under ``<store_dir>/tooling/`` (availability.json, runs.json,
out/<tool>/) — never in the scanned project.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pipeline import resources
from pipeline.audits import offline as audits_offline
from pipeline.state import is_skipped_dir, iter_source_files
from pipeline.tooling import tool_dir
from pipeline.tooling.discover import probe_version
from pipeline.tooling.locate import resolved_argv
from pipeline.tooling.registry import ToolEntry
from pipeline.tooling.state import write_run_records

STATUS_RAN = "ran"
STATUS_SKIPPED = "skipped"
STATUS_FAILED = "failed"

#: Manifests/lockfiles/build files whose mutation a read-only run must reveal,
#: beyond what source enumeration covers (requirements.txt, go.mod, wrappers
#: and Gradle files carry no enumerated suffix).
_GUARD_NAMES = (
    set(audits_offline._MANIFEST_NAMES)
    | {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "poetry.lock",
        "Pipfile.lock",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "gradle.lockfile",
        "mvnw",
        "gradlew",
    }
)


@dataclass
class ToolRun:
    """What one invocation established — the honest tri-state in structured form."""

    tool_id: str
    status: str  # ran | skipped | failed
    reason: str = ""
    invocation: str = ""
    report_text: str = ""
    read_only_guard: str = "waived-not-applicable"
    tool_version: str | None = None
    db_version: str | None = None
    finding_count: int = 0

    def to_record(self) -> dict[str, Any]:
        # No scan_id: scan correlation comes from the store state; embedding it
        # would break byte-identity across two scans of identical input (SC-013
        # invariant test).
        record: dict[str, Any] = {
            "tool_id": self.tool_id,
            "status": self.status,
            "invocation": self.invocation,
            "read_only_guard": self.read_only_guard,
            "finding_count": self.finding_count,
        }
        if self.reason:
            record["reason"] = self.reason
        if self.tool_version:
            record["tool_version"] = self.tool_version
        if self.db_version:
            record["db_version"] = self.db_version
        return record


def _project_fingerprint(root: Path) -> dict[str, int]:
    """size+mtime of every enumerated source file plus guarded manifest names."""
    out: dict[str, int] = {}
    root = Path(root).resolve()
    candidates = {p for p in iter_source_files(root)}
    for path in root.rglob("*"):
        if not path.is_file() or path.name not in _GUARD_NAMES:
            continue
        directories = path.relative_to(root).parts[:-1]
        if any(is_skipped_dir(part) for part in directories):
            continue
        candidates.add(path)
    for path in candidates:
        try:
            rel = path.relative_to(root).as_posix()
            stat = path.stat()
            out[rel] = hash((stat.st_size, int(stat.st_mtime_ns)))
        except OSError:
            continue
    return out


def render_argv(template: list[str], mapping: dict[str, str]) -> list[str]:
    return [
        arg.format(**mapping) if "{" in arg else arg
        for arg in (str(a) for a in template)
    ]


def run_tool(
    entry: ToolEntry,
    project_root: Path,
    store_dir: Path,
    *,
    timeout_s: int | None = None,
    project_invocation: str | None = None,
    redactor: Any = None,
) -> ToolRun:
    """Execute one tool per its registry invocation contract. Never raises."""
    root = Path(project_root).resolve()
    store_dir = Path(store_dir).resolve()
    timeout = timeout_s if timeout_s is not None else entry.timeout_s

    invoke = entry.invoke
    if project_invocation and entry.invoke_project:
        invoke = entry.invoke_project

    out_dir = store_dir / "tooling" / "out" / entry.id
    out_dir.mkdir(parents=True, exist_ok=True)
    mapping = {
        "project": str(root),
        "out_dir": str(out_dir),
        "out_file": str(out_dir / "report.json"),
        "data_dir": str(tool_dir() / "data"),
        "payload_data": str(resources.data_dir()),
        "wrapper": project_invocation or entry.system_executable,
    }
    argv = render_argv(list(invoke.get("argv") or []), mapping)
    if not argv:
        return ToolRun(entry.id, STATUS_FAILED, reason="registry entry has no invocation")
    if project_invocation and not entry.invoke_project:
        # project-provided binary from manifest-dep/bin-path discovery: swap argv0
        argv = [project_invocation, *argv[1:]]
    elif not argv[0].startswith("./"):
        # system tool: PATH, else the Go bin dir (`go install` target) — argv0
        # becomes the absolute path only when PATH alone cannot resolve it
        argv = resolved_argv(argv)

    run = ToolRun(
        entry.id,
        STATUS_FAILED,
        invocation=" ".join(argv),
        tool_version=probe_version(tuple(resolved_argv(entry.version_probe))),
    )

    executable = argv[0].removeprefix("./")
    if argv[0].startswith("./"):
        if not (root / executable).exists():
            run.status = STATUS_SKIPPED
            run.reason = f"project-declared invocation '{argv[0]}' is not present"
            return run
    elif shutil.which(executable) is None:
        run.status = STATUS_SKIPPED
        run.reason = f"'{executable}' is not installed on this machine"
        return run

    before = _project_fingerprint(root)
    try:
        proc = subprocess.run(  # noqa: S603 - registry-declared fixed argv
            argv,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        run.reason = f"'{entry.id}' did not finish within {timeout}s"
        run.read_only_guard = "passed"
        return run
    except OSError as exc:
        run.reason = f"'{entry.id}' could not be executed: {exc}"
        run.read_only_guard = "passed"
        return run

    run.read_only_guard = "passed"
    if before != _project_fingerprint(root):
        # The read-only contract was violated; the output is untrustworthy
        # because the tool changed the thing it was measuring (FR-004).
        run.read_only_guard = "tripped"
        run.reason = (
            f"'{entry.id}' modified project files, which the read-only contract "
            "forbids; its output is discarded"
        )
        return run

    report_path: Path | None = None
    if invoke.get("report_out") == "file":
        if "{out_file}" in " ".join(invoke.get("argv") or []):
            report_path = Path(mapping["out_file"])
        else:
            report_path = out_dir / str(invoke.get("report_file") or "report.json")
        try:
            run.report_text = report_path.read_text(errors="replace")
        except OSError:
            run.report_text = ""
    else:
        run.report_text = proc.stdout or ""

    if redactor is not None and run.report_text:
        # FR-011: redact before parse AND before the artifact stays on disk —
        # the raw file is the tool's own output and may embed matched secrets.
        run.report_text = redactor.redact(run.report_text, origin=f"tool:{entry.id}").text
        if report_path is not None and report_path.exists():
            report_path.write_text(run.report_text)

    if not run.report_text.strip() and proc.returncode != 0:
        run.reason = (
            f"'{entry.id}' exited {proc.returncode} without usable output — "
            "most often a missing lockfile/input or no network access "
            "to the advisory source"
        )
        return run

    run.status = STATUS_RAN
    return run


def write_runs(store_dir: Path, runs: list[ToolRun]) -> Path:
    """Persist ToolRunRecords, stable-sorted by tool id."""
    records = [run.to_record() for run in sorted(runs, key=lambda r: r.tool_id)]
    return write_run_records(store_dir, records)
