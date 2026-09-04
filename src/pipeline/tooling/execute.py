"""Scan-stage external tooling execution (feature 008, FR-005/FR-009/T026).

Runs every applicable, available tool read-only, normalizes its report through
the adapters, and feeds the ingestion seam (``findings/external/*.json``) so
``ingest_findings`` remains the single owner of dedupe and displacement.

Honesty rules wired here:

* every applicable tool not run produces a CoverageLimitationDeclaration —
  missing, config-disabled, lockfile-absent — never silent (FR-009)
* availability is re-probed at scan time; init's availability.json is
  informational only (research.md R8)
* tool output passes through the redactor before any artifact write (FR-011)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from config.loader import Config
from pipeline import adapters
from pipeline.progress import NullReporter
from pipeline.state import ArtifactStore, is_skipped_dir
from pipeline.tooling import discover, ecosystem, registry, runner
from pipeline.tooling.discover import SOURCE_MISSING, SOURCE_PROJECT
from pipeline.tooling.state import write_run_records

#: legacy config toggle names -> registry ids (config.schema stability: the
#: existing `scanners:` section keeps its 001-era names)
_LEGACY_TOGGLE = {
    "semgrep": "semgrep",
    "gitleaks": "gitleaks",
    "osv": "osv-scanner",
    "trivy": "trivy",
}


def _project_relative(file: str, root: Path) -> str | None:
    """``file`` relative to ``root`` (posix), or None when it lies outside."""
    if not file:
        return file
    path = Path(file)
    if not path.is_absolute():
        return path.as_posix()
    for base in (root, root.resolve()):
        try:
            return path.relative_to(base).as_posix()
        except ValueError:
            continue
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return None


def scope_to_project(findings: list[dict[str, Any]], root: Path) -> list[dict[str, Any]]:
    """Keep only findings inside the scanned source tree, with relative paths.

    Whole-tree scanners (gitleaks, trivy fs, ...) walk directories the
    repository model deliberately skips — ``.secscan/`` most importantly, whose
    own state and hashes look exactly like secrets, plus ``.git``,
    ``node_modules`` and friends. Findings there are noise about non-source
    content and would make re-scans of an unchanged tree non-deterministic.
    Absolute paths are also relativized so artifacts never embed the checkout
    location (adapters/common: run-varying content never survives).
    """
    kept: list[dict[str, Any]] = []
    for finding in findings:
        location = finding.get("location") or {}
        relative = _project_relative(str(location.get("file") or ""), root)
        if relative is None:
            continue
        if any(is_skipped_dir(part) for part in Path(relative).parts[:-1]):
            continue
        location["file"] = relative
        for evidence in finding.get("evidence") or []:
            if evidence.get("file"):
                evidence["file"] = _project_relative(str(evidence["file"]), root) or relative
        kept.append(finding)
    return kept


def run_external_scans(
    store: ArtifactStore,
    roots: dict[str, Path],
    config: Config,
    *,
    redactor: Any = None,
    progress: Any = None,
) -> list[dict[str, Any]]:
    """Execute applicable tools; return coverage-limitation declarations.

    ``progress`` (feature 011) receives one ``tool_started``/``tool_done`` pair
    per applicable tool, including the ones skipped before they could run, so
    the operator sees each skip and its reason at the moment it is decided.
    """
    reporter = progress if progress is not None else NullReporter()
    detections = ecosystem.detect_ecosystems(roots)
    present = {d.ecosystem for d in detections}
    if not present:
        return []  # no ecosystems: nothing applicable; init declared this already
    entries = registry.applicable_tools(present)
    toggles = config.scanners()
    primary = sorted(roots)[0]
    root = roots[primary]
    availability_by_id = {a.tool_id: a for a in discover.discover_roots(roots, entries)}

    limitations: list[dict[str, Any]] = []
    runs: list[runner.ToolRun] = []
    total = len(entries)
    stage = "external_tooling"
    for index, entry in enumerate(entries, start=1):
        legacy = next((k for k, v in _LEGACY_TOGGLE.items() if v == entry.id), None)
        setting = toggles.get(legacy) if legacy else None
        if setting is not None and setting.enabled is False:
            limitations.append(
                {
                    "tool_id": entry.id,
                    "status": runner.STATUS_SKIPPED,
                    "reason": f"disabled in project configuration (scanners.{legacy}.enabled)",
                    "affected_ecosystems": sorted(set(entry.ecosystems) & present),
                }
            )
            reporter.tool_done(
                stage, entry.id, index, total,
                status=runner.STATUS_SKIPPED, reason=limitations[-1]["reason"],
            )
            continue

        availability = availability_by_id[entry.id]
        if availability.source == SOURCE_MISSING:
            limitations.append(
                {
                    "tool_id": entry.id,
                    "status": "missing",
                    "reason": f"'{entry.display_name}' is not installed; run init to provision it",
                    "affected_ecosystems": sorted(set(entry.ecosystems) & present),
                }
            )
            reporter.tool_done(
                stage, entry.id, index, total,
                status=runner.STATUS_SKIPPED, reason=limitations[-1]["reason"],
            )
            continue

        lockfile = entry.requires_lockfile
        if lockfile and not (root / lockfile).exists():
            run = runner.ToolRun(
                entry.id,
                runner.STATUS_SKIPPED,
                reason=f"requires {lockfile}, which this project does not have",
            )
            runs.append(run)
            limitations.append(
                {
                    "tool_id": entry.id,
                    "status": runner.STATUS_SKIPPED,
                    "reason": run.reason,
                    "affected_ecosystems": sorted(set(entry.ecosystems) & present),
                }
            )
            reporter.tool_done(
                stage, entry.id, index, total, status=runner.STATUS_SKIPPED, reason=run.reason
            )
            continue

        reporter.tool_started(stage, entry.id, index, total)
        run = runner.run_tool(
            entry,
            root,
            store.dir,
            timeout_s=config.tooling_timeout_s,
            project_invocation=(
                availability.invocation if availability.source == SOURCE_PROJECT else None
            ),
            redactor=redactor,
        )
        if run.status == runner.STATUS_RAN:
            try:
                findings = adapters.normalize(entry.id, run.report_text, primary)
            except adapters.AdapterError as exc:
                run.status = runner.STATUS_FAILED
                run.reason = str(exc)
                run.report_text = ""
            else:
                findings = scope_to_project(findings, root)
                run.finding_count = len(findings)
                store.write(
                    f"findings/external/{entry.id}.json",
                    "ingest_findings",
                    {"findings": findings},
                )
        runs.append(run)
        reporter.tool_done(
            stage,
            entry.id,
            index,
            total,
            status=run.status,
            reason=run.reason,
            tool_version=run.tool_version or "",
            invocation=run.invocation or "",
        )
        if run.status == runner.STATUS_FAILED:
            limitations.append(
                {
                    "tool_id": entry.id,
                    "status": runner.STATUS_FAILED,
                    "reason": run.reason,
                    "affected_ecosystems": sorted(set(entry.ecosystems) & present),
                }
            )

    write_run_records(store.dir, [r.to_record() for r in runs])
    return limitations
