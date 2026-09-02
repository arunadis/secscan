"""Derived report views (FR-018).

The unified workspace report is the single source of truth; per-repository views
are *projections* of it, never separate scans. This module re-renders a stored
report, optionally filtered to one repository, so subsystem teams can see only
what is theirs while cross-system findings remain visible to whichever repos they
implicate.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pipeline.generate_report import BANDS, render_markdown
from pipeline.state import SCAN_DIR_NAME, canonical_json


def reports_dir(scan_root: Path | str) -> Path:
    return Path(scan_root).resolve() / SCAN_DIR_NAME / "reports"


def latest_report(scan_root: Path | str) -> dict[str, Any]:
    """Most recent report payload for ``scan_root``."""
    directory = reports_dir(scan_root)
    candidates = sorted(directory.glob("*.json")) if directory.exists() else []
    if not candidates:
        raise FileNotFoundError(
            f"no report found in {directory}. Run `secscan run` first."
        )
    document = json.loads(candidates[-1].read_text())
    if isinstance(document, dict) and "payload" in document and "produced_by" in document:
        return document["payload"]
    return document


def _touches_repo(finding: dict[str, Any], repo: str) -> bool:
    """True when the finding is located in, or cites evidence from, ``repo``."""
    if finding.get("location", {}).get("repo") == repo:
        return True
    return any(item.get("repo") == repo for item in finding.get("evidence") or [])


def filter_by_repo(report: dict[str, Any], repo: str) -> dict[str, Any]:
    """Project the unified report onto a single repository."""
    members = report.get("workspace", {}).get("members") or []
    if repo not in members:
        raise ValueError(
            f"unknown repository '{repo}'. This scan covered: {', '.join(members) or 'none'}"
        )

    view = json.loads(canonical_json(report))  # deep copy
    kept_ids: set[str] = set()
    grouped: dict[str, list[dict[str, Any]]] = {}
    for band in BANDS:
        candidates = report["findings_by_band"].get(band) or []
        findings = [f for f in candidates if _touches_repo(f, repo)]
        if findings:
            grouped[band] = findings
            kept_ids.update(f["id"] for f in findings)

    view["findings_by_band"] = grouped
    view["workspace"] = {"id": report["workspace"]["id"], "members": [repo]}
    view["view"] = {"scope": "repository", "repo": repo, "derived_from": report["scan_id"]}

    if report.get("cross_system_findings"):
        retained = [i for i in report["cross_system_findings"] if i in kept_ids]
        if retained:
            view["cross_system_findings"] = retained
        else:
            view.pop("cross_system_findings", None)

    if report.get("attack_paths"):
        paths = [
            path
            for path in report["attack_paths"]
            if any(i in kept_ids for i in path.get("finding_ids") or [])
        ]
        if paths:
            view["attack_paths"] = paths
        else:
            view.pop("attack_paths", None)

    coverage = dict(report.get("coverage") or {})
    coverage["repos_analyzed"] = [repo]
    coverage["clean"] = not kept_ids
    view["coverage"] = coverage

    total = sum(len(v) for v in report["findings_by_band"].values())
    view["executive_summary"] = (
        f"Repository view: {repo}. {len(kept_ids)} of {total} finding(s) from workspace scan "
        f"{report['scan_id']} involve this repository. "
        + ("Cross-system findings are shown to every repository they implicate. " if
           view.get("cross_system_findings") else "")
        + "See the unified workspace report for the full picture."
    )
    return view


def render(
    report: dict[str, Any], repo: str | None = None, output_format: str = "markdown"
) -> str:
    """Render a (optionally repo-filtered) report as markdown, JSON, or HTML."""
    view = filter_by_repo(report, repo) if repo else report
    if output_format == "json":
        return canonical_json(view).rstrip("\n")
    if output_format == "html":
        from pipeline.render_html import render_html

        return render_html(view)
    return render_markdown(view)
