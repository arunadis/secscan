"""Finding correlation and deduplication (FR-014, FR-015).

US1 scope: collapse identical root causes so the report never shows the same
underlying issue as several independent vulnerabilities, and record the
relationship classification. Cross-repo grouping and conflict reconciliation
deepen with US4 on this same structure.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
from typing import Any

RELATIONSHIPS = ("same", "related", "dependent", "duplicate", "independent")


def _root_cause_key(finding: dict[str, Any]) -> tuple:
    """Findings sharing this key describe the same underlying weakness."""
    location = finding["location"]
    return (
        finding["cwe"],
        location.get("repo"),
        location.get("file"),
        location.get("symbol"),
        # spec 007: distinct deterministic rules at one artifact are distinct
        # root causes (e.g. separate excessive-agency grants in one file);
        # `tool_ref` is absent on model findings, which merge as before.
        finding.get("tool_ref"),
    )


def _systemic_key(finding: dict[str, Any]) -> str:
    """Same weakness class appearing in several places = one systemic issue."""
    return finding["cwe"]


def correlate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group findings, mark duplicates, and attach relationships."""
    groups: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        groups[_root_cause_key(finding)].append(finding)

    canonical: list[dict[str, Any]] = []
    for key in sorted(groups, key=lambda k: tuple(str(p) for p in k)):
        members = sorted(
            groups[key], key=lambda f: (-float(f.get("confidence", 0)), f["id"])
        )
        primary, duplicates = members[0], members[1:]

        for duplicate in duplicates:
            duplicate["status"] = "rejected"
            duplicate["canonical_id"] = primary["id"]
            duplicate.setdefault("relationships", []).append(
                {
                    "target_id": primary["id"],
                    "type": "duplicate",
                    "reason": "same weakness at the same location",
                }
            )
            # Consolidate evidence onto the canonical finding (FR-014).
            seen = {(e["file"], e["reason"]) for e in primary["evidence"]}
            for item in duplicate["evidence"]:
                if (item["file"], item["reason"]) not in seen:
                    primary["evidence"].append(item)
                    seen.add((item["file"], item["reason"]))
        primary["status"] = "correlated"
        canonical.append(primary)

    _link_systemic(canonical)
    return sorted(canonical, key=lambda f: f["id"])


def _link_systemic(findings: list[dict[str, Any]]) -> None:
    """Relate findings that share a weakness class across different locations."""
    by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        by_class[_systemic_key(finding)].append(finding)

    for members in by_class.values():
        if len(members) < 2:
            continue
        ordered = sorted(members, key=lambda f: f["id"])
        anchor = ordered[0]
        for other in ordered[1:]:
            other.setdefault("relationships", []).append(
                {
                    "target_id": anchor["id"],
                    "type": "same",
                    "reason": "same weakness class at a different location (systemic issue)",
                }
            )


def systemic_groups(findings: list[dict[str, Any]]) -> dict[str, list[str]]:
    """CWE -> finding ids, for the report's systemic view."""
    groups: dict[str, list[str]] = defaultdict(list)
    for finding in findings:
        groups[finding["cwe"]].append(finding["id"])
    return {k: sorted(v) for k, v in sorted(groups.items()) if len(v) > 1}


# ---------------------------------------------------------------- finalization


def finalize(
    findings: list[dict[str, Any]],
    graph: dict[str, Any],
    flows: list[Any],
    redactor: Any = None,
    roots: dict[str, Any] | None = None,
    profiles: dict[str, Any] | None = None,
    workspace: dict[str, Any] | None = None,
    manifest: dict[str, Any] | None = None,
    requested_cwes: set[str] | None = None,
    segments: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve → applicability → verify → correlate → calibrate → reproduce.

    Returns ``(kept, rejected, reclassifications)``.

    Shared by the pipeline driver and the standalone stage CLI so the two paths
    can never diverge.

    Location resolution leads (FR-001, FR-007): the code model, not the model's
    output, sets every published line range, and doing it before deduplication is
    what lets findings differing only in guessed line numbers collapse into one.
    Findings whose location cannot be resolved at all are rejected here and join
    the returned rejected bucket rather than being published with a caveat
    (FR-003).
    """
    from pipeline import applicability, controls, reproduce, verify
    from pipeline import calibrate as calibrate_mod
    from pipeline.normalize_findings import resolve_and_dedupe

    deduped, unresolved = resolve_and_dedupe(findings, graph, roots)

    # Applicability precedes correlation so a remap that creates a duplicate is
    # deduplicated rather than reported twice (FR-018).
    reclassifications = applicability.apply_applicability(
        deduped, graph, profiles or {}, workspace, requested_cwes, segments
    )

    kept, disproven = verify.apply_verification(deduped, graph, flows)
    correlated = correlate(kept)

    # Control state, then calibration: the cap is keyed on the verification
    # verdict and on whether a control could be established, so both must be
    # settled first (FR-020, FR-022c).
    frameworks_present = controls.detect_frameworks(manifest, graph)
    for finding in correlated:
        finding["framework_control"] = controls.evaluate(finding, graph, frameworks_present)
    calibrate_mod.apply_calibration(correlated)

    reproduce.apply_reproduction(correlated, redactor, graph=graph)
    rejected = [*disproven, *unresolved]
    for finding in (*correlated, *rejected):
        finding.pop("_flow", None)
    return correlated, rejected, reclassifications


def write(
    store: Any,
    correlated: list[dict[str, Any]],
    disproven: list[dict[str, Any]],
    reclassifications: list[dict[str, Any]] | None = None,
) -> None:
    payload = {
        "findings": correlated,
        "disproven": [f["id"] for f in disproven],
        "systemic_groups": systemic_groups(correlated),
    }
    if reclassifications:
        # Retained even for findings later filtered out by profile thresholds, so
        # a suppression decision is always auditable (FR-017).
        payload["reclassifications"] = reclassifications
    store.write("findings/correlated.json", "correlate_findings", payload)


def load_local_findings(store: Any) -> list[dict[str, Any]]:
    """Every finding produced by segment analysis (`findings/local/*.json`)."""
    findings: list[dict[str, Any]] = []
    for path in store.glob("findings/local/*.json"):
        payload = store.read(f"findings/local/{path.name}")
        findings.extend(payload.get("findings") or [])
    return findings


def main() -> None:  # pragma: no cover - CLI wrapper
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    args = parser.parse_args()

    from config.loader import load
    from pipeline import architecture, dataflow, discover_repo
    from pipeline.redact import Redactor
    from pipeline.state import ArtifactStore

    store = ArtifactStore(args.workdir)
    config = load(store.dir)
    graph = store.read("code-graph.json")
    workspace = store.read_optional("workspace.json") or {}
    roots = discover_repo.member_paths(store, workspace) if workspace else {}
    manifests = {
        name: store.read_optional(f"repository/{name}.manifest.json") or {} for name in roots
    }
    profiles = {
        name: architecture.ArchitectureProfile.from_dict(manifest["architecture"])
        for name, manifest in manifests.items()
        if manifest.get("architecture")
    }
    correlated, disproven, reclassifications = finalize(
        load_local_findings(store),
        graph,
        dataflow.trace_flows(graph),
        Redactor(config.redaction_patterns),
        roots=roots,
        profiles=profiles,
        workspace=workspace,
        manifest=next(iter(manifests.values()), {}),
    )
    write(store, correlated, disproven, reclassifications)
    print(
        f"correlated {len(correlated)} finding(s); {len(disproven)} rejected; "
        f"{len(reclassifications)} reclassified"
    )


if __name__ == "__main__":  # pragma: no cover
    main()
