"""Pipeline driver: stage sequencing, resume, and execution-mode switching.

Same code path in both execution modes (FR-027): only the analysis client differs.
Every stage checkpoints, so an interrupted scan resumes on the next invocation
(FR-016a) — including across agent sessions.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from config import mode as mode_mod
from config import profiles as profiles_mod
from config.loader import Config, load
from pipeline import (
    agent_config,
    architecture,
    build_code_graph,
    build_context,
    compound,
    correlate_findings,
    dataflow,
    discover_repo,
    generate_report,
    ingest_findings,
    llm_findings,
    misconfig,
    partition_repo,
    prompts,
    secret_findings,
    supply_chain,
)
from pipeline.budget import TokenBudget, estimate_tokens
from pipeline.escalate import EscalationRunner
from pipeline.llm_client import AgentHandoff, build_client
from pipeline.normalize_findings import (
    FindingNormalizer,
    MalformedAnalysisOutput,
)
from pipeline.redact import Redactor
from pipeline.state import ArtifactStore, hash_document, iter_source_files
from pipeline.usage import UsageTracker


@dataclass
class ScanResult:
    """Everything a caller (or test) needs to inspect a completed scan."""

    scan_root: Path
    scan_id: str
    config: Config
    profile: profiles_mod.ScanProfile
    workspace: dict[str, Any]
    graph: dict[str, Any]
    segments: list[dict[str, Any]]
    context_packets: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    report: dict[str, Any]
    report_path: Path
    report_json_path: Path
    report_html_path: Path
    usage: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    pending_requests: list[str] = field(default_factory=list)

    @property
    def reported_findings(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for band_findings in self.report["findings_by_band"].values():
            out.extend(band_findings)
        return out

    @property
    def all_source_files(self) -> list[str]:
        files: list[str] = []
        for repo, root in discover_repo.member_paths(
            ArtifactStore(self.scan_root), self.workspace
        ).items():
            files.extend(f"{repo}:{p.relative_to(root)}" for p in iter_source_files(root))
        return sorted(files)

    @property
    def total_source_tokens(self) -> int:
        total = 0
        for _repo, root in discover_repo.member_paths(
            ArtifactStore(self.scan_root), self.workspace
        ).items():
            for path in iter_source_files(root):
                try:
                    total += estimate_tokens(path.read_text(errors="replace"))
                except OSError:
                    continue
        return total


def run_scan(
    scan_root: Path | str,
    *,
    responder: Any | None = None,
    transport: Any | None = None,
    profile: str | None = None,
    overrides: dict[str, Any] | None = None,
    full: bool = False,
    only_segment: str | None = None,
    environ: dict[str, str] | None = None,
) -> ScanResult:
    """Execute the pipeline against ``scan_root``.

    ``only_segment`` re-runs analysis for a single segment from persisted
    artifacts (SC-007) without re-executing the other segments.
    """
    scan_root = Path(scan_root).resolve()
    store = ArtifactStore(scan_root)
    config = load(store.dir, environ=environ)

    resolution = mode_mod.resolve(config, environ=environ)
    active_profile = profiles_mod.resolve(
        profile, custom=config.custom_profiles, overrides=overrides
    )
    budget = TokenBudget.from_dict(config.budgets)
    redactor = Redactor(config.redaction_patterns, **_entropy_kwargs(config))
    usage = UsageTracker()
    warnings: list[str] = []

    # A deeper profile than the last run must re-analyze (FR-028 edge case).
    previous_depth = store.get_meta("profile_depth_key")
    if previous_depth and previous_depth != active_profile.depth_key:
        full = True
        warnings.append(
            f"analysis depth changed ({previous_depth} -> {active_profile.depth_key}); "
            "re-analyzing so earlier shallow results are not presented as exhaustive"
        )
    if full:
        store.invalidate(*_ANALYSIS_STAGES)

    # ---------------------------------------------------- stage 1: discover
    workspace = _stage(
        store,
        "discover_repo",
        resume_key=hash_document(
            {"members": config.workspace_members, "root": str(scan_root)}
        ),
        artifact="workspace.json",
        run=lambda: discover_repo.run(
            store, config.workspace_members, config.workspace_integrations
        ),
    )

    roots = discover_repo.member_paths(store, workspace)
    file_hashes = store.snapshot_files(roots)

    # -------------------------------------------------- stage 2: code graph
    graph = _stage(
        store,
        "build_code_graph",
        resume_key=hash_document(file_hashes),
        artifact="code-graph.json",
        run=lambda: build_code_graph.run(store, workspace),
    )

    # -------------------------------------------------- stage 3: partition
    graph_key = hash_document(graph)
    segments = _stage_list(
        store,
        "partition_repo",
        resume_key=f"{graph_key}|{budget.max_context_tokens}",
        pattern="segments/*.json",
        run=lambda: partition_repo.run(store, workspace, graph, budget.max_context_tokens),
    )

    if only_segment:
        known = {segment["id"] for segment in segments}
        if only_segment not in known:
            raise ValueError(
                f"unknown segment '{only_segment}'. This scan has: {', '.join(sorted(known))}"
            )
        segments = [s for s in segments if s["id"] == only_segment]
        warnings.append(
            f"single-segment run: only '{only_segment}' was analyzed; the report covers "
            "this segment alone"
        )

    # ------------------------------------------- stage 4-6: bounded analysis
    flows = dataflow.trace_flows(graph)
    builder = build_context.ContextBuilder(store, workspace, graph, budget, redactor)
    client = build_client(
        resolution,
        config.api_key(),
        responder=responder,
        transport=transport,
        handoff_dir=store.dir / "handoff",
    )
    runner = EscalationRunner(
        client=client,
        builder=builder,
        usage=usage,
        prompt=prompts.render_prompt("segment_scan.md"),
        max_level=active_profile.analysis_depth.max_escalation_level,
    )

    normalizer = FindingNormalizer()
    packets: list[dict[str, Any]] = []
    #: segment id -> findings produced at the local stage (analysis + secrets).
    #: Accumulated before writing so `findings/local/*.json` is the complete
    #: record of the stage — a standalone `correlate_findings` run must see
    #: exactly what the driver saw.
    per_segment: dict[str, list[dict[str, Any]]] = {s["id"]: [] for s in segments}
    pending: list[str] = []
    store.mark_running("segment_analysis")

    for segment in segments:
        segment_flows = dataflow.flows_for_segment(graph, segment, flows)
        outcome = runner.run(segment, segment_flows, on_packet=packets.append)
        if outcome.pending:
            pending.append(outcome.segment_id)
            continue
        try:
            parsed = normalizer.parse(outcome.content)
        except MalformedAnalysisOutput as exc:
            warnings.append(f"{segment['id']}: {exc}")
            continue
        result = normalizer.normalize(
            parsed,
            source="analysis",
            status="local",
            default_repo=segment["repos"][0],
            segment_id=segment["id"],
        )
        for rejected in result.rejected:
            warnings.append(
                f"{segment['id']}: rejected non-conforming finding "
                f"({rejected['cwe']} in {rejected['file']}): {rejected['reason']}"
            )
        per_segment[segment["id"]].extend(result.findings)

    # Hard-coded credentials are detected deterministically by the redactor: their
    # values never reach a model, so no analysis step could report them (FR-006a).
    for segment in segments:
        hits = builder.secret_hits.get(segment["id"])
        if not hits:
            continue
        secret_result = normalizer.normalize(
            secret_findings.findings_from_hits(hits, segment["repos"][0], segment["id"]),
            source="analysis",
            status="local",
            default_repo=segment["repos"][0],
            segment_id=segment["id"],
        )
        per_segment[segment["id"]].extend(secret_result.findings)
        for rejected in secret_result.rejected:
            warnings.append(f"{segment['id']}: secret finding rejected: {rejected['reason']}")

    raw_findings: list[dict[str, Any]] = []
    for segment_id, findings in sorted(per_segment.items()):
        raw_findings.extend(findings)
        store.write(
            f"findings/local/{segment_id}.json",
            "segment_analysis",
            {"segment_id": segment_id, "findings": findings},
        )

    # ------------------------------------- deterministic whole-repo stages (feature 004)
    # Misconfiguration rules and compound weakness rules evaluate whole-repo
    # deterministic facts (R1, R2); findings append to raw_findings so they get
    # location resolution, verification, and calibration like any other.
    misconfig_raw = misconfig.run(roots)
    if misconfig_raw:
        misconfig_findings = normalizer.normalize(
            misconfig_raw,
            source="scanner-ingest",
            status="local",
            default_repo=sorted(roots)[0],
        ).findings
        raw_findings.extend(misconfig_findings)
        store.write(
            "findings/misconfig.json",
            "misconfig",
            {"findings": misconfig_findings},
        )
    compound_raw = compound.run(roots)
    if compound_raw:
        compound_findings = normalizer.normalize(
            compound_raw,
            source="scanner-ingest",
            status="local",
            default_repo=sorted(roots)[0],
        ).findings
        raw_findings.extend(compound_findings)
        store.write(
            "findings/compound.json",
            "compound",
            {"findings": compound_findings},
        )
    # Spec 007: flow-derived LLM/modern-exploit findings over graph annotations.
    # Deterministic; findings get location resolution, verification, and
    # calibration like any other downstream (misconfig precedent).
    llm_raw = llm_findings.run(graph)
    # Spec 007 FR-001/honest-uncertainty: prompt-shaped context with no
    # recognized integration is declared, never silently skipped.
    for node in graph["nodes"]:
        if node["type"] != "file":
            continue
        if "llm_undetermined" in (node.get("annotations") or []):
            warnings.append(
                f"{node['id']}: prompt-shaped context found but no recognized "
                "LLM integration; integration posture undetermined at this call site"
            )
    if llm_raw:
        llm_norm = normalizer.normalize(
            llm_raw,
            source="scanner-ingest",
            status="local",
            default_repo=sorted(roots)[0],
        ).findings
        raw_findings.extend(llm_norm)
        store.write(
            "findings/llm.json",
            "llm_findings",
            {"findings": llm_norm},
        )
    # Spec 007 US3: deterministic review of shipped AI configuration artifacts.
    # Credentials embedded in prompt artifacts are reported while their values
    # appear nowhere (redactor hit labels only - FR-009).
    supply_raw = supply_chain.run(roots)
    if supply_raw:
        supply_findings = normalizer.normalize(
            supply_raw,
            source="scanner-ingest",
            status="local",
            default_repo=sorted(roots)[0],
        ).findings
        raw_findings.extend(supply_findings)
        store.write(
            "findings/supply_chain.json",
            "supply_chain",
            {"findings": supply_findings},
        )
    config_review = agent_config.run(roots, redactor=redactor)
    agent_config_findings: list[dict[str, Any]] = []
    if config_review.findings:
        agent_config_findings = normalizer.normalize(
            config_review.findings,
            source="scanner-ingest",
            status="local",
            default_repo=sorted(roots)[0],
        ).findings
        raw_findings.extend(agent_config_findings)
        store.write(
            "findings/agent_config.json",
            "agent_config",
            {"findings": agent_config_findings},
        )
    if config_review.secret_hits:
        for repo in sorted(roots):
            root = roots[repo]
            enumerated = {str(p.relative_to(root)) for p in iter_source_files(root)}
            hits = [h for h in config_review.secret_hits if h.origin in enumerated]
            if not hits:
                continue
            secret_result = normalizer.normalize(
                secret_findings.findings_from_hits(hits, repo),
                source="analysis",
                status="local",
                default_repo=repo,
            )
            raw_findings.extend(secret_result.findings)

    # --------------------------- external tooling (feature 008, FR-005/FR-009)
    # Runs BEFORE the native audits so the ingestion seam sees external output
    # when deciding displacement (the documented no-silent-skip trap). Every
    # applicable tool not run becomes a declared coverage limitation (FR-009).
    from pipeline.tooling import execute as tooling_execute

    tool_limitations = tooling_execute.run_external_scans(store, roots, config, redactor=redactor)

    # ------------------------------------- dependency audits (FR-030 - FR-035)
    # Deterministic, read-only, and per member against that member's own
    # ecosystem. Runs regardless of what analysis found, because the reviewed
    # benchmark's largest real exposure lived entirely in this domain.
    #
    # Routed through `ingest_findings` so de-duplication against external scanner
    # output has exactly one owner (FR-030c).
    dependency_findings, audit_outcomes, audit_gaps = ingest_findings.run_dependency_audits(
        store, roots, start_id=len(raw_findings) + 1
    )
    suppressions_payload = store.read_optional("tooling/suppressions.json", {"suppressions": []})
    suppressions = suppressions_payload.get("suppressions") or []
    raw_findings.extend(dependency_findings)
    if dependency_findings:
        store.write(
            "findings/dependencies.json",
            "ingest_findings",
            {"findings": dependency_findings},
        )
    store.write("dependency-audit.json", "ingest_findings", {"outcomes": audit_outcomes})

    warnings.extend(builder.warnings)

    if pending:
        store.save_state()
        handoff = AgentHandoff(pending)
        handoff.request_dir = store.dir / "handoff" / "requests"
        handoff.response_dir = store.dir / "handoff" / "responses"
        raise handoff

    store.mark_done("segment_analysis", hash_document(file_hashes))

    # --------------------------------- stage 7-9: normalize, verify, correlate
    # Shared with `python -m pipeline.correlate_findings` so the driver and the
    # standalone stage can never diverge.
    manifests = {
        name: store.read_optional(f"repository/{name}.manifest.json") or {}
        for name in roots
    }
    profiles = {
        name: architecture.ArchitectureProfile.from_dict(manifest["architecture"])
        for name, manifest in manifests.items()
        if manifest.get("architecture")
    }
    primary_manifest = next(iter(manifests.values()), {})

    correlated, disproven, reclassifications = correlate_findings.finalize(
        raw_findings,
        graph,
        flows,
        redactor,
        roots=roots,
        profiles=profiles,
        workspace=workspace,
        manifest=primary_manifest,
        segments=segments,
    )
    correlate_findings.write(store, correlated, disproven, reclassifications)

    # ---------------------------------------------- stage 10-11: review, report
    system_review = ""
    if active_profile.analysis_depth.system_review:
        system_review = _system_review_narrative(correlated, workspace)
        store.write_text("system-review.md", system_review)

    report = generate_report.build_report(
        scan_id=store.scan_id,
        workspace=workspace,
        execution_mode=resolution.mode.value,
        profile=active_profile,
        findings=correlated,
        usage=usage,
        segments_analyzed=len(segments),
        coverage_gaps=warnings,
        gap_records=builder.gap_records,
        unavailable_features=list(resolution.unavailable_features),
        rejected=disproven,
        graph=graph,
        audit_outcomes=audit_outcomes,
        blocking_gaps=audit_gaps,
        tool_limitations=tool_limitations,
        suppressions=suppressions,
        scan_root=scan_root,
    )
    markdown_path, json_path, html_path = generate_report.write(store, report, system_review)
    store.write("usage.json", "generate_report", usage.to_dict(), "usage")

    store.record_files(file_hashes)
    store.set_meta("profile_depth_key", active_profile.depth_key)
    store.mark_done("generate_report", hash_document(report["findings_by_band"]))

    return ScanResult(
        scan_root=scan_root,
        scan_id=store.scan_id,
        config=config,
        profile=active_profile,
        workspace=workspace,
        graph=graph,
        segments=segments,
        context_packets=packets,
        findings=correlated,
        report=report,
        report_path=markdown_path,
        report_json_path=json_path,
        report_html_path=html_path,
        usage=usage.to_dict(),
        warnings=warnings,
        pending_requests=pending,
    )


#: Stages invalidated when analysis depth changes. Ordered as in `state.STAGES`.
#: The feature-002 accuracy stages belong here because each of them consumes an
#: analysis result: a change in depth changes the findings, which changes their
#: applicability conclusion, calibration, and reproduction blocks.
_ANALYSIS_STAGES = (
    "partition_repo",
    "build_context",
    "segment_analysis",
    "normalize_findings",
    "applicability",
    "verify_findings",
    "correlate_findings",
    "calibrate",
    "reproduce",
    "consistency",
    "system_review",
    "generate_report",
)


def _entropy_kwargs(config: Config) -> dict[str, float]:
    threshold = config.entropy_threshold
    return {"entropy_threshold": threshold} if threshold is not None else {}


def _stage(
    store: ArtifactStore, name: str, *, resume_key: str, artifact: str, run: Any
) -> dict[str, Any]:
    """Run a single-artifact stage, honouring the resume checkpoint."""
    if store.should_skip(name, resume_key) and store.exists(artifact):
        return store.read(artifact)
    store.mark_running(name)
    try:
        document = run()
    except Exception as exc:
        store.mark_failed(name, str(exc))
        raise
    store.mark_done(name, resume_key, [artifact])
    return document


def _stage_list(
    store: ArtifactStore, name: str, *, resume_key: str, pattern: str, run: Any
) -> list[dict[str, Any]]:
    if store.should_skip(name, resume_key):
        existing = store.glob(pattern)
        if existing:
            return [store.read(str(p.relative_to(store.dir))) for p in existing]
    store.mark_running(name)
    try:
        documents = run()
    except Exception as exc:
        store.mark_failed(name, str(exc))
        raise
    store.mark_done(name, resume_key)
    return documents


def _system_review_narrative(
    findings: list[dict[str, Any]], workspace: dict[str, Any]
) -> str:
    """Deterministic system-level narrative from structured evidence only.

    In agent-mediated operation the host agent enriches this via
    ``prompts/final_review.md``; the deterministic baseline guarantees the artifact
    always exists and never reads source.
    """
    members = [m["name"] for m in workspace["members"]]
    systemic = correlate_findings.systemic_groups(findings)
    lines = [
        "# System-Level Security Review",
        "",
        f"Workspace: {', '.join(members)} "
        f"({len(workspace.get('integrations') or [])} declared integration point(s))",
        "",
    ]
    if systemic:
        lines.append("## Systemic weaknesses")
        lines.append("")
        for identifier, ids in systemic.items():
            from pipeline import cwe as cwe_mod

            lines.append(
                f"- **{cwe_mod.name_for(identifier)}** ({identifier}) appears in "
                f"{len(ids)} location(s): {', '.join(ids)}. Consider a shared control "
                "rather than per-site fixes."
            )
        lines.append("")

    cross = [
        f
        for f in findings
        if len({e.get("repo") for e in f.get("evidence") or []}) > 1
    ]
    lines.append("## Cross-boundary observations")
    lines.append("")
    if cross:
        for finding in cross:
            repos = sorted({e.get("repo") for e in finding["evidence"] if e.get("repo")})
            lines.append(
                f"- `{finding['id']}` spans {', '.join(repos)}: {finding['description']}"
            )
    elif len(members) > 1:
        lines.append(
            "- No vulnerability was traced across the workspace's integration points in "
            "this scan."
        )
    else:
        lines.append(
            "- Single-repository workspace: cross-repository analysis is not applicable."
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:  # pragma: no cover - CLI wrapper
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()

    try:
        result = run_scan(args.workdir, profile=args.profile, full=args.full)
    except AgentHandoff as handoff:
        print(handoff.instructions())
        raise SystemExit(3) from None

    print(f"scan {result.scan_id}: {len(result.reported_findings)} finding(s) reported")
    print(f"report: {result.report_path}")


if __name__ == "__main__":  # pragma: no cover
    main()
