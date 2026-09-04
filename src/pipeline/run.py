"""Pipeline driver: stage sequencing, resume, and execution-mode switching.

Same code path in both execution modes (FR-027): only the analysis client differs.
Every stage checkpoints, so an interrupted scan resumes on the next invocation
(FR-016a) — including across agent sessions.
"""

from __future__ import annotations

import argparse
import time
from collections.abc import Callable
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
    triage,
    triage_apply,
    triage_declarations,
)
from pipeline.answers import AnswerStore
from pipeline.batch_runner import BatchLedger, BatchRoundRunner
from pipeline.budget import TokenBudget, estimate_tokens
from pipeline.escalate import EscalationRunner
from pipeline.llm_client import AgentHandoff, RetryPolicy, build_client
from pipeline.normalize_findings import (
    FindingNormalizer,
    MalformedAnalysisOutput,
)
from pipeline.progress import NullReporter
from pipeline.providers import EndpointError
from pipeline.redact import Redactor
from pipeline.state import ANSWERS_DIR, ArtifactStore, hash_document, iter_source_files
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
    progress: Any | None = None,
    clock: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> ScanResult:
    """Execute the pipeline against ``scan_root``.

    ``only_segment`` re-runs analysis for a single segment from persisted
    artifacts (SC-007) without re-executing the other segments.

    ``progress`` is a ``pipeline.progress.ProgressReporter`` (feature 011). It
    is a side channel only: nothing it receives is written to an artifact.

    ``transport`` is a ``pipeline.providers.HttpTransport`` — the endpoint
    adapters' only I/O seam (feature 012); ``clock``/``sleep`` drive retry waits
    and batch polling so tests run without wall time.
    """
    scan_root = Path(scan_root).resolve()
    store = ArtifactStore(scan_root)
    config = load(store.dir, environ=environ)
    reporter = progress if progress is not None else NullReporter()
    clock = clock or time.monotonic
    sleep = sleep or time.sleep

    resolution = mode_mod.resolve(config, environ=environ)
    active_profile = profiles_mod.resolve(
        profile, custom=config.custom_profiles, overrides=overrides
    )
    budget = TokenBudget.from_dict(config.budgets)
    redactor = Redactor(config.redaction_patterns, **_entropy_kwargs(config))
    usage = UsageTracker()
    warnings: list[str] = []

    def _warn(message: str, *, stage: str, subject: str | None = None) -> None:
        # One helper both records and reports, so the terminal can never
        # disagree with the report's coverage notes (FR-006).
        warnings.append(message)
        reporter.warning(message, stage=stage, subject=subject)

    def _fail_text(exc: BaseException) -> str:
        return redactor.redact(str(exc)).text

    reporter.scan_started(store.scan_id, profile=active_profile.name, mode=resolution.mode_label)
    stage_kwargs = {"reporter": reporter, "fail_text": _fail_text}

    # A deeper profile than the last run must re-analyze (FR-028 edge case).
    previous_depth = store.get_meta("profile_depth_key")
    if previous_depth and previous_depth != active_profile.depth_key:
        full = True
        _warn(
            f"analysis depth changed ({previous_depth} -> {active_profile.depth_key}); "
            "re-analyzing so earlier shallow results are not presented as exhaustive",
            stage="partition_repo",
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
        **stage_kwargs,
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
        **stage_kwargs,
    )

    # -------------------------------------------------- stage 3: partition
    graph_key = hash_document(graph)
    segments = _stage_list(
        store,
        "partition_repo",
        resume_key=f"{graph_key}|{budget.max_context_tokens}",
        pattern="segments/*.json",
        run=lambda: partition_repo.run(store, workspace, graph, budget.max_context_tokens),
        **stage_kwargs,
    )

    if only_segment:
        known = {segment["id"] for segment in segments}
        if only_segment not in known:
            raise ValueError(
                f"unknown segment '{only_segment}'. This scan has: {', '.join(sorted(known))}"
            )
        segments = [s for s in segments if s["id"] == only_segment]
        _warn(
            f"single-segment run: only '{only_segment}' was analyzed; the report covers "
            "this segment alone",
            stage="partition_repo",
        )

    # ------------------------------------------- stage 4-6: bounded analysis
    flows = dataflow.trace_flows(graph)
    builder = build_context.ContextBuilder(store, workspace, graph, budget, redactor)
    answers = AnswerStore(store.dir / ANSWERS_DIR)

    def _on_retry(request_id: str | None, attempt: int, wait_s: float, status: int | None):
        # Retry notices are progress only, never coverage notes (FR-015).
        kind = (
            "rate limited (HTTP 429)"
            if status == 429
            else f"transient endpoint error (HTTP {status})" if status else
            "transient endpoint error (connection)"
        )
        reporter.warning(
            f"{request_id}: {kind}, attempt {attempt}/{resolution.retry_attempts}, "
            f"waiting {round(wait_s)}s",
            stage="segment_analysis",
            subject=request_id,
        )

    client = build_client(
        resolution,
        config.api_key(),
        responder=responder,
        transport=transport,
        handoff_dir=store.dir / "handoff",
        answers=answers,
        retry=RetryPolicy(
            attempts=resolution.retry_attempts,
            max_wait_s=float(resolution.retry_max_wait_s),
            sleep=sleep,
        ),
        on_retry=_on_retry,
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
    reporter.stage_started("segment_analysis")
    total_segments = len(segments)

    def _absorb_outcome(segment: dict[str, Any], outcome: Any) -> None:
        # One post-processing path for both execution policies (feature 012, FR-012):
        # the batch and interactive branches cannot diverge in how an answer is judged.
        if outcome.pending:
            pending.append(outcome.segment_id)
            return
        try:
            parsed = normalizer.parse(outcome.content)
        except MalformedAnalysisOutput as exc:
            _warn(f"{segment['id']}: {exc}", stage="segment_analysis", subject=segment["id"])
            return
        result = normalizer.normalize(
            parsed,
            source="analysis",
            status="local",
            default_repo=segment["repos"][0],
            segment_id=segment["id"],
        )
        for rejected in result.rejected:
            _warn(
                f"{segment['id']}: rejected non-conforming finding "
                f"({rejected['cwe']} in {rejected['file']}): {rejected['reason']}",
                stage="segment_analysis",
                subject=segment["id"],
            )
        per_segment[segment["id"]].extend(result.findings)
        # Persisted as soon as the segment is judged, so an interruption later in the
        # stage loses nothing already analysed (FR-018); rewritten below once the
        # deterministic secret findings are appended, with identical content otherwise.
        _write_local(segment["id"])

    def _write_local(segment_id: str) -> None:
        store.write(
            f"findings/local/{segment_id}.json",
            "segment_analysis",
            {"segment_id": segment_id, "findings": per_segment[segment_id]},
        )

    def _endpoint_failed(exc: EndpointError) -> None:
        # Work already persisted (answers, findings) survives; the CLI reports the
        # failure without a traceback and the next run resumes here (FR-017).
        store.mark_failed("segment_analysis", str(exc))
        reporter.stage_failed("segment_analysis", _fail_text(exc))

    if resolution.mode is mode_mod.ExecutionMode.ENDPOINT_BATCH:
        batch_runner = BatchRoundRunner(
            client,  # type: ignore[arg-type]
            runner,
            BatchLedger(store),
            answers,
            usage,
            reporter,
            window_hours=resolution.batch_window_hours,
            clock=clock,
            sleep=sleep,
            offpeak_window=resolution.offpeak_window,
        )
        try:
            outcomes = batch_runner.run(
                segments,
                lambda s: dataflow.flows_for_segment(graph, s, flows),
                on_packet=packets.append,
            )
        except EndpointError as exc:
            _endpoint_failed(exc)
            raise
        for note in builder.warnings:
            reporter.warning(note, stage="segment_analysis")
        warnings.extend(batch_runner.warnings)
        for segment in segments:
            _absorb_outcome(segment, outcomes[segment["id"]])
    else:
        builder_warnings_seen = 0
        for index, segment in enumerate(segments, start=1):
            segment_flows = dataflow.flows_for_segment(graph, segment, flows)
            reporter.segment_started("segment_analysis", segment["id"], index, total_segments)
            try:
                outcome = runner.run(segment, segment_flows, on_packet=packets.append)
            except EndpointError as exc:
                _endpoint_failed(exc)
                raise
            # Context/budget notes raised while building this segment's packets are
            # surfaced now, attributed to the segment; the report still takes them
            # from ``builder.warnings`` below, so nothing is appended twice.
            for note in builder.warnings[builder_warnings_seen:]:
                reporter.warning(note, stage="segment_analysis", subject=segment["id"])
            builder_warnings_seen = len(builder.warnings)
            reporter.segment_done(
                "segment_analysis",
                segment["id"],
                index,
                total_segments,
                escalation_level=outcome.escalation_level,
                estimated_tokens=(
                    outcome.packets[-1].get("estimated_tokens", 0) if outcome.packets else 0
                ),
            )
            _absorb_outcome(segment, outcome)

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
            _warn(
                f"{segment['id']}: secret finding rejected: {rejected['reason']}",
                stage="segment_analysis",
                subject=segment["id"],
            )

    raw_findings: list[dict[str, Any]] = []
    for segment_id, findings in sorted(per_segment.items()):
        raw_findings.extend(findings)
        _write_local(segment_id)
    reporter.stage_done("segment_analysis")

    def _run_stage(name: str, fn: Any) -> Any:
        # Deterministic passes are not individually checkpointed; announce them
        # so the operator sees the same stage list on every run (FR-001).
        reporter.stage_started(name)
        try:
            result = fn()
        except Exception as exc:
            reporter.stage_failed(name, _fail_text(exc))
            raise
        reporter.stage_done(name)
        return result

    # ------------------------------------- deterministic whole-repo stages (feature 004)
    # Misconfiguration rules and compound weakness rules evaluate whole-repo
    # deterministic facts (R1, R2); findings append to raw_findings so they get
    # location resolution, verification, and calibration like any other.
    misconfig_raw = _run_stage("misconfig", lambda: misconfig.run(roots))
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
    compound_raw = _run_stage("compound", lambda: compound.run(roots))
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
    llm_raw = _run_stage("llm_findings", lambda: llm_findings.run(graph))
    # Spec 007 FR-001/honest-uncertainty: prompt-shaped context with no
    # recognized integration is declared, never silently skipped.
    for node in graph["nodes"]:
        if node["type"] != "file":
            continue
        if "llm_undetermined" in (node.get("annotations") or []):
            _warn(
                f"{node['id']}: prompt-shaped context found but no recognized "
                "LLM integration; integration posture undetermined at this call site",
                stage="llm_findings",
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
    supply_raw = _run_stage("supply_chain", lambda: supply_chain.run(roots))
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
    config_review = _run_stage(
        "agent_config", lambda: agent_config.run(roots, redactor=redactor)
    )
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

    tool_limitations = _run_stage(
        "external_tooling",
        lambda: tooling_execute.run_external_scans(
            store, roots, config, redactor=redactor, progress=reporter
        ),
    )
    for limitation in tool_limitations:
        # Same wording the report's coverage section uses (FR-006).
        reporter.warning(
            f"External tool: {limitation['tool_id']} — {limitation['status']}"
            + (f": {limitation['reason']}" if limitation.get("reason") else ""),
            stage="external_tooling",
            subject=limitation["tool_id"],
        )

    # ------------------------------------- dependency audits (FR-030 - FR-035)
    # Deterministic, read-only, and per member against that member's own
    # ecosystem. Runs regardless of what analysis found, because the reviewed
    # benchmark's largest real exposure lived entirely in this domain.
    #
    # Routed through `ingest_findings` so de-duplication against external scanner
    # output has exactly one owner (FR-030c).
    dependency_findings, audit_outcomes, audit_gaps = _run_stage(
        "dependency_audits",
        lambda: ingest_findings.run_dependency_audits(
            store, roots, start_id=len(raw_findings) + 1
        ),
    )
    for gap in audit_gaps:
        reporter.warning(f"Blocking gap: {gap}", stage="dependency_audits")
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

    def _correlate() -> tuple[Any, Any, Any]:
        result = correlate_findings.finalize(
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
        correlate_findings.write(store, *result)
        return result

    correlated, disproven, reclassifications = _run_stage("correlate_findings", _correlate)

    # --------------------------------- finding triage round (feature 013, FR-001)
    # One post-correlation reasoning pass per candidate finding. Every verdict
    # that would suppress or regrade is gated by deterministic citation
    # re-verification (FR-007); unanswerable rounds are declared, never silent
    # (FR-009). Refuted findings join the auditable suppression list rather than
    # the report's finding bands (FR-010/FR-013).
    triage_suppressions: list[dict[str, Any]] = []
    triage_summary: dict[str, Any] = {"enabled": False}
    if _finding_triage_enabled(active_profile, config):
        min_band = config.triage_min_severity_band or _triage_min_band_default(active_profile)
        # User declarations participate in the stage identity: recording or
        # removing an answer re-runs the round (correct resume, FR-018/019).
        declarations = triage_declarations.load_declarations(store)
        triage_resume_key = hash_document(
            {
                "finding_ids": [str(f.get("id", "")) for f in correlated],
                "depth": active_profile.depth_key,
                "minimum_band": min_band,
                "include_unverified": bool(config.triage_include_unverified),
                "declarations": triage_declarations.declarations_key(declarations),
            }
        )
        if store.should_skip("finding_triage", triage_resume_key) and store.exists(
            "findings/triaged.json"
        ):
            triaged = store.read("findings/triaged.json")
            correlated = list(triaged.get("findings") or [])
            triage_suppressions = list(triaged.get("suppressions") or [])
            triage_summary = dict(
                triaged.get("summary") or {"enabled": True, "candidates": 0, "adjudicated": 0}
            )
            reporter.stage_reused("finding_triage", triage_resume_key)
            # The gap declaration survives resumes: it is derived from the
            # persisted summary, not from this run having executed the round.
            missing = triage_summary.get("candidates", 0) - triage_summary.get(
                "adjudicated", 0
            )
            if missing > 0:
                warnings.append(_triage_gap_note(missing, triage_summary["candidates"]))
        else:
            correlated, triage_suppressions, triage_note, triage_summary = _run_finding_triage(
                store=store,
                correlated=correlated,
                declarations=declarations,
                config=config,
                profile=active_profile,
                workspace=workspace,
                graph=graph,
                roots=roots,
                redactor=redactor,
                client=client,
                answers=answers,
                usage=usage,
                reporter=reporter,
                budget=budget,
                resolution=resolution,
                min_band=min_band,
                resume_key=triage_resume_key,
                clock=clock,
                sleep=sleep,
            )
            if triage_note:
                warnings.append(triage_note)
    else:
        reporter.stage_skipped("finding_triage", "disabled by profile/config")
    # Suppressions from both channels ride the same report list (contracts §1);
    # triage's own copies persist in findings/triaged.json so the suppression
    # artifact this run loaded earlier is never double-appended on resume.
    if triage_suppressions:
        suppressions = [*suppressions, *triage_suppressions]

    # ---------------------------------------------- stage 10-11: review, report
    system_review = ""
    if active_profile.analysis_depth.system_review:

        def _review() -> str:
            narrative = _system_review_narrative(correlated, workspace)
            store.write_text("system-review.md", narrative)
            return narrative

        system_review = _run_stage("system_review", _review)
    else:
        reporter.stage_skipped("system_review", "disabled by profile")

    # Conditions the reporter itself detected (e.g. the scan log could not be
    # written) are declared in the report like any other coverage note (FR-019).
    warnings.extend(reporter.internal_warnings)

    def _report() -> tuple[Any, Any, Any, Any]:
        built = generate_report.build_report(
            scan_id=store.scan_id,
            workspace=workspace,
            execution_mode=resolution.mode.value,
            policy_source=resolution.policy_source,
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
            triage_summary=triage_summary,
        )
        paths = generate_report.write(store, built, system_review)
        store.write("usage.json", "generate_report", usage.to_dict(), "usage")
        return (built, *paths)

    report, markdown_path, json_path, html_path = _run_stage("generate_report", _report)

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
    "finding_triage",
    "system_review",
    "generate_report",
)


def _finding_triage_enabled(profile: profiles_mod.ScanProfile, config: Config) -> bool:
    """Profile default with config override (contracts/triage-round.md §2)."""
    enabled = config.triage_enabled
    if enabled == "on":
        return True
    if enabled == "off":
        return False
    return bool(profile.analysis_depth.finding_triage)


def _triage_min_band_default(profile: profiles_mod.ScanProfile) -> str:
    return "Low" if profile.name == "audit" else "Medium"


def _triage_gap_note(not_adjudicated: int, candidates: int) -> str:
    """The FR-009 coverage declaration. Recomputed identically on the fresh-run
    and resume paths so the report and summary never disagree (determinism)."""
    return (
        f"Finding triage: {not_adjudicated} of {candidates} candidates were not "
        "adjudicated (request unanswered, over budget, or answer rejected) — "
        "their findings are reported unchanged"
    )


def _run_finding_triage(
    *,
    store: ArtifactStore,
    correlated: list[dict[str, Any]],
    declarations: list[dict[str, Any]],
    config: Config,
    profile: profiles_mod.ScanProfile,
    workspace: dict[str, Any],
    graph: dict[str, Any],
    roots: dict[str, Path],
    redactor: Redactor,
    client: Any,
    answers: AnswerStore,
    usage: UsageTracker,
    reporter: Any,
    budget: TokenBudget,
    resolution: Any,
    min_band: str,
    resume_key: str,
    clock: Callable[[], float] | None,
    sleep: Callable[[float], None] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None, dict[str, Any]]:
    """Run the triage round.

    Returns (kept findings, triage suppressions, unanswered gap note, and the
    methodology summary the report's coverage section renders, FR-006/FR-009).
    """
    reporter.stage_started("finding_triage")
    store.mark_running("finding_triage")
    try:
        candidates = triage.select_candidates(
            correlated,
            minimum_band=min_band,
            include_unverified=bool(config.triage_include_unverified),
        )

        agent_mode = resolution.mode is mode_mod.ExecutionMode.AGENT_MEDIATED
        runner = triage.TriageRunner(
            client=client, budget=budget, usage=usage, answers=answers,
        )
        consult_cache: dict[str, bool] = {}
        packets = [
            triage.build_packet(
                finding,
                roots=roots,
                redactor=redactor,
                graph=graph,
                workspace=workspace,
                excerpt_settings=profile.excerpts,
                agent_mode=agent_mode,
                _consult_cache=consult_cache,
            )
            for finding in candidates
        ]

        pending: list[str] = []
        outcomes: dict[str, triage.TriageOutcome] = {}
        if resolution.mode is mode_mod.ExecutionMode.ENDPOINT_BATCH:
            for packet in packets:
                store.write(
                    f"triage/packets/triage-{packet['finding_id']}.json",
                    "finding_triage",
                    packet,
                )
            outcomes = triage.run_batch(
                packets,
                runner=runner,
                client=client,
                ledger=BatchLedger(store),
                reporter=reporter,
                window_hours=resolution.batch_window_hours,
                clock=clock,
                sleep=sleep,
            )
        else:
            for index, packet in enumerate(packets, start=1):
                fid = str(packet["finding_id"])
                reporter.segment_started("finding_triage", fid, index, len(packets))
                store.write(f"triage/packets/triage-{fid}.json", "finding_triage", packet)
                outcome = runner.run(packet)
                outcomes[fid] = outcome
                if outcome.pending:
                    pending.append(f"triage-{fid}")
                reporter.segment_done(
                    "finding_triage",
                    fid,
                    index,
                    len(packets),
                    escalation_level=1,
                    estimated_tokens=packet.get("estimated_tokens", 0),
                )

        if pending:
            store.save_state()
            handoff = AgentHandoff(pending)
            handoff.request_dir = store.dir / "handoff" / "requests"
            handoff.response_dir = store.dir / "handoff" / "responses"
            store.mark_failed("finding_triage", f"{len(pending)} triage request(s) pending")
            raise handoff

        unanswered = {
            fid
            for fid, outcome in outcomes.items()
            if outcome.pending or outcome.oversized or not outcome.content
        }
        # Candidates whose packet was never even built count as unanswered too.
        unanswered.update(
            str(f["id"]) for f in candidates if str(f["id"]) not in outcomes
        )
        verdicts = {
            fid: triage.parse_verdict(outcome.content, finding, redactor)
            for fid, outcome in outcomes.items()
            if fid not in unanswered
            for finding in [next(f for f in candidates if str(f.get("id")) == fid)]
        }
        kept, triage_suppressions, decisions = triage_apply.apply_outcomes(
            correlated,
            verdicts,
            roots=roots,
            graph=graph,
            unanswered=unanswered,
            unanswered_reason="triage round did not produce an answer for this finding",
        )
        if any(d["applied_effect"] == "grading-adjusted" for d in decisions):
            # The ordering invariant (no unproven finding outranks a proven one)
            # must still hold over the post-triage set (FR-013).
            from pipeline import calibrate as _calibrate

            _calibrate.apply_calibration(kept)
        not_adjudicated = {
            str(d["finding_id"])
            for d in decisions
            if d["outcome"] in ("unanswered", "rejected-malformed")
        }
        # User-declared answers resolve open flags after the reasoning verdicts
        # land (FR-018/019/020). They are stage input, not reasoning output, and
        # never count as candidate adjudication.
        kept, triage_suppressions, declaration_decisions = (
            triage_declarations.apply_declarations(
                declarations, kept, triage_suppressions, redactor=redactor
            )
        )
        decisions.extend(declaration_decisions)
        decisions.sort(key=lambda d: str(d.get("finding_id", "")))
        triage_apply.write_decisions(store, decisions)
        # FR-009: unanswered or rejected verdicts both mean "not adjudicated";
        # only applied or degraded-flagged decisions settle a candidate.
        summary = {
            "enabled": True,
            "candidates": len(candidates),
            "adjudicated": len(candidates) - len(not_adjudicated),
            "mode_note": (
                "hybrid consultation: zero-redaction-hit files were consultable"
                if agent_mode
                else "packet-only: the reasoner saw redacted packets only"
            ),
        }
        store.write(
            "findings/triaged.json",
            "finding_triage",
            {
                "findings": kept,
                "suppressions": triage_suppressions,
                "decisions": decisions,
                "summary": summary,
            },
        )
        store.mark_done(
            "finding_triage",
            resume_key,
            ["findings/triaged.json", "triage/decisions.json"],
        )
        reporter.stage_done("finding_triage")
        note = None
        if not_adjudicated:
            note = _triage_gap_note(len(not_adjudicated), len(candidates))
            reporter.warning(note, stage="finding_triage")
        return kept, triage_suppressions, note, summary
    except AgentHandoff:
        raise
    except Exception as exc:
        store.mark_failed("finding_triage", str(exc))
        reporter.stage_failed("finding_triage", str(exc))
        raise


def _entropy_kwargs(config: Config) -> dict[str, float]:
    threshold = config.entropy_threshold
    return {"entropy_threshold": threshold} if threshold is not None else {}


def _stage(
    store: ArtifactStore,
    name: str,
    *,
    resume_key: str,
    artifact: str,
    run: Any,
    reporter: Any = None,
    fail_text: Any = str,
) -> dict[str, Any]:
    """Run a single-artifact stage, honouring the resume checkpoint."""
    reporter = reporter if reporter is not None else NullReporter()
    if store.should_skip(name, resume_key) and store.exists(artifact):
        reporter.stage_reused(name, resume_key)
        return store.read(artifact)
    store.mark_running(name)
    reporter.stage_started(name)
    try:
        document = run()
    except Exception as exc:
        store.mark_failed(name, str(exc))
        reporter.stage_failed(name, fail_text(exc))
        raise
    store.mark_done(name, resume_key, [artifact])
    reporter.stage_done(name)
    return document


def _stage_list(
    store: ArtifactStore,
    name: str,
    *,
    resume_key: str,
    pattern: str,
    run: Any,
    reporter: Any = None,
    fail_text: Any = str,
) -> list[dict[str, Any]]:
    reporter = reporter if reporter is not None else NullReporter()
    if store.should_skip(name, resume_key):
        existing = store.glob(pattern)
        if existing:
            reporter.stage_reused(name, resume_key)
            return [store.read(str(p.relative_to(store.dir))) for p in existing]
    store.mark_running(name)
    reporter.stage_started(name)
    try:
        documents = run()
    except Exception as exc:
        store.mark_failed(name, str(exc))
        reporter.stage_failed(name, fail_text(exc))
        raise
    store.mark_done(name, resume_key)
    reporter.stage_done(name)
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
    except EndpointError as exc:
        print(f"{exc}\nre-run to resume: segments already analysed are kept.")
        raise SystemExit(1) from None

    print(f"scan {result.scan_id}: {len(result.reported_findings)} finding(s) reported")
    print(f"report: {result.report_path}")


if __name__ == "__main__":  # pragma: no cover
    main()
