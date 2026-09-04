"""Finding triage round (feature 013).

One post-correlation reasoning pass per *finalized* finding: the reasoner may
confirm, downgrade, refute, or flag — but only verdicts whose citations the
deterministic pipeline re-verifies (:mod:`pipeline.triage_evidence`) change a
finding's fate. Everything here is bounded by the same budget machinery as
segment analysis, persisted through the same answer store, and judged by the
same rules in interactive, batch, and agent-mediated execution (the packets are
built once and reused for either policy — feature 012's parity rule).

Secrets discipline (constitution III): packets carry redacted excerpts only, the
``consultable_files`` list (agent-mediated mode) is computed from the redactor's
own per-file verdicts, and verdict content is swept before persistence — a
swept verdict is rejected, never stored.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pipeline import excerpts, prompts, schemas
from pipeline.answers import AnswerStore, answer_key
from pipeline.budget import TokenBudget, estimate_tokens
from pipeline.llm_client import AnalysisClient, AnalysisRequest
from pipeline.redact import Redactor
from pipeline.usage import UsageTracker

STAGE = "finding_triage"
TRIAGE_PROMPT = "triage_finding.md"

#: Severity band ordering for the candidate-selection threshold (contracts §2).
BAND_ORDER = ("Low", "Medium", "High", "Critical")

#: Credential-class findings: the reasoner never sees the matched value, so
#: ``refuted`` is invalid by construction for these (FR-008).
CREDENTIAL_CWES = frozenset({"CWE-798", "CWE-522"})

#: Control-shaped annotations on graph nodes whose *files* seed the candidate
#: control set (research R4 — the baseline false positives' disproofs lived in
#: exactly these places).
CONTROL_ANNOTATIONS = frozenset(
    {"authentication_required", "authorization_required", "security_sink", "trust_boundary"}
)

#: Upper bound on candidate-control entries per packet (sheds shed whole entries,
#: never truncates — Principle II).
MAX_CANDIDATE_CONTROLS = 12


# ------------------------------------------------------------------ selection


def _band_at_least(band: str, minimum: str) -> bool:
    try:
        return BAND_ORDER.index(band) >= BAND_ORDER.index(minimum)
    except ValueError:
        return True  # unknown band: include rather than silently skip (Principle V)


def is_credential_finding(finding: dict[str, Any]) -> bool:
    return str(finding.get("cwe", "")).upper() in CREDENTIAL_CWES


def select_candidates(
    findings: list[dict[str, Any]],
    *,
    minimum_band: str = "Medium",
    include_unverified: bool = True,
) -> list[dict[str, Any]]:
    """The finding set the triage round will examine (contracts §2, FR-001).

    Known-vulnerable-dependency findings are excluded — their domain belongs to
    the deterministic structural cross-check, not to reasoning.
    """
    out: list[dict[str, Any]] = []
    for finding in findings:
        if finding.get("dependency"):
            continue
        if not include_unverified and (finding.get("verification") or {}).get(
            "status"
        ) != "verified":
            continue
        band = str(finding.get("severity_band") or "")
        detection = str(finding.get("detection") or "")
        if not (_band_at_least(band, minimum_band) or detection == "heuristic"):
            continue
        out.append(finding)
    return sorted(out, key=lambda f: str(f.get("id", "")))


# --------------------------------------------------------------- packet build


def collect_candidate_controls(
    finding: dict[str, Any],
    *,
    graph: dict[str, Any],
    workspace: dict[str, Any],
) -> list[dict[str, Any]]:
    """Deterministic seed of possibly-relevant controls (R4; FR-003).

    Sources, in a fixed order: control-annotated files from the code graph,
    the finding's own traced verification path, and the workspace's typed
    integration points. Bounded; the packet builder sheds whole entries.
    """
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(repo: str, file: str, reason: str, symbol: str | None = None) -> None:
        key = f"{repo}:{file}"
        if file and key not in seen:
            seen.add(key)
            entry: dict[str, Any] = {"repo": repo, "file": file, "reason": reason}
            if symbol:
                entry["symbol"] = symbol
            entries.append(entry)

    for node in sorted(graph.get("nodes") or [], key=lambda n: str(n.get("id", ""))):
        if node.get("type") != "file":
            continue
        annotations = set(node.get("annotations") or [])
        shared = sorted(annotations & CONTROL_ANNOTATIONS)
        if not shared:
            continue
        repo = str(node.get("repo") or "")
        add(
            repo,
            str(node.get("path") or node.get("id", "").split(":", 1)[-1].split("#")[0]),
            "graph annotation: " + ", ".join(shared),
        )

    verification = finding.get("verification") or {}
    for step in verification.get("path") or []:
        step = str(step)
        if "#" in step and ":" in step:
            repo, rest = step.split(":", 1)
            file, _, symbol = rest.partition("#")
            add(repo, file, "on the finding's traced verification path", symbol or None)

    for integration in sorted(
        workspace.get("integrations") or [],
        key=lambda i: (str(i.get("from_repo", "")), str(i.get("to_repo", ""))),
    ):
        for endpoint in sorted(integration.get("endpoints_or_channels") or []):
            add(
                str(integration.get("from_repo", "")),
                str(endpoint),
                "typed integration point at a trust boundary",
            )

    return entries[:MAX_CANDIDATE_CONTROLS]


def consultable_files(
    paths: list[tuple[str, str]],
    *,
    roots: dict[str, Path],
    redactor: Redactor,
    _cache: dict[str, bool] | None = None,
) -> list[str]:
    """Zero-redaction-hit consultation allow-list (agent-mediated mode, FR-006).

    Each argument is a ``(repo, file)`` pair. A file is consultable only when the
    redactor finds nothing to redact and nothing to block in it — the exact same
    predicate that keeps secrets out of every packet. The result is a sorted list
    of ``repo:file`` strings.
    """
    cache = _cache if _cache is not None else {}
    out: list[str] = []
    for repo, file in sorted(set(paths)):
        key = f"{repo}:{file}"
        clean = cache.get(key)
        if clean is None:
            root = roots.get(repo)
            path = (root / file) if root else None
            if path is None or not path.is_file():
                cache[key] = clean = False
            else:
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    cache[key] = clean = False
                else:
                    result = redactor.redact(text, origin=file)
                    cache[key] = clean = result.clean
        if clean:
            out.append(key)
    return sorted(out)


def build_packet(
    finding: dict[str, Any],
    *,
    roots: dict[str, Path],
    redactor: Redactor,
    graph: dict[str, Any],
    workspace: dict[str, Any],
    excerpt_settings: Any,
    agent_mode: bool,
    _consult_cache: dict[str, bool] | None = None,
) -> dict[str, Any]:
    """The context packet for one finding's triage request (contracts §3)."""
    candidates = collect_candidate_controls(finding, graph=graph, workspace=workspace)
    packet: dict[str, Any] = {
        "finding_id": finding["id"],
        "finding": finding,
        "excerpt": excerpts.build_excerpt(
            finding, roots=roots, settings=excerpt_settings, redactor=redactor
        ),
        "candidate_controls": candidates,
    }
    if agent_mode:
        pairs = [(str(c.get("repo") or ""), str(c.get("file") or "")) for c in candidates]
        location = finding.get("location") or {}
        pairs.append((str(location.get("repo") or ""), str(location.get("file") or "")))
        packet["consultable_files"] = consultable_files(
            pairs, roots=roots, redactor=redactor, _cache=_consult_cache
        )
    return packet


# ---------------------------------------------------------------- verdicts


@dataclass
class ParsedVerdict:
    """Outcome of parsing one answer; ``document`` is None when rejected."""

    finding_id: str
    document: dict[str, Any] | None
    reason: str | None = None

    @property
    def rejected(self) -> bool:
        return self.document is None


def _extract_json(content: str) -> Any | None:
    content = content.strip()
    if not content:
        return None
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        start = content.find("{")
        if start == -1:
            return None
        try:
            return json.loads(content[start:])
        except json.JSONDecodeError:
            return None


def parse_verdict(
    content: str, finding: dict[str, Any], redactor: Redactor
) -> ParsedVerdict:
    """Parse and gate one triage answer (contracts §4 rules 1–6).

    Whole-answer rejection on any violation; the finding proceeds as untriaged.
    The sweep gate (rule 6) runs over the answer's free-text fields: a verdict
    that would carry a credential-like string into an artifact is rejected
    outright, so reasoner output can never leak a value (T013/R7).
    """
    fid = str(finding.get("id", ""))
    document = _extract_json(content)
    if not isinstance(document, dict):
        return ParsedVerdict(fid, None, "answer is not a JSON object")
    if not schemas.is_valid("triage_answer", document):
        return ParsedVerdict(fid, None, "answer does not conform to triage_answer schema")
    if str(document.get("finding_id", "")) != fid:
        return ParsedVerdict(
            fid,
            None,
            f"answer finding_id {document.get('finding_id')!r} does not match {fid!r}",
        )
    if document.get("verdict") == "refuted" and is_credential_finding(finding):
        return ParsedVerdict(
            fid,
            None,
            "credential-class findings cannot be refuted by reasoning (FR-008)",
        )
    texts = [
        str(document.get(k, ""))
        for k in ("rationale", "user_question", "settling_evidence_hint")
    ]
    texts.extend(str(c.get("pattern", "")) for c in document.get("citations") or [])
    for text in texts:
        if not text:
            continue
        result = redactor.redact(text)
        if result.blocked or not result.clean:
            return ParsedVerdict(
                fid, None, "answer content failed the credential sweep; rejected, not stored"
            )
    return ParsedVerdict(fid, document)


# ------------------------------------------------------------------- runner


@dataclass
class TriageOutcome:
    finding_id: str
    content: str = ""
    pending: bool = False
    oversized: bool = False
    packet: dict[str, Any] | None = None


class TriageRunner:
    """One bounded request per candidate finding; no escalation ladder (R3).

    Mirrors the ``EscalationRunner`` discipline: packets recorded, budgets checked
    against the serialized request, answers reused/persisted through the
    ``AnswerStore`` keyed by exact content, usage recorded only for requests
    actually made this run.
    """

    def __init__(
        self,
        *,
        client: AnalysisClient,
        budget: TokenBudget,
        usage: UsageTracker,
        answers: AnswerStore,
        level: str = "segment",
    ) -> None:
        self.client = client
        self.budget = budget
        self.usage = usage
        self.answers = answers
        #: request level label; the *answer* tier is resolved through the
        #: client's model map exactly like segment analysis, so persisted
        #: answer keys match across interactive and batch policies (feature
        #: 012's same-answer guarantee, SC-003).
        self.level = level
        self.prompt = prompts.render_prompt(TRIAGE_PROMPT)

    def tier_for(self, request: AnalysisRequest) -> str:
        resolution = getattr(self.client, "resolution", None)
        if resolution is not None:
            return resolution.tier_for(request.level)
        return "agent"

    def request_for(self, packet: dict[str, Any]) -> AnalysisRequest | None:
        payload = {
            k: packet[k]
            for k in ("finding_id", "finding", "excerpt", "candidate_controls")
        }
        if "consultable_files" in packet:
            payload["consultable_files"] = packet["consultable_files"]

        def make() -> AnalysisRequest:
            return AnalysisRequest(
                id=f"triage-{packet['finding_id']}",
                stage=STAGE,
                prompt=self.prompt,
                payload=payload,
                budget=self.budget,
                level=self.level,
                escalation_level=1,
            )

        request = make()
        shed: list[dict[str, Any]] = []
        while not self.budget.fits(request.estimated_tokens()) and payload[
            "candidate_controls"
        ]:
            shed.append(payload["candidate_controls"].pop())
            request = make()
        if shed:
            packet.setdefault("shed_controls", []).extend(shed)
        packet["estimated_tokens"] = request.estimated_tokens()
        if not self.budget.fits(request.estimated_tokens()):
            packet["oversized"] = True
            return None
        return request

    def run(self, packet: dict[str, Any]) -> TriageOutcome:
        outcome = TriageOutcome(finding_id=str(packet["finding_id"]), packet=packet)
        request = self.request_for(packet)
        if request is None:
            outcome.oversized = True
            return outcome
        cached = self.answers.get(request, self.tier_for(request))
        if cached is not None:
            outcome.content = cached
            return outcome
        response = self.client.run(request)
        outcome.pending = response.pending
        outcome.content = response.content
        if not response.pending and response.content and not response.cached:
            # Naive-context baseline (SC-004 analog): without triage's bounded
            # packet, re-reviewing a finding means sending the ceiling context.
            self.usage.record(
                STAGE,
                response.input_tokens,
                response.output_tokens,
                model_tier=response.model_tier,
                batch=response.batch,
                baseline_input_tokens=self.budget.max_context_tokens,
            )
            if response.fell_back and response.fallback_reason:
                self.usage.record_fallback(request.id, response.fallback_reason)
        return outcome


# -------------------------------------------------------------------- batch


#: Ledger namespace for triage rounds. BatchRoundRunner keys records by
#: escalation level ("1:model" …); the triage round carries no levels, so it
#: occupies level 0 — no collision with segment-analysis rounds by construction.
BATCH_LEVEL = 0


def run_batch(
    packets: list[dict[str, Any]],
    *,
    runner: TriageRunner,
    client: Any,
    ledger: Any,
    reporter: Any,
    window_hours: float,
    clock: Any = None,
    sleep: Any = None,
) -> dict[str, TriageOutcome]:
    """Provider-batch execution of the triage round (research R3, contracts §7).

    ``BatchRoundRunner`` is segment-shaped and stays untouched; this thin driver
    reuses its shared helpers (grouping, ledger, polling, per-item classification)
    over the same adapter, so batch items are byte-identical to what interactive
    mode sends (feature 012 parity rule).
    """
    import time

    from pipeline.batch_runner import (
        BatchRecord,
        check_budgets,
        classify_items,
        group_and_split,
        poll_schedule,
        resume_check,
        round_key,
    )
    from pipeline.providers import BatchItemSpec, BatchUnsupported, custom_id_for

    clock = clock or time.time
    sleep = sleep or time.sleep
    outcomes = {str(p["finding_id"]): TriageOutcome(str(p["finding_id"]), packet=p)
                for p in packets}

    requests: dict[str, AnalysisRequest] = {}
    to_send: list[tuple[AnalysisRequest, str]] = []
    for packet in packets:
        request = runner.request_for(packet)
        if request is None:
            outcomes[str(packet["finding_id"])].oversized = True
            continue
        requests[request.id] = request
        cached = runner.answers.get(request, runner.tier_for(request))
        if cached is not None:
            outcomes[str(packet["finding_id"])].content = cached
        else:
            to_send.append((request, runner.tier_for(request)))

    if not to_send:
        return outcomes
    check_budgets([r for r, _ in to_send], STAGE)
    keys = {r.id: answer_key(r, t) for r, t in to_send}

    def spec(request: AnalysisRequest, model: str) -> BatchItemSpec:
        return BatchItemSpec(
            custom_id=custom_id_for(request.id),
            model=model,
            prompt=request.prompt,
            payload=request.payload,
            max_output_tokens=request.budget.max_output_tokens,
        )

    adapter = client.adapter
    transport = client.transport
    answered: dict[str, str] = {}
    remaining = {r.id: (r, t) for r, t in to_send}

    # Resume batches recorded by an earlier run whose items are unchanged.
    pending: list[BatchRecord] = []
    for key in sorted(ledger.load()):
        if not key.startswith(round_key(BATCH_LEVEL, "")[:-1]):
            continue
        for record in ledger.open_records(key):
            if resume_check(record, keys) == "abandon":
                ledger.update(key, record.handle, status="abandoned",
                              reason="request changed")
                continue
            covered = [rid for rid in record.items if rid in remaining]
            if not covered:
                ledger.update(key, record.handle, status="abandoned",
                              reason="no longer requested")
                continue
            pending.append(record)
            for rid in covered:
                remaining.pop(rid)

    chunks = group_and_split(
        list(remaining.values()),
        adapter.batch_limits(),
        size_of=lambda r: adapter.item_bytes(spec(r, remaining[r.id][1])),
    )
    fallback_from_submission: list[tuple[AnalysisRequest, str]] = []
    submitted_total = len(pending) + len(chunks)
    for _offset, (model, items) in enumerate(chunks):
        key = round_key(BATCH_LEVEL, model)
        try:
            specs = [spec(r, model) for r in items]
            handle = adapter.submit_batch(transport, specs, model=model)
        except BatchUnsupported as exc:
            note = (
                "triage round: provider does not support batch submission "
                f"(HTTP {exc.status}); affected findings run interactively"
            )
            reporter.warning(note, stage=STAGE)
            runner.usage.record_fallback(STAGE, note)
            fallback_from_submission.extend((r, remaining[r.id][1]) for r in items)
            continue
        now = clock()
        custom_map = {s.custom_id: r.id for s, r in zip(specs, items, strict=True)
                      if s.custom_id != r.id}
        record = BatchRecord(
            handle=handle,
            provider=adapter.name,
            base_url=client.resolution.base_url,
            model=model,
            level=BATCH_LEVEL,
            items={r.id: keys[r.id] for r in items},
            submitted_at=now,
            expires_at=now + window_hours * 3600.0,
            custom_id_map=custom_map or None,
        )
        ledger.record(key, record)
        pending.append(record)
        reporter.batch_submitted(
            STAGE, len(pending), submitted_total, items=len(record.items),
            model=record.model, handle=record.handle,
        )

    # Wait out the round, collect results, fall back to interactive per failure.
    schedule = poll_schedule()
    while any(not record.terminal for record in pending):
        interval = next(schedule)
        for record in pending:
            if record.terminal:
                continue
            if clock() >= record.expires_at:
                record.status = "expired"
                ledger.update(
                    round_key(BATCH_LEVEL, record.model), record.handle,
                    status="expired", reason="window expired",
                )
                continue
            status = adapter.batch_status(transport, record.handle)
            record.polls += 1
            if status.state == "in_progress":
                ledger.update(round_key(BATCH_LEVEL, record.model), record.handle,
                              status="in_progress", polls=record.polls)
                record.status = "in_progress"
            elif status.state in ("ended", "failed", "not_found"):
                record.status = "ended" if status.state == "ended" else status.state
        if any(not record.terminal for record in pending):
            sleep(interval)

    failed: list[tuple[AnalysisRequest, str]] = list(fallback_from_submission)
    from pipeline.providers import BatchStatus, EndpointError

    index_total = len(pending) or 1
    for index, record in enumerate(pending, start=1):
        results: list[Any] = []
        status: Any = None
        if record.status == "ended":
            try:
                results = adapter.batch_results(transport, record.handle)
                status = BatchStatus("ended", len(record.items), len(record.items))
            except EndpointError as exc:
                if exc.status != 404:
                    raise
                record.status = "not_found"
                status = BatchStatus("not_found", 0, 0, reason=str(exc))
                ledger.update(round_key(BATCH_LEVEL, record.model), record.handle,
                              status="not_found")
        item_outcomes = classify_items(record, status, results)
        answered_count = sum(1 for o in item_outcomes if o.outcome == "answered")
        failed_count = len(item_outcomes) - answered_count
        reporter.batch_done(
            STAGE, index, index_total, succeeded=answered_count,
            failed=failed_count, expired=failed_count, fallbacks=failed_count,
        )
        for item in item_outcomes:
            request = requests.get(item.request_id)
            if request is None:
                continue
            tier = runner.tier_for(request)
            if item.outcome == "answered":
                runner.answers.put(request, tier, item.content or "")
                runner.usage.record(
                    STAGE,
                    request.estimated_tokens(),
                    estimate_tokens(item.content or ""),
                    model_tier=tier,
                    batch=True,
                    baseline_input_tokens=runner.budget.max_context_tokens,
                )
                answered[request.id] = item.content or ""
            else:
                failed.append((request, tier))

    for request, _tier in failed:
        response = client.run(request)
        if response.pending:
            continue  # agent mode never lands here; defensive keep
        runner.usage.record(
            STAGE,
            response.input_tokens,
            response.output_tokens,
            model_tier=response.model_tier,
            baseline_input_tokens=runner.budget.max_context_tokens,
        )
        if response.fell_back and response.fallback_reason:
            runner.usage.record_fallback(request.id, response.fallback_reason)
        answered[request.id] = response.content

    for request_id, content in answered.items():
        request = requests[request_id]
        fid = request_id.removeprefix("triage-")
        outcomes[fid].content = content
    return outcomes
