"""Business-flow (functional) vulnerability analysis (feature 015).

Two halves, per research.md Decision 1:

* :func:`build_flows` — deterministic. Reconstructs business flows (a named user
  journey: actor, ordered steps, trust transitions) from the code graph and the
  workspace's declared integrations. Steps stitch across repositories ONLY through
  declared, typed integration points; an undeclared hop closes the flow as
  ``partial`` with a machine-readable reason (FR-016). No model participates.

* :func:`analyze` — one bounded reasoning request per flow (`level="system"`),
  answers validated against ``flow_answer.json``, findings normalized through the
  standard :class:`FindingNormalizer` so they inherit every downstream pass
  (verification, correlation, triage, reporting).

Everything is opt-in: when :func:`enabled_for` resolves False neither half runs and
no artifact is produced (FR-001/FR-004/FR-005).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from config.loader import Config
from config.profiles import ScanProfile
from pipeline import prompts as prompts_mod
from pipeline.budget import BudgetExceeded
from pipeline.dataflow import Flow, FlowGraph, trace_flows
from pipeline.llm_client import AnalysisRequest
from pipeline.normalize_findings import FindingNormalizer
from pipeline.schemas import SchemaError, validate

STAGE_MODEL = "business_flow_model"
STAGE_ANALYSIS = "business_flow_analysis"
ARTIFACT = "business-flows.json"
FINDINGS_ARTIFACT = "findings/flows.json"

#: Sanity ceiling for one reconstructed journey; longer expansions are truncated
#: deterministically and the flow is marked partial (never silently shortened).
MAX_STEPS = 12

#: Edge kinds a journey may follow (the same set tracing treats as traversable).
_TRAVERSABLE = ("calls", "handler", "reads", "writes", "publishes", "consumes", "renders")

_CHECK_ANNOTATIONS = ("authentication_required", "authorization_required")


def enabled_for(profile: ScanProfile, config: Config) -> bool:
    """Effective enablement: explicit profile flag > config > default off (FR-001)."""
    flag = profile.analysis_depth.business_flow
    if flag is not None:
        return flag
    cfg = config.business_flow_enabled
    return cfg if cfg is not None else False


# ------------------------------------------------------------------- regimes


def regimes_dataset() -> dict[str, Any]:
    """Load and validate the versioned regime dataset (feature 015, FR-020)."""
    import functools

    from pipeline import resources

    @functools.cache
    def _load() -> dict[str, Any]:
        try:
            data = json.loads(resources.data_path("regimes.json").read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise InvalidRegimesData(f"regimes dataset is unreadable: {exc}") from exc
        if "version" not in data or not isinstance(data.get("regimes"), list):
            raise InvalidRegimesData("regimes dataset lacks version/regimes fields")
        return data

    return _load()


class InvalidRegimesData(ValueError):
    """Shipped regime data is malformed; fail the build, not a scan."""


def regimes_version() -> str:
    return str(regimes_dataset().get("version", "0"))


# ------------------------------------------------------------------- enable


@dataclass
class _Step:
    node_id: str
    operation: str
    annotations: list[str] = field(default_factory=list)
    data_categories: list[str] = field(default_factory=list)
    integration_leg: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "node_id": self.node_id,
            "operation": self.operation,
            "annotations": sorted(self.annotations),
            "data_categories": sorted(self.data_categories),
        }
        if self.integration_leg:
            out["integration_leg"] = dict(self.integration_leg)
        return out


def _flow_id(workspace_id: str, entry_id: str, step_ids: list[str]) -> str:
    digest = hashlib.sha256((entry_id + "\n" + "\n".join(step_ids)).encode()).hexdigest()
    return f"flow:{workspace_id}:{digest[:12]}"


def _integration_between(
    integrations: list[dict[str, Any]], from_repo: str, to_repo: str
) -> dict[str, Any] | None:
    for link in integrations:
        if link.get("from_repo") == from_repo and link.get("to_repo") == to_repo:
            return link
    return None


def _host_is_member(host: str, member_names: set[str]) -> str | None:
    """Match an external-service hostname to a workspace member.

    Exact match first, then dotted-prefix (``api.internal`` → ``api``); a host that
    matches no member is a third party, not a hop.
    """
    host = host.lower()
    if host in member_names:
        return host
    for name in sorted(member_names):
        if host.startswith(name + "."):
            return name
    return None


def _integration_targets(
    nodes: dict[str, dict[str, Any]], member: str, link: dict[str, Any]
) -> list[str]:
    """Entry points in ``member`` that a declared integration stitches to.

    Routes listed on the integration pin the join exactly; none listed means the
    declaration names the partnership but not the surface — join the member's
    endpoints and record the coarse join on the leg (never silently absent).
    """
    declared = [str(c) for c in link.get("endpoints_or_channels") or []]
    entries = sorted(
        node_id
        for node_id, node in nodes.items()
        if node["type"] == "endpoint" and node.get("repo") == member
    )
    if not declared:
        return entries
    matched = [
        node_id
        for node_id in entries
        if any(str(nodes[node_id].get("route", "")) in channel for channel in declared)
    ]
    return matched or entries


def build_flows(
    store: Any,
    workspace: dict[str, Any],
    graph: dict[str, Any],
    data_flows: list[Flow] | None = None,
    config: Any | None = None,
) -> dict[str, Any]:
    """Rebuild flows + coverage and write ``business-flows.json``.

    Roots are endpoint nodes and client files that call out (``outbound_hosts``).
    Hops follow those hostnames: a hop landing on a member with a declared, typed
    integration stitches that member's steps (FR-015); a hop landing on a member
    with no declared integration closes the flow as partial
    ``integration-undeclared`` (FR-016); a host matching no member is an ordinary
    external call. Cross-repo ``calls`` edges never stitch — only declared
    integrations do.
    """
    fgraph = FlowGraph.from_document(graph)
    nodes = fgraph.nodes
    integrations = list(workspace.get("integrations") or [])
    workspace_id = str(workspace.get("id") or "workspace")
    members = {str(m["name"]) for m in workspace.get("members") or []}
    data_flows = data_flows if data_flows is not None else trace_flows(graph)

    datastore_callers = {
        edge["from"] for edge in graph["edges"] if edge["type"] in ("reads", "writes")
    }
    file_hosts = {
        node_id: list(node.get("outbound_hosts") or [])
        for node_id, node in nodes.items()
        if node["type"] == "file"
    }
    file_categories = {
        node_id: list(node.get("data_categories") or [])
        for node_id, node in nodes.items()
        if node["type"] == "file"
    }

    roots = sorted(
        node_id
        for node_id, node in nodes.items()
        if node["type"] == "endpoint"
        or (node["type"] == "file" and node.get("outbound_hosts"))
    )

    flows: list[dict[str, Any]] = []
    partial_coverage: list[dict[str, Any]] = []

    for root in roots:
        root_node = nodes[root]
        steps: list[_Step] = []
        gap_reasons: list[str] = []
        seen: set[str] = {root}
        queue: list[str] = [root]
        hops_seen: set[tuple[str, str]] = set()
        if root_node["type"] == "endpoint":
            root_op = "entry"
            root_annotations = [
                a
                for a in sorted(set(root_node.get("annotations") or []))
                if a != "trust_boundary"
            ]
        else:
            root_op = "external-call"
            root_annotations = sorted(set(root_node.get("annotations") or []))
        steps.append(_Step(node_id=root, operation=root_op, annotations=root_annotations))

        while queue and len(steps) < MAX_STEPS:
            current = queue.pop(0)
            current_node = nodes.get(current)
            if current_node is None:
                continue
            current_repo = str(current_node.get("repo", ""))

            # Cross-repo hops are pinned to the file the step lives in:
            # outbound_hosts record exactly which hosts that file calls. Members
            # without a declared integration are declared as a gap, never stitched
            # and never inferred (FR-016).
            file_id = f"{current_repo}:{current_node.get('path', '')}"
            if file_hosts.get(file_id):
                for host in file_hosts[file_id]:
                    member = _host_is_member(host, members - {current_repo})
                    if member is None or (current_repo, member) in hops_seen:
                        continue
                    hops_seen.add((current_repo, member))
                    link = _integration_between(integrations, current_repo, member)
                    if link is None:
                        gap_reasons.append("integration-undeclared")
                        continue
                    for target in _integration_targets(nodes, member, link):
                        if target in seen or len(steps) >= MAX_STEPS:
                            continue
                        seen.add(target)
                        target_node = nodes[target]
                        steps.append(
                            _Step(
                                node_id=target,
                                operation="entry",
                                annotations=[
                                    a
                                    for a in sorted(target_node.get("annotations") or [])
                                    if a != "trust_boundary"
                                ],
                                integration_leg={
                                    "type": str(link.get("type")),
                                    "target_repo": member,
                                },
                            )
                        )
                        queue.append(target)

            for target, _kind in fgraph.outgoing.get(current, []):
                if target in seen or len(steps) >= MAX_STEPS:
                    continue
                target_node = nodes.get(target)
                if target_node is None or target_node.get("repo") != current_repo:
                    continue  # cross-repo movement happens through hops only
                seen.add(target)
                target_file_id = f"{current_repo}:{target_node.get('path', '')}"
                if target_node["type"] == "endpoint":
                    step_op = "entry"
                elif target_node["type"] == "datastore" or target in datastore_callers:
                    step_op = "mutation"
                elif file_hosts.get(target_file_id):
                    step_op = "external-call"
                else:
                    step_op = "transition"
                steps.append(
                    _Step(
                        node_id=target,
                        operation=step_op,
                        annotations=sorted(set(target_node.get("annotations") or [])),
                    )
                )
                if target_node["type"] != "datastore":
                    queue.append(target)

        if queue and len(steps) >= MAX_STEPS:
            gap_reasons.append("budget-unreconstructable")

        actor = _actor_for(root_node, nodes, steps)
        if actor["determination"] == "undetermined":
            gap_reasons.append("actor-undetermined")

        related = sorted(
            {
                f"{flow.source}->{flow.sink}"
                for flow in data_flows
                if set(flow.path) & {step.node_id for step in steps}
            }
        )
        steps_document = [step.to_dict() for step in steps]
        for step_doc in steps_document:
            repo, _, rest = step_doc["node_id"].partition(":")
            path = rest.split("#", 1)[0]
            merged = set(step_doc["data_categories"]) | set(
                file_categories.get(f"{repo}:{path}", [])
            )
            step_doc["data_categories"] = sorted(merged)
        step_dicts = categorize_steps(steps_document, regimes_dataset())
        flow = {
            "id": _flow_id(workspace_id, root, [s["node_id"] for s in step_dicts]),
            "name": str(root_node.get("route") or root_node.get("path")),
            "actor": actor,
            "steps": step_dicts,
            "related_data_flows": related,
            "partial": bool(gap_reasons),
        }
        if gap_reasons:
            flow["gap_reasons"] = sorted(set(gap_reasons))
            partial_coverage.append(
                {"flow_id": flow["id"], "gap_reasons": list(flow["gap_reasons"])}
            )
        flows.append(flow)

    coverage: dict[str, Any] = {
        "reconstructed": sorted(flow["id"] for flow in flows),
        "analyzed": [],
        "partial": sorted(partial_coverage, key=lambda p: p["flow_id"]),
        "unanalyzed": [],
        "undetermined": [],
        "candidate_regimes": [],
        "applicability": {"mode": "hybrid", "evaluated_regimes": []},
    }
    document_tmp = {"flows": sorted(flows, key=lambda f: f["id"]), "coverage": coverage}
    # Regime applicability is part of the model: deterministic from config +
    # detected categories, never from reasoning output (FR-022/FR-023).
    resolution = resolve_applicability(config, document_tmp)
    coverage["candidate_regimes"] = resolution["candidate_regimes"]
    app_section: dict[str, Any] = {
        "mode": resolution["mode"],
        "evaluated_regimes": resolution["evaluated_regimes"],
    }
    if resolution["skipped_reason"]:
        app_section["skipped_reason"] = resolution["skipped_reason"]
    coverage["applicability"] = app_section
    document = {"flows": sorted(flows, key=lambda f: f["id"]), "coverage": coverage}
    validate("business_flow", document)
    store.write(ARTIFACT, STAGE_MODEL, document, schema="business_flow")
    return document


def _actor_for(
    entry_node: dict[str, Any], nodes: dict[str, dict[str, Any]], steps: list[_Step]
) -> dict[str, Any]:
    """Actor posture from proven annotations; honest three-state (FR-010).

    A declared authorization demand whose role the model cannot name is genuinely
    *undetermined*. An entry with no authentication annotation is anonymous by
    *inference* (a trust boundary with no auth evidence), stated as such rather
    than dressed as either fact — inference never buys silence or severity.
    """
    annotations = set(entry_node.get("annotations") or [])
    for step in steps[1:2]:
        annotations |= set(step.annotations)
    if "authorization_required" in annotations:
        return {"kind": "role", "determination": "undetermined"}
    if "authentication_required" in annotations:
        return {"kind": "authenticated", "determination": "declared"}
    return {"kind": "anonymous", "determination": "inferred"}


# ------------------------------------------------- regime applicability (US3)

DATA_CATEGORIES = ("personal-data", "health-data", "financial-data")


def detect_categories(node_id: str, dataset: dict[str, Any]) -> list[str]:
    """Deterministic regulated-data category detection over a step's identity.

    Signals are substring matches shipped in the dataset (FR-020/FR-022): model
    output never decides applicability.
    """
    lowered = node_id.lower()
    found: set[str] = set()
    for regime in dataset.get("regimes") or []:
        for category in regime.get("regulated_data_categories") or []:
            if any(sign in lowered for sign in category.get("signals") or []):
                found.add(str(category["category"]))
    return sorted(found)


def categorize_steps(
    steps: list[dict[str, Any]], dataset: dict[str, Any]
) -> list[dict[str, Any]]:
    out = []
    for step in steps:
        detected = detect_categories(step["node_id"], dataset)
        merged = sorted(set(step.get("data_categories") or []) | set(detected))
        out.append({**step, "data_categories": merged})
    return out


def _resolved_config(config: Any | None) -> Any:
    """Accept None in tests: hybrid mode, no declared regimes."""
    class _Fallback:
        business_flow_applicability_mode = "hybrid"
        business_flow_declared_regimes: list[str] = []

    return config if config is not None else _Fallback()


def resolve_applicability(
    config: Any, flows_doc: dict[str, Any]
) -> dict[str, Any]:
    """Which regimes are evaluated, suggested, or skipped (FR-022/FR-023).

    Returns ``{mode, evaluated_regimes, candidate_regimes, basis}`` and is written
    into coverage by the caller. Deterministic in every mode.
    """
    config = _resolved_config(config)
    dataset = regimes_dataset()
    known = {str(r["id"]): r for r in dataset.get("regimes") or []}
    mode = config.business_flow_applicability_mode
    declared = [r for r in config.business_flow_declared_regimes if r in known]

    detected: dict[str, dict[str, Any]] = {}
    for flow in flows_doc.get("flows") or []:
        for step in flow.get("steps") or []:
            for category in step.get("data_categories") or []:
                for regime in dataset.get("regimes") or []:
                    cats = regime.get("regulated_data_categories") or []
                    if category not in [c["category"] for c in cats]:
                        continue
                    entry = detected.setdefault(
                        str(regime["id"]),
                        {"regime": str(regime["id"]), "detected_categories": set(),
                         "step_refs": set()},
                    )
                    entry["detected_categories"].add(category)
                    entry["step_refs"].add(step["node_id"])

    basis = {
        regime: "detected " + ", ".join(sorted(v["detected_categories"]))
        for regime, v in detected.items()
    }
    candidates: list[dict[str, Any]] = []
    if mode == "declared-only":
        evaluated = declared
    elif mode == "inferred-only":
        evaluated = sorted(detected)
    else:  # hybrid
        evaluated = declared
        candidates = [
            {
                "regime": regime,
                "detected_categories": sorted(v["detected_categories"]),
                "step_refs": sorted(v["step_refs"]),
            }
            for regime, v in sorted(detected.items())
            if regime not in declared
        ]

    skipped_reason = None
    if not evaluated:
        skipped_reason = (
            "no regime is applicable under the configured applicability mode "
            f"({mode}); obligation evaluation skipped"
        )
    return {
        "mode": mode,
        "evaluated_regimes": evaluated,
        "candidate_regimes": candidates,
        "basis": basis,
        "obligations": [
            {"regime": regime, "name": known[regime]["name"],
             "obligations": known[regime]["obligations"]}
            for regime in evaluated
        ],
        "skipped_reason": skipped_reason,
    }


# -------------------------------------------------------------------- round


def _extract_json_object(content: str) -> dict[str, Any] | None:
    text = content.strip()
    if text.startswith("```"):
        lines = [line for line in text.splitlines() if not line.startswith("```")]
        text = "\n".join(lines).strip()
    try:
        doc = json.loads(text)
        return doc if isinstance(doc, dict) else None
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            try:
                doc = json.loads(text[start : end + 1])
                return doc if isinstance(doc, dict) else None
            except json.JSONDecodeError:
                return None
        return None


@dataclass
class FlowRoundResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    pending: list[str] = field(default_factory=list)
    assessments: dict[str, str] = field(default_factory=dict)
    undetermined: dict[str, list[str]] = field(default_factory=dict)
    #: flow id -> reason for flows that could not fit any bounded request
    #: (declared coverage gaps per FR-012, never truncated, never crashed).
    oversized: dict[str, str] = field(default_factory=dict)


class FlowRound:
    """One bounded reasoning request per reconstructed flow (research.md D10)."""

    def __init__(
        self,
        *,
        client: Any,
        usage: Any,
        budget: Any,
        normalizer: FindingNormalizer | None = None,
        max_level: int = 3,
        regime_obligations: list[dict[str, Any]] | None = None,
        regime_basis: dict[str, str] | None = None,
    ) -> None:
        self.client = client
        self.usage = usage
        self.budget = budget
        self.normalizer = normalizer or FindingNormalizer()
        self.max_level = max_level
        self.regime_obligations = list(regime_obligations or [])
        self.regime_basis = dict(regime_basis or {})

    # ------------------------------------------------------------ packets

    def build_packet(self, flow: dict[str, Any], level: int) -> dict[str, Any]:
        """Smallest useful slice first; level > 1 adds narrative hints (FR-012)."""
        packet: dict[str, Any] = {
            "flow": {
                "id": flow["id"],
                "name": flow["name"],
                "actor": flow["actor"],
                "partial": flow["partial"],
                "gap_reasons": list(flow.get("gap_reasons") or []),
                "steps": flow["steps"],
                "related_data_flows": list(flow.get("related_data_flows") or []),
            },
            "escalation_level": level,
        }
        if self.regime_obligations:
            # Only evaluated regimes reach the reasoning layer (FR-023).
            packet["regimes"] = self.regime_obligations
        return packet

    def request_for(self, flow: dict[str, Any], level: int) -> AnalysisRequest:
        prompt = prompts_mod.render_prompt("business_flow.md")
        return AnalysisRequest(
            id=f"flow-{flow['id'].rsplit(':', 1)[-1]}-l{level}",
            stage=STAGE_ANALYSIS,
            prompt=prompt,
            payload=self.build_packet(flow, level),
            budget=self.budget,
            level="system",
            escalation_level=level,
        )

    # ------------------------------------------------------------ running

    def run(self, flows: list[dict[str, Any]]) -> FlowRoundResult:
        result = FlowRoundResult()
        for flow in flows:
            try:
                response = self._run_flow(flow)
            except BudgetExceeded:
                # The smallest useful slice already exceeds the budget: declared
                # oversized, never truncated, never a crash (FR-012).
                result.oversized[flow["id"]] = "budget-ceiling"
                continue
            if response is None:  # pending handoff
                result.pending.append(flow["id"])
                continue
            result.assessments[flow["id"]] = response["assessment"]
            if response["assessment"] == "undetermined":
                result.undetermined[flow["id"]] = list(
                    response.get("undetermined_reasons") or ["undetermined"]
                )
            result.findings.extend(response["findings"])
        return result

    def _run_flow(self, flow: dict[str, Any]) -> dict[str, Any] | None:
        level = 1
        while True:
            request = self.request_for(flow, level)
            # Budgets bind the serialized request, never an estimate of it (FR-012).
            self.budget.check(request.estimated_tokens(), context=flow["id"])
            response = self.client.run(request)
            if response.pending:
                return None
            if not response.cached:
                self.usage.record(
                    STAGE_ANALYSIS,
                    response.input_tokens,
                    response.output_tokens,
                    model_tier=response.model_tier,
                    escalation_level=request.escalation_level,
                    batch=response.batch,
                )
                if response.fell_back:
                    self.usage.record_fallback(
                        request.id, response.fallback_reason or "batch fallback"
                    )
            answer = _extract_json_object(response.content)
            if answer is None:
                return {"assessment": "undetermined",
                        "undetermined_reasons": ["answer was not structured flow JSON"],
                        "findings": []}
            try:
                validate("flow_answer", answer)
            except SchemaError as exc:
                # A malformed reasoning answer is an undetermined state, never a
                # crash and never silently dropped (FR-010).
                return {"assessment": "undetermined",
                        "undetermined_reasons": [f"answer failed flow_answer schema: {exc}"],
                        "findings": []}
            outcome = self._absorb(flow, answer)
            # Escalate only on stated insufficiency, capped by the profile ceiling.
            if outcome["assessment"] == "undetermined" and level < self.max_level:
                level += 1
                continue
            if outcome["assessment"] == "undetermined" and level >= self.max_level:
                # Deepest the profile allows and still undetermined: name the
                # ceiling as the reason rather than reading as settled (FR-012).
                outcome["undetermined_reasons"].append(
                    f"escalation ceiling L{self.max_level} reached (profile depth cap)"
                )
            return outcome

    def _absorb(self, flow: dict[str, Any], answer: dict[str, Any]) -> dict[str, Any]:
        assessment = str(answer.get("assessment"))
        findings: list[dict[str, Any]] = []
        for raw in answer.get("findings") or []:
            enriched = dict(raw)
            is_violation = bool(enriched.get("regulatory_refs")) or assessment == "violation"
            enriched["flow_category"] = (
                "regulatory-violation" if is_violation else "flow-gap"
            )
            enriched["flow_ref"] = flow["id"]
            enriched["flow_narrative"] = {
                "name": flow["name"],
                "steps": [
                    {"node_id": step["node_id"]} for step in flow["steps"]
                ],
                "missing_check": str(enriched.get("missing_check") or "unspecified"),
                "compromise": str(enriched.get("compromise") or enriched.get("impact") or ""),
            }
            # FR-023: an inferred-only regime's findings state the detection basis.
            if enriched.get("regulatory_refs"):
                for ref in enriched["regulatory_refs"]:
                    basis = self.regime_basis.get(str(ref.get("regime")), "")
                    if basis and not ref.get("basis"):
                        ref["basis"] = basis

            normalized = self.normalizer.normalize(
                [enriched],
                source="analysis",
                status="local",
                default_repo=flow["steps"][0]["node_id"].split(":", 1)[0],
            )
            findings.extend(normalized.findings)
        return {
            "assessment": assessment,
            "undetermined_reasons": list(answer.get("undetermined_reasons") or []),
            "findings": findings,
        }

    def _note_malformed(self, flow: dict[str, Any]) -> None:
        """Placeholder for driver-side progress notes (declarations ride the
        undetermined assessment; progress is only emitted through the driver)."""
        del flow
