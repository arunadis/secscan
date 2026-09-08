"""Static verification of findings (FR-029).

A finding is verified by *tracing*, never by attacking: the traced source-to-sink
path from :mod:`pipeline.dataflow` decides the verdict.

  verified  - a complete path exists from an external entry point to the sink,
              with the entry point and preconditions identified
  plausible - only a partial path could be traced; the gap is documented
  disproven - the trace refutes the finding (e.g. the sink is unreachable from
              any external source, or a mitigating control the finding did not
              implicate sits on every path)

Disproven findings never reach the report.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pipeline.dataflow import Flow, find_flow_for_location

#: annotations that, on the path, indicate an enforced control
MITIGATING = ("authorization_required", "authentication_required")

#: Presence is itself the finding for these classes (feature 017, FR-001):
#: hard-coded secrets and dangerous configuration states are valid by the
#: code's presence alone. Long-standing static members plus every class the
#: identity-archetype pack ships (its detectors are design-committed as
#: presence-valid) — the pack extends the contract without a stage edit.
_STATIC_PRESENCE = (
    "CWE-798", "CWE-259", "CWE-256", "CWE-522", "CWE-532",
    "CWE-352", "CWE-942", "CWE-306", "CWE-489", "CWE-1188", "CWE-295",
    "CWE-1004",
)

#: presence classes whose verdict strength still rests on reachability of the
#: weakness: under the run's reachability gap these demote, others hold.
_REACHABILITY_SENSITIVE_PRESENCE = frozenset({"CWE-306", "CWE-290"})


def presence_valid_cwes() -> frozenset[str]:
    """The union: static config/secret classes + any class the identity
    archetype pack ships (its rules are defined as presence-valid)."""
    from pipeline import identity_rules

    return frozenset(_STATIC_PRESENCE) | identity_rules.no_refute_cwes()


def implicated_locations(finding: dict[str, Any]) -> set[str]:
    """``file``, ``file#symbol`` and symbol names the finding blames.

    Used to decide whether a mitigating-control validation on the traced path
    *is* the guard the finding questions: evidence and related-symbol markers
    carry the finding's whole accusation perimeter, never only its headline
    location.
    """
    targets: set[str] = set()
    candidates = [finding.get("location") or {}]
    candidates.extend(finding.get("evidence") or ())
    for candidate in candidates:
        file = str(candidate.get("file") or "")
        if not file:
            continue
        targets.add(file)
        symbol = candidate.get("symbol")
        if symbol:
            targets.add(symbol)
            targets.add(f"{file}#{symbol}")
    for ref in finding.get("related_symbols") or ():
        ref = str(ref)
        targets.add(ref)
        if "#" in ref:
            targets.add(ref.rsplit("#", 1)[-1])
    return targets


class UnresolvedLocation(RuntimeError):
    """A finding reached verification with a location absent from the code model.

    Location resolution (:mod:`pipeline.locate`) runs first and rejects these, so
    reaching verification means the pipeline was wired wrong. Failing loudly beats
    the old behaviour, which published the finding while stating that its location
    could not be matched — an admission of ignorance dressed as a result (FR-003b).
    """


@dataclass
class Verdict:
    status: str
    gap: str | None = None
    path: tuple[str, ...] = ()
    flow: Flow | None = None
    #: Feature 016 (traceability contract §1): what the strongest verdict rests
    #: on — a walked path ("traced") or the weakness's presence in source
    #: ("presence"). Written whenever status is "verified".
    basis: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"status": self.status}
        if self.basis:
            out["basis"] = self.basis
        if self.gap:
            out["gap"] = self.gap
        if self.path:
            out["path"] = list(self.path)
        return out


class Verifier:
    """Assigns a verification verdict to each finding."""

    def __init__(
        self,
        graph: dict[str, Any],
        flows: list[Flow],
        business_flows: dict[str, Any] | None = None,
        reachability_unconfirmed: bool = False,
    ) -> None:
        self.graph = graph
        self.flows = flows
        self.nodes = {node["id"]: node for node in graph["nodes"]}
        # FR-009: while the run-level reachability gap is active, presence
        # verdicts for reachability-sensitive classes may not stand as verified.
        self.reachability_unconfirmed = reachability_unconfirmed
        self.business_flows = {
            str(flow["id"]): flow
            for flow in (business_flows or {}).get("flows", [])
        }

    def verify(self, finding: dict[str, Any]) -> Verdict:
        # Feature 015, FR-017: flow findings use path-based verdicts over the
        # reconstructed business flow, never a source-to-sink trace.
        if finding.get("flow_ref"):
            return self.verify_flow_finding(finding)
        location = finding["location"]
        repo = location.get("repo", "")
        path = location.get("file", "")
        symbol = location.get("symbol")

        flow = find_flow_for_location(self.flows, self.graph, repo, path, symbol)
        if flow is None:
            return self._no_flow_verdict(finding, repo, path, symbol)

        readable = tuple(self._label(node_id) for node_id in flow.path)

        # A control on the path that matches the finding's own category means the
        # concern is already mitigated for this route.
        if self._mitigated(flow, finding):
            return Verdict(
                status="disproven",
                gap=None,
                path=readable,
                flow=flow,
            )

        if flow.complete and flow.transforms is not None:
            return Verdict(status="verified", path=readable, flow=flow, basis="traced")

        return Verdict(
            status="plausible",
            gap="a complete source-to-sink path could not be traced end to end",
            path=readable,
            flow=flow,
        )

    # ----------------------------------------------------------- internals

    def verify_flow_finding(self, finding: dict[str, Any]) -> Verdict:
        """Path-based verdict for a flow finding (feature 015, FR-017).

        *verified*   - a concrete traversable step path reaches the privileged
                       operation without the missing/violated check anywhere on
                       the way, and the flow's actor/posture are determined
        *plausible*  - the path exists, but the flow is partial or some state
                       along it is undetermined (never grounds for suppression)
        *disproven*  - the missing check is present on the path after all
        """
        flow = self.business_flows.get(str(finding.get("flow_ref")))
        if flow is None:
            return Verdict(
                status="plausible",
                gap="the referenced business flow is absent from the flow model",
            )
        steps = list(flow.get("steps") or [])
        target_index = self._privileged_step(finding, steps)
        if target_index is None:
            return Verdict(
                status="plausible",
                gap="the privileged step of the flow could not be identified "
                "from the evidence",
                path=tuple(self._label(step["node_id"]) for step in steps),
            )
        route = steps[: target_index + 1]
        labels = tuple(self._label(step["node_id"]) for step in route)

        missing = str(
            (finding.get("flow_narrative") or {}).get("missing_check", "")
        ).lower()
        # A role/permission gap is only disproven by an authorization check;
        # an identity gap also by authentication.
        if any(
            word in missing
            for word in ("role", "staff", "admin", "authoriz", "permiss", "tenant")
        ):
            wants = ("authorization_required",)
        else:
            wants = ("authorization_required", "authentication_required")
        gated = any(
            hint in set(step.get("annotations") or []) for step in route for hint in wants
        )
        if gated:
            return Verdict(status="disproven", path=labels)

        reasons = [str(r) for r in flow.get("gap_reasons") or []]
        actor = flow.get("actor") or {}
        if actor.get("determination") == "undetermined":
            reasons.append("actor-undetermined")
        if flow.get("partial") or actor.get("determination") == "undetermined":
            return Verdict(
                status="plausible",
                gap="flow is partial or undetermined: " + "; ".join(sorted(set(reasons))),
                path=labels,
            )
        return Verdict(status="verified", path=labels)

    @staticmethod
    def _privileged_step(finding: dict[str, Any], steps: list[dict[str, Any]]) -> int | None:
        """Index of the step the finding's location pins down (or the flow's
        last effective operation when the location names no step).

        A symbol, when present, pins exactly; otherwise the *last* step at the
        location — the deepest point of the journey in that file, i.e. the most
        privileged operation the path reaches there.
        """
        loc = finding.get("location") or {}
        file = str(loc.get("file") or "")
        symbol = loc.get("symbol")
        matched: int | None = None
        for index, step in enumerate(steps):
            node_id = str(step["node_id"])
            path_part = node_id.split("#", 1)[0].split(":", 1)[-1]
            if not file or path_part != file:
                continue
            if symbol and node_id.rsplit("#", 1)[-1] == symbol:
                return index
            matched = index
        if matched is not None:
            return matched
        for index in range(len(steps) - 1, -1, -1):
            if steps[index]["operation"] in ("mutation", "terminal", "external-call"):
                return index
        return None

    def _label(self, node_id: str) -> str:
        node = self.nodes.get(node_id)
        if node is None:
            return node_id
        if node["type"] == "endpoint":
            return f"{node.get('route', 'endpoint')} [{node['repo']}]"
        symbol = node.get("symbol")
        return f"{node['repo']}:{node['path']}" + (f"#{symbol}" if symbol else "")

    def _mitigated(self, flow: Flow, finding: dict[str, Any]) -> bool:
        """True when an enforced control on the path refutes this finding.

        A control the finding itself implicates can never refute it (feature
        016): a finding located at, evidenced through, or naming as related the
        very guard function annotated here asserts that guard is defective, and
        marking the path ``authentication_required`` on its account would
        convert the finding into its own disproof — silence by self-reference.
        Only an *independent* annotated control on the path mitigates.
        """
        if not flow.validations:
            return False
        cwe_id = finding["cwe"]
        # Spec 007: an explicit data-boundary label on the traced path refutes a
        # prompt-injection claim for that route (demonstrated isolation).
        if cwe_id == "CWE-1427":
            return any("boundary_labeled" in validation for validation in flow.validations)
        # Only authorization/authentication findings are refuted by such controls.
        if cwe_id not in ("CWE-862", "CWE-863", "CWE-285", "CWE-284", "CWE-306", "CWE-287"):
            return False
        implicated = implicated_locations(finding)
        return any(
            hint in validation and not any(target in validation for target in implicated)
            for validation in flow.validations
            for hint in MITIGATING
        )

    def _no_flow_verdict(
        self, finding: dict[str, Any], repo: str, path: str, symbol: str | None
    ) -> Verdict:
        """No traced flow: distinguish 'not externally reachable' from 'unknown'."""
        # A location resolved at the *file* tier carries an unconfirmed symbol name
        # (locate.py keeps it as a hint). Matching on it would fail spuriously, so
        # only a confirmed symbol narrows the lookup.
        location = finding.get("location") or {}
        confirmed = symbol if location.get("symbol_confirmed", symbol is not None) else None

        target = None
        for node in self.graph["nodes"]:
            if node["repo"] == repo and node["path"] == path:
                if confirmed is None or node.get("symbol") == confirmed:
                    target = node
                    break

        # Configuration-style findings (hard-coded secrets) have no data flow by
        # nature: presence in source is itself the finding. That argument holds
        # only when presence is *confirmed* — a known credential format. A
        # heuristic-only match is precisely a doubt about presence, so it takes
        # the standard trace path and cannot come out verified without one
        # (FR-008, contract C4). Findings with no provenance field (analysis
        # stage) keep the prior behaviour.
        if finding["cwe"] in presence_valid_cwes() and (
            finding.get("detection", "format") == "format"
        ):
            # Feature 016→017 (FR-009/FR-001): presence classes whose verdict
            # strength still rests on reachability (missing auth, header-asserted
            # identity) demote while the run's reachability gap is active; the
            # secret/config classes hold regardless — presence is their finding.
            if finding["cwe"] in _REACHABILITY_SENSITIVE_PRESENCE and self.reachability_unconfirmed:
                from pipeline.dataflow import REACHABILITY_GAP_REASON

                return Verdict(
                    status="plausible",
                    gap=REACHABILITY_GAP_REASON,
                    path=(f"{repo}:{path}" + (f"#{symbol}" if symbol else ""),),
                )
            return Verdict(
                status="verified",
                basis="presence",
                path=(f"{repo}:{path}" + (f"#{symbol}" if symbol else ""),),
            )

        if target is None:
            # Unreachable once location resolution runs ahead of verification
            # (FR-003): a finding whose location cannot be matched to the code
            # model is rejected there and never arrives here. Publishing one while
            # admitting the location was unmatched is prohibited by FR-003b, so
            # this is an internal invariant failure rather than a verdict.
            raise UnresolvedLocation(
                f"{repo}:{path}" + (f"#{symbol}" if symbol else "")
            )

        return Verdict(
            status="plausible",
            gap=(
                "no externally controllable source could be traced to this location; "
                "reachability from an entry point is unconfirmed"
            ),
            path=(self._label(target["id"]),),
        )


def apply_verification(
    findings: list[dict[str, Any]],
    graph: dict[str, Any],
    flows: list[Flow],
    business_flows: dict[str, Any] | None = None,
    reachability_unconfirmed: bool | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Attach verdicts; returns (kept, disproven).

    ``reachability_unconfirmed`` defaults to the shared computation
    (feature 016, T022): pipeline, resume, and standalone callers agree by
    construction — no flag threading.
    """
    if reachability_unconfirmed is None:
        from pipeline import dataflow

        reachability_unconfirmed = dataflow.reachability_unconfirmed(graph, flows)
    verifier = Verifier(
        graph,
        flows,
        business_flows=business_flows,
        reachability_unconfirmed=reachability_unconfirmed,
    )
    kept: list[dict[str, Any]] = []
    disproven: list[dict[str, Any]] = []
    for finding in findings:
        verdict = verifier.verify(finding)
        finding["verification"] = verdict.to_dict()
        finding["_flow"] = verdict.flow  # consumed by reproduce.py, stripped before write
        if verdict.status == "disproven":
            finding["status"] = "rejected"
            finding["rejection_reason"] = (
                "static verification refuted the finding: an enforced control was found "
                "on every traced path"
            )
            disproven.append(finding)
        else:
            kept.append(finding)
    return kept, disproven
