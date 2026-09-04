"""Evidence escalation (FR-006, SC-004).

Analysis starts at the smallest useful context and grows only when the evidence is
insufficient. The escalation ladder:

  L1  security-relevant symbols only
  L2  + calling/called code within the segment
  L3  + the full segment and its data flows
  L4  + cross-segment context

The profile caps the ceiling (``analysis_depth.max_escalation_level``), so `quick`
stays shallow and `audit` may climb all the way. Keeping the large majority of
invocations at L1 is what produces the SC-004 token savings.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pipeline import prompts
from pipeline.budget import estimate_tokens
from pipeline.build_context import ContextBuilder
from pipeline.llm_client import AnalysisClient, AnalysisRequest, AnalysisResponse
from pipeline.usage import UsageTracker

__all__ = ["EscalationRunner", "SegmentOutcome", "needs_escalation"]


@dataclass
class SegmentOutcome:
    segment_id: str
    content: str
    escalation_level: int
    packets: list[dict[str, Any]] = field(default_factory=list)
    pending: bool = False
    escalated: bool = False


def _needs_escalation(content: str) -> bool:
    """True when the analysis said its evidence was insufficient."""
    if not content:
        return False
    try:
        document = json.loads(content)
    except json.JSONDecodeError:
        block_start = content.find("{")
        if block_start == -1:
            return False
        try:
            document = json.loads(content[block_start:])
        except json.JSONDecodeError:
            return False
    if isinstance(document, dict):
        return bool(document.get("needs_escalation"))
    return False


needs_escalation = _needs_escalation


class EscalationRunner:
    """Runs one segment through the escalation ladder until confident or capped."""

    def __init__(
        self,
        client: AnalysisClient,
        builder: ContextBuilder,
        usage: UsageTracker,
        prompt: str,
        max_level: int,
        stage: str = "segment_analysis",
    ) -> None:
        self.client = client
        self.builder = builder
        self.usage = usage
        #: fallback when a segment declares no domains
        self.prompt = prompt
        self.max_level = max(1, min(4, max_level))
        self.stage = stage

    def prompt_for(self, segment: dict[str, Any]) -> str:
        """Guidance for this segment's domains only (FR-011)."""
        domains = segment.get("domains") or []
        if not domains:
            return self.prompt
        return prompts.render_segment_prompt(domains)

    def run(
        self,
        segment: dict[str, Any],
        flows: list[Any] | None = None,
        on_packet: Callable[[dict[str, Any]], None] | None = None,
    ) -> SegmentOutcome:
        outcome = SegmentOutcome(segment_id=segment["id"], content="", escalation_level=1)
        for level in range(1, self.max_level + 1):
            request, packet = self.prepare(segment, level, flows, on_packet)
            response = self.client.run(request)
            if not self.absorb(segment, outcome, request, response, packet):
                return outcome
        return outcome

    def prepare(
        self,
        segment: dict[str, Any],
        level: int,
        flows: list[Any] | None = None,
        on_packet: Callable[[dict[str, Any]], None] | None = None,
    ) -> tuple[AnalysisRequest, dict[str, Any]]:
        """Build, fit, and record the level-``level`` request for ``segment``.

        Shared by the per-segment ladder and the batch round runner (feature 012) so
        both policies send exactly the same content.
        """
        packet = self.builder.build(segment, level, flows)
        request = self._fit(segment, packet, level)
        self.builder.write(packet)
        if on_packet:
            on_packet(packet)
        return request, packet

    def absorb(
        self,
        segment: dict[str, Any],
        outcome: SegmentOutcome,
        request: AnalysisRequest,
        response: AnalysisResponse,
        packet: dict[str, Any],
    ) -> bool:
        """Record ``response`` into ``outcome``; return True when escalation continues.

        A cached response (persisted answer from an earlier run) is not counted in
        this run's usage: the report describes only what this run actually sent.
        """
        level = request.escalation_level
        outcome.packets.append(packet)
        if not response.cached:
            self.usage.record(
                self.stage,
                response.input_tokens,
                response.output_tokens,
                model_tier=response.model_tier,
                escalation_level=level,
                batch=response.batch,
                baseline_input_tokens=self._baseline_tokens(segment),
            )
            if response.fell_back and response.fallback_reason:
                self.usage.record_fallback(request.id, response.fallback_reason)

        outcome.content = response.content
        outcome.escalation_level = level
        outcome.pending = response.pending

        if response.pending or not _needs_escalation(response.content):
            return False
        outcome.escalated = True
        if level >= self.max_level:
            return False
        # Nothing more to add: the packet already holds the whole segment.
        return not (level >= 3 and len(packet["source"]) >= len(segment["files"]))

    def _fit(
        self, segment: dict[str, Any], packet: dict[str, Any], level: int
    ) -> AnalysisRequest:
        """Shrink the packet until the *actual serialized request* fits the budget.

        Sizing the packet alone is not enough: the prompt and JSON encoding add
        real tokens. SC-001 requires that no invocation ever exceeds its budget,
        so the request is measured, not estimated by proxy — and whole files are
        shed (never truncated) until it fits.
        """
        budget = self.builder.budget
        prompt = self.prompt_for(segment)

        def make() -> AnalysisRequest:
            return AnalysisRequest(
                id=f"{segment['id']}-l{level}",
                stage=self.stage,
                prompt=prompt,
                payload=self._payload(segment, packet),
                budget=budget,
                level="local" if level == 1 else "segment",
                escalation_level=level,
            )

        request = make()
        dropped: list[str] = []
        while not budget.fits(request.estimated_tokens()) and packet["source"]:
            largest = max(
                sorted(packet["source"]), key=lambda k: estimate_tokens(packet["source"][k])
            )
            del packet["source"][largest]
            dropped.append(largest)
            request = make()

        # The recorded size is the size actually sent, so artifacts stay auditable.
        packet["estimated_tokens"] = request.estimated_tokens()
        if dropped:
            self.builder.warnings.append(
                f"{segment['id']}: omitted {len(dropped)} file(s) from the level-{level} "
                f"request to stay within the {budget.max_context_tokens}-token budget"
            )
        return request

    def _payload(self, segment: dict[str, Any], packet: dict[str, Any]) -> dict[str, Any]:
        return {
            "segment_id": segment["id"],
            "repo": segment["repos"][0],
            "purpose": packet["purpose"],
            "domains": packet["domains"],
            "entrypoints": packet["entrypoints"],
            "call_graph_summary": packet["call_graph_summary"],
            "data_flows": packet["data_flows"],
            "security_relevant_symbols": packet["security_relevant_symbols"],
            "source": packet["source"],
        }

    def _baseline_tokens(self, segment: dict[str, Any]) -> int:
        """What a naive 'send everything' call would have cost (SC-004 baseline)."""
        cached = segment.get("_baseline_tokens")
        if cached is not None:
            return int(cached)
        roots = self.builder.roots
        repo = segment["repos"][0]
        root = roots.get(repo)
        total = 0
        if root is not None:
            for relative in segment["files"]:
                try:
                    total += estimate_tokens((root / relative).read_text(errors="replace"))
                except OSError:
                    continue
        # A naive approach sends the whole segment at the maximum budget every call.
        baseline = max(total, self.builder.budget.max_context_tokens)
        segment["_baseline_tokens"] = baseline
        return baseline
