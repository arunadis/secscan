"""Usage and cost tracking (FR-019).

Every scan emits tokens per stage and model tier, the batch/interactive split,
fallbacks, and estimated savings versus a maximal-context baseline — which is how
SC-004 becomes auditable rather than aspirational.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _bucket() -> dict[str, int]:
    return {"input_tokens": 0, "output_tokens": 0, "invocations": 0}


@dataclass
class UsageTracker:
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    invocations: int = 0
    by_stage: dict[str, dict[str, int]] = field(default_factory=dict)
    by_model_tier: dict[str, dict[str, int]] = field(default_factory=dict)
    by_escalation_level: dict[str, int] = field(default_factory=dict)
    batch_invocations: int = 0
    interactive_invocations: int = 0
    fallbacks: int = 0
    fallback_log: list[dict[str, str]] = field(default_factory=list)
    #: Sum of the context each invocation *would* have used under a naive
    #: "send everything" approach, for the SC-004 comparison.
    baseline_input_tokens: int = 0

    def record(
        self,
        stage: str,
        input_tokens: int,
        output_tokens: int,
        *,
        model_tier: str = "agent",
        escalation_level: int | None = None,
        batch: bool = False,
        baseline_input_tokens: int | None = None,
    ) -> None:
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.invocations += 1

        for target, key in ((self.by_stage, stage), (self.by_model_tier, model_tier)):
            entry = target.setdefault(key, _bucket())
            entry["input_tokens"] += input_tokens
            entry["output_tokens"] += output_tokens
            entry["invocations"] += 1

        if escalation_level is not None:
            level = str(escalation_level)
            self.by_escalation_level[level] = self.by_escalation_level.get(level, 0) + 1

        if batch:
            self.batch_invocations += 1
        else:
            self.interactive_invocations += 1

        self.baseline_input_tokens += (
            baseline_input_tokens if baseline_input_tokens is not None else input_tokens
        )

    def record_fallback(self, item: str, reason: str) -> None:
        """Record a batch item re-executed interactively (FR-016b)."""
        self.fallbacks += 1
        self.fallback_log.append({"item": item, "reason": reason})

    @property
    def savings_factor(self) -> float:
        if self.total_input_tokens == 0:
            return 0.0
        return round(self.baseline_input_tokens / self.total_input_tokens, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "invocations": self.invocations,
            "by_stage": {k: dict(v) for k, v in sorted(self.by_stage.items())},
            "by_model_tier": {k: dict(v) for k, v in sorted(self.by_model_tier.items())},
            "by_escalation_level": dict(sorted(self.by_escalation_level.items())),
            "batch_share": {
                "batch_invocations": self.batch_invocations,
                "interactive_invocations": self.interactive_invocations,
                "fallbacks": self.fallbacks,
            },
            "fallback_log": list(self.fallback_log),
            "baseline_comparison": {
                "maximal_context_tokens": self.baseline_input_tokens,
                "actual_tokens": self.total_input_tokens,
                "savings_factor": self.savings_factor,
            },
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> UsageTracker:
        share = raw.get("batch_share") or {}
        baseline = raw.get("baseline_comparison") or {}
        return cls(
            total_input_tokens=int(raw.get("total_input_tokens", 0)),
            total_output_tokens=int(raw.get("total_output_tokens", 0)),
            invocations=int(raw.get("invocations", 0)),
            by_stage={k: dict(v) for k, v in (raw.get("by_stage") or {}).items()},
            by_model_tier={k: dict(v) for k, v in (raw.get("by_model_tier") or {}).items()},
            by_escalation_level=dict(raw.get("by_escalation_level") or {}),
            batch_invocations=int(share.get("batch_invocations", 0)),
            interactive_invocations=int(share.get("interactive_invocations", 0)),
            fallbacks=int(share.get("fallbacks", 0)),
            fallback_log=list(raw.get("fallback_log") or []),
            baseline_input_tokens=int(baseline.get("maximal_context_tokens", 0)),
        )

    def render_markdown(self) -> str:
        lines = [
            "| Metric | Value |",
            "|--------|-------|",
            f"| Analysis invocations | {self.invocations} |",
            f"| Input tokens | {self.total_input_tokens:,} |",
            f"| Output tokens | {self.total_output_tokens:,} |",
            f"| Batch / interactive | {self.batch_invocations} / {self.interactive_invocations} |",
            f"| Batch fallbacks | {self.fallbacks} |",
            f"| Savings vs maximal-context baseline | {self.savings_factor}x |",
        ]
        if self.by_escalation_level:
            spread = ", ".join(
                f"L{level}: {count}" for level, count in sorted(self.by_escalation_level.items())
            )
            lines.append(f"| Escalation spread | {spread} |")
        if self.by_stage:
            lines.append("")
            lines.append("| Stage | Invocations | Input tokens | Output tokens |")
            lines.append("|-------|-------------|--------------|---------------|")
            for stage, entry in sorted(self.by_stage.items()):
                lines.append(
                    f"| {stage} | {entry['invocations']} | "
                    f"{entry['input_tokens']:,} | {entry['output_tokens']:,} |"
                )
        return "\n".join(lines)
