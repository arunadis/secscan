"""Token accounting and budget enforcement (FR-007).

Budgets are enforced in *both* execution modes: against the configured endpoint
limits, and against the host agent's context window in agent-mediated mode
(FR-007a). Estimation is deterministic and provider-independent — a heuristic
character-per-token ratio, deliberately conservative so that budget checks never
under-count.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Conservative characters-per-token ratio for source code.
CHARS_PER_TOKEN = 3.5


def estimate_tokens(text: str) -> int:
    """Deterministic, conservative token estimate for ``text``."""
    if not text:
        return 0
    return max(1, int(len(text) / CHARS_PER_TOKEN) + 1)


def estimate_mapping_tokens(mapping: dict[str, str]) -> int:
    return sum(estimate_tokens(value) for value in mapping.values())


class BudgetExceeded(RuntimeError):
    """Raised when a payload cannot be fitted within its budget."""

    def __init__(self, estimated: int, limit: int, context: str = "") -> None:
        self.estimated = estimated
        self.limit = limit
        where = f" for {context}" if context else ""
        super().__init__(
            f"context budget exceeded{where}: estimated {estimated} tokens > limit {limit}"
        )


@dataclass(frozen=True)
class TokenBudget:
    """Per-invocation budget (contracts/config-schema.md ``budgets``)."""

    max_context_tokens: int
    max_output_tokens: int
    escalation_threshold: float

    def __post_init__(self) -> None:
        if self.max_context_tokens < 1 or self.max_output_tokens < 1:
            raise ValueError("token budgets must be positive")
        if not 0 < self.escalation_threshold <= 1:
            raise ValueError("escalation_threshold must be in (0, 1]")

    def to_dict(self) -> dict[str, float | int]:
        return {
            "max_context_tokens": self.max_context_tokens,
            "max_output_tokens": self.max_output_tokens,
            "escalation_threshold": self.escalation_threshold,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> TokenBudget:
        return cls(
            max_context_tokens=int(raw["max_context_tokens"]),
            max_output_tokens=int(raw["max_output_tokens"]),
            escalation_threshold=float(raw["escalation_threshold"]),
        )

    # ------------------------------------------------------------- checking

    def fits(self, estimated: int) -> bool:
        return estimated <= self.max_context_tokens

    def check(self, estimated: int, context: str = "") -> None:
        if not self.fits(estimated):
            raise BudgetExceeded(estimated, self.max_context_tokens, context)

    def headroom(self, estimated: int) -> int:
        return self.max_context_tokens - estimated

    def utilization(self, estimated: int) -> float:
        return estimated / self.max_context_tokens

    def should_escalate(self, estimated: int) -> bool:
        """True when a larger context would still leave room to escalate into."""
        return self.utilization(estimated) < self.escalation_threshold

    def trim_to_fit(self, mapping: dict[str, str]) -> tuple[dict[str, str], list[str]]:
        """Drop whole files (largest first) until the mapping fits.

        Returns the retained mapping plus the names of dropped files so callers
        can record a coverage gap instead of silently truncating code.
        """
        retained = dict(mapping)
        dropped: list[str] = []
        while retained and not self.fits(estimate_mapping_tokens(retained)):
            largest = max(sorted(retained), key=lambda k: estimate_tokens(retained[k]))
            del retained[largest]
            dropped.append(largest)
        return retained, sorted(dropped)
