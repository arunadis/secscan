"""Execution-mode resolution (FR-025, FR-027).

Agent-mediated is the default: the coding agent running the skill reasons with
its own model, so a scan needs no API key at all. Configuring an endpoint
switches analysis to it — explicit configuration always takes precedence.

Endpoint-only capabilities (batch APIs, off-peak scheduling, provider model
tiers) are reported as *unavailable* in agent-mediated mode rather than silently
ignored (FR-007a).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import StrEnum

from config.loader import Config


class ExecutionMode(StrEnum):
    AGENT_MEDIATED = "agent-mediated"
    ENDPOINT_INTERACTIVE = "endpoint-interactive"
    ENDPOINT_BATCH = "endpoint-batch"

    @property
    def uses_endpoint(self) -> bool:
        return self is not ExecutionMode.AGENT_MEDIATED


class MissingCredential(RuntimeError):
    """Endpoint configured but its credential env var is unset (edge case)."""

    def __init__(self, var: str) -> None:
        self.var = var
        super().__init__(
            f"An external analysis endpoint is configured but ${var} is not set.\n"
            f"Export the credential (export {var}=...) or remove llm.endpoint from the "
            "configuration to run in agent-mediated mode using this agent's own model."
        )


#: Capabilities that require a direct provider relationship.
ENDPOINT_ONLY_FEATURES = {
    "batch-api": "provider batch API submission (~50% cost discount)",
    "offpeak-scheduling": "off-peak window scheduling",
    "model-tiering": "per-analysis-level provider model tiers",
}


@dataclass(frozen=True)
class Resolution:
    """Resolved execution mode plus the capability report for this scan."""

    mode: ExecutionMode
    reason: str
    model_map: dict[str, str] = field(default_factory=dict)
    unavailable_features: tuple[str, ...] = ()
    api_key_env: str | None = None

    @property
    def batch(self) -> bool:
        return self.mode is ExecutionMode.ENDPOINT_BATCH

    def tier_for(self, level: str) -> str:
        """Model identifier for an analysis level (``local``/``segment``/``system``)."""
        if not self.mode.uses_endpoint:
            return "agent"
        return self.model_map.get(level) or self.model_map.get("segment") or "endpoint-default"

    def describe(self) -> str:
        lines = [f"Execution mode: {self.mode.value} ({self.reason})"]
        if self.unavailable_features:
            lines.append("Unavailable in this mode:")
            lines.extend(f"  - {feature}" for feature in self.unavailable_features)
        return "\n".join(lines)


def resolve(config: Config, environ: dict[str, str] | None = None) -> Resolution:
    """Determine the execution mode for this scan."""
    env = dict(environ if environ is not None else os.environ)
    endpoint = config.endpoint
    declared = config.llm_mode

    # Explicit agent mode, or no endpoint configured -> agent-mediated (default).
    if declared == "agent" or endpoint is None:
        reason = (
            "llm.mode is 'agent'"
            if declared == "agent"
            else "no external endpoint configured; using this agent's own model"
        )
        return Resolution(
            mode=ExecutionMode.AGENT_MEDIATED,
            reason=reason,
            unavailable_features=tuple(sorted(ENDPOINT_ONLY_FEATURES.values())),
        )

    # Endpoint configured: credential must be present.
    api_key_env = str(endpoint.get("api_key_env") or "")
    if api_key_env and not env.get(api_key_env):
        raise MissingCredential(api_key_env)

    batch = config.batch_enabled or config.execution_mode == "batch-offpeak"
    mode = ExecutionMode.ENDPOINT_BATCH if batch else ExecutionMode.ENDPOINT_INTERACTIVE
    return Resolution(
        mode=mode,
        reason=f"external endpoint configured (provider={endpoint.get('provider', 'anthropic')})",
        model_map={k: str(v) for k, v in (endpoint.get("model_map") or {}).items()},
        api_key_env=api_key_env or None,
    )


def credential_status(config: Config, environ: dict[str, str] | None = None) -> dict[str, object]:
    """Credential presence for the init environment check — never the value (FR-025)."""
    env = dict(environ if environ is not None else os.environ)
    endpoint = config.endpoint
    if endpoint is None:
        return {"required": False, "variable": None, "present": None}
    var = endpoint.get("api_key_env")
    return {
        "required": True,
        "variable": var,
        "present": bool(env.get(str(var))) if var else False,
    }
