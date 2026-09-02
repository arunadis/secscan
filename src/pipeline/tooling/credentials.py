"""Credential-decision helpers for credential-bearing tools (feature 009).

Everything here is pure: presence is read from an *injected* ``environ``
mapping (mirroring ``run_init``'s injection point), never from ``os.environ``
directly, so the decision logic is unit-testable without a process. The
credential VALUE is never touched, read, compared, or returned by anything in
this module — only its presence state under the declared variable name.

States are the closed enum from data-model.md §2; user-facing text is built
from the registry-declared fields so the wording travels with the tool it
describes (research.md R3).
"""

from __future__ import annotations

from pipeline.tooling.registry import CredentialSpec

#: Closed credential-state enum (data-model.md §2). Values are written into
#: availability records; renaming/removing is a contract change.
STATE_AVAILABLE = "available"
STATE_AWAITING_KEY = "awaiting-key"
KEYLESS_STATE_DEGRADED = "degraded-no-key"
STATE_SKIPPED_NO_KEY = "skipped-no-key"

STATES = (
    STATE_AVAILABLE,
    STATE_AWAITING_KEY,
    KEYLESS_STATE_DEGRADED,
    STATE_SKIPPED_NO_KEY,
)


def key_present(spec: CredentialSpec, environ: dict[str, str]) -> bool:
    """Presence check ONLY (FR-002/FR-003): non-empty, non-whitespace value.

    Never validates the key against any service, never inspects its shape.
    An unset, empty, or whitespace-only variable counts as *not provided*.
    """
    return bool(environ.get(spec.env_var, "").strip())


def warning_text(spec: CredentialSpec) -> str:
    """The keyless implication shown BEFORE any install of the tool (FR-004)."""
    return (
        f"No ${spec.env_var} is set: {spec.absence_impact}. "
        f"You can request a key at {spec.obtain_url}."
    )


def guidance_text(spec: CredentialSpec) -> str:
    """Install-and-wire guidance for the provide-a-key choice (FR-005c).

    Instructs the user to make the key available in their shell environment by
    NAME. The scanner never asks for the value, never accepts it as input, and
    never writes it anywhere (FR-011): the tool reads the environment variable
    itself at scan time (research.md R1).
    """
    return (
        f"To supply a key: set ${spec.env_var} in your shell environment "
        f"(e.g. add an export to your shell profile). Request one at "
        f"{spec.obtain_url}. This run installs and configures the tool "
        f"referencing ${spec.env_var} by name only — the key takes effect at "
        f"scan time once set, and re-running init upgrades the status."
    )


def report_line(tool_id: str, spec: CredentialSpec, state: str) -> str:
    """Informational per-tool credential line for the init report (FR-007)."""
    if state == STATE_AVAILABLE:
        return (
            f"${spec.env_var} is set — {tool_id} will run at full speed "
            f"(presence checked, key not validated)"
        )
    if state == STATE_AWAITING_KEY:
        return (
            f"awaiting key — installed and ready; set ${spec.env_var} and it "
            f"takes effect at scan time"
        )
    if state == KEYLESS_STATE_DEGRADED:
        return f"no NVD key — {tool_id} runs rate-limited (explicit choice)"
    if state == STATE_SKIPPED_NO_KEY:
        return (
            f"skipped — no NVD key; set ${spec.env_var} and re-run init to "
            f"add {tool_id}"
        )
    raise ValueError(f"unknown credential state {state!r}")
