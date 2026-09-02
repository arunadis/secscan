"""Reproduction block generation (FR-030).

Derives runnable-shaped reproduction steps from a finding's own evidence and its
traced flow. Safety constraints (the "benign-proof standard"):

* triggers use non-destructive **canary** values that demonstrate the flaw
  without causing damage — never destructive payloads;
* no real credentials or secrets appear (the redactor is applied as a backstop);
* steps explicitly target a local/test deployment.
"""

from __future__ import annotations

import re
from typing import Any

from pipeline.dataflow import Flow
from pipeline.redact import Redactor

CANARY = "SECSCAN-CANARY-1"

_METHOD_ROUTE = re.compile(r"^([A-Z|]+)\s+(\S+)")
_PATH_PARAM = re.compile(r"<[^>]+>|\{[^}]+\}|:[A-Za-z_]\w*")

#: CWE -> (benign probe value, what it proves)
_PROBES: dict[str, tuple[str, str]] = {
    "CWE-89": (
        f"' OR '{CANARY}'='{CANARY}",
        "a benign always-true predicate proves the value reaches the SQL parser",
    ),
    "CWE-78": (
        f"; echo {CANARY}",
        "an echo of a canary marker proves command interpolation without side effects",
    ),
    "CWE-77": (f"; echo {CANARY}", "an echo of a canary marker proves command interpolation"),
    "CWE-79": (
        f"<span data-canary=\"{CANARY}\">{CANARY}</span>",
        "an inert markup canary proves unescaped rendering without executing script",
    ),
    "CWE-22": (
        f"../{CANARY}",
        "a traversal segment to a non-existent canary path proves path concatenation",
    ),
    "CWE-918": (
        f"http://127.0.0.1:9/{CANARY}",
        "a request to a closed local port proves outbound fetch of user input",
    ),
    "CWE-502": (
        f"canary-marker:{CANARY}",
        "a benign marker object proves untrusted data reaches the deserializer",
    ),
    "CWE-639": (
        f"{CANARY}-other-tenant-id",
        "substituting another tenant's identifier proves the key is not scoped",
    ),
}

_AUTHZ_CWES = ("CWE-862", "CWE-863", "CWE-285", "CWE-284", "CWE-306", "CWE-287")
_SECRET_CWES = ("CWE-798", "CWE-259", "CWE-256", "CWE-522", "CWE-532")


def _entry_point(flow: Flow | None, finding: dict[str, Any]) -> str | None:
    if flow is None:
        return None
    match = _METHOD_ROUTE.match(flow.source)
    if match:
        return flow.source.split(" (")[0]
    return None


def _concrete_route(route: str, probe: str | None) -> str:
    """Fill path parameters with a canary (or probe) value."""
    match = _METHOD_ROUTE.match(route)
    if not match:
        return route
    method, path = match.group(1).split("|")[0], match.group(2)
    filler = probe or CANARY
    concrete = _PATH_PARAM.sub(_urlencode(filler), path)
    return f"{method} {concrete}"


def _urlencode(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")


#: Probes whose success criterion requires the attacker to control the *whole*
#: value — scheme and host included. Against a sink that interpolates after a
#: fixed prefix these can never succeed, so emitting one states a falsehood
#: (FR-009). The benchmark's request-forgery repro is exactly this case.
_WHOLE_VALUE_PROBES = ("CWE-918",)


def probe_feasible(cwe_id: str, fixed_prefix_sink: bool) -> bool:
    """Can a probe for ``cwe_id`` succeed against this sink's value construction?

    The only judgement here: a probe that has to supply its own scheme and host
    cannot work when the sink pins them. Everything else is assumed feasible,
    because refusing to emit a workable probe is its own failure.
    """
    return not (fixed_prefix_sink and cwe_id in _WHOLE_VALUE_PROBES)


def build_reproduction(
    finding: dict[str, Any],
    flow: Flow | None,
    redactor: Redactor | None = None,
    fixed_prefix_sink: bool = False,
) -> dict[str, Any]:
    """Construct the reproduction block for ``finding``.

    Two properties this must never violate:

    * **Nothing is claimed as observed unless it was.** The scanner never runs
      anything, so only a finding verified end to end may carry an
      ``observed_behavior``; everything else states a hypothesis and says plainly
      that the behaviour was not observed (FR-008).
    * **The trail is a path or it is absent.** ``traced_trail`` carries traced
      graph nodes only. Supporting evidence stays under ``evidence`` and is never
      rendered with dataflow notation (FR-005, FR-006).
    """
    cwe_id = finding["cwe"]
    location = finding["location"]
    where = f"{location.get('file')}#{location.get('symbol') or ''}".rstrip("#")
    probe, proves = _PROBES.get(cwe_id, (CANARY, "the canary value reaches the unsafe operation"))

    verified = (finding.get("verification") or {}).get("status") == "verified"
    feasible = probe_feasible(cwe_id, fixed_prefix_sink)

    entry = _entry_point(flow, finding)
    preconditions, trigger, expected, observed = _build_parts(
        cwe_id, finding, entry, probe, proves, where
    )

    block: dict[str, Any] = {
        "preconditions": preconditions,
        "expected_behavior": expected,
        "mode": "observed" if verified else "hypothesis",
        "target_scope": "local/test",
    }

    if feasible:
        block["trigger"] = trigger
    else:
        block["trigger_omitted_reason"] = (
            f"No achievable probe exists for {cwe_id} at this sink: the untrusted value is "
            "interpolated after a fixed prefix the caller does not control, so any probe "
            "whose success depends on supplying its own scheme or host cannot succeed. "
            "Inspect the constructed value instead."
        )

    if verified:
        block["observed_behavior"] = observed
    else:
        block["outcome_to_check"] = (
            f"{observed} The scanner did not observe this — verification is "
            f"'{(finding.get('verification') or {}).get('status', 'unverified')}', so treat "
            "this as the hypothesis to test rather than a result."
        )

    # A trail is a traced path or nothing at all. Concatenating unrelated evidence
    # under dataflow arrows is what made the benchmark's trail read as a path
    # through a pluralisation pipe and a hosting config file. The published trail
    # must be a subset of verification.path, so prefer it verbatim when tracing
    # succeeded — flow.path spells its entry node differently (file#@ROUTE) and
    # would render off-path.
    path = (finding.get("verification") or {}).get("path")
    if path:
        block["traced_trail"] = list(path)
    elif flow is not None and flow.path:
        block["traced_trail"] = list(flow.path)

    # Backstop: reproduction blocks must never carry a real secret.
    redactor = redactor or Redactor()
    for key in (
        "preconditions",
        "trigger",
        "expected_behavior",
        "observed_behavior",
        "outcome_to_check",
        "trigger_omitted_reason",
    ):
        if block.get(key):
            block[key] = redactor.redact(block[key], origin=f"reproduction.{key}").text
    return block


def _build_parts(
    cwe_id: str,
    finding: dict[str, Any],
    entry: str | None,
    probe: str,
    proves: str,
    where: str,
) -> tuple[str, str, str, str]:
    local = "against a local/test deployment of this code"

    if cwe_id in _SECRET_CWES:
        return (
            "Read access to the repository at the reported revision. No running service needed.",
            (
                f"Inspect {where} in a local checkout and grep for the assignment "
                f"(marker {CANARY} denotes the redacted literal in this report)."
            ),
            "Credentials are supplied from environment or a secret manager at runtime.",
            "A credential literal is committed in source and readable by anyone with repo access.",
        )

    if cwe_id in _AUTHZ_CWES:
        route = _concrete_route(entry or "GET /<resource>", None)
        return (
            (
                "Two accounts on a local/test deployment: a low-privilege user and a resource "
                "owned by another account. Capture the low-privilege session token."
            ),
            (
                f"Send `{route}` {local} using the LOW-PRIVILEGE session, targeting a resource "
                f"tagged `{CANARY}` that belongs to the other account. "
                "Use a read-only or reversible operation for the probe."
            ),
            "The request is rejected (401/403) or scoped to the caller's own resources.",
            (
                f"The request succeeds and acts on the `{CANARY}`-tagged resource owned by "
                "another account, showing no authorization check is enforced."
            ),
        )

    if entry:
        route = _concrete_route(entry, probe)
        return (
            (
                "A local/test deployment of the service with a seeded, disposable dataset. "
                "Any session sufficient to reach the entry point."
            ),
            (
                f"Send `{route}` {local} "
                f"(payload/parameter value: `{probe}`) - {proves}."
            ),
            (
                "The input is validated, escaped, or parameterized so the canary is treated "
                "as inert data."
            ),
            (
                f"The canary is interpreted by the downstream operation at {where}, "
                "confirming the untrusted value crosses the boundary unchecked."
            ),
        )

    return (
        (
            "A local/test deployment with a debugger or unit-test harness able to invoke "
            f"{where} directly."
        ),
        (
            f"Invoke `{where}` {local} with the parameter value `{probe}` - {proves}."
        ),
        "The value is validated or neutralized before reaching the unsafe operation.",
        f"The value reaches the unsafe operation at {where} unchanged.",
    )


def _fixed_prefix_sinks(graph: dict[str, Any] | None) -> set[tuple[str, str, str | None]]:
    """(repo, path, symbol) for symbols annotated as building a fixed-prefix value."""
    if not graph:
        return set()
    return {
        (node["repo"], node["path"], node.get("symbol"))
        for node in graph.get("nodes") or []
        if "fixed_prefix_sink" in (node.get("annotations") or [])
    }


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def apply_reproduction(
    findings: list[dict[str, Any]],
    redactor: Redactor | None = None,
    graph: dict[str, Any] | None = None,
) -> None:
    """Attach reproduction blocks to every reportable finding (in place).

    ``graph`` supplies the sink value-construction shape used for probe
    feasibility. Without it every probe is assumed feasible, which is the
    pre-002 behaviour.
    """
    fixed_prefix = _fixed_prefix_sinks(graph)
    for finding in findings:
        flow = finding.get("_flow")
        location = finding.get("location") or {}
        key = (location.get("repo"), location.get("file"), location.get("symbol"))
        finding["reproduction"] = build_reproduction(
            finding, flow, redactor, fixed_prefix_sink=key in fixed_prefix
        )
