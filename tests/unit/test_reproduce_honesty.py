"""T024: reproduction blocks state only what was established (FR-005–FR-011).

The reviewed benchmark scan failed here twice over: it asserted an "Observed"
behaviour for a finding nothing had observed, and it emitted a probe whose success
criterion could never be met. Both are asserted against below.
"""

from __future__ import annotations

import pytest

from pipeline.dataflow import Flow
from pipeline.extract import extract_file
from pipeline.reproduce import build_reproduction, probe_feasible


def finding(cwe="CWE-918", status="plausible", **location) -> dict:
    loc = {"repo": "web", "file": "src/api/client.ts", "symbol": "fetchUser",
           "line_start": 5, "line_end": 8}
    loc.update(location)
    return {
        "id": "SEC-0001",
        "cwe": cwe,
        "location": loc,
        "evidence": [{"repo": "web", "file": "src/api/client.ts", "reason": "unencoded id"}],
        "verification": {"status": status},
    }


# --------------------------------------------------------- probe feasibility


def test_whole_value_probe_is_infeasible_against_a_fixed_prefix() -> None:
    """FR-009: the benchmark's `http://127.0.0.1:9/...` probe, now rejected.

    The value is interpolated after `${baseUrl}`, so scheme and host are pinned by
    the code. A probe proving 'an outbound fetch of user input' by targeting a
    local port cannot succeed, and the report said as much elsewhere while still
    printing the probe.
    """
    assert probe_feasible("CWE-918", fixed_prefix_sink=True) is False
    assert probe_feasible("CWE-918", fixed_prefix_sink=False) is True


def test_other_probes_stay_feasible_against_a_fixed_prefix() -> None:
    """Refusing to emit a workable probe would be its own failure."""
    for cwe in ("CWE-89", "CWE-79", "CWE-78", "CWE-22"):
        assert probe_feasible(cwe, fixed_prefix_sink=True) is True


def test_infeasible_probe_omits_the_trigger_and_says_why() -> None:
    """FR-010: state the limitation instead of printing something unachievable."""
    block = build_reproduction(finding(), flow=None, fixed_prefix_sink=True)
    assert "trigger" not in block
    assert block["trigger_omitted_reason"]
    assert "fixed prefix" in block["trigger_omitted_reason"]


def test_feasible_probe_emits_a_canary_trigger() -> None:
    block = build_reproduction(finding(cwe="CWE-89"), flow=None, fixed_prefix_sink=False)
    assert "CANARY" in block["trigger"].upper()
    assert "trigger_omitted_reason" not in block


# ------------------------------------------------- observation vs hypothesis


def test_unverified_finding_states_a_hypothesis_not_an_observation() -> None:
    """FR-008: the scanner never ran anything, so it may not claim it saw anything."""
    block = build_reproduction(finding(status="plausible"), flow=None)
    assert block["mode"] == "hypothesis"
    assert "observed_behavior" not in block
    assert block["outcome_to_check"]
    assert "did not observe" in block["outcome_to_check"]


def test_verified_finding_may_report_an_observation() -> None:
    flow = Flow(source="GET /user/<id>", sink="web:client.ts#fetchUser",
                path=("a", "b"), transforms=("t",))
    block = build_reproduction(finding(status="verified"), flow=flow)
    assert block["mode"] == "observed"
    assert block["observed_behavior"]
    assert "outcome_to_check" not in block


@pytest.mark.parametrize("status", ["plausible", "disproven", "unverified"])
def test_only_verified_may_claim_observation(status: str) -> None:
    block = build_reproduction(finding(status=status), flow=None)
    assert block["mode"] == "hypothesis"


# ---------------------------------------------------------------- the trail


def test_traced_trail_comes_only_from_the_traced_path() -> None:
    """FR-005: a trail rendered as a path must contain only traced edges."""
    flow = Flow(
        source="GET /user/<id>",
        sink="web:client.ts#fetchUser",
        path=("web:routes.ts#route", "web:client.ts#fetchUser"),
    )
    block = build_reproduction(finding(status="verified"), flow=flow)
    assert block["traced_trail"] == list(flow.path)


def test_no_trail_when_no_path_was_traced() -> None:
    """Omission beats substituting unrelated evidence under dataflow arrows."""
    block = build_reproduction(finding(), flow=None)
    assert "traced_trail" not in block


def test_evidence_is_never_folded_into_the_trail() -> None:
    """The concrete benchmark defect: a pipeline and a hosting config in the trail."""
    doc = finding(status="verified")
    doc["evidence"] = [
        {"repo": "web", "file": "src/pipes/comment.pipe.ts", "reason": "unrelated pipe"},
        {"repo": "web", "file": "firebase.json", "reason": "no CSP configured"},
    ]
    flow = Flow(source="s", sink="web:client.ts#fetchUser", path=("web:client.ts#fetchUser",))
    block = build_reproduction(doc, flow=flow)
    assert block["traced_trail"] == ["web:client.ts#fetchUser"]
    joined = " ".join(block["traced_trail"])
    assert "comment.pipe" not in joined
    assert "firebase.json" not in joined


# ------------------------------------------------------ shape detection input


def test_extractor_annotates_a_fixed_prefix_sink() -> None:
    """The annotation that makes feasibility decidable (FR-009, research.md A1)."""
    source = """export class ApiClient {
  private baseUrl = "https://api.example.com";

  fetchUser(id: string) {
    return fetch(`${this.baseUrl}/user/${id}`).then((r) => r.json());
  }
}
"""
    facts = extract_file("src/api/client.ts", source, "typescript")
    assert facts is not None
    annotated = {s.name: set(s.annotations) for s in facts.symbols}
    assert "fixed_prefix_sink" in annotated.get("fetchUser", set()), annotated


def test_extractor_does_not_annotate_a_fully_controlled_url() -> None:
    """A caller-supplied whole URL is genuinely probe-able; don't suppress it."""
    source = """export function fetchAny(url: string) {
  return fetch(url).then((r) => r.json());
}
"""
    facts = extract_file("src/api/any.ts", source, "typescript")
    assert facts is not None
    annotated = {s.name: set(s.annotations) for s in facts.symbols}
    assert "fixed_prefix_sink" not in annotated.get("fetchAny", set())


# ---------------------------------- feature 010: location tokens stay readable


def _secret_finding(**location) -> dict:
    loc = {
        "repo": "skh",
        "file": "skillhunt-portal-backend/migration/p0/verify-account.sh",
        "symbol": "AWS_SECRET_ACCESS_KEY",
        "line_start": 47,
        "line_end": 53,
    }
    loc.update(location)
    return {"id": "SEC-0080", "cwe": "CWE-798", "location": loc, "evidence": [],
            "verification": {"status": "verified"}}


def test_reproduction_trigger_keeps_the_file_path_verbatim() -> None:
    """FR-009/FR-011: the report must not tell the reader to inspect [REDACTED].sh."""
    block = build_reproduction(_secret_finding(), flow=None)
    assert "skillhunt-portal-backend/migration/p0/verify-account.sh#AWS_SECRET_ACCESS_KEY" in (
        block["trigger"]
    )
    assert "[REDACTED" not in block["trigger"] and "[BLOCKED" not in block["trigger"]


def test_reproduction_keeps_a_high_entropy_symbol_from_the_code_model() -> None:
    symbol = "Zk3Qp9Xr7Lm2Vn8Bt4Wy6Cd0Hj5Gs1F"
    block = build_reproduction(_secret_finding(symbol=symbol), flow=None)
    assert symbol in block["trigger"]


def test_reproduction_still_redacts_a_credential_value(monkeypatch) -> None:
    """FR-010: protecting locations must not protect values."""
    from pipeline import reproduce

    value = "Xh8Kq2Lm9Rt4Wv7Zy1Bc3Df6Gj0Np5Sa"
    real = reproduce._build_parts

    def leaky(*args, **kwargs):
        pre, trig, exp, obs = real(*args, **kwargs)
        return pre, f"{trig} secret={value}", exp, obs

    monkeypatch.setattr(reproduce, "_build_parts", leaky)
    block = build_reproduction(_secret_finding(), flow=None)
    assert value not in block["trigger"]
    assert "verify-account.sh" in block["trigger"]
