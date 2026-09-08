"""Feature 017 T009 (US2, FR-004): identity-channel family grouping — dependents
link to the trust-point anchor; generic channel names never link."""

from __future__ import annotations

import copy

from pipeline.correlate_findings import correlate


def _finding(
    fid: str,
    file: str,
    symbol: str | None = None,
    tool_ref: str | None = None,
    evidence_reason: str = "",
    description: str = "",
) -> dict:
    finding = {
        "id": fid,
        "cwe": "CWE-290",
        "severity_score": 9.1,
        "severity_band": "Critical",
        "confidence": 0.9,
        "location": {"repo": "app", "file": file, "line_start": 1},
        "description": description or "x",
        "evidence": [
            {
                "repo": "app",
                "file": file,
                "symbol": symbol,
                "reason": evidence_reason,
            }
        ],
        "attack_scenario": "a",
        "impact": "i",
        "recommendation": "r",
        "source": "analysis",
        "status": "correlated",
    }
    if symbol:
        finding["location"]["symbol"] = symbol
    if tool_ref:
        finding["tool_ref"] = tool_ref
    return finding


BACKEND = _finding(
    "SEC-0002",
    "src/middleware/auth.js",
    symbol="authenticateUser",
    tool_ref="identity-archetype@1:node-header-identity-no-credential",
    evidence_reason="reads identity from req.headers['x-user-email'] with no credential",
)
FRONTEND = _finding(
    "SEC-0003",
    "src/api/client.ts",
    symbol="ApiClient.constructor",
    description="localStorage userEmail is sent as the x-user-email header verbatim",
    evidence_reason="localStorage value copied into config.headers['x-user-email']",
)
UNRELATED = _finding(
    "SEC-0004",
    "src/api/search.ts",
    symbol="searchBox",
    description="the search box submits ?q= directly",
    evidence_reason="query reaches the URL unchecked",
)

_GRAPH = {
    "nodes": [],
    "edges": [],
    "unresolved_wiring": [],
}


def test_same_identity_channel_links_dependents_to_anchor() -> None:
    correlated = correlate([copy.deepcopy(BACKEND), copy.deepcopy(FRONTEND)])
    anchor = next(f for f in correlated if f["id"] == "SEC-0002")
    dependent = next(f for f in correlated if f["id"] == "SEC-0003")
    anchor_rel = {r["type"]: r["target_id"] for r in anchor.get("relationships") or []}
    dep_rel = {r["type"]: r["target_id"] for r in dependent.get("relationships") or []}
    assert dep_rel.get("dependent") == "SEC-0002"
    assert anchor_rel.get("related") == "SEC-0003"


def test_non_identity_mentions_do_not_join_the_family() -> None:
    correlated = correlate([copy.deepcopy(BACKEND), copy.deepcopy(UNRELATED)])
    unrelated = next(f for f in correlated if f["id"] == "SEC-0004")
    assert not any(
        r.get("type") == "dependent" for r in unrelated.get("relationships") or []
    )


def test_anchor_decision_prefers_pack_then_auth_annotated() -> None:
    """Two pack findings at two trust points form separate families, never merged."""
    other_anchor = _finding(
        "SEC-0009",
        "src/middleware/session.js",
        symbol="requireSession",
        tool_ref="identity-archetype@1:node-header-identity-no-credential",
        evidence_reason="reads identity from req.cookies['session_user_email']",
    )
    correlated = correlate([copy.deepcopy(BACKEND), copy.deepcopy(other_anchor)])
    anchors = {
        f["id"]
        for f in correlated
        if not any(r.get("type") == "dependent" for r in f.get("relationships") or [])
    }
    assert anchors == {"SEC-0002", "SEC-0009"}


def test_solo_findings_carry_no_family_links() -> None:
    correlated = correlate([copy.deepcopy(BACKEND)])
    anchor = correlated[0]
    assert not any(
        r.get("type") == "dependent" or r.get("type") == "related"
        for r in anchor.get("relationships") or []
    )
