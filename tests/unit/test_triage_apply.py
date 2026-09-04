"""Feature 013: verdict parsing gates and application effects (T014/T021).

Dismissal classes under test, end to end:
  parse-level (T009):   non-JSON, schema non-conformance, id mismatch,
                        credential-class refute, credential sweep
  evidence-level (T010): any failed citation degrades refute/downgrade to a flag
  application (T018):   verified refute removes the finding and records a
                        suppression; verified downgrade regrades with provenance;
                        unanswered findings carry the explicit unresolved state
"""

from __future__ import annotations

import json
from pathlib import Path

from pipeline import cwe
from pipeline.redact import Redactor
from pipeline.triage import (
    ParsedVerdict,
    is_credential_finding,
    parse_verdict,
    select_candidates,
)
from pipeline.triage_apply import apply_downgrade, apply_outcomes, attach_flag


def make_finding(
    fid: str = "SEC-0007",
    *,
    cwe_id: str = "CWE-862",
    severity: float = 8.2,
    confidence: float = 0.8,
    repo: str = "shop",
    file: str = "src/api/admin.py",
    line: int = 12,
    detection: str | None = None,
    dependency: dict | None = None,
    verified: bool = True,
) -> dict:
    finding = {
        "id": fid,
        "cwe": cwe_id,
        "severity_score": severity,
        "severity_band": cwe.band_for(severity),
        "confidence": confidence,
        "location": {"repo": repo, "file": file, "line_start": line, "line_end": line + 2},
        "description": "A destructive endpoint lacks an authorization check.",
        "evidence": [{"repo": repo, "file": file, "reason": "no guard in handler"}],
        "attack_scenario": "An attacker calls the endpoint directly.",
        "impact": "Unauthorized modification.",
        "recommendation": "Add an authorization guard.",
        "source": "analysis",
        "status": "correlated",
        "verification": {"status": "verified" if verified else "plausible"},
    }
    if detection:
        finding["detection"] = detection
    if dependency is not None:
        finding["dependency"] = dependency
    return finding


def verdict(fid: str = "SEC-0007", v: str = "confirmed", **extra) -> str:
    return json.dumps({"finding_id": fid, "verdict": v, **extra})


CITATION = {
    "repo": "shop",
    "file": "src/security.py",
    "line_start": 1,
    "line_end": 10,
    "pattern": "RoleAuthorizationFilter",
}


def write_control(
    tmp_path: Path, content: str | None = "class RoleAuthorizationFilter:\n    pass\n"
) -> dict[str, Path]:
    root = tmp_path / "shop"
    (root / "src").mkdir(parents=True)
    (root / "src" / "security.py").write_text(content or "")
    return {"shop": root}


# ------------------------------------------------------------ candidacy gates


def test_dependency_findings_are_never_candidates() -> None:
    dep = make_finding("SEC-0001", dependency={"package": "lib", "ecosystem": "python"})
    code = make_finding("SEC-0002")
    candidates = select_candidates([dep, code])
    assert [f["id"] for f in candidates] == ["SEC-0002"]


def test_band_threshold_and_heuristic_override() -> None:
    low = make_finding("SEC-0001", severity=3.1)
    heuristic = make_finding("SEC-0002", severity=3.1, detection="heuristic")
    candidates = select_candidates([low, heuristic], minimum_band="Medium")
    assert [f["id"] for f in candidates] == ["SEC-0002"]


def test_include_unverified_toggle() -> None:
    plausible = make_finding("SEC-0001", verified=False)
    assert select_candidates([plausible], minimum_band="Medium")
    assert select_candidates([plausible], minimum_band="Medium", include_unverified=False) == []


# ---------------------------------------------------------------- parse gates


def test_parse_accepts_valid_verdicts() -> None:
    finding = make_finding()
    for v, extra in (
        ("confirmed", {}),
        ("flagged", {"user_question": "Is dev-only?"}),
        ("refuted", {"rationale": "filter chain guards it", "citations": [CITATION]}),
        ("downgraded", {"rationale": "no credentials forwarded", "citations": [CITATION]}),
    ):
        parsed = parse_verdict(verdict(v=v, **extra), finding, Redactor())
        assert not parsed.rejected, (v, parsed.reason)
        assert parsed.document and parsed.document["verdict"] == v


def test_parse_rejects_non_json() -> None:
    parsed = parse_verdict("not json at all", make_finding(), Redactor())
    assert parsed.rejected


def test_parse_rejects_schema_violations() -> None:
    finding = make_finding()
    # flagged without user_question
    parsed = parse_verdict(verdict(v="flagged"), finding, Redactor())
    assert parsed.rejected and "schema" in (parsed.reason or "")
    # unknown verdict
    parsed = parse_verdict(verdict(v="maybe"), finding, Redactor())
    assert parsed.rejected


def test_parse_rejects_finding_id_mismatch() -> None:
    parsed = parse_verdict(verdict(fid="SEC-9999", v="confirmed"), make_finding(), Redactor())
    assert parsed.rejected and "does not match" in (parsed.reason or "")


def test_parse_rejects_credential_refute() -> None:
    for cwe_id in ("CWE-798", "CWE-522"):
        finding = make_finding(cwe_id=cwe_id)
        assert is_credential_finding(finding)
        parsed = parse_verdict(
            verdict(v="refuted", rationale="not a real key", citations=[CITATION]),
            finding,
            Redactor(),
        )
        assert parsed.rejected and "credential" in (parsed.reason or "")


def test_parse_allows_credential_downgrade_and_flag() -> None:
    finding = make_finding(cwe_id="CWE-798")
    parsed = parse_verdict(
        verdict(v="downgraded", rationale="test fixture", citations=[CITATION]),
        finding,
        Redactor(),
    )
    assert not parsed.rejected
    parsed = parse_verdict(
        verdict(v="flagged", user_question="Is this value live anywhere?"),
        finding,
        Redactor(),
    )
    assert not parsed.rejected


def test_parse_sweeps_credential_shaped_content() -> None:
    """A citation pattern that looks like a credential is rejected, not stored."""
    dangerous = dict(CITATION, pattern='aws_secret = "AKIAIOSFODNN7EXAMPLE"')
    parsed = parse_verdict(
        verdict(v="refuted", rationale="demo", citations=[dangerous]),
        make_finding(),
        Redactor(),
    )
    assert parsed.rejected and "sweep" in (parsed.reason or "")


# ---------------------------------------------------------------- application


def parsed(v: str, **extra) -> ParsedVerdict:
    json.loads(verdict(v=v, **extra))  # sanity
    return ParsedVerdict("SEC-0007", json.loads(verdict(v=v, **extra)))


def test_verified_refute_suppresses_with_citation_evidence(tmp_path: Path) -> None:
    roots = write_control(tmp_path)
    finding = make_finding()
    kept, suppressions, decisions = apply_outcomes(
        [finding],
        {"SEC-0007": parsed("refuted", rationale="filter chain guards it",
                            citations=[CITATION])},
        roots=roots,
        graph={"nodes": []},
    )
    assert kept == []
    assert len(suppressions) == 1
    record = suppressions[0]
    assert record["tool_id"] == "triage"
    assert record["disproof_ground"] == "triage-control-present"
    assert any("RoleAuthorizationFilter" in line for line in record["evidence"])
    assert decisions[0]["outcome"] == "applied"
    assert decisions[0]["applied_effect"] == "suppression-added"


def test_unverified_citation_degrades_to_flag(tmp_path: Path) -> None:
    roots = write_control(tmp_path, content="class SomethingElse:\n    pass\n")
    finding = make_finding()
    kept, suppressions, decisions = apply_outcomes(
        [finding],
        {"SEC-0007": parsed("refuted", rationale="guarded", citations=[CITATION])},
        roots=roots,
        graph={"nodes": []},
    )
    assert len(kept) == 1 and suppressions == []
    assert kept[0]["awaiting_verification"]["question"]
    assert decisions[0]["outcome"] == "degraded-flagged"


def test_missing_file_citation_degrades(tmp_path: Path) -> None:
    roots = write_control(tmp_path)
    bad = dict(CITATION, file="src/nope.py")
    kept, suppressions, decisions = apply_outcomes(
        [make_finding()],
        {"SEC-0007": parsed("downgraded", rationale="limited", citations=[bad])},
        roots=roots,
        graph={"nodes": []},
    )
    assert len(kept) == 1 and suppressions == []
    assert decisions[0]["outcome"] == "degraded-flagged"
    assert "does not exist" in "; ".join(
        fail for c in decisions[0]["citations"] for fail in c.get("failures", [])
    )


def test_confirmed_leaves_finding_untouched(tmp_path: Path) -> None:
    finding = make_finding()
    kept, suppressions, decisions = apply_outcomes(
        [finding], {"SEC-0007": parsed("confirmed")}, roots=write_control(tmp_path),
        graph={"nodes": []},
    )
    assert kept == [finding]
    assert "triage" not in finding and "awaiting_verification" not in finding
    assert decisions[0]["applied_effect"] == "none"


def test_flagged_attaches_question(tmp_path: Path) -> None:
    finding = make_finding()
    kept, _, decisions = apply_outcomes(
        [finding],
        {"SEC-0007": parsed("flagged", user_question="Dev-only?",
                            settling_evidence_hint="deploy configs")},
        roots=write_control(tmp_path),
        graph={"nodes": []},
    )
    entry = kept[0]["awaiting_verification"]
    assert entry["question"] == "Dev-only?"
    assert entry["settling_evidence_hint"] == "deploy configs"
    assert entry["provenance"] == "triage"
    assert kept[0]["severity_score"] == 8.2  # flagging changes nothing (FR-012)
    assert decisions[0]["applied_effect"] == "flag-attached"


def test_downgrade_lowers_only_and_records_provenance(tmp_path: Path) -> None:
    finding = make_finding(severity=8.2, confidence=0.95)
    kept, suppressions, decisions = apply_outcomes(
        [finding],
        {"SEC-0007": parsed("downgraded", rationale="wildcard without credentials",
                            citations=[CITATION])},
        roots=write_control(tmp_path),
        graph={"nodes": []},
    )
    assert suppressions == []
    adjusted = kept[0]
    assert adjusted["severity_score"] < 8.2
    assert adjusted["severity_band"] == cwe.band_for(adjusted["severity_score"])
    assert adjusted["confidence"] <= 0.8
    triage = adjusted["triage"]
    assert triage["verdict"] == "downgraded"
    assert triage["previous_severity"] == 8.2
    assert triage["previous_confidence"] == 0.95
    assert decisions[0]["applied_effect"] == "grading-adjusted"


def test_downgrade_can_never_raise(tmp_path: Path) -> None:
    finding = make_finding(severity=4.0)
    apply_downgrade(finding, {"rationale": "r", "citations": [CITATION]})
    assert finding["severity_score"] < 4.0
    assert finding["severity_band"] == cwe.band_for(finding["severity_score"])


def test_unanswered_and_rejected_mark_unresolved(tmp_path: Path) -> None:
    rejected = ParsedVerdict("SEC-0007", None, reason="answer is not a JSON object")
    findings = [make_finding(), make_finding("SEC-0008")]
    kept, suppressions, decisions = apply_outcomes(
        findings,
        {"SEC-0007": rejected, "SEC-0008": rejected},
        roots=write_control(tmp_path),
        graph={"nodes": []},
        unanswered={"SEC-0008"},
        unanswered_reason="no answer this round",
    )
    assert len(kept) == 2 and suppressions == []
    assert kept[1]["triage_unresolved"]["reason"] == "no answer this round"
    by_id = {d["finding_id"]: d for d in decisions}
    assert by_id["SEC-0007"]["outcome"] == "rejected-malformed"
    assert by_id["SEC-0008"]["outcome"] == "unanswered"


def test_attach_flag_is_the_single_flag_path() -> None:
    finding = make_finding()
    attach_flag(finding, "q?", hint="h")
    assert finding["awaiting_verification"] == {
        "question": "q?",
        "settling_evidence_hint": "h",
        "provenance": "triage",
    }
