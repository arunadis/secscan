"""Applying triage verdicts to the finding set (feature 013).

The reasoner proposes; the pipeline disposes. Every attempted verdict lands in
``triage/decisions.json`` — applied, rejected, degraded, or unanswered — and only
verdicts whose citations re-verified (:mod:`pipeline.triage_evidence`) may remove
or regrade a finding. Undetermined outcomes (unanswered round, malformed answer)
leave the finding untouched and are recorded, never silent (Principle V).
"""

from __future__ import annotations

from typing import Any

from pipeline import cwe
from pipeline.calibrate import CREDITED_CONTROL_FACTOR
from pipeline.triage import ParsedVerdict
from pipeline.triage_evidence import verify_citations

STAGE = "finding_triage"

#: Confidence cap after a cited downgrade: the finding's own evidence stands, but
#: the reasoner's limiting facts — even verified — soften certainty, they do not
#: strengthen it.
DOWNGRADED_CONFIDENCE_CAP = 0.8


def attach_flag(
    finding: dict[str, Any],
    question: str,
    *,
    hint: str | None = None,
    provenance: str = "triage",
) -> None:
    """The single flag-attachment path (T019/T027 share it; never two)."""
    entry: dict[str, Any] = {"question": question}
    if hint:
        entry["settling_evidence_hint"] = hint
    entry["provenance"] = provenance
    finding["awaiting_verification"] = entry


def _citation_summary(citation: dict[str, Any]) -> str:
    pattern = str(citation.get("pattern") or "")
    short = pattern[:60] + ("…" if len(pattern) > 60 else "")
    return (
        f"citation verified: {citation.get('repo')}/{citation.get('file')}:"
        f"{citation.get('line_start')}-{citation.get('line_end')} contains {short!r}"
    )


def _record_suppression(
    finding: dict[str, Any], document: dict[str, Any], citations: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "finding": {
            "tool_ref": "triage",
            "description": str(finding.get("description") or ""),
            "location": dict(finding.get("location") or {}),
        },
        "tool_id": "triage",
        "disproof_ground": "triage-control-present",
        "evidence": [
            f"verdict: refuted — {document.get('rationale', '')}".rstrip(" —"),
            *[_citation_summary(c) for c in citations],
        ],
    }


def apply_downgrade(finding: dict[str, Any], document: dict[str, Any]) -> None:
    """Cited downgrade: lower severity boundedly, record provenance (FR-011).

    Scores may only fall. The factor is the calibration stage's credited-control
    factor so "a control exists that limits impact" grades identically whether
    calibration or triage established it.
    """
    previous_severity = float(finding.get("severity_score", 0.0))
    previous_confidence = float(finding.get("confidence", 0.0))
    severity = max(1.0, round(previous_severity * CREDITED_CONTROL_FACTOR, 1))
    finding["severity_score"] = severity
    finding["severity_band"] = cwe.band_for(severity)
    finding["confidence"] = round(min(previous_confidence, DOWNGRADED_CONFIDENCE_CAP), 2)
    finding["triage"] = {
        "verdict": "downgraded",
        "rationale": str(document.get("rationale") or ""),
        "citations": list(document.get("citations") or []),
        "previous_severity": previous_severity,
        "previous_confidence": previous_confidence,
    }


def apply_outcomes(
    findings: list[dict[str, Any]],
    verdicts: dict[str, ParsedVerdict],
    *,
    roots: dict[str, Any],
    graph: dict[str, Any],
    unanswered: set[str] | None = None,
    unanswered_reason: str = "no answered triage request",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Apply every verdict to ``findings``.

    Returns (kept findings, triage suppressions, decision log entries). Findings
    that were never candidates are not mentioned in ``verdicts`` and pass through
    untouched with no decision entry.
    """
    unanswered = unanswered or set()
    kept: list[dict[str, Any]] = []
    suppressions: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []

    for finding in findings:
        fid = str(finding.get("id", ""))
        if fid not in verdicts:
            kept.append(finding)
            continue

        parsed = verdicts[fid]
        base = {"finding_id": fid, "verdict_attempted": None}
        if fid in unanswered:
            finding.setdefault("triage_unresolved", {"reason": unanswered_reason})
            decisions.append(
                {**base, "outcome": "unanswered", "applied_effect": "none",
                 "reason": unanswered_reason, "citations": []}
            )
            kept.append(finding)
            continue
        if parsed.rejected:
            finding.setdefault("triage_unresolved", {"reason": parsed.reason})
            decisions.append(
                {**base, "outcome": "rejected-malformed", "applied_effect": "none",
                 "reason": parsed.reason, "citations": []}
            )
            kept.append(finding)
            continue

        document = parsed.document or {}
        verdict = str(document.get("verdict", ""))
        base["verdict_attempted"] = verdict
        citations_raw = list(document.get("citations") or [])

        if verdict == "confirmed":
            decisions.append(
                {**base, "outcome": "applied", "applied_effect": "none",
                 "reason": None, "citations": []}
            )
            kept.append(finding)
            continue

        if verdict == "flagged":
            attach_flag(
                finding,
                str(document.get("user_question") or ""),
                hint=document.get("settling_evidence_hint"),
            )
            decisions.append(
                {**base, "outcome": "applied", "applied_effect": "flag-attached",
                 "reason": None, "citations": []}
            )
            kept.append(finding)
            continue

        # refuted / downgraded: evidence gates first, always.
        ok, results = verify_citations(citations_raw, roots=roots, graph=graph)
        decision_citations = [
            {
                "repo": r["repo"],
                "file": r["file"],
                "line_start": r["line_start"],
                "line_end": r["line_end"],
                "verified": r["verified"],
                **({"failures": r["failures"]} if r.get("failures") else {}),
            }
            for r in results
        ]
        if not ok:
            failures = [
                f"{r['file']}: {'; '.join(r.get('failures') or [])}"
                for r in results
                if not r["verified"]
            ]
            attach_flag(
                finding,
                "A proposed refutation/downgrade could not be verified: "
                + str(document.get("rationale") or "")
                + ". Please confirm manually.",
                hint="; ".join(failures)[:300],
            )
            decisions.append(
                {**base, "outcome": "degraded-flagged", "applied_effect": "flag-attached",
                 "reason": "citation re-verification failed", "citations": decision_citations}
            )
            kept.append(finding)
            continue

        if verdict == "refuted":
            suppressions.append(_record_suppression(finding, document, citations_raw))
            decisions.append(
                {**base, "outcome": "applied", "applied_effect": "suppression-added",
                 "reason": None, "citations": decision_citations}
            )
            continue  # excluded from the stream

        # downgraded
        apply_downgrade(finding, document)
        decisions.append(
            {**base, "outcome": "applied", "applied_effect": "grading-adjusted",
             "reason": None, "citations": decision_citations}
        )
        kept.append(finding)

    decisions.sort(key=lambda d: str(d.get("finding_id", "")))
    return kept, suppressions, decisions


def write_decisions(store: Any, decisions: list[dict[str, Any]]) -> None:
    """The auditable decision log (FR-014)."""
    store.write("triage/decisions.json", STAGE, {"decisions": decisions})
