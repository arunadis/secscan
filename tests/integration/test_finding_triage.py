"""Feature 013 integration: the triage round over a full scan (T016/T022/T026).

Fixture and scripted answers live in ``tests/fixtures/triage_targets.py`` —
ground truth is declared there, next to the code that produces it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.run import run_scan
from tests.fixtures.triage_targets import (
    DECLARATION_QUESTION,
    DEV_TOKEN_FLAG,
    FABRICATED_REFUTAL,
    REFUTING_ANSWER,
    build_repo,
    scripted_responder,
)
from tests.integration.conftest import write_config


@pytest.fixture
def scanned_refuted(tmp_path: Path) -> tuple[Path, object]:
    root = tmp_path
    member = build_repo(root)
    write_config(member)
    result = run_scan(member, responder=scripted_responder(REFUTING_ANSWER), full=True)
    return root, result


def test_refuted_finding_leaves_the_report_body(scanned_refuted) -> None:
    _root, result = scanned_refuted
    # The credential finding (credential class is never refutable) stays; the
    # CWE-862 one is suppressed.
    assert {f["cwe"] for f in result.reported_findings} == {"CWE-798"}
    suppressions = result.report.get("suppressions") or []
    assert len(suppressions) == 1
    assert suppressions[0]["disproof_ground"] == "triage-control-present"
    assert suppressions[0]["tool_id"] == "triage"
    assert any(
        "RoleAuthorizationFilter" in line for line in suppressions[0]["evidence"]
    )


def test_decision_log_records_the_refutation(scanned_refuted) -> None:
    root, _result = scanned_refuted
    decisions = json.loads(
        (root / "shop" / ".secscan" / "triage" / "decisions.json").read_text()
    )["payload"]["decisions"]
    refuted = next(d for d in decisions if d["verdict_attempted"] == "refuted")
    assert refuted["outcome"] == "applied"
    assert refuted["applied_effect"] == "suppression-added"
    assert all(c["verified"] for c in refuted["citations"])
    # The credential finding was only confirmable — FR-008 holds end to end.
    confirmed = next(d for d in decisions if d["verdict_attempted"] == "confirmed")
    assert confirmed["outcome"] == "applied" and confirmed["applied_effect"] == "none"


def test_markdown_report_shows_the_suppression(scanned_refuted) -> None:
    _root, result = scanned_refuted
    text = result.report_path.read_text()
    assert "triage-control-present" in text
    assert "Suppressed" in text


def test_rerun_with_persisted_answers_is_byte_identical(scanned_refuted) -> None:
    """SC-005: a plain re-run replays triage outcomes byte-identically.

    The usage section describes *this run's* invocations (cached answers are
    never counted — feature 012 rule), so it legitimately differs between a fresh
    scan and a resumed one; everything else must match.
    """
    root, first = scanned_refuted
    first_text = first.report_path.read_text()
    second = run_scan(root / "shop", responder=scripted_responder())
    assert second.report_path.read_text().split("## Usage & Cost")[0] == first_text.split(
        "## Usage & Cost"
    )[0]
    decisions_text = (root / "shop" / ".secscan" / "triage" / "decisions.json").read_text()
    assert '"outcome": "applied"' in decisions_text
    assert (second.report.get("suppressions") or []) == (first.report.get("suppressions") or [])


def test_unanswerable_round_keeps_findings_and_declares_gap(tmp_path: Path) -> None:
    member = build_repo(tmp_path)
    write_config(member)
    result = run_scan(
        member,
        responder=scripted_responder(triage_answer=lambda _request: "not json"),
        full=True,
    )
    assert len(result.reported_findings) == 2  # one code + one credential finding
    coverage_note = " ".join(result.report["coverage"].get("gaps", []))
    assert result.report["coverage"]["triage"]["enabled"] is True
    assert result.report["coverage"]["triage"]["adjudicated"] == 0
    assert "not adjudicated" in coverage_note
    assert all(f.get("triage_unresolved") for f in result.findings)


def test_verified_downgrade_regrades_with_provenance(tmp_path: Path) -> None:
    member = build_repo(tmp_path)
    write_config(member)
    result = run_scan(
        member,
        responder=scripted_responder(
            {
                "only_cwe": "CWE-862",
                "verdict": "downgraded",
                "rationale": (
                    "The destructive handler is batch-only; RoleAuthorizationFilter "
                    "blocks interactive callers, limiting practical impact."
                ),
                "citations": [REFUTING_ANSWER["citations"][0]],
            }
        ),
        full=True,
    )
    adjusted = next(f for f in result.reported_findings if f["cwe"] == "CWE-862")
    assert adjusted["triage"]["verdict"] == "downgraded"
    # Severity strictly falls (calibration may already have capped it; the check
    # is previous > current, not a hardcoded number).
    previous = adjusted["triage"]["previous_severity"]
    assert adjusted["severity_score"] < previous
    assert adjusted["confidence"] <= adjusted["triage"]["previous_confidence"]
    # Still reported — a downgrade is not a suppression (FR-011).
    assert not (result.report.get("suppressions") or [])


def test_failed_citation_never_suppresses(tmp_path: Path) -> None:
    member = build_repo(tmp_path)
    write_config(member)
    result = run_scan(
        member,
        responder=scripted_responder(FABRICATED_REFUTAL),
        full=True,
    )
    assert len(result.reported_findings) == 2
    assert not (result.report.get("suppressions") or [])
    awaiting = result.report.get("awaiting_verification") or []
    assert len(awaiting) == 1
    assert "could not be verified" in awaiting[0]["question"]


# ------------------------------------------------------- declaration loop (US3)


def test_declaration_round_trip(tmp_path: Path) -> None:
    """US3: flag → declaration resolves with provenance → removal re-flags."""
    member = build_repo(tmp_path)
    write_config(member)

    first = run_scan(member, responder=scripted_responder(DEV_TOKEN_FLAG), full=True)
    awaiting = first.report.get("awaiting_verification") or []
    assert len(awaiting) == 1
    assert awaiting[0]["question"] == DECLARATION_QUESTION
    token_finding = next(f for f in first.findings if f["cwe"] == "CWE-798")
    assert "triage" not in token_finding  # flagging changes nothing (FR-012)

    # The operator records the answer and re-runs (a plain run — the declaration
    # content joins the stage resume key, so the round re-runs).
    scan_dir = member / ".secscan"
    (scan_dir / "triage").mkdir(exist_ok=True)
    (scan_dir / "triage" / "declarations.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "declarations": [
                    {
                        "finding_ref": {
                            "repo": "shop",
                            "file": "src/dev/auth.py",
                            "cwe": "CWE-798",
                        },
                        "question": DECLARATION_QUESTION,
                        "answer": "Dev-compose only; the gateway rejects it externally.",
                        "resolution": "downgrade",
                    }
                ],
            }
        )
    )
    second = run_scan(member, responder=scripted_responder(DEV_TOKEN_FLAG))
    resolved = next(f for f in second.findings if f["cwe"] == "CWE-798")
    assert not second.report.get("awaiting_verification")
    assert resolved["triage"]["user_declaration"]["resolution"] == "downgrade"
    assert "user-declared" in resolved["triage"]["rationale"]
    assert resolved["severity_score"] < token_finding["severity_score"]

    # Reversibility: removing the declaration restores the flag on the next scan.
    (scan_dir / "triage" / "declarations.json").unlink()
    third = run_scan(member, responder=scripted_responder(DEV_TOKEN_FLAG))
    awaiting3 = third.report.get("awaiting_verification") or []
    assert len(awaiting3) == 1
    restored = next(f for f in third.findings if f["cwe"] == "CWE-798")
    assert "user_declaration" not in restored.get("triage", {})


def test_triage_round_batches_through_provider(monkeypatch, tmp_path: Path) -> None:
    """Quickstart 3c: in endpoint-batch mode the triage round is one batch round
    with byte-identical packet content (the batch/interactive parity rule),
    and the verified refutation suppresses through it."""
    from tests.helpers.fake_provider import FakeProvider, Scenario

    monkeypatch.setenv("TRIAGE_FAKE_KEY", "sk-fake")
    member = build_repo(tmp_path)
    write_config(
        member,
        {
            "llm": {
                "endpoint": {
                    "provider": "anthropic",
                    "api_key_env": "TRIAGE_FAKE_KEY",
                    "model_map": {"local": "m-local", "segment": "m-segment"},
                }
            }
        },
    )

    def answer(custom_id: str, payload: dict) -> str:
        if "finding" in payload:  # triage packet shape
            fid = payload["finding"]["id"]
            if payload["finding"]["cwe"] == "CWE-862":
                body = dict(REFUTING_ANSWER)
                body.pop("only_cwe", None)
                body["finding_id"] = fid
                return json.dumps(body)
            return json.dumps({"finding_id": fid, "verdict": "confirmed"})
        if payload.get("source") and any("admin.py" in p for p in payload["source"]):
            from tests.fixtures.triage_targets import segment_findings

            return segment_findings(str(payload.get("repo") or "shop"))
        return json.dumps({"findings": []})

    now = {"t": 1_700_000_000.0}

    def sleep(seconds: float) -> None:
        now["t"] += seconds

    provider = FakeProvider("anthropic", Scenario(polls_until_ended=1), answer=answer)
    result = run_scan(
        member,
        transport=provider,
        full=True,
        clock=lambda: now["t"],
        sleep=sleep,
    )
    assert provider.batch_submissions == 2  # one segment round, one triage round
    suppressions = result.report.get("suppressions") or []
    assert any(s["disproof_ground"] == "triage-control-present" for s in suppressions)
    assert {f["cwe"] for f in result.reported_findings} == {"CWE-798"}
    assert result.report["coverage"]["triage"]["adjudicated"] == 2


def test_lapsed_declaration_never_suppresses(tmp_path: Path) -> None:
    """A declaration for a question this run didn't ask is recorded as lapsed."""
    member = build_repo(tmp_path)
    write_config(member)
    scan_dir = member / ".secscan"
    (scan_dir / "triage").mkdir(exist_ok=True)
    (scan_dir / "triage" / "declarations.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "declarations": [
                    {
                        "finding_ref": {
                            "repo": "shop",
                            "file": "src/dev/auth.py",
                            "cwe": "CWE-798",
                        },
                        "question": "An outdated question no longer asked.",
                        "answer": "whatever",
                        "resolution": "refute",
                    }
                ],
            }
        )
    )
    result = run_scan(member, responder=scripted_responder(DEV_TOKEN_FLAG), full=True)
    assert {f["cwe"] for f in result.reported_findings} == {"CWE-798", "CWE-862"}
    assert not (result.report.get("suppressions") or [])
