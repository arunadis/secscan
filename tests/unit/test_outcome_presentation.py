"""Feature 017 T010 (US2, report presentation): presence/exposure wording,
folded families, deduped coverage, batched questions."""

from __future__ import annotations

from tests.unit.test_reachability_report import _report, _verified_finding

# -------------------------------------------------------------- helpers


def _format_plausible_finding(band_badges="plausible") -> dict:
    import copy

    from tests.unit.test_family_grouping import BACKEND

    f = copy.deepcopy(BACKEND)
    f["verification"] = {
        "status": "plausible",
        "gap": (
            "reachability unconfirmed: endpoints and security-relevant "
            "operations exist but tracing connected none"
        ),
    }
    f["detection"] = "format"
    return f


# ---------------------------------------------------------- FR-005 wording


def test_presence_proven_format_finding_reads_proven() -> None:
    from pipeline import generate_report

    report = _report([_format_plausible_finding()])
    text = generate_report.render_markdown(report)
    assert "Weakness proven at this location; exposure path unconfirmed" in text


def test_traced_findings_keep_unchanged_rendering() -> None:
    from pipeline import generate_report

    report = _report([_verified_finding("traced")])
    text = generate_report.render_markdown(report)
    assert "Weakness proven at this location" not in text


# --------------------------------------------------- FR-004 family folding


def test_anchor_block_lists_dependents() -> None:
    import copy

    from pipeline import generate_report
    from tests.unit.test_family_grouping import BACKEND, FRONTEND

    backend, frontend = copy.deepcopy(BACKEND), copy.deepcopy(FRONTEND)
    for f in (backend, frontend):
        f["verification"] = {"status": "plausible", "gap": "gap"}
    # correlation-side producer is covered in test_family_grouping; here the
    # renderer is exercised with the links as produced
    backend["relationships"] = [
        {"target_id": "SEC-0003", "type": "related",
         "reason": "same client-asserted identity channel (x-user-email)"}
    ]
    frontend["relationships"] = [
        {"target_id": "SEC-0002", "type": "dependent",
         "reason": "same client-asserted identity channel (x-user-email)"}
    ]
    report = _report([backend, frontend])
    text = generate_report.render_markdown(report)
    assert "part of the SEC-0002 family" in text
    assert "**Related findings**" in text


# --------------------------------------------------- FR-006 coverage dedupe


def test_budget_drops_deduped_across_levels() -> None:
    gaps = [
        (
            "seg-app-p2: 1 file(s) exceeded the 12000-token budget at level 1 "
            "and were analyzed separately or deferred: backend/package-lock.json"
        ),
        (
            "seg-app-p2: 1 file(s) exceeded the 12000-token budget at level 2 "
            "and were analyzed separately or deferred: backend/package-lock.json"
        ),
    ]
    records = [
        {"cause": "budget-dropped", "file": "backend/package-lock.json",
         "segment_id": "seg-app-p2"},
        {"cause": "budget-dropped", "file": "backend/package-lock.json",
         "segment_id": "seg-app-p2"},
    ]
    report = _report([], coverage_overrides={"coverage_gaps": gaps, "gap_records": records})
    lines = report["coverage"]["gaps"]
    assert len(lines) == 1
    assert "(levels" in lines[0]
    assert "levels 1, 2" in lines[0]
    details = report["coverage"]["gap_details"]
    assert len(details) == 1
    from pipeline import generate_report

    text = generate_report.render_markdown(report)
    assert text.count("package-lock.json") <= 3  # exactly one coverage entry


def test_distinct_files_dedupe_nothing() -> None:
    gaps = [
        (
            "seg-p2: 1 file(s) exceeded the 12000-token budget at level 1 "
            "and were analyzed separately or deferred: a/package-lock.json"
        ),
        (
            "seg-p3: 1 file(s) exceeded the 12000-token budget at level 1 "
            "and were analyzed separately or deferred: b/package-lock.json"
        ),
    ]
    report = _report([], coverage_overrides={"coverage_gaps": gaps})
    assert len(report["coverage"]["gaps"]) == 2


# --------------------------------------------- FR-008 question batching


def _awaiting_finding(fid: str, question: str) -> dict:
    f = _verified_finding("traced")
    f["id"] = fid
    f["awaiting_verification"] = {"question": question, "provenance": "triage"}
    return f


def test_identical_questions_collapse_to_one_entry() -> None:
    report = _report(
        [
            _awaiting_finding("SEC-0002", "Is the backend internet-facing?"),
            _awaiting_finding("SEC-0003", "Is the backend internet-facing?"),
            _awaiting_finding("SEC-0004", "Is this local-only?"),
        ]
    )
    entries = report["awaiting_verification"]
    assert len(entries) == 2
    grouped = next(
        e for e in entries if e["question"] == "Is the backend internet-facing?"
    )
    assert set(grouped["finding_ids"]) == {"SEC-0002", "SEC-0003"}


def test_grouped_entry_renders_members_once() -> None:
    from pipeline import generate_report

    report = _report(
        [
            _awaiting_finding("SEC-0002", "Is the backend internet-facing?"),
            _awaiting_finding("SEC-0003", "Is the backend internet-facing?"),
        ]
    )
    text = generate_report.render_markdown(report)
    # one Awaiting entry for both findings (per-finding blocks may restate the
    # question; what must not repeat is the operator-facing answer slot)
    assert "Awaiting Verification (1)" in text
    assert "SEC-0002" in text and "SEC-0003" in text
