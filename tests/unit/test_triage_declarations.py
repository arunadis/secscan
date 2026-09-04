"""T025: user-declared answers to triage flags (contracts/report-and-decisions.md §4).

Lifecycle under test: strict loading, identity + question matching (line drift
tolerated), application with user-declared provenance, lapse on mismatch,
credential-refute rejection, reversibility, answer cap and sweep.
"""

from __future__ import annotations

import pytest

from pipeline.redact import Redactor
from pipeline.triage_apply import attach_flag
from pipeline.triage_declarations import (
    DeclarationError,
    apply_declarations,
    declarations_key,
    load_declarations,
)
from tests.unit.test_triage_apply import make_finding


class FakeStore:
    def __init__(self, payload=None) -> None:
        self.payload = payload

    def read_optional(self, _path):
        return self.payload


def declaration(**extra) -> dict:
    return {
        "finding_ref": {"repo": "shop", "file": "src/api/admin.py", "cwe": "CWE-862"},
        "question": "Is this endpoint reachable without the filter?",
        "answer": "No — internal batch only.",
        "resolution": "downgrade",
        **extra,
    }


def flagged_finding(**kwargs) -> dict:
    finding = make_finding(**kwargs)
    attach_flag(finding, "Is this endpoint reachable without the filter?")
    return finding


# --------------------------------------------------------------- loading


def test_absent_file_means_no_declarations() -> None:
    assert load_declarations(FakeStore(None)) == []


def test_valid_file_loads() -> None:
    store = FakeStore({"schema_version": 1, "declarations": [declaration()]})
    assert len(load_declarations(store)) == 1


@pytest.mark.parametrize(
    "payload",
    [
        ["not-a-mapping"],
        {"schema_version": 2, "declarations": []},
        {"schema_version": 1},  # missing list
        {"schema_version": 1, "declarations": [declaration(surprise=True)]},
        {"schema_version": 1, "declarations": [declaration(resolution="erase")]},
        {"schema_version": 1, "declarations": [declaration(answer="x" * 2001)]},
        {
            "schema_version": 1,
            "declarations": [declaration(finding_ref={"repo": "shop", "cwe": "CWE-862"})],
        },
    ],
)
def test_malformed_files_are_rejected_strictly(payload) -> None:
    with pytest.raises(DeclarationError):
        load_declarations(FakeStore(payload))


# --------------------------------------------------------------- matching


def test_downgrade_applies_with_provenance() -> None:
    finding = flagged_finding()
    kept, suppressions, decisions = apply_declarations(
        [declaration()], [finding], [], redactor=Redactor()
    )
    assert suppressions == []
    assert "awaiting_verification" not in kept[0]
    triage = kept[0]["triage"]
    assert triage["verdict"] == "downgraded"
    assert triage["user_declaration"] == {
        "answer": "No — internal batch only.",
        "resolution": "downgrade",
    }
    assert decisions[0]["verdict_attempted"] == "user-declared-downgrade"
    assert decisions[0]["applied_effect"] == "grading-adjusted"
    assert kept[0]["severity_score"] < 8.2


def test_refute_removes_with_user_declared_suppression() -> None:
    finding = flagged_finding()
    kept, suppressions, decisions = apply_declarations(
        [declaration(resolution="refute", answer="This route is internal-only.")],
        [finding],
        [],
        redactor=Redactor(),
    )
    assert kept == []
    assert len(suppressions) == 1
    assert suppressions[0]["provenance"] == "user-declared"
    assert decisions[0]["applied_effect"] == "suppression-added"


def test_identity_and_question_both_gate(flags=None) -> None:
    # Wrong file → lapse; wrong question wording → lapse.
    for mismatch in (
        declaration(finding_ref={"repo": "shop", "file": "src/other.py", "cwe": "CWE-862"}),
        declaration(question="Is this endpoint reachable?"),  # dropped "without the filter"
    ):
        finding = flagged_finding()
        kept, suppressions, decisions = apply_declarations(
            [mismatch], [finding], [], redactor=Redactor()
        )
        assert kept == [finding] and suppressions == []
        assert kept[0].get("awaiting_verification")
        assert decisions[0]["outcome"] == "declared-lapsed"


def test_line_drift_is_tolerated() -> None:
    finding = flagged_finding(line=44)  # moved since the declaration was written
    kept, _, decisions = apply_declarations(
        [declaration()], [finding], [], redactor=Redactor()
    )
    assert decisions[0]["outcome"] == "applied"


def test_symbol_refinement_mismatches_lapse() -> None:
    finding = flagged_finding()  # no symbol
    kept, _, decisions = apply_declarations(
        [declaration(finding_ref={"repo": "shop", "file": "src/api/admin.py",
                                  "cwe": "CWE-862", "symbol": "other_handler"})],
        [finding],
        [],
        redactor=Redactor(),
    )
    assert decisions[0]["outcome"] == "declared-lapsed"
    assert kept == [finding]


def test_credential_refute_is_rejected() -> None:
    finding = flagged_finding(cwe_id="CWE-798")
    kept, suppressions, decisions = apply_declarations(
        [declaration(
            finding_ref={"repo": "shop", "file": "src/api/admin.py", "cwe": "CWE-798"},
            resolution="refute",
        )],
        [finding],
        [],
        redactor=Redactor(),
    )
    assert kept == [finding] and suppressions == []
    assert kept[0].get("awaiting_verification")
    assert decisions[0]["outcome"] == "rejected-credential-refute"


def test_answer_sweep_rejects_credential_shaped_text() -> None:
    finding = flagged_finding()
    kept, _, decisions = apply_declarations(
        [declaration(answer='it equals "AKIAIOSFODNN7EXAMPLE" trust me')],
        [finding],
        [],
        redactor=Redactor(),
    )
    assert decisions[0]["outcome"] == "rejected-declaration"
    assert "awaiting_verification" in kept[0]


def test_unflagged_finding_means_lapse() -> None:
    finding = make_finding()  # no flag attached
    kept, _, decisions = apply_declarations(
        [declaration()], [finding], [], redactor=Redactor()
    )
    assert decisions[0]["outcome"] == "declared-lapsed"
    assert "triage" not in kept[0]


def test_declarations_key_changes_with_content() -> None:
    assert declarations_key([declaration()]) != declarations_key(
        [declaration(answer="Different answer.")]
    )
    assert declarations_key([]) != declarations_key([declaration()])
