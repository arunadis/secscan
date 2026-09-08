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


# ---------------------------------------------------------------- feature 017
# FR-008 (clarify): one answered question resolves every flag carrying that text.


def test_one_answer_resolves_the_whole_question_group() -> None:
    findings = [
        flagged_finding(fid="SEC-0002", **{}),
        flagged_finding(fid="SEC-0003", file="src/api/users.py"),
        flagged_finding(fid="SEC-0004", file="src/api/reports.py"),
    ]
    answers = apply_declarations([declaration()], findings, [], redactor=Redactor())
    kept, _suppressions, decisions = answers
    by_id = {f["id"]: f for f in kept}
    for fid in ("SEC-0002", "SEC-0003", "SEC-0004"):
        assert "awaiting_verification" not in by_id[fid]
        assert by_id[fid]["triage"]["user_declaration"]
    assert sum(
        1 for d in decisions if d["outcome"] == "applied"
    ) == 3


def test_group_resolution_respects_per_finding_admission() -> None:
    """A credential-class member is refused even when its question group resolves."""
    flagged = flagged_finding(fid="SEC-0005", file="src/config/secrets.py", cwe_id="CWE-798")
    group = [flagged_finding(fid="SEC-0006"), flagged]
    declaration_refute = declaration(resolution="refute")
    kept, suppressions, decisions = apply_declarations(
        [declaration_refute], group, [], redactor=Redactor()
    )
    kept_ids = {f["id"] for f in kept}
    # refute resolution removes the admissible member into the suppression list…
    assert "SEC-0006" not in kept_ids
    assert suppressions
    # …while the credential-class member rides the refusal gate (FR-008 parity) and
    # stays flagged.
    assert "awaiting_verification" in kept[0]
    assert any(d["outcome"] == "rejected-credential-refute" for d in decisions)


def test_different_questions_stay_independent() -> None:
    other = flagged_finding(fid="SEC-0007")
    other["awaiting_verification"]["question"] = "A different question entirely?"
    findings = [flagged_finding(fid="SEC-0008"), other]
    kept, _s, _d = apply_declarations(
        [declaration()], findings, [], redactor=Redactor()
    )
    by_id = {f["id"]: f for f in kept}
    assert "awaiting_verification" not in by_id["SEC-0008"]
    assert "awaiting_verification" in by_id["SEC-0007"]


def test_lapse_when_no_identity_match() -> None:
    moved = flagged_finding(fid="SEC-0009", file="src/moved.py")
    kept, _s, decisions = apply_declarations(
        [declaration()], [moved], [], redactor=Redactor()
    )
    assert "awaiting_verification" in kept[0]
    assert decisions[0]["outcome"] == "declared-lapsed"
