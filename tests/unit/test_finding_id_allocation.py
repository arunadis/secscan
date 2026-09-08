"""Finding-id allocation invariants (single id space for the whole scan).

Duplicate SEC-XXXX ids corrupt everything keyed on them downstream — dedupe's
id ordering, triage verdict binding, the triage resume key. These tests pin:
reserved ids are never reissued, pre-assigned raw ids advance the sequence,
the flow round draws from the scan-wide normalizer, and correlation refuses a
duplicated input instead of silently misapplying verdicts.
"""

from __future__ import annotations

import json

import pytest

from pipeline.budget import TokenBudget
from pipeline.business_flow import FlowRound
from pipeline.correlate_findings import _ensure_unique_ids
from pipeline.llm_client import AnalysisResponse
from pipeline.normalize_findings import FindingNormalizer
from pipeline.usage import UsageTracker


def _raw_finding(**over) -> dict:
    raw = {
        "cwe": "CWE-89",
        "severity_score": 7.0,
        "confidence": 0.9,
        "location": {"repo": "shop", "file": "src/app.py", "line_start": 3},
        "evidence": [{"file": "src/app.py", "reason": "string concatenation into SQL"}],
    }
    raw.update(over)
    return raw


class TestReserveThrough:
    def test_reserved_ids_are_never_reissued(self):
        normalizer = FindingNormalizer()
        assert normalizer.allocate_id() == "SEC-0001"
        normalizer.reserve_through("SEC-0005")
        assert normalizer.allocate_id() == "SEC-0006"

    def test_never_rewinds_below_the_counter(self):
        normalizer = FindingNormalizer()
        normalizer.allocate_id()
        normalizer.allocate_id()
        normalizer.reserve_through("SEC-0001")
        assert normalizer.allocate_id() == "SEC-0003"

    def test_accepts_a_bare_int(self):
        normalizer = FindingNormalizer()
        normalizer.reserve_through(7)
        assert normalizer.allocate_id() == "SEC-0008"

    def test_next_id_reports_the_pending_sequence_number(self):
        normalizer = FindingNormalizer()
        assert normalizer.next_id == 1
        normalizer.allocate_id()
        assert normalizer.next_id == 2

    def test_ids_outside_the_sequence_reserve_nothing(self):
        normalizer = FindingNormalizer()
        normalizer.reserve_through("vendor-tool-42")
        normalizer.reserve_through("not-an-id")
        assert normalizer.allocate_id() == "SEC-0001"


class TestPreassignedIds:
    def test_preassigned_raw_id_steps_the_sequence_over_it(self):
        normalizer = FindingNormalizer()
        assigned = normalizer.normalize([_raw_finding(id="SEC-0010")]).findings
        assert assigned[0]["id"] == "SEC-0010"
        allocated = normalizer.normalize([_raw_finding()]).findings
        assert allocated[0]["id"] == "SEC-0011"

    def test_non_sequence_preassigned_id_keeps_the_counter(self):
        normalizer = FindingNormalizer()
        normalizer.normalize([_raw_finding(id="advisory-GHSA-xxxx")])
        allocated = normalizer.normalize([_raw_finding()]).findings
        assert allocated[0]["id"] == "SEC-0001"


class _FlowClient:
    """Answers every flow request with one seeded gap finding."""

    def run(self, request) -> AnalysisResponse:
        flow = request.payload["flow"]
        repo = flow["steps"][0]["node_id"].split(":", 1)[0]
        return AnalysisResponse(
            request_id=request.id,
            content=json.dumps(
                {
                    "flow_id": flow["id"],
                    "assessment": "gap",
                    "findings": [
                        {
                            "cwe": "CWE-862",
                            "severity_score": 8.0,
                            "confidence": 0.85,
                            "location": {
                                "repo": repo,
                                "file": "src/app.py",
                                "line_start": 9,
                            },
                            "evidence": [
                                {"file": "src/app.py", "reason": "no authorization check"}
                            ],
                            "description": "privileged mutation without a role check",
                            "missing_check": "staff role",
                            "compromise": "attacker invokes the mutation directly",
                        }
                    ],
                }
            ),
            input_tokens=100,
            output_tokens=20,
            model_tier="agent",
        )


_FLOW = {
    "id": "flow:ws:stub1",
    "name": "/x",
    "actor": {"kind": "anonymous", "determination": "inferred"},
    "partial": False,
    "steps": [
        {
            "node_id": "shop:src/app.py#@/x",
            "operation": "entry",
            "annotations": [],
            "data_categories": [],
        }
    ],
}


class TestFlowRoundSharesTheNormalizer:
    def _budget(self) -> TokenBudget:
        return TokenBudget(
            max_context_tokens=100000, max_output_tokens=5000, escalation_threshold=0.75
        )

    def test_passed_normalizer_continues_its_sequence(self):
        shared = FindingNormalizer()
        shared.reserve_through("SEC-0042")
        result = FlowRound(
            client=_FlowClient(),
            usage=UsageTracker(),
            budget=self._budget(),
            normalizer=shared,
        ).run([_FLOW])
        assert result.findings[0]["id"] == "SEC-0043"

    def test_default_normalizer_still_works_standalone(self):
        result = FlowRound(
            client=_FlowClient(), usage=UsageTracker(), budget=self._budget()
        ).run([_FLOW])
        assert result.findings[0]["id"] == "SEC-0001"


class TestDuplicateIdsFailLoudly:
    def test_duplicates_raise_with_the_ids_named(self):
        with pytest.raises(ValueError, match="SEC-0001"):
            _ensure_unique_ids(
                [
                    {"id": "SEC-0001"},
                    {"id": "SEC-0002"},
                    {"id": "SEC-0001"},
                ]
            )

    def test_unique_ids_pass(self):
        assert (
            _ensure_unique_ids([{"id": "SEC-0001"}, {"id": "SEC-0002"}]) is None
        )
