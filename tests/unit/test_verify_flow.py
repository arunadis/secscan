"""T018: path-based verification verdicts for flow findings (feature 015, FR-017)."""

from __future__ import annotations

from pipeline.verify import Verifier

GRAPH = {"nodes": [], "edges": []}


def _flow(partial=False, actor="declared", annotations_per_step=None) -> dict:
    annotations_per_step = annotations_per_step or [[], [], []]
    return {
        "id": "flow:ws:abc123",
        "name": "/order/start",
        "actor": {"kind": "anonymous", "determination": actor},
        "partial": partial,
        "gap_reasons": ["integration-undeclared"] if partial else [],
        "steps": [
            {
                "node_id": f"shop:src/app.py#step{index}",
                "operation": operation,
                "annotations": annotations_per_step[index],
                "data_categories": [],
            }
            for index, operation in enumerate(("entry", "transition", "mutation"))
        ],
    }


def _finding(missing_check="staff role", file="src/app.py") -> dict:
    return {
        "id": "SEC-1001",
        "cwe": "CWE-862",
        "location": {"repo": "shop", "file": file, "line_start": 1, "line_end": 1},
        "flow_ref": "flow:ws:abc123",
        "flow_narrative": {
            "name": "/order/start",
            "steps": [{"node_id": "shop:src/app.py#step0"}],
            "missing_check": missing_check,
            "compromise": "shopper gains staff pricing",
        },
    }


class TestFlowVerdicts:
    def test_verified_when_check_absent_and_flow_determined(self):
        verifier = Verifier(GRAPH, [], business_flows={"flows": [_flow()]})
        verdict = verifier.verify(_finding())
        assert verdict.status == "verified"
        assert verdict.path  # the traversable step path is attached

    def test_disproven_when_check_is_present(self):
        gated = _flow(
            annotations_per_step=[[], ["authorization_required"], []]
        )
        verifier = Verifier(GRAPH, [], business_flows={"flows": [gated]})
        verdict = verifier.verify(_finding())
        assert verdict.status == "disproven"

    def test_plausible_when_flow_partial(self):
        verifier = Verifier(
            GRAPH, [], business_flows={"flows": [_flow(partial=True)]}
        )
        verdict = verifier.verify(_finding())
        assert verdict.status == "plausible"
        assert "integration-undeclared" in verdict.gap

    def test_plausible_when_actor_undetermined(self):
        verifier = Verifier(
            GRAPH, [], business_flows={"flows": [_flow(actor="undetermined")]}
        )
        verdict = verifier.verify(_finding())
        assert verdict.status == "plausible"
        assert "actor-undetermined" in verdict.gap

    def test_plausible_when_flow_reference_missing(self):
        verifier = Verifier(GRAPH, [], business_flows={"flows": []})
        verdict = verifier.verify(_finding())
        assert verdict.status == "plausible"
        assert "absent from the flow model" in verdict.gap

    def test_identity_gap_disproven_by_authentication(self):
        gated = _flow(annotations_per_step=[["authentication_required"], [], []])
        verifier = Verifier(GRAPH, [], business_flows={"flows": [gated]})
        verdict = verifier.verify(_finding(missing_check="identity of the caller"))
        assert verdict.status == "disproven"

    def test_role_gap_not_disproven_by_authentication_alone(self):
        gated = _flow(annotations_per_step=[["authentication_required"], [], []])
        verifier = Verifier(GRAPH, [], business_flows={"flows": [gated]})
        verdict = verifier.verify(_finding(missing_check="staff role"))
        # authentication establishes identity, not role: the role gap stands
        assert verdict.status == "verified"

    def test_privileged_step_pinned_by_location(self):
        verifier = Verifier(GRAPH, [], business_flows={"flows": [_flow()]})
        verdict = verifier.verify(_finding(file="does/not/exist.py"))
        # Falls back to the flow's last effective operation, still a path verdict.
        assert verdict.status == "verified"
        assert verdict.path


class TestHonestRanking:
    def test_unproven_never_outranks_proven(self):
        """FR-010 / analysis finding C2: plausible must rank below verified, even at
        a higher raw severity/confidence."""
        from pipeline.generate_report import rank_key

        proven = {"id": "SEC-1", "verification": {"status": "verified"},
                  "severity_score": 5.0, "confidence": 0.5}
        unproven = {"id": "SEC-2", "verification": {"status": "plausible"},
                    "severity_score": 9.0, "confidence": 1.0}
        assert rank_key(proven) < rank_key(unproven)
