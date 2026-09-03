"""T016: schema conformance contract tests (contracts/finding-schema.md, artifact-schemas.md)."""

from __future__ import annotations

import copy

import pytest

from pipeline import cwe
from pipeline.schemas import SCHEMA_DIR, SchemaError, is_valid, validate

# --------------------------------------------------------------- golden docs


def valid_finding() -> dict:
    return {
        "id": "SEC-0001",
        "cwe": "CWE-89",
        "owasp_top10": "A03:2021 Injection",
        "severity_score": 9.8,
        "severity_band": "Critical",
        "confidence": 0.92,
        "location": {
            "repo": "shop",
            "file": "src/orders/repository.py",
            "symbol": "find_by_id",
            "line_start": 41,
            "line_end": 48,
        },
        "description": "User-controlled id is concatenated into a SQL statement.",
        "evidence": [
            {
                "repo": "shop",
                "file": "src/orders/repository.py",
                "symbol": "find_by_id",
                "reason": "f-string interpolation into cursor.execute",
            }
        ],
        "attack_scenario": "Attacker supplies `1 OR 1=1` to enumerate all orders.",
        "impact": "Full read access to the orders table.",
        "recommendation": "Use parameterized queries.",
        "source": "analysis",
        "status": "reported",
        "verification": {"status": "verified", "path": ["shop:api#get_order", "shop:db#execute"]},
        "reproduction": {
            "preconditions": "Any authenticated user session.",
            "trigger": "GET /orders/CANARY-1%20OR%201%3D1 against a local deployment",
            "expected_behavior": "Request rejected or scoped to the caller's own orders.",
            "observed_behavior": "Returns orders belonging to other users.",
            "evidence_trail": ["src/orders/repository.py:41"],
            "target_scope": "local/test",
        },
    }


def valid_workspace() -> dict:
    return {
        "id": "ws-demo",
        "source": "manifest",
        "members": [
            {"name": "orders", "path": "../orders"},
            {"name": "payments", "path": "../pay"},
        ],
        "integrations": [
            {
                "from_repo": "orders",
                "to_repo": "payments",
                "type": "sync-api",
                "endpoints_or_channels": ["POST /payments"],
                "trust_boundary": True,
                "declared": True,
                "confidence": 1.0,
            }
        ],
    }


def valid_manifest() -> dict:
    return {
        "repository": "shop",
        "languages": ["python"],
        "frameworks": ["flask"],
        "modules": [{"name": "orders", "path": "src/orders", "file_count": 4}],
        "entrypoints": [{"symbol": "get_order", "kind": "http", "route": "GET /orders/<id>"}],
        "databases": ["orders_db"],
        "external_services": [],
    }


def valid_code_graph() -> dict:
    return {
        "nodes": [
            {
                "id": "shop:src/orders/api.py#get_order",
                "repo": "shop",
                "type": "function",
                "path": "src/orders/api.py",
                "symbol": "get_order",
                "language": "python",
                "line_start": 10,
                "line_end": 20,
                "annotations": ["user_controlled_input", "trust_boundary"],
            }
        ],
        "edges": [
            {
                "from": "shop:src/orders/api.py#get_order",
                "to": "shop:src/orders/repository.py#find_by_id",
                "type": "calls",
                "cross_repo": False,
                "resolution": "name-based",
            }
        ],
    }


def valid_segment() -> dict:
    return {
        "id": "seg-orders",
        "name": "Orders",
        "repos": ["shop"],
        "purpose": "Order retrieval and listing",
        "domains": ["injection", "authorization"],
        "entrypoints": ["GET /orders/<id>"],
        "files": ["src/orders/api.py", "src/orders/repository.py"],
        "dependencies": ["orders_db"],
        "data_stores": ["orders_db"],
        "estimated_tokens": 900,
    }


def valid_context_packet() -> dict:
    return {
        "segment_id": "seg-orders",
        "escalation_level": 1,
        "purpose": "Order retrieval and listing",
        "domains": ["injection"],
        "entrypoints": ["GET /orders/<id>"],
        "call_graph_summary": "get_order -> find_by_id -> execute",
        "data_flows": [
            {
                "source": "GET /orders/<id> id",
                "transforms": ["str"],
                "validations": [],
                "sink": "cursor.execute",
                "crosses_repo": False,
            }
        ],
        "security_relevant_symbols": ["get_order", "find_by_id"],
        "source": {"src/orders/api.py": "def get_order(id): ..."},
        "token_budget": {
            "max_context_tokens": 12000,
            "max_output_tokens": 3000,
            "escalation_threshold": 0.75,
        },
        "estimated_tokens": 900,
        "redaction": {
            "applied": True,
            "redacted_items": 0,
            "blocked_items": 0,
            "rules_version": "1",
        },
    }


def valid_usage() -> dict:
    return {
        "total_input_tokens": 1200,
        "total_output_tokens": 300,
        "invocations": 3,
        "by_stage": {
            "segment_analysis": {
                "input_tokens": 1200,
                "output_tokens": 300,
                "invocations": 3,
            }
        },
    }


GOLDEN = {
    "finding": valid_finding,
    "workspace": valid_workspace,
    "manifest": valid_manifest,
    "code_graph": valid_code_graph,
    "segment": valid_segment,
    "context_packet": valid_context_packet,
    "usage": valid_usage,
}


# -------------------------------------------------------------------- tests


def test_every_schema_file_loads() -> None:
    names = sorted(p.stem for p in SCHEMA_DIR.glob("*.json"))
    assert names, "no schemas found"
    for name in names:
        assert is_valid(name, GOLDEN[name]()) if name in GOLDEN else True


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_golden_documents_validate(name: str) -> None:
    validate(name, GOLDEN[name]())


@pytest.mark.parametrize(
    ("mutation", "expect_in_message"),
    [
        ({"id": "BAD-1"}, "id"),
        ({"cwe": "89"}, "cwe"),
        ({"severity_score": 11.5}, "severity_score"),
        ({"severity_band": "Severe"}, "severity_band"),
        ({"confidence": 1.7}, "confidence"),
        ({"evidence": []}, "evidence"),
        ({"source": "guesswork"}, "source"),
        ({"status": "maybe"}, "status"),
    ],
)
def test_invalid_findings_are_rejected(mutation: dict, expect_in_message: str) -> None:
    doc = valid_finding()
    doc.update(mutation)
    with pytest.raises(SchemaError) as exc:
        validate("finding", doc)
    assert expect_in_message in str(exc.value)


def test_finding_rejects_unknown_fields() -> None:
    """Free-form output must not sneak through as extra keys (FR-013)."""
    doc = valid_finding()
    doc["freeform_notes"] = "the model wanted to add prose here"
    with pytest.raises(SchemaError):
        validate("finding", doc)


@pytest.mark.parametrize("field", ["preconditions", "expected_behavior"])
def test_reproduction_requires_unconditional_parts(field: str) -> None:
    """These two hold regardless of what the pipeline managed to establish."""
    doc = valid_finding()
    del doc["reproduction"][field]
    with pytest.raises(SchemaError):
        validate("finding", doc)


def test_reproduction_pre_002_block_still_validates() -> None:
    """Backward compatibility: a block written before feature 002 carries no `mode`.

    The delta relaxes `trigger`/`observed_behavior` from unconditionally required to
    conditional, so artifacts from the previous tool version must keep validating
    (contracts/schema-deltas.md "assert both directions").
    """
    doc = valid_finding()
    doc["reproduction"] = {
        "preconditions": "A local deployment with a seeded dataset.",
        "trigger": "Send `GET /orders/1` with the canary value.",
        "expected_behavior": "The input is parameterized.",
        "observed_behavior": "The canary reaches the SQL parser.",
        "evidence_trail": ["shop:api#get_order", "shop:db#execute"],
        "target_scope": "local/test",
    }
    validate("finding", doc)


def test_reproduction_observed_mode_requires_an_observation() -> None:
    """FR-008: `observed` may not be claimed without the observation itself."""
    doc = valid_finding()
    doc["reproduction"] = {
        "preconditions": "p",
        "expected_behavior": "e",
        "mode": "observed",
        "trigger": "t",
        "target_scope": "local/test",
    }
    with pytest.raises(SchemaError):
        validate("finding", doc)


def test_reproduction_hypothesis_mode_requires_outcome_to_check() -> None:
    """FR-008: an unverified finding states what to check, not what was seen."""
    doc = valid_finding()
    doc["reproduction"] = {
        "preconditions": "p",
        "expected_behavior": "e",
        "mode": "hypothesis",
        "trigger": "t",
        "target_scope": "local/test",
    }
    with pytest.raises(SchemaError):
        validate("finding", doc)

    doc["reproduction"]["outcome_to_check"] = "Check whether the canary is escaped."
    validate("finding", doc)


def test_reproduction_omitted_trigger_requires_a_reason() -> None:
    """FR-010: no achievable probe is a statable fact, not a silent omission."""
    doc = valid_finding()
    doc["reproduction"] = {
        "preconditions": "p",
        "expected_behavior": "e",
        "mode": "hypothesis",
        "outcome_to_check": "c",
        "target_scope": "local/test",
    }
    with pytest.raises(SchemaError):
        validate("finding", doc)

    doc["reproduction"]["trigger_omitted_reason"] = (
        "The value is interpolated after a fixed scheme and host, so no probe "
        "targeting another origin can succeed."
    )
    validate("finding", doc)


def test_reproduction_target_scope_is_pinned() -> None:
    """FR-030: reproduction steps target a local/test deployment only."""
    doc = valid_finding()
    doc["reproduction"]["target_scope"] = "production"
    with pytest.raises(SchemaError):
        validate("finding", doc)


def test_verification_status_enum() -> None:
    doc = valid_finding()
    doc["verification"]["status"] = "rejected"  # lifecycle value, not a verdict
    with pytest.raises(SchemaError):
        validate("finding", doc)
    for status in ("verified", "plausible", "disproven"):
        ok = copy.deepcopy(doc)
        ok["verification"]["status"] = status
        validate("finding", ok)


def test_context_packet_must_declare_redaction_applied() -> None:
    """FR-006a: packets are only valid once redaction has run."""
    doc = valid_context_packet()
    doc["redaction"]["applied"] = False
    with pytest.raises(SchemaError):
        validate("context_packet", doc)


def _exemption(decision: str) -> dict:
    return {
        "origin": "migration/p0/verify-account.sh",
        "line": 47,
        "rule": "assigned-secret",
        "classification": "runtime-reference:shell-bare",
        "reason": "every letter and digit lies inside a well-formed reference",
        "decision": decision,
    }


def test_context_packet_accepts_exempt_reference_decision() -> None:
    """Feature 010, contract R5: additive enum member, no schema_version bump."""
    doc = valid_context_packet()
    doc["redaction"]["exempted_items"] = [_exemption("exempt-reference")]
    validate("context_packet", doc)


def test_context_packet_rejects_exempt_location_decision() -> None:
    """exempt-location arises only in reproduction text and never reaches a packet."""
    doc = valid_context_packet()
    doc["redaction"]["exempted_items"] = [_exemption("exempt-location")]
    with pytest.raises(SchemaError):
        validate("context_packet", doc)


def test_workspace_requires_at_least_one_member() -> None:
    doc = valid_workspace()
    doc["members"] = []
    with pytest.raises(SchemaError):
        validate("workspace", doc)


def test_integration_types_are_the_four_classes() -> None:
    doc = valid_workspace()
    doc["integrations"][0]["type"] = "carrier-pigeon"
    with pytest.raises(SchemaError):
        validate("workspace", doc)


def test_schema_error_lists_every_problem() -> None:
    doc = valid_finding()
    doc["id"] = "nope"
    doc["confidence"] = 3.0
    doc["severity_score"] = -1
    with pytest.raises(SchemaError) as exc:
        validate("finding", doc)
    assert len(exc.value.errors) >= 3


def test_severity_band_derivation_matches_schema_enum() -> None:
    """finding-schema rule 1: band is derived from the score."""
    assert cwe.band_for(9.8) == "Critical"
    assert cwe.band_for(7.0) == "High"
    assert cwe.band_for(6.9) == "Medium"
    assert cwe.band_for(0.5) == "Low"
    assert cwe.band_for(0.0) == "None"


def test_cwe_dataset_validation_rejects_unknown_ids() -> None:
    """finding-schema rule 2: no hallucinated CWE ids."""
    assert cwe.validate_cwe("CWE-89") == "CWE-89"
    with pytest.raises(cwe.UnknownCWE):
        cwe.validate_cwe("CWE-999999")


def test_cwe_dataset_has_owasp_and_domain_coverage() -> None:
    for identifier in sorted(cwe.known_cwes()):
        assert cwe.owasp_for(identifier), f"{identifier} missing OWASP mapping"
        assert cwe.domain_for(identifier), f"{identifier} missing domain"
        assert 0.0 <= cwe.default_severity(identifier) <= 10.0


# ------------------------------------------- feature 002 additive schema deltas
#
# T010. Every delta is additive, so these assert BOTH directions: new documents
# validate, and a document captured before feature 002 still validates. That pair
# is what keeps `schema_version` at "1" honest.


def test_location_resolution_tier_accepted() -> None:
    """FR-003a: a reported finding declares how strongly its location is known."""
    doc = valid_finding()
    doc["location"]["tier"] = "symbol"
    doc["location"]["alternatives_existed"] = True
    doc["location"]["chosen_by"] = "same-repo definition"
    validate("finding", doc)

    doc["location"]["tier"] = "file"
    doc["location"]["symbol_confirmed"] = False
    validate("finding", doc)

    doc["location"]["tier"] = "guessed"
    with pytest.raises(SchemaError):
        validate("finding", doc)


def test_pre_002_finding_still_validates() -> None:
    """Backward compatibility: no tier, no mode, no new blocks."""
    doc = valid_finding()
    for key in ("reclassification", "applicability", "framework_control", "calibration"):
        doc.pop(key, None)
    doc["location"].pop("tier", None)
    validate("finding", doc)


def test_reclassification_block() -> None:
    """FR-016/FR-017: the remap is recorded, reason included."""
    doc = valid_finding()
    doc["reclassification"] = {
        "original_cwe": "CWE-918",
        "new_cwe": "CWE-116",
        "original_severity": 4.3,
        "new_severity": 2.0,
        "reason": "no server-side request issuer is reachable from this location",
    }
    validate("finding", doc)

    del doc["reclassification"]["reason"]
    with pytest.raises(SchemaError):
        validate("finding", doc)


def test_applicability_block_allows_a_third_state() -> None:
    """FR-015c: 'undetermined' is a first-class value, not a missing boolean."""
    doc = valid_finding()
    for value in (True, False, "undetermined"):
        doc["applicability"] = {"applicable": value, "reason": "r"}
        validate("finding", doc)

    doc["applicability"] = {"applicable": "maybe"}
    with pytest.raises(SchemaError):
        validate("finding", doc)


def test_framework_control_states_and_bypass_site() -> None:
    """FR-022: a bypass carries a location; 'unassessed' is distinct from 'absent'."""
    doc = valid_finding()
    for state in ("credited", "bypassed", "absent", "unassessed"):
        doc["framework_control"] = {"state": state}
        validate("finding", doc)

    doc["framework_control"] = {
        "state": "bypassed",
        "control": "angular-dom-sanitizer",
        "bypass_site": {
            "repo": "shop",
            "file": "src/app/unsafe.ts",
            "line_start": 12,
            "line_end": 12,
        },
    }
    validate("finding", doc)

    doc["framework_control"] = {"state": "not-a-state"}
    with pytest.raises(SchemaError):
        validate("finding", doc)


def test_calibration_records_why_severity_changed() -> None:
    """FR-020: the cap and its reason are visible in the finding."""
    doc = valid_finding()
    doc["calibration"] = {
        "proposed_severity": 6.1,
        "proposed_confidence": 0.85,
        "caps_applied": [
            {"rule": "plausible-unconfirmed-reachability", "reason": "no external source traced"}
        ],
    }
    validate("finding", doc)

    doc["calibration"]["caps_applied"] = [{"rule": "x"}]
    with pytest.raises(SchemaError):
        validate("finding", doc)


def test_dependency_finding_shape() -> None:
    """FR-030b/FR-030f: exposure and attribution are required, never implied."""
    doc = valid_finding()
    doc["source"] = "dependency-audit"
    doc["dependency"] = {
        "package": "lodash",
        "ecosystem": "npm",
        "affected_range": "<4.17.21",
        "fixed_version": "4.17.21",
        "advisory_ids": ["GHSA-35jh-r3h4-6jhm"],
        "exposure": "runtime",
        "affected_members": ["web", "admin"],
        "attribution": "per-member",
    }
    validate("finding", doc)

    doc["dependency"]["attribution"] = "guessed"
    with pytest.raises(SchemaError):
        validate("finding", doc)

    doc["dependency"]["attribution"] = "workspace-not-derivable"
    validate("finding", doc)

    del doc["dependency"]["exposure"]
    with pytest.raises(SchemaError):
        validate("finding", doc)


def test_code_graph_file_tier_node_shape() -> None:
    """FR-003c: an unparsed file is representable, and only at file granularity."""
    validate(
        "code_graph",
        {
            "nodes": [
                {
                    "id": "shop:lib/legacy.rb",
                    "repo": "shop",
                    "type": "file",
                    "path": "lib/legacy.rb",
                    "language": "ruby",
                    "parsed": False,
                    "file_class": "source",
                }
            ],
            "edges": [],
        },
    )


def test_code_graph_template_sink_and_renders_edge() -> None:
    """FR-025: a template binding is a sink linked back to its data source."""
    validate(
        "code_graph",
        {
            "nodes": [
                {
                    "id": "web:src/app/comment.html#innerHTML",
                    "repo": "web",
                    "type": "template",
                    "path": "src/app/comment.html",
                    "format": "html",
                    "file_class": "template",
                    "annotations": ["template_sink"],
                }
            ],
            "edges": [
                {
                    "from": "web:src/app/api.ts#fetch",
                    "to": "web:src/app/comment.html#innerHTML",
                    "type": "renders",
                }
            ],
        },
    )


def test_code_graph_rejects_unknown_annotation() -> None:
    assert not is_valid(
        "code_graph",
        {
            "nodes": [
                {
                    "id": "a:b",
                    "repo": "a",
                    "type": "file",
                    "path": "b",
                    "annotations": ["totally_made_up"],
                }
            ],
            "edges": [],
        },
    )


def test_architecture_profile_requires_evidence_or_a_reason() -> None:
    """FR-013b: a recorded shape reflects positive evidence; unknown says why."""
    validate(
        "architecture_profile",
        {
            "scope": "member",
            "shape": "browser-client",
            "evidence": ["no server entry points; static build output"],
        },
    )
    validate(
        "architecture_profile",
        {
            "scope": "segment",
            "shape": "undetermined",
            "undetermined_reason": "no recognizable manifest markers",
        },
    )
    with pytest.raises(SchemaError):
        validate("architecture_profile", {"scope": "member", "shape": "browser-client"})
    with pytest.raises(SchemaError):
        validate("architecture_profile", {"scope": "member", "shape": "undetermined"})


def _empty_usage() -> dict:
    """Minimal conforming usage block (usage.schema.json required fields)."""
    return {
        "total_input_tokens": 0,
        "total_output_tokens": 0,
        "invocations": 0,
        "by_stage": {},
    }


def test_report_coverage_extensions() -> None:
    """FR-029/FR-033: coverage separates represented, unparsed, and not attempted."""
    coverage = {
        "repos_analyzed": ["web"],
        "segments_analyzed": 3,
        "file_classes": [
            {
                "file_class": "template",
                "represented": 4,
                "unparsed": [{"path": "a.vue", "format": "vue", "reason": "no parser"}],
                "not_attempted": [],
            }
        ],
        "audit_outcomes": [
            {
                "member": "web",
                "ecosystem": "npm",
                "status": "could-not-check",
                "reason": "registry unreachable",
                "remediation_command": "npm audit --json --omit=dev",
            }
        ],
        "resolution_tiers": {"symbol": 5, "file": 2, "rejected": 1},
        "blocking_gaps": ["dependency domain unassessed for member 'web'"],
    }
    assert is_valid(
        "report",
        {
            "scan_id": "s",
            "workspace": {"id": "w", "members": ["web"]},
            "execution_mode": "agent-mediated",
            "profile": {"name": "full"},
            "executive_summary": "summary",
            "findings_by_band": {},
            "coverage": coverage,
            "usage": _empty_usage(),
        },
    )
    coverage["audit_outcomes"][0]["status"] = "probably-fine"
    assert not is_valid(
        "report",
        {
            "scan_id": "s",
            "workspace": {"id": "w", "members": ["web"]},
            "execution_mode": "agent-mediated",
            "profile": {"name": "full"},
            "executive_summary": "summary",
            "findings_by_band": {},
            "coverage": coverage,
            "usage": _empty_usage(),
        },
    )
