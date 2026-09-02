"""T021: compound cross-file findings (FR-004, FR-005, FR-006; contract D2).

Compound rules evaluate deterministic whole-repo evidence legs; a finding
publishes only when every leg is evidenced or its absence proven — with the
searched space recorded. An undetermined leg downgrades, never suppresses.
"""

from __future__ import annotations

import json

from tests.fixtures.missed_detection_sites import SITES


def _evaluate(site: str):
    from pipeline import compound

    return compound.evaluate_files(SITES[site], repo="test")


def _by_rule(findings, rule_id):
    return [f for f in findings if f["tool_ref"] == f"compound:{rule_id}"]


def test_graphql_depth_dos_publishes_with_all_legs_evidenced() -> None:
    """D2: permitAll endpoint + cyclic schema + proven-absent depth config."""
    findings = _by_rule(_evaluate("compound_graphql_dos"), "graphql-depth-dos")
    assert findings, "graphql-depth-dos did not fire"
    finding = findings[0]
    assert finding["cwe"] == "CWE-400"
    rendered = json.dumps(finding["evidence"])
    # Each leg's evidence is present, with locations.
    assert "endpoint-unauthenticated" in rendered
    assert "graphql-schema-cycle" in rendered
    assert "config-absent" in rendered
    assert "WebSecurityConfig.java" in rendered
    assert "schema.graphqls" in rendered
    # The absence claim names the searched space (FR-005).
    assert "searched" in rendered


def test_depth_limit_config_retracts_the_finding() -> None:
    """D2: a configured depth limit anywhere in the search space retracts it."""
    findings = _by_rule(_evaluate("compound_graphql_dos_retracted"), "graphql-depth-dos")
    assert findings == []


def test_seeded_shared_password_publishes_without_values() -> None:
    """D2 + Principle III: migration + public login; no password value emitted."""
    findings = _by_rule(_evaluate("compound_seed_data"), "seeded-shared-password")
    assert findings, "seeded-shared-password did not fire"
    finding = findings[0]
    assert finding["cwe"] == "CWE-1391"
    rendered = json.dumps(finding)
    assert "password123" not in rendered
    assert "N9qo8uLOickgx2ZMRZoMyeIjRZGaa" not in rendered
    assert "V2__seed_data.sql" in rendered
    assert "AuthController.java" in rendered


def test_undetermined_leg_downgrades_and_names_itself() -> None:
    """D2/Principle V: an unevaluatable leg is published, not silent, not proven."""
    findings = _by_rule(
        _evaluate("compound_seed_data_unparsed_login"), "seeded-shared-password"
    )
    assert findings, "an undetermined leg must not suppress the finding"
    finding = findings[0]
    assert "public-auth-entrypoint" in json.dumps(finding)
    assert "undetermined" in json.dumps(finding)
    # Never claims proof: the finding must not present itself as verified.
    assert (finding.get("verification") or {}).get("status") != "verified"


def test_adding_a_rule_binding_existing_leg_kinds_is_data_only() -> None:
    """D2: a new rule over existing leg kinds needs no code change."""
    from pipeline import compound

    rules = compound.load_rules()
    sentinel = {
        "id": "contract-compound-sentinel",
        "cwe": "CWE-1188",
        "severity_score": 4.0,
        "title": "Contract compound sentinel",
        "summary": "Proves rules bind leg kinds from data.",
        "recommendation": "Remove the marker.",
        "legs": [
            {"kind": "seeded-credential-pattern", "params": {}},
        ],
    }
    findings = compound.evaluate_files(
        SITES["compound_seed_data"], repo="test", rules=[*rules, sentinel]
    )
    assert _by_rule(findings, "contract-compound-sentinel")


def test_schema_parser_handles_field_arguments() -> None:
    """Field args carry their own colons (`first: Int`); the return type follows."""
    from pipeline.extract.graphql_schema import find_cycles, parse_schema

    schema = (
        "type Article {\n"
        "  comments(first: Int, after: String): CommentsConnection\n"
        "}\n"
        "type CommentsConnection {\n"
        "  edges: [CommentEdge]\n"
        "}\n"
        "type CommentEdge {\n"
        "  node: Comment\n"
        "}\n"
        "type Comment {\n"
        "  article: Article\n"
        "}\n"
    )
    refs = parse_schema(schema)
    assert refs["Article"] == ["CommentsConnection"]
    cycles = find_cycles(refs)
    assert any("Article" in cycle and "Comment" in cycle for cycle in cycles)
