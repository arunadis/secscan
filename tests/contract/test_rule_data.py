"""T012/T041: rule-data and additive-schema contracts (D1, D4).

Rule packs ship as versioned data; the contract is what makes "extensibility as
data" true: invalid data fails the build, not the scan.
"""

from __future__ import annotations

from pipeline.schemas import is_valid, validate


def test_misconfig_rule_data_is_valid() -> None:
    """D1: unique ids, compiling patterns, catalogue CWEs."""
    from pipeline import misconfig

    rules = misconfig.load_rules()
    assert rules, "misconfig_rules.json shipped no rules"
    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    for rule in rules:
        assert rule["file_globs"] and rule["pattern"] and rule["recommendation"]


def test_adding_a_rule_is_data_only() -> None:
    """D1: a rule absent from code is still evaluated — data drives behaviour."""
    from pipeline import misconfig

    rules = misconfig.load_rules()
    sentinel = {
        "id": "contract-sentinel",
        "stacks": ["jvm"],
        "file_globs": ["**/*.java"],
        "pattern": r"ContractSentinel\.marker\(\)",
        "cwe": "CWE-1188",
        "severity_score": 4.0,
        "title": "Contract sentinel",
        "description": "Proves rules evaluate from data alone.",
        "recommendation": "Remove the marker.",
    }
    findings = misconfig.evaluate_files(
        {"src/Main.java": "class Main { void f() { ContractSentinel.marker(); } }"},
        repo="test",
        rules=[*rules, sentinel],
    )
    assert any(f["tool_ref"] == "misconfig:contract-sentinel" for f in findings)


def test_compound_rule_data_is_valid() -> None:
    """D2: unique ids, known leg kinds, catalogue CWEs."""
    from pipeline import compound

    rules = compound.load_rules()
    assert rules, "compound_rules.json shipped no rules"
    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    for rule in rules:
        assert rule["legs"], f"{rule['id']}: a compound rule needs at least one leg"


def test_report_schema_accepts_gap_details_additively() -> None:
    """D4: gap_details is optional and structured; legacy gaps strings unchanged."""
    report = _minimal_report()
    validate("report", report)
    report["coverage"]["gap_details"] = [
        {
            "cause": "blocked-value",
            "file": "src/main/java/com/example/WebSecurityConfig.java",
            "segment_id": "seg-1",
            "security_critical": True,
            "impact": "security-config rules could not be assessed over 1 blocked line",
        }
    ]
    validate("report", report)
    report["coverage"]["gap_details"][0]["cause"] = "mysterious"
    assert not is_valid("report", report)


def _minimal_report() -> dict:
    """Smallest schema-valid report (coverage included)."""
    return {
        "scan_id": "s",
        "execution_mode": "agent-mediated",
        "profile": {"name": "full"},
        "workspace": {"id": "w", "members": ["shop"]},
        "executive_summary": "s",
        "findings_by_band": {},
        "coverage": {
            "repos_analyzed": ["shop"],
            "segments_analyzed": 1,
            "clean": False,
            "gaps": ["seg-1: legacy string form"],
            "resolution_tiers": {"symbol": 0, "file": 0, "rejected": 0},
        },
        "usage": _empty_usage(),
    }


def _empty_usage() -> dict:
    return {
        "total_input_tokens": 0,
        "total_output_tokens": 0,
        "invocations": 0,
        "by_stage": {},
    }
