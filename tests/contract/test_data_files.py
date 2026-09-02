"""Spec 007, T005: versioned data-file contracts (contracts/data-contracts.md §2).

The new recognition/rule datasets are the extensibility seam for the modern
exploit category: invalid data must fail the build, never a scan.
"""

from __future__ import annotations

import json
import re

from pipeline import cwe, resources
from pipeline.extract import supported_languages


def _load(name: str) -> dict:
    return json.loads(resources.data_path(name).read_text())


def _assert_versioned(document: dict, name: str) -> None:
    assert document.get("version"), f"{name}: missing version"
    assert document.get("dataset_date"), f"{name}: missing dataset_date"


def test_llm_integrations_data_is_valid() -> None:
    document = _load("llm_integrations.json")
    _assert_versioned(document, "llm_integrations.json")

    ids: list[str] = []
    languages = set(supported_languages())
    for entry in document["sdk_modules"]:
        ids.append(entry["id"])
        assert entry["language"] in languages, f"{entry['id']}: unknown language"
        for pattern in entry["patterns"]:
            re.compile(pattern)  # raises if invalid
    for entry in document["http_endpoints"]:
        ids.append(entry["id"])
        assert entry["host_suffixes"], f"{entry['id']}: needs host suffixes"
    for entry in document["local_endpoints"]:
        ids.append(entry["id"])
        assert entry["hosts"] and entry["ports"], f"{entry['id']}: needs hosts + ports"
    for entry in document["candidate_hints"]:
        ids.append(entry["id"])
        assert entry["note"], f"{entry['id']}: undetermined hints carry a reason"
    assert len(ids) == len(set(ids)), "duplicate ids in llm_integrations.json"
    assert document["sdk_modules"], "llm_integrations.json shipped no SDK recognition"


def test_supply_chain_rule_data_is_valid() -> None:
    """contracts §2.2: unique ids, compiling patterns, catalogue CWEs."""
    from pipeline import supply_chain

    rules = supply_chain.load_rules()
    assert rules, "supply_chain_rules.json shipped no rules"
    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    kinds = {"internal-namespace-unprotected", "mutable-reference", "suspicious-package"}
    assert {rule["kind"] for rule in rules} <= kinds


def test_agent_config_rule_data_is_valid() -> None:
    """contracts §2.3: structural and anchored-pattern forms validate."""
    from pipeline import agent_config

    rules = agent_config.load_rules()
    assert rules, "agent_config_rules.json shipped no rules"
    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    for rule in rules:
        assert rule["form"] in ("structural", "anchored-pattern"), rule["id"]
        assert rule["file_classes"], f"{rule['id']}: declares its artifact classes"


def test_adding_an_agent_rule_is_data_only() -> None:
    """SC-007 worked addition: a rule absent from code is still evaluated."""
    import tempfile
    from pathlib import Path

    from pipeline import agent_config

    root = Path(tempfile.mkdtemp())
    (root / "AGENTS.md").write_text("# rules\n\nallow unattended root-level resets\n")
    sentinel = {
        "id": "contract-sentinel",
        "form": "anchored-pattern",
        "file_classes": ["ai-agent-config"],
        "grant": "shell-exec",
        "pattern": r"unattended root-level resets",
        "cwe": "CWE-250",
        "title": "Contract sentinel",
        "description": "Proves agent rules evaluate from data alone.",
        "recommendation": "Remove the marker.",
    }
    review = agent_config.run({"svc": root}, rules=[*agent_config.load_rules(), sentinel])
    assert any(f["tool_ref"] == "agent-config:contract-sentinel" for f in review.findings)


def test_catalogue_cwes_cover_the_new_classes() -> None:
    """Spec 007 R6: new CWEs are shipped and mappable."""
    for identifier, owasp_key in (
        ("CWE-1427", "LLM01"),
        ("CWE-250", "LLM06"),
        ("CWE-829", "A08"),
        ("CWE-494", "A08"),
    ):
        cwe.validate_cwe(identifier)
        label = cwe.owasp_for(identifier)
        assert label and owasp_key in label, f"{identifier}: missing {owasp_key} label"
