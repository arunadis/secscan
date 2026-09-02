"""Spec 007, T039: supply-chain / dependency-confusion evaluation unit tests."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from pipeline import supply_chain
from pipeline.supply_chain import InvalidRuleData


def _root(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return root


VULNERABLE_PACKAGE_JSON = json.dumps(
    {
        "name": "shop",
        "dependencies": {
            "@internal-utils/logging": "^2.0.0",
            "lodash": "latest",
        },
    }
)

HARDENED_PACKAGE_JSON = json.dumps(
    {
        "name": "shop",
        "dependencies": {
            "@internal-utils/logging": "2.0.1",
            "lodash": "4.17.21",
        },
    }
)


def test_internal_namespace_without_guard_is_a_confusion_finding() -> None:
    root = _root({"package.json": VULNERABLE_PACKAGE_JSON})
    findings = supply_chain.run({"svc": root})
    confusion = [
        f
        for f in findings
        if f["tool_ref"] == "supply-chain:npm-scoped-internal-namespace-unprotected"
    ]
    assert confusion
    assert confusion[0]["cwe"] == "CWE-829"
    assert "guard: undetermined" in confusion[0]["evidence"][0]["reason"]


def test_mutable_reference_without_lockfile_is_flagged() -> None:
    root = _root({"package.json": VULNERABLE_PACKAGE_JSON})
    findings = supply_chain.run({"svc": root})
    mutable = [f for f in findings if f["tool_ref"] == "supply-chain:npm-mutable-reference"]
    names = {f["description"].split("package: ")[1].rstrip(")") for f in mutable}
    assert names == {"@internal-utils/logging", "lodash"}
    assert all(f["cwe"] == "CWE-494" for f in mutable)


def test_committed_lockfile_clears_mutable_references() -> None:
    root = _root({"package.json": VULNERABLE_PACKAGE_JSON, "package-lock.json": "{}"})
    findings = supply_chain.run({"svc": root})
    assert not [f for f in findings if f["tool_ref"] == "supply-chain:npm-mutable-reference"]


def test_scope_mapping_and_lockfile_clear_confusion_finding() -> None:
    root = _root(
        {
            "package.json": HARDENED_PACKAGE_JSON,
            "package-lock.json": "{}",
            ".npmrc": "@internal-utils:registry=https://registry.internal.example.test/\n",
        }
    )
    findings = supply_chain.run({"svc": root})
    assert findings == [], (
        f"false positives on hardened manifest: {[f['tool_ref'] for f in findings]}"
    )


def test_exact_versions_with_no_lockfile_are_still_flagged_honestly() -> None:
    # Pinned versions but no lockfile: no *mutable* finding, but confusion stays
    # undetermined - a guard outside the repo is never assumed.
    root = _root({"package.json": HARDENED_PACKAGE_JSON})
    findings = supply_chain.run({"svc": root})
    refs = {f["tool_ref"] for f in findings}
    assert "supply-chain:npm-mutable-reference" not in refs
    assert "supply-chain:npm-scoped-internal-namespace-unprotected" in refs


def test_pypi_requirements_unpinned_and_internal_names() -> None:
    root = _root(
        {
            "requirements.txt": "requests==2.32.3\ninternal-billing\nreqeusts\n"
        }
    )
    findings = supply_chain.run({"svc": root})
    refs = {(f["tool_ref"], f["description"]) for f in findings}
    assert any(
        r == "supply-chain:pypi-mutable-reference" and "internal-billing" in d
        for r, d in refs
    )
    assert any(r == "supply-chain:known-suspicious-package" and "reqeusts" in d for r, d in refs)
    assert any(r == "supply-chain:pypi-internal-namespace-unprotected" for r, _d in refs)
    assert not any("requests==" in d for _r, d in refs), "pinned requirement flagged"


def test_invalid_rule_data_fails_the_build(tmp_path, monkeypatch) -> None:
    bad = {
        "id": "bad",
        "kind": "internal-namespace-unprotected",
        "ecosystems": ["pypi"],
        "pattern": "(broken",
        "cwe": "CWE-829",
        "title": "t",
        "description": "d",
        "recommendation": "r",
    }
    payload = tmp_path / "supply_chain_rules.json"
    payload.write_text(json.dumps({"version": "9", "dataset_date": "x", "rules": [bad]}))
    monkeypatch.setattr(supply_chain.resources, "data_path", lambda _name: payload)
    with pytest.raises(InvalidRuleData):
        supply_chain.load_rules()
