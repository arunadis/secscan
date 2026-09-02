"""Contract test for the external-tool registry (feature 008, FR-001).

Asserts the schema pinned in specs/008/contracts/data-contracts.md §1. The
registry is shipped versioned data: these rules are the stability contract, so
adding a tool must stay a data change that passes here without pipeline edits.
"""

from __future__ import annotations

import re

import pytest

from pipeline.tooling import registry
from pipeline.tooling.registry import KNOWN_LOCKFILES, load_registry

VALID_KINDS = {"sast", "secrets", "iac", "dependency-audit"}
VALID_NETWORK = {"none", "on-first-use", "per-run"}
VALID_MECHANISMS = {"manifest-dep", "manifest-plugin", "bin-path", "wrapper"}
KNOWN_ECOSYSTEMS = {"npm", "pypi", "maven", "go", "any"}


@pytest.fixture(scope="module")
def tools():
    return load_registry()


def test_registry_has_version(tools) -> None:
    assert isinstance(tools, tuple) and tools, "registry must contain entries"


def test_ids_are_unique(tools) -> None:
    ids = [tool.id for tool in tools]
    assert len(ids) == len(set(ids)), "tool ids must be unique"


def test_required_fields_present(tools) -> None:
    for tool in tools:
        assert tool.id and tool.display_name, "id and display_name are required"
        assert tool.kind in VALID_KINDS, f"{tool.id}: unknown kind {tool.kind!r}"
        assert tool.network in VALID_NETWORK, f"{tool.id}: unknown network {tool.network!r}"
        assert tool.report_format in {"json", "sarif"}, (
            f"{tool.id}: unknown report format {tool.report_format!r}"
        )
        assert tool.timeout_s > 0, f"{tool.id}: timeout must be positive"
        assert tool.invoke.get("argv"), f"{tool.id}: invoke.argv is required"
        assert set(tool.ecosystems) <= KNOWN_ECOSYSTEMS, (
            f"{tool.id}: unknown ecosystems {tool.ecosystems!r}"
        )


def test_dependency_audit_entries_cover_ecosystems(tools) -> None:
    for tool in tools:
        if tool.kind == "dependency-audit":
            assert tool.covers_ecosystems, (
                f"{tool.id}: dependency-audit entries must declare covers_ecosystems"
            )
            assert set(tool.covers_ecosystems) <= set(tool.ecosystems), (
                f"{tool.id}: covers_ecosystems must be a subset of ecosystems"
            )


def test_lockfile_requirements_reference_known_lockfiles(tools) -> None:
    for tool in tools:
        lockfile = tool.invoke.get("requires_lockfile")
        if lockfile:
            assert lockfile in KNOWN_LOCKFILES, (
                f"{tool.id}: requires_lockfile names unknown lockfile {lockfile!r}"
            )


def test_project_local_mechanisms_are_closed(tools) -> None:
    for tool in tools:
        for rule in tool.project_local:
            assert rule["mechanism"] in VALID_MECHANISMS, (
                f"{tool.id}: unknown project_local mechanism {rule['mechanism']!r}"
            )


def test_expected_tools_present(tools) -> None:
    ids = {tool.id for tool in tools}
    assert {
        "semgrep",
        "gitleaks",
        "osv-scanner",
        "trivy",
        "npm-audit",
        "pip-audit",
        "govulncheck",
        "owasp-dependency-check",
    } <= ids


# ---------------------------------------------------------------- feature 009
# Credential block contract (contracts/init-nvd-credential.md §3): optional,
# additive, but strictly validated when present.

_ENV_VAR_SHAPE = re.compile(r"[A-Z][A-Z0-9_]*")


def test_credential_block_optional_and_shaped(tools) -> None:
    """Entries without a credential block load unchanged; a block is strict."""
    with_credential = [tool for tool in tools if tool.credential is not None]
    assert with_credential, "expected at least owasp-dependency-check to declare one"
    for tool in with_credential:
        assert _ENV_VAR_SHAPE.fullmatch(tool.credential.env_var), (
            f"{tool.id}: env_var is not an uppercase env-name: "
            f"{tool.credential.env_var!r}"
        )
        assert tool.credential.obtain_url.startswith("https://"), (
            f"{tool.id}: obtain_url must be an https URL"
        )
        assert tool.credential.absence_impact.strip(), (
            f"{tool.id}: absence_impact must be non-empty"
        )
    # only NVD-backed tools carry the block
    assert {t.id for t in with_credential} == {"owasp-dependency-check"}


def test_dependency_check_declares_nvd_key(tools) -> None:
    odc = next(tool for tool in tools if tool.id == "owasp-dependency-check")
    assert odc.credential is not None
    assert odc.credential.env_var == "NVD_API_KEY"
    assert odc.credential.obtain_url == (
        "https://nvd.nist.gov/developers/request-an-api-key"
    )


def _base_document() -> dict:
    # otherwise-fully-valid entry, so failures below are credential-specific
    return {
        "registry_version": 1,
        "tools": [
            {
                "id": "demo",
                "display_name": "Demo",
                "kind": "sast",
                "ecosystems": ["any"],
                "network": "per-run",
                "report_format": "json",
                "invoke": {"argv": ["demo", "{project}"]},
            }
        ],
    }


def test_base_document_is_valid() -> None:
    assert registry._validate(_base_document()) == []


def test_malformed_credential_blocks_are_rejected() -> None:
    doc = _base_document
    cases = [
        {"credential": {"obtain_url": "https://x.test", "absence_impact": "slow"}},
        {"credential": {"env_var": "NVD_API_KEY", "absence_impact": "slow"}},
        {
            "credential": {
                "env_var": "nvd_api_key",  # lowercase: not an env-name shape
                "obtain_url": "https://x.test",
                "absence_impact": "slow",
            }
        },
        {
            "credential": {
                "env_var": "NVD_API_KEY",
                "obtain_url": "http://x.test",  # not https
                "absence_impact": "slow",
            }
        },
        {
            "credential": {
                "env_var": "NVD_API_KEY",
                "obtain_url": "https://x.test",
                "absence_impact": "  ",  # whitespace-only
            }
        },
        {"credential": "NVD_API_KEY"},
    ]
    for extra in cases:
        document = doc()
        document["tools"][0].update(extra)
        problems = registry._validate(document)
        assert problems, f"credential block must be rejected: {extra}"
