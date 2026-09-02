"""Project-local + system tool discovery rules (feature 008, FR-003a, T012)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline.tooling.discover import discover_tool
from pipeline.tooling.registry import load_registry
from tests.helpers.tool_shims import install_shims

ENTRIES = {tool.id: tool for tool in load_registry()}


def test_manifest_dep_mechanism_detects_project_local_package(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"devDependencies": {"semgrep": "1.0.0"}}\n'
    )
    bin_dir = tmp_path / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    shim = bin_dir / "semgrep"
    shim.write_text("#!/bin/sh\necho 1.0.0\n")
    shim.chmod(0o755)

    record = discover_tool(tmp_path, ENTRIES["semgrep"])

    assert record.source == "project-provided"
    assert "node_modules" in record.invocation


def test_manifest_plugin_mechanism_detects_maven_plugin_with_wrapper(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project><build><plugins><plugin>"
        "<groupId>org.owasp</groupId><artifactId>dependency-check-maven</artifactId>"
        "</plugin></plugins></build></project>"
    )
    wrapper = tmp_path / "mvnw"
    wrapper.write_text("#!/bin/sh\nexit 1\n")
    wrapper.chmod(0o755)

    record = discover_tool(tmp_path, ENTRIES["owasp-dependency-check"])

    assert record.source == "project-provided"
    assert "./mvnw" in record.invocation


def test_manifest_plugin_without_plugin_falls_back_to_system(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pom.xml").write_text("<project/>")
    bin_dir = install_shims(tmp_path, {"dependency-check.sh": "odc.json"})
    monkeypatch.setenv("PATH", str(bin_dir))

    record = discover_tool(tmp_path, ENTRIES["owasp-dependency-check"])

    assert record.source == "system-installed"
    assert record.version == "0.0.0-fixture"


def test_missing_tool_reports_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))

    record = discover_tool(tmp_path, ENTRIES["trivy"])

    assert record.source == "missing"
    assert record.version is None
    assert record.invocation is None


def test_project_provided_precedence_over_system(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project><build><plugins><plugin>"
        "<groupId>org.owasp</groupId><artifactId>dependency-check-maven</artifactId>"
        "<version>9.0.0</version></plugin></plugins></build></project>"
    )
    bin_dir = install_shims(tmp_path, {"dependency-check.sh": "odc.json"})
    monkeypatch.setenv("PATH", str(bin_dir))

    record = discover_tool(tmp_path, ENTRIES["owasp-dependency-check"])

    assert record.source == "project-provided"
    assert "mvn" in record.invocation  # system mvn fallback: no mvnw in this fixture


def test_undetermined_version_is_declared_not_guessed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A version probe that fails leaves version unset — never assumed."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    broken = bin_dir / "trivy"
    broken.write_text("#!/bin/sh\nexit 1\n")  # fails even for --version
    broken.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))

    record = discover_tool(tmp_path, ENTRIES["trivy"])

    assert record.source == "system-installed"
    assert record.version is None


def test_gradle_plugin_id_rule(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "build.gradle").write_text(
        "plugins { id 'org.owasp.dependencycheck' version '9.0.0' }\n"
    )
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))

    record = discover_tool(tmp_path, ENTRIES["owasp-dependency-check"])

    assert record.source == "project-provided"
    assert "gradle" in record.invocation


def test_discovery_spans_all_members(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A plugin declared in a non-primary member is still project-provided (C1)."""
    svc = tmp_path / "svc"
    web = tmp_path / "web"
    svc.mkdir()
    web.mkdir()
    (web / "package.json").write_text('{"name": "web"}\n')
    (svc / "pom.xml").write_text(
        "<project><build><plugins><plugin>"
        "<groupId>org.owasp</groupId><artifactId>dependency-check-maven</artifactId>"
        "</plugin></plugins></build></project>"
    )
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))

    from pipeline.tooling.discover import discover_roots

    roots = {"web": web, "svc": svc}
    records = {a.tool_id: a for a in discover_roots(roots, list(ENTRIES.values()))}
    assert records["owasp-dependency-check"].source == "project-provided"
    assert records["npm-audit"].source == "missing"
