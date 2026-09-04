"""Executable resolution beyond PATH: the Go bin directory fallback.

``go install`` lands binaries in ``$GOBIN`` (default ``$GOPATH/bin``, default
``~/go/bin``), which is not on PATH by default. Discovery, post-install
verification, and execution must all agree on where a Go-provisioned tool is.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline.tooling import locate
from pipeline.tooling.discover import discover_tool
from pipeline.tooling.registry import load_registry
from tests.helpers.tool_shims import install_shims

ENTRIES = {tool.id: tool for tool in load_registry()}


def _go_bin_with(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tools: dict[str, str]) -> Path:
    """A fake $GOBIN holding the given shims, with PATH pointing elsewhere."""
    go_bin = install_shims(tmp_path / "gopath", tools)
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.setenv("GOBIN", str(go_bin))
    return go_bin


# ------------------------------------------------------------------- locate


def test_gobin_env_wins_without_running_go(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))  # no `go` here: env alone decides
    monkeypatch.setenv("GOBIN", str(tmp_path / "gobin"))
    monkeypatch.setenv("GOPATH", str(tmp_path / "gopath"))
    assert locate.go_bin_dir() == tmp_path / "gobin"


def test_gopath_first_entry_bin_when_gobin_unset(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("GOPATH", f"{tmp_path / 'a'}:{tmp_path / 'b'}")
    assert locate.go_bin_dir() == tmp_path / "a" / "bin"


def test_no_go_toolchain_and_no_env_means_no_go_bin_dir(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    assert locate.go_bin_dir() is None
    assert locate.resolve_executable("gitleaks") is None


def test_go_env_is_consulted_when_go_is_present(tmp_path, monkeypatch) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_go = bin_dir / "go"
    fake_go.write_text(f'#!/bin/sh\necho ""\necho "{tmp_path / "from-go-env"}"\n')
    fake_go.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    locate._go_env_bin_dir.cache_clear()

    assert locate.go_bin_dir() == tmp_path / "from-go-env" / "bin"


def test_path_hit_is_returned_unchanged(tmp_path, monkeypatch) -> None:
    bin_dir = install_shims(tmp_path, {"trivy": "trivy.json"})
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("GOBIN", str(tmp_path / "gobin"))
    assert locate.resolve_executable("trivy") == str(bin_dir / "trivy")
    # argv0 stays the bare name when PATH already resolves it
    assert locate.resolved_argv(["trivy", "--version"]) == ["trivy", "--version"]


def test_go_bin_fallback_resolves_and_rewrites_argv0(tmp_path, monkeypatch) -> None:
    go_bin = _go_bin_with(tmp_path, monkeypatch, {"osv-scanner": "osv_crosscheck.json"})
    assert locate.resolve_executable("osv-scanner") == str(go_bin / "osv-scanner")
    assert locate.resolved_argv(["osv-scanner", "--version"]) == [
        str(go_bin / "osv-scanner"), "--version",
    ]


def test_unresolvable_argv0_is_left_for_the_caller_to_report(tmp_path, monkeypatch) -> None:
    _go_bin_with(tmp_path, monkeypatch, {})
    assert locate.resolved_argv(["trivy", "--version"]) == ["trivy", "--version"]


# ---------------------------------------------------------------- discovery


def test_discovery_finds_go_installed_tool_off_path(tmp_path, monkeypatch) -> None:
    go_bin = _go_bin_with(tmp_path, monkeypatch, {"gitleaks": "gitleaks.json"})

    record = discover_tool(tmp_path, ENTRIES["gitleaks"])

    assert record.source == "system-installed"
    assert record.invocation == str(go_bin / "gitleaks")  # absolute: runnable sans PATH
    assert record.version == "0.0.0-fixture"  # probe ran through the resolved path


def test_discovery_keeps_bare_name_for_path_installed_tool(tmp_path, monkeypatch) -> None:
    bin_dir = install_shims(tmp_path, {"gitleaks": "gitleaks.json"})
    monkeypatch.setenv("PATH", str(bin_dir))

    record = discover_tool(tmp_path, ENTRIES["gitleaks"])

    assert record.source == "system-installed"
    assert record.invocation == "gitleaks"
