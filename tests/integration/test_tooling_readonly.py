"""Read-only guarantee for init (feature 008, FR-004, SC-002, T017).

Guard, not fail-first: byte-identity holds trivially pre-change and this test
exists to keep it holding. Init legitimately creates ``.secscan/`` — that
is scanner state, established behavior since FR-024 — so the guarantee covers
everything *outside* it: manifests, lockfiles, and sources.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline.init_cmd import run_init
from pipeline.state import SCAN_DIR_NAME, hash_text
from tests.helpers.tool_shims import copy_fixture, install_brew_shim


def _fingerprint(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel.split("/")[0] == SCAN_DIR_NAME:
            continue
        out[rel] = hash_text(path.read_text(errors="replace"))
    return out


@pytest.mark.parametrize("fixture", ["multi_eco", "project_provided"])
def test_init_never_mutates_the_project(fixture, tmp_path, monkeypatch) -> None:
    for mode in ("declined", "no_input", "install_all"):
        root = copy_fixture(fixture, tmp_path / mode)
        bin_dir = tmp_path / mode / "brew-bin"
        install_brew_shim(
            bin_dir,
            mapping={"npm": "npm_audit.json", "semgrep": "semgrep.json"},
        )
        monkeypatch.setenv("PATH", str(bin_dir))

        before = _fingerprint(root)
        if mode == "declined":
            run_init(root, environ={}, prompt=lambda _t: "none")
        elif mode == "no_input":
            run_init(root, environ={}, no_input=True)
        else:
            run_init(root, environ={}, yes=True)
        after = _fingerprint(root)

        assert before == after, f"{fixture}/{mode}: init modified a project file"
