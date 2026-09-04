"""External-tool findings are scoped to the scanned source tree.

Whole-tree scanners walk ``.secscan/``, ``.git``, ``node_modules`` ... which
the repository model skips; findings there are dropped and surviving paths are
made project-relative so artifacts never embed the checkout location.
"""

from __future__ import annotations

from pathlib import Path

from pipeline.adapters.common import code_finding
from pipeline.tooling.execute import scope_to_project


def _finding(file: str) -> dict:
    return code_finding(
        "shop", file=file, line=3, cwe_id="CWE-798", severity="high",
        message="m", tool="gitleaks", rule="r",
    )


def test_artifacts_and_skipped_dirs_are_dropped(tmp_path: Path) -> None:
    root = tmp_path / "shop"
    findings = [
        _finding(str(root / ".secscan" / "state.json")),
        _finding(str(root / ".git" / "config")),
        _finding(str(root / "node_modules" / "x" / "index.js")),
        _finding(str(root / "src" / "api.py")),
        _finding("config/settings.py"),
    ]
    kept = scope_to_project(findings, root)
    assert [f["location"]["file"] for f in kept] == ["src/api.py", "config/settings.py"]
    assert kept[0]["evidence"][0]["file"] == "src/api.py"


def test_paths_outside_the_project_are_dropped(tmp_path: Path) -> None:
    root = tmp_path / "shop"
    kept = scope_to_project([_finding(str(tmp_path / "other" / "a.py"))], root)
    assert kept == []


def test_dotfiles_at_top_level_are_kept(tmp_path: Path) -> None:
    """Only skipped *directories* are excluded: a top-level ``.env`` is source."""
    root = tmp_path / "shop"
    kept = scope_to_project([_finding(str(root / ".env"))], root)
    assert [f["location"]["file"] for f in kept] == [".env"]
