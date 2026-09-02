"""Source enumeration must not scan tooling — least of all the scanner itself."""

from __future__ import annotations

from pathlib import Path

from pipeline.state import is_skipped_dir, iter_source_files


def test_installed_skill_payload_is_not_scanned(tmp_path: Path) -> None:
    """Regression: the scanner analysed its own `.claude/skills/...` payload."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("def main():\n    return 1\n")

    payload = tmp_path / ".claude" / "skills" / "secscan" / "scripts" / "pipeline"
    payload.mkdir(parents=True)
    (payload / "run.py").write_text("# the scanner's own code\n")

    found = [p.relative_to(tmp_path).as_posix() for p in iter_source_files(tmp_path)]
    assert found == ["src/app.py"]


def test_every_agent_skill_directory_is_skipped(tmp_path: Path) -> None:
    from installer.agents import ADAPTERS

    (tmp_path / "app.py").write_text("x = 1\n")
    for adapter in ADAPTERS.values():
        directory = tmp_path.joinpath(*adapter.skills_subdir, "secscan")
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "payload.py").write_text("# payload\n")

    found = [p.relative_to(tmp_path).as_posix() for p in iter_source_files(tmp_path)]
    assert found == ["app.py"]


def test_tooling_and_vcs_directories_are_skipped(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text("package main\n")
    for noise in (
        ".git/config.py",
        ".venv/lib/x.py",
        ".secscan/state.json",
        "node_modules/pkg/index.js",
        "__pycache__/x.py",
        "dist/bundle.js",
        "vendor/dep/lib.go",
        "target/classes/A.java",
    ):
        path = tmp_path / noise
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("noise")

    found = [p.relative_to(tmp_path).as_posix() for p in iter_source_files(tmp_path)]
    assert found == ["main.go"]


def test_dotfiles_are_not_treated_as_source(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / ".env").write_text("SECRET=abc\n")
    (tmp_path / ".gitignore").write_text("*.pyc\n")

    found = [p.name for p in iter_source_files(tmp_path)]
    assert found == ["app.py"]


def test_real_source_directories_are_kept(tmp_path: Path) -> None:
    for keep in ("src/a.py", "lib/b.ts", "internal/c.go", "app/models/d.java"):
        path = tmp_path / keep
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("code")

    found = {p.relative_to(tmp_path).as_posix() for p in iter_source_files(tmp_path)}
    assert found == {"src/a.py", "lib/b.ts", "internal/c.go", "app/models/d.java"}


def test_enumeration_is_deterministic(tmp_path: Path) -> None:
    for name in ("c.py", "a.py", "b.py"):
        (tmp_path / name).write_text("x = 1\n")
    first = iter_source_files(tmp_path)
    assert first == iter_source_files(tmp_path)
    assert [p.name for p in first] == ["a.py", "b.py", "c.py"]


def test_is_skipped_dir_predicate() -> None:
    assert is_skipped_dir(".claude")
    assert is_skipped_dir(".git")
    assert is_skipped_dir("node_modules")
    assert not is_skipped_dir("src")
    assert not is_skipped_dir("payments")


def test_tooling_artifacts_are_never_enumerated(tmp_path: Path) -> None:
    """Feature 008 (FR-012): the scanner ignores its own tooling outputs.

    `.secscan/` is dot-hidden so its tooling artifacts (runs, reports,
    caches) can never enter enumeration, and the same holds for the offline
    audits' manifest walk.
    """
    from pipeline.audits.offline import _iter_manifests

    root = tmp_path / "proj"
    tooling = root / ".secscan" / "tooling"
    tooling.mkdir(parents=True)
    (tooling / "requirements.txt").write_text("pip-audit==2.7.0\n")
    (tooling / "package.json").write_text('{"dependencies": {"osv-scanner": "1.0.0"}}\n')
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("x = 1\n")

    enumerated = [str(p.relative_to(root)) for p in iter_source_files(root)]
    assert enumerated == ["src/app.py"]
    assert list(_iter_manifests(root)) == []

    # and the user-level tooling dir lives outside any scanned project
    import os

    os.environ["SECSCAN_TOOL_DIR"] = str(tmp_path / "user-tools")
    from pipeline.tooling import tool_dir

    assert tool_dir() == tmp_path / "user-tools"
    os.environ.pop("SECSCAN_TOOL_DIR")
