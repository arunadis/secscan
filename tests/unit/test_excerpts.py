"""005:T014-T016 — redacted code-excerpt extraction.

Contract: specs/005-html-report-code-snippets/contracts/report-artifacts.md and
data-model.md. Every excerpt line is redactor output (Constitution III); a window
the redactor blocks is withheld with a stated reason, never passed through and
never silently absent (FR-008/FR-010).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline.excerpts import build_excerpt, member_roots
from pipeline.redact import BLOCKED, Redactor
from pipeline.state import ArtifactStore

SOURCE_LINES = [f"# line {n} of the module" for n in range(1, 61)]


def _workspace() -> dict:
    return {"id": "ws", "members": [{"name": "shop", "path": "."}]}


def _finding(
    line_start: int = 10,
    line_end: int = 12,
    repo: str = "shop",
    file: str = "src/app.py",
) -> dict:
    return {
        "id": "SEC-0001",
        "location": {
            "repo": repo,
            "file": file,
            "line_start": line_start,
            "line_end": line_end,
            "tier": "symbol",
        },
    }


class _Settings:
    context_lines = 3
    max_lines = 40
    max_line_length = 200


@pytest.fixture
def repo_root(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("\n".join(SOURCE_LINES) + "\n")
    return tmp_path


def _roots(root: Path) -> dict[str, Path]:
    return member_roots(ArtifactStore(root), _workspace())


# ------------------------------------------------------------------ T014


def test_window_includes_cited_lines_plus_context(repo_root: Path) -> None:
    excerpt = build_excerpt(
        _finding(10, 12), roots=_roots(repo_root), settings=_Settings(), redactor=Redactor()
    )
    assert excerpt["status"] == "ok"
    assert (excerpt["window_start"], excerpt["window_end"]) == (7, 15)
    assert (excerpt["cited_start"], excerpt["cited_end"]) == (10, 12)
    numbers = [line["number"] for line in excerpt["lines"]]
    assert numbers == list(range(7, 16))
    cited = [line["number"] for line in excerpt["lines"] if line["cited"]]
    assert cited == [10, 11, 12]
    assert excerpt["lines"][0]["text"] == "# line 7 of the module"
    assert excerpt["language"] == "python"


def test_window_clamps_at_file_boundaries(repo_root: Path) -> None:
    excerpt = build_excerpt(
        _finding(1, 2), roots=_roots(repo_root), settings=_Settings(), redactor=Redactor()
    )
    assert excerpt["window_start"] == 1
    excerpt = build_excerpt(
        _finding(59, 60), roots=_roots(repo_root), settings=_Settings(), redactor=Redactor()
    )
    assert excerpt["window_end"] == 60


def test_window_capped_at_max_lines_context_reduced_first(repo_root: Path) -> None:
    class Tight:
        context_lines = 3
        max_lines = 8  # full window would be 9 (cited 3 + context 6), so context shrinks
        max_line_length = 200

    excerpt = build_excerpt(
        _finding(20, 22), roots=_roots(repo_root), settings=Tight(), redactor=Redactor()
    )
    assert excerpt["window_end"] - excerpt["window_start"] + 1 <= 8
    numbers = [line["number"] for line in excerpt["lines"] if line["cited"]]
    assert numbers == [20, 21, 22], "cited range is always fully included"
    assert excerpt["truncated"] is True


def test_cited_range_larger_than_cap_is_kept_and_flagged(repo_root: Path) -> None:
    excerpt = build_excerpt(
        _finding(10, 55), roots=_roots(repo_root), settings=_Settings(), redactor=Redactor()
    )
    cited = [line["number"] for line in excerpt["lines"] if line["cited"]]
    assert cited == list(range(10, 56))
    assert excerpt["truncated"] is True


def test_long_lines_are_truncated_with_flag(repo_root: Path) -> None:
    (repo_root / "src" / "app.py").write_text("x = 1\n" + "y = '" + "a" * 500 + "'\n")
    excerpt = build_excerpt(
        _finding(1, 2), roots=_roots(repo_root), settings=_Settings(), redactor=Redactor()
    )
    long_line = next(line for line in excerpt["lines"] if line["number"] == 2)
    assert long_line["truncated"] is True
    assert len(long_line["text"]) <= 200
    assert excerpt["truncated"] is True


# ------------------------------------------------------------------ T015


def test_excerpt_text_is_redactor_output(repo_root: Path) -> None:
    (repo_root / "src" / "app.py").write_text(
        'DB_PASSWORD = "Pr0d-Sh0p-DB-2024!"\n' + "\n".join(SOURCE_LINES[:10]) + "\n"
    )
    excerpt = build_excerpt(
        _finding(1, 1), roots=_roots(repo_root), settings=_Settings(), redactor=Redactor()
    )
    assert excerpt["status"] == "ok"
    secret_line = next(line for line in excerpt["lines"] if line["number"] == 1)
    assert "Pr0d-Sh0p-DB-2024!" not in secret_line["text"]
    assert "[REDACTED:" in secret_line["text"]


def test_blocked_window_is_withheld_with_reason(repo_root: Path) -> None:
    # A bare high-entropy run with no identifier segments and no credential
    # context: the redactor blocks it rather than classifying it.
    (repo_root / "src" / "app.py").write_text(
        "data = (\n    'kX9vB2mN8qR4tY7uI1oP5aS3dF6gH'\n)\n"
    )
    redactor = Redactor()
    probe = redactor.redact((repo_root / "src" / "app.py").read_text())
    assert probe.blocked > 0 and BLOCKED in probe.text, "fixture must trigger a block"

    excerpt = build_excerpt(
        _finding(1, 3), roots=_roots(repo_root), settings=_Settings(), redactor=redactor
    )
    assert excerpt["status"] == "unavailable"
    assert "could not be confirmed as a non-credential" in excerpt["reason"]
    assert "lines" not in excerpt


# ------------------------------------------------------------------ T016


def test_missing_file_yields_unavailable_with_reason(repo_root: Path) -> None:
    excerpt = build_excerpt(
        _finding(file="src/gone.py"),
        roots=_roots(repo_root),
        settings=_Settings(),
        redactor=Redactor(),
    )
    assert excerpt["status"] == "unavailable"
    assert "not found" in excerpt["reason"]
    assert "lines" not in excerpt


def test_unknown_repo_yields_unavailable_with_reason(repo_root: Path) -> None:
    excerpt = build_excerpt(
        _finding(repo="ghost"), roots=_roots(repo_root), settings=_Settings(), redactor=Redactor()
    )
    assert excerpt["status"] == "unavailable"
    assert "ghost" in excerpt["reason"]


def test_build_excerpt_never_raises_on_io_errors(repo_root: Path) -> None:
    path = repo_root / "src" / "app.py"
    path.write_text("irrelevant = True\n")
    path.chmod(0)  # unreadable
    try:
        excerpt = build_excerpt(
            _finding(1, 1), roots=_roots(repo_root), settings=_Settings(), redactor=Redactor()
        )
    finally:
        path.chmod(0o644)
    assert excerpt["status"] == "unavailable"
    assert excerpt["reason"]
