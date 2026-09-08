"""Feature 017 T014 (US2, FR-007) + T010 tail: tool-limitation reasons describe
the artifact's state, not a filesystem guess."""

from __future__ import annotations

from pathlib import Path

from pipeline.tooling.execute import _lockfile_skip_reason


def test_member_root_lockfile_absent_absent_everywhere_says_absent(tmp_path: Path) -> None:
    assert _lockfile_skip_reason(tmp_path, "package-lock.json") == (
        "requires package-lock.json, which this project does not have"
    )


def test_nested_lockfile_is_present_but_out_of_scope(tmp_path: Path) -> None:
    nested = tmp_path / "backend"
    nested.mkdir()
    (nested / "package-lock.json").write_text("{}")
    reason = _lockfile_skip_reason(tmp_path, "package-lock.json")
    assert "present" in reason and "outside" in reason
    assert "backend/package-lock.json" in reason
    assert "does not have" not in reason
