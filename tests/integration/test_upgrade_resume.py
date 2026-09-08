"""Feature 017 T004 (US1, FR-002): tool/recognizer-version bumps invalidate the
graph checkpoint — an upgraded tool never silently resumes a stale extraction."""

from __future__ import annotations

import io
from pathlib import Path

from pipeline import progress
from pipeline import run as run_mod
from tests.fixtures import header_identity_app
from tests.integration.conftest import oracle_responder, silent_responder, write_config


def _scan(root: Path) -> str:
    stream = io.StringIO()
    reporter = progress.build_reporter(
        progress.OutputLevel.DEFAULT, stream=stream, log_path=None
    )
    try:
        run_mod.run_scan(
            root,
            responder=lambda request: oracle_responder(request) or silent_responder(request),
            progress=reporter,
        )
    finally:
        reporter.close()
    return stream.getvalue()


def test_unchanged_toolchain_resumes_the_graph(tmp_path: Path) -> None:
    header_identity_app.build(tmp_path)
    write_config(tmp_path)
    first = _scan(tmp_path)
    assert "done  build_code_graph" in first or " start" in first
    second = _scan(tmp_path)
    assert "reuse build_code_graph" in second


def test_extractor_version_bump_rebuilds_the_graph(tmp_path: Path, monkeypatch) -> None:
    header_identity_app.build(tmp_path)
    write_config(tmp_path)
    _scan(tmp_path)
    bump = "016 → 017"
    from pipeline import state as state_mod

    monkeypatch.setattr(state_mod, "EXTRACTOR_VERSION", f"{state_mod.EXTRACTOR_VERSION}-next")
    third = _scan(tmp_path)
    assert "reuse build_code_graph" not in third, (
        f"resume path reused the graph across an extractor version bump ({bump})"
    )
    assert " build_code_graph" in third
