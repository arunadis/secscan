"""Suite-wide hermeticity guards."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_go_bin_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tool discovery falls back to the Go bin dir (``locate.go_bin_dir``).

    Tests restrict PATH to shim directories and assert tools are *missing*;
    a developer's real ``$GOBIN``/``$GOPATH`` must not leak real binaries into
    those assertions. Tests that exercise the fallback set GOBIN explicitly.
    """
    monkeypatch.delenv("GOBIN", raising=False)
    monkeypatch.delenv("GOPATH", raising=False)
