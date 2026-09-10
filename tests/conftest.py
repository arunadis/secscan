"""Suite-wide hermeticity guards."""

from __future__ import annotations

import os
import resource
import sys

import pytest

# Memory ceiling per test process, active only under a mutmut campaign (mutmut 3.x
# forks children that run pytest in-process, setting MUTANT_UNDER_TEST per child).
# A mutant can allocate unboundedly (e.g. a mutated loop bound); without a cap each
# child can eat tens of GB and OOM the machine. Prefer a hard RLIMIT_AS where the
# kernel enforces it (Linux); on macOS the kernel refuses to lower it (dyld shared
# cache inflates every process's address space), so fall back to a watchdog thread
# polling ru_maxrss and hard-exiting over the cap — mutmut records that as a killed
# mutant, exactly like a timeout.
_MUTMUT_MEM_CAP_ENV = "MUTMUT_MEM_CAP_GB"
_MUTMUT_MEM_CAP_DEFAULT_GB = 4.0


def _memory_watchdog(cap_bytes: int) -> None:
    import threading
    import time

    def _watch() -> None:
        # ru_maxrss is bytes on macOS, KiB on Linux.
        factor = 1 if sys.platform == "darwin" else 1024
        while True:
            if resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * factor > cap_bytes:
                os.write(2, b"mutmut memory cap exceeded; killing mutant child\n")
                os._exit(1)
            time.sleep(0.2)

    threading.Thread(target=_watch, daemon=True, name="mutmut-mem-watchdog").start()


if os.environ.get("MUTANT_UNDER_TEST"):
    _cap_gb = float(os.environ.get(_MUTMUT_MEM_CAP_ENV, _MUTMUT_MEM_CAP_DEFAULT_GB))
    _cap_bytes = int(_cap_gb * (1 << 30))
    try:
        resource.setrlimit(resource.RLIMIT_AS, (_cap_bytes, _cap_bytes))
    except (OSError, ValueError):
        _memory_watchdog(_cap_bytes)


@pytest.fixture(autouse=True)
def _isolate_go_bin_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tool discovery falls back to the Go bin dir (``locate.go_bin_dir``).

    Tests restrict PATH to shim directories and assert tools are *missing*;
    a developer's real ``$GOBIN``/``$GOPATH`` must not leak real binaries into
    those assertions. Tests that exercise the fallback set GOBIN explicitly.
    """
    monkeypatch.delenv("GOBIN", raising=False)
    monkeypatch.delenv("GOPATH", raising=False)
