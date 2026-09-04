"""Executable resolution beyond PATH (feature 008 follow-up).

``go install`` always drops binaries into ``$GOBIN`` (default
``$GOPATH/bin``, default ``~/go/bin``), a directory that is *not* on PATH by
default on macOS/Linux. Provisioning a tool through the ``go`` channel and
then declaring it missing because PATH does not contain that directory would
be dishonest, so every executable lookup in the tooling layer goes through
:func:`resolve_executable`: PATH first, then the Go bin directory.

Resolution is read-only and never mutates the environment.
"""

from __future__ import annotations

import functools
import os
import shutil
import subprocess
from pathlib import Path

_GO_ENV_TIMEOUT_S = 10


def go_bin_dir() -> Path | None:
    """Where ``go install`` puts binaries, or ``None`` when undeterminable.

    Order mirrors Go's own precedence: ``$GOBIN``, ``$GOPATH/bin`` (first
    entry), ``go env`` (honours ``go env -w`` settings), then Go's built-in
    default ``~/go/bin``. Only consulted when ``go`` is present, since without
    it nothing could have installed there through the registry channel.
    """
    if os.environ.get("GOBIN"):
        return Path(os.environ["GOBIN"])
    if os.environ.get("GOPATH"):
        return Path(os.environ["GOPATH"].split(os.pathsep)[0]) / "bin"
    go = shutil.which("go")
    if go is None:
        return None
    return _go_env_bin_dir(go) or Path.home() / "go" / "bin"


@functools.lru_cache(maxsize=8)
def _go_env_bin_dir(go: str) -> Path | None:
    """``go env`` answer for the given ``go`` binary; cached per toolchain path."""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, bounded, read-only
            [go, "env", "GOBIN", "GOPATH"],
            capture_output=True,
            text=True,
            timeout=_GO_ENV_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    lines = [line.strip() for line in proc.stdout.splitlines()]
    gobin = lines[0] if len(lines) > 0 else ""
    gopath = lines[1] if len(lines) > 1 else ""
    if gobin:
        return Path(gobin)
    if gopath:
        return Path(gopath.split(os.pathsep)[0]) / "bin"
    return None


def resolve_executable(name: str) -> str | None:
    """Absolute path for ``name`` via PATH, else the Go bin directory; else None.

    A PATH hit returns exactly what ``shutil.which`` returns so callers that
    already worked keep identical behaviour; only the Go fallback yields a
    path outside PATH.
    """
    if not name:
        return None
    found = shutil.which(name)
    if found:
        return found
    go_bin = go_bin_dir()
    if go_bin is None:
        return None
    candidate = go_bin / name
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None


def resolved_argv(argv: list[str] | tuple[str, ...]) -> list[str]:
    """``argv`` with argv[0] swapped for its resolved path when PATH lacks it.

    argv[0] is left untouched when it already resolves through PATH (so
    recorded invocations stay stable) or cannot be resolved at all (the
    caller reports that honestly).
    """
    argv = list(argv)
    if not argv or shutil.which(argv[0]) is not None:
        return argv
    resolved = resolve_executable(argv[0])
    return [resolved, *argv[1:]] if resolved else argv
