"""Exclusive run lock per scan root (feature 018, FR-008; research R5)."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import pytest

from pipeline import run as run_mod
from pipeline import scan_cli
from pipeline.llm_client import AgentHandoff, ScanPaused
from pipeline.state import (
    RUN_LOCK_NAME,
    ScanLocked,
    acquire_run_lock,
    read_run_lock,
    release_run_lock,
)
from tests.fixtures.single_repo_shop import build as build_shop
from tests.integration.conftest import oracle_responder, write_config


@pytest.fixture
def shop(tmp_path: Path) -> Path:
    root = build_shop(tmp_path / "shop")
    write_config(root, {"triage": {"enabled": "off"}})
    return root


def _write_lock(store_dir: Path, **fields) -> Path:
    store_dir.mkdir(parents=True, exist_ok=True)
    payload = {"pid": os.getpid(), "started_at": 1.0, "scan_id": "s", "driver": "cli",
               "tool_version": "0.1.0"}
    payload.update(fields)
    path = store_dir / RUN_LOCK_NAME
    path.write_text(json.dumps(payload))
    return path


def test_acquire_writes_lock_fields(tmp_path: Path) -> None:
    store_dir = tmp_path / ".secscan"
    path = acquire_run_lock(store_dir, driver="plugin", scan_id="abc")
    lock = json.loads(path.read_text())
    assert lock["pid"] == os.getpid()
    assert lock["driver"] == "plugin"
    assert lock["scan_id"] == "abc"
    assert set(lock) == {"pid", "started_at", "scan_id", "driver", "tool_version"}
    assert read_run_lock(store_dir) == lock
    release_run_lock(store_dir)
    assert not path.exists()


def test_live_lock_refuses(tmp_path: Path) -> None:
    store_dir = tmp_path / ".secscan"
    _write_lock(store_dir, driver="cli", scan_id="running")
    with pytest.raises(ScanLocked) as exc:
        acquire_run_lock(store_dir, driver="plugin", scan_id="new")
    assert "scan already running" in str(exc.value)
    assert exc.value.lock["scan_id"] == "running"
    assert "via cli" in str(exc.value)


def test_dead_pid_lock_is_reclaimed(tmp_path: Path) -> None:
    store_dir = tmp_path / ".secscan"
    _write_lock(store_dir, pid=2**22 + 12345)  # almost certainly not alive
    assert read_run_lock(store_dir) is None
    path = acquire_run_lock(store_dir, driver="plugin", scan_id="new")
    assert json.loads(path.read_text())["pid"] == os.getpid()
    release_run_lock(store_dir)


def test_release_only_removes_own_lock(tmp_path: Path) -> None:
    store_dir = tmp_path / ".secscan"
    path = _write_lock(store_dir, pid=os.getpid() + 1)
    release_run_lock(store_dir)
    assert path.exists()


def test_run_scan_releases_on_every_exit(shop: Path) -> None:
    lock_path = shop / ".secscan" / RUN_LOCK_NAME

    # success
    run_mod.run_scan(shop, responder=oracle_responder)
    assert not lock_path.exists()

    # agent handoff (no responder)
    with pytest.raises(AgentHandoff):
        run_mod.run_scan(shop, full=True)
    assert not lock_path.exists()

    # deadline pause (full=True so a checkpointed stage actually runs and can pause)
    with pytest.raises(ScanPaused):
        run_mod.run_scan(
            shop, responder=oracle_responder, clock=lambda: 10.0, deadline=5.0, full=True
        )
    assert not lock_path.exists()

    # arbitrary exception inside a stage
    def boom(request):
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        run_mod.run_scan(shop, responder=boom, full=True)
    assert not lock_path.exists()


def test_run_scan_refuses_when_locked(shop: Path) -> None:
    _write_lock(shop / ".secscan", scan_id="other", driver="plugin")
    with pytest.raises(ScanLocked):
        run_mod.run_scan(shop, responder=oracle_responder)
    # The foreign lock is left in place.
    assert (shop / ".secscan" / RUN_LOCK_NAME).exists()


def test_cli_run_reports_lock_on_stderr_and_exits_1(shop: Path, capsys) -> None:
    _write_lock(shop / ".secscan", scan_id="other", driver="plugin")
    args = argparse.Namespace(
        workdir=shop, profile=None, overrides=None, policy=None, tool_timeout=None,
        full=False, segment=None, output="quiet",
    )
    code = scan_cli.cmd_run(args)
    out, err = capsys.readouterr()
    assert code == scan_cli.EXIT_ERROR
    assert out == ""
    assert "scan already running" in err
    assert "via plugin" in err
    assert RUN_LOCK_NAME in err


def test_cli_status_shows_live_lock(shop: Path, capsys) -> None:
    _write_lock(shop / ".secscan", driver="cli")
    code = scan_cli.cmd_status(argparse.Namespace(workdir=shop))
    out, _ = capsys.readouterr()
    assert code == scan_cli.EXIT_OK
    assert "Running:" in out and "via cli" in out
