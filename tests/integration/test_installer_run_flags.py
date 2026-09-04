"""`secscan run --output / -q / -v` on the click surface (feature 011, FR-011/FR-017).

`installer.cli.run_command` only assembles an ``argparse.Namespace`` for
``scan_cli.cmd_run``; that handoff is what these tests pin down.
"""

from __future__ import annotations

import argparse

import pytest
from click.testing import CliRunner

from installer import cli
from pipeline import scan_cli


@pytest.fixture
def captured(monkeypatch) -> list[argparse.Namespace]:
    seen: list[argparse.Namespace] = []

    def fake_run(args: argparse.Namespace) -> int:
        seen.append(args)
        return 0

    monkeypatch.setattr(scan_cli, "cmd_run", fake_run)
    return seen


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["run", "--output", "verbose"], "verbose"),
        (["run", "--output", "quiet"], "quiet"),
        (["run", "-q"], "quiet"),
        (["run", "-v"], "verbose"),
        (["run"], None),
    ],
)
def test_output_flags_reach_cmd_run(captured, argv, expected) -> None:
    result = CliRunner().invoke(cli.main, argv)
    assert result.exit_code == 0, result.output
    assert captured[0].output == expected


@pytest.mark.parametrize(
    "argv",
    [["run", "-q", "-v"], ["run", "-q", "--output", "verbose"], ["run", "-v", "--output", "quiet"]],
)
def test_conflicting_level_flags_are_a_usage_error(captured, argv) -> None:
    result = CliRunner().invoke(cli.main, argv)
    assert result.exit_code == 2
    assert "cannot be combined" in result.output
    assert not captured


def test_unknown_output_value_is_rejected_by_click(captured) -> None:
    result = CliRunner().invoke(cli.main, ["run", "--output", "loud"])
    assert result.exit_code == 2
    assert not captured
