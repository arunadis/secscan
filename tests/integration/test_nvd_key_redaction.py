"""Secret-hygiene sweep for the NVD key flow (feature 009, SC-004/Principle III).

Run init with a distinctive sentinel in ``NVD_API_KEY`` and assert the value
appears in NO artifact under ``.secscan/`` and NOT in the rendered
report. The scanner only ever sees the variable NAME (FR-011).
"""

from __future__ import annotations

from pathlib import Path

from pipeline.init_cmd import run_init
from tests.helpers.tool_shims import copy_fixture, install_shims

SENTINEL = "qs-nvd-sentinel-7f3a9c2b-0000-4d1e"


def _sweep(root: Path, rendered: str) -> None:
    store = root / ".secscan"
    offenders = [
        str(p)
        for p in sorted(store.rglob("*"))
        if p.is_file() and SENTINEL in p.read_text(errors="replace")
    ]
    assert not offenders, f"sentinel leaked into artifact(s): {offenders}"
    assert SENTINEL not in rendered


def test_key_value_never_appears_in_artifacts_or_report_keyless_install(
    tmp_path, monkeypatch
) -> None:
    root = copy_fixture("multi_eco", tmp_path)
    bin_dir = install_shims(tmp_path, {"dependency-check.sh": "odc.json"})
    monkeypatch.setenv("PATH", str(bin_dir))

    report = run_init(root, environ={"NVD_API_KEY": SENTINEL}, no_input=True)
    _sweep(root, report.render())


def test_key_value_never_appears_in_artifacts_or_report_provide_flow(
    tmp_path, monkeypatch
) -> None:
    root = copy_fixture("multi_eco", tmp_path)
    bin_dir = install_shims(tmp_path, {"dependency-check.sh": "odc.json"})
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("NVD_API_KEY", SENTINEL)  # real env path (environ=None)

    report = run_init(root, yes=True)
    _sweep(root, report.render())
