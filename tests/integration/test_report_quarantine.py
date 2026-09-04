"""Feature 014 T024: quarantine + publish end to end (FR-010).

A report whose narrative names a finding id that does not exist must still
publish — minus the offending section, with the omission declared, and with the
scan signalling the defect via exit code 4 (clarification Q5). The frozen
stdout summary must not change.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from pipeline import run as run_mod
from pipeline import scan_cli
from tests.integration.conftest import silent_responder, write_config


def _scan_with_dangling_review(tmp_path: Path):
    from tests.fixtures.single_repo_shop import build

    root = build(tmp_path)
    write_config(root)
    original = run_mod._system_review_narrative

    def poisoned(findings, workspace):
        text = original(findings, workspace)
        return (text + "\n\nSystemic risk concentrated in SEC-9999.").strip()

    run_mod._system_review_narrative = poisoned
    try:
        result = run_mod.run_scan(root, responder=silent_responder, full=True)
    finally:
        run_mod._system_review_narrative = original
    return root, result


def test_dangling_reference_quarantines_but_publishes(tmp_path: Path, capsys) -> None:
    root, result = _scan_with_dangling_review(tmp_path / "a")

    report = result.report
    quarantined = report.get("quarantined_sections") or []
    assert quarantined, "no quarantine recorded for a dangling SEC-9999 reference"
    assert any(
        q["section"] == "system_review" and q["dangling_id"] == "SEC-9999"
        for q in quarantined
    )

    markdown = Path(result.report_path).read_text()
    assert "SEC-9999" in markdown, "the omission and the identifier must be declared"
    assert "quarantined" in markdown.lower() or "omitted" in markdown.lower()
    # The offending narrative is gone; the report's real findings are intact.
    assert "Systemic risk concentrated" not in markdown
    assert result.reported_findings, "valid findings must still publish"


def _stub_result(root: Path, quarantined: list[dict] | None):
    """A completed scan result without re-running the pipeline."""
    from types import SimpleNamespace

    report = {"quarantined_sections": quarantined} if quarantined else {}
    return SimpleNamespace(
        scan_id="20260904T000000Z-stub",
        reported_findings=[],
        report_path=str(root / ".secscan" / "reports" / "x.md"),
        # one coverage note so the full frozen three-line summary prints
        warnings=["coverage note"],
        report=report,
    )


def _args(root: Path) -> argparse.Namespace:
    return argparse.Namespace(
        workdir=root, overrides=[], policy=None, tool_timeout=None, output=None,
        profile=None, full=True, segment=None,
    )


def test_clean_scan_keeps_exit_zero_and_exact_summary(tmp_path: Path, capsys, monkeypatch) -> None:
    from tests.fixtures.single_repo_shop import build

    root = build(tmp_path / "clean")
    write_config(root)
    monkeypatch.setattr(run_mod, "run_scan", lambda *a, **k: _stub_result(root, None))
    assert scan_cli.cmd_run(_args(root)) == scan_cli.EXIT_OK
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 3, f"frozen stdout summary changed: {lines}"


def test_quarantined_scan_exits_four(tmp_path: Path, capsys, monkeypatch) -> None:
    from tests.fixtures.single_repo_shop import build

    root = build(tmp_path / "quarantined")
    write_config(root)
    quarantined = [
        {
            "section": "system_review",
            "dangling_id": "SEC-9999",
            "reason": "identifier not admitted to the report",
        }
    ]
    monkeypatch.setattr(
        run_mod, "run_scan", lambda *a, **k: _stub_result(root, quarantined)
    )
    assert scan_cli.cmd_run(_args(root)) == 4
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 3, f"frozen stdout summary changed under defect: {lines}"
