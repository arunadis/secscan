"""005:T008/T009/T017/T022/T023 — the three report artifacts as a set.

One scan produces JSON + Markdown + HTML from one data set: identical finding
ids across all three, byte-identical HTML across identical runs, every internal
reference resolving, and zero credential values anywhere (with the redaction
sweep in tests/contract/test_artifact_redaction.py covering the same ground
end-to-end).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from pipeline import run as run_mod
from pipeline.redact import Redactor
from pipeline.render_html import anchor_for, render_html
from tests.integration.conftest import oracle_responder, write_config

REPORTS = Path(".secscan/reports")

SEEDED_SECRET = "Pr0d-Sh0p-DB-2024!"


@pytest.fixture(scope="module")
def scanned(tmp_path_factory) -> Path:
    from tests.fixtures.single_repo_shop import build

    root = build(tmp_path_factory.mktemp("report-artifacts"))
    write_config(root)
    run_mod.run_scan(root, responder=oracle_responder, full=True)
    return root


def _report_paths(root: Path) -> dict[str, Path]:
    reports = {p.suffix: p for p in (root / REPORTS).iterdir()}
    return reports


# ------------------------------------------------------------------ T008


def test_scan_writes_json_markdown_and_html(scanned: Path) -> None:
    reports = _report_paths(scanned)
    for suffix in (".json", ".md", ".html"):
        assert suffix in reports, f"no {suffix} report was written"
    stems = {p.stem for p in reports.values()}
    assert len(stems) == 1, "the three renderings must share one scan id"


def test_html_is_byte_identical_across_identical_runs(tmp_path: Path) -> None:
    """SC-007 for the new artifact (scan id and root path normalized out, exactly
    as tests/integration/test_determinism.py does for the JSON artifacts)."""
    from tests.fixtures.single_repo_shop import build

    contents: list[str] = []
    for name in ("a", "b"):
        root = build(tmp_path / name)
        write_config(root)
        run_mod.run_scan(root, responder=oracle_responder, full=True)
        html_path = next((root / REPORTS).glob("*.html"))
        text = html_path.read_text()
        text = text.replace(html_path.stem, "<scan-id>").replace(str(root), "<root>")
        contents.append(text)
    assert contents[0] == contents[1], "HTML differs between identical runs"


# ------------------------------------------------------------------ spec 007


def test_llm_category_artifacts_are_byte_identical_across_runs(tmp_path: Path) -> None:
    """SC-005: the new category's findings and artifacts are deterministic."""
    from tests.integration.conftest import silent_responder

    fixture = Path("tests/fixtures/llm_workspace/us1_direct/vulnerable")
    contents: list[dict[str, str]] = []
    for name in ("a", "b"):
        # stable member name ("shop"), so only scan_id and root path vary
        target = tmp_path / name / "shop"
        import shutil

        shutil.copytree(fixture, target)
        write_config(target)
        run_mod.run_scan(target, responder=silent_responder, full=True)
        scan_dir = target / ".secscan"
        snapshot: dict[str, str] = {}
        for artifact in sorted(scan_dir.rglob("*.json")):
            name = str(artifact.relative_to(scan_dir))
            if name == "state.json":
                continue  # resume bookkeeping (timestamps), not a deliverable
            if name.startswith("reports/"):
                name = f"reports/report{artifact.suffix}"  # filename embeds scan id
            text = artifact.read_text()
            text = re.sub(r'"scan_id": "[^"]+"', '"scan_id": "<id>"', text)
            text = text.replace(str(target), "<root>")
            snapshot[name] = text
        contents.append(snapshot)
    assert contents[0], "scan produced no artifacts"
    assert contents[0] == contents[1], (
        "artifacts differ between identical runs: "
        "{k for k in contents[0] if contents[0][k] != contents[1].get(k)}"
    )
    assert "findings/llm.json" in contents[0], "the category's artifact was not written"


# ------------------------------------------------------------------ T009


def _scaled_report(count: int) -> dict:
    findings = []
    for i in range(count):
        band = ("Critical", "High", "Medium", "Low")[i % 4]
        findings.append(
            {
                "id": f"SEC-{i:04d}",
                "cwe": "CWE-89",
                "severity_score": 8.0,
                "severity_band": band,
                "confidence": 0.9,
                "location": {
                    "repo": "shop",
                    "file": f"src/mod{i % 25}.py",
                    "symbol": "handler",
                    "line_start": 10,
                    "line_end": 12,
                    "tier": "symbol",
                },
                "description": f"Finding {i} description.",
                "evidence": [
                    {"repo": "shop", "file": f"src/mod{i % 25}.py", "reason": "why"}
                ],
                "attack_scenario": "scenario",
                "impact": "impact",
                "recommendation": "fix it",
                "verification": {"status": "plausible"},
            }
        )
    grouped: dict[str, list[dict]] = {}
    for finding in findings:
        grouped.setdefault(finding["severity_band"], []).append(finding)
    return {
        "scan_id": "scale-test",
        "workspace": {"id": "ws-scale", "members": ["shop"]},
        "execution_mode": "endpoint-batch",
        "profile": {"name": "full"},
        "executive_summary": "Scale test.",
        "findings_by_band": grouped,
        "recommendations": [],
        "coverage": {"repos_analyzed": ["shop"], "segments_analyzed": 25, "clean": False},
        "usage": {
            "segments": [],
            "totals": {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0},
        },
    }


def test_html_scales_to_500_findings_with_all_links_resolving() -> None:
    """SC-004/SC-002 at scale: render succeeds, no dangling href, sane size."""
    html = render_html(_scaled_report(500))
    assert len(html) < 20 * 1024 * 1024, "HTML report too large to open comfortably"
    emitted_ids = set(re.findall(r'id="([^"]+)"', html))
    hrefs = re.findall(r'href="#([^"]+)"', html)
    assert hrefs, "no internal links at all"
    for href in hrefs:
        assert href in emitted_ids, f"dangling reference to #{href}"
    for i in range(500):
        assert anchor_for(f"SEC-{i:04d}") in emitted_ids


# ------------------------------------------------------------------ T017


def _report_payload(scanned: Path) -> dict:
    document = json.loads(_report_paths(scanned)[".json"].read_text())
    return document.get("payload", document)


def _all_findings(payload: dict) -> list[dict]:
    return [f for findings in payload["findings_by_band"].values() for f in findings]


def test_every_reported_finding_carries_an_excerpt(scanned: Path) -> None:
    findings = _all_findings(_report_payload(scanned))
    assert findings, "fixture scan reported nothing"
    for finding in findings:
        excerpt = finding.get("code_excerpt")
        assert excerpt is not None, f"{finding['id']} has no code_excerpt"
        if excerpt["status"] == "unavailable":
            assert excerpt["reason"], f"{finding['id']}: unavailable without a reason"


def test_excerpts_match_the_redacted_source(scanned: Path) -> None:
    """SC-003: excerpt lines are byte-equal to redactor output over the window."""
    redactor = Redactor()
    checked = 0
    for finding in _all_findings(_report_payload(scanned)):
        excerpt = finding["code_excerpt"]
        if excerpt["status"] != "ok":
            continue
        source = (scanned / excerpt["file"]).read_text(errors="replace").splitlines()
        window = "\n".join(source[excerpt["window_start"] - 1 : excerpt["window_end"]])
        expected = redactor.redact(window, origin=excerpt["file"]).text.split("\n")
        actual = [line["text"] for line in excerpt["lines"]]
        # Per-line truncation is the only permitted deviation.
        assert len(actual) == len(expected)
        for got, want in zip(actual, expected, strict=True):
            assert want.startswith(got) or got == want
        checked += 1
    assert checked, "no ok excerpt was verified against the source"


def test_no_seeded_secret_in_any_rendering(scanned: Path) -> None:
    """SC-005 across all three artifacts, including excerpt content."""
    for path in _report_paths(scanned).values():
        assert SEEDED_SECRET not in path.read_text(errors="replace"), path.name


def test_excerpt_appears_in_markdown_and_html(scanned: Path) -> None:
    markdown = _report_paths(scanned)[".md"].read_text()
    html = _report_paths(scanned)[".html"].read_text()
    assert "```" in markdown and "**Code** — `" in markdown or "excerpt unavailable" in markdown
    assert 'class="excerpt"' in html or "excerpt unavailable" in html.lower()


# ------------------------------------------------------------------ T022 / T023


def test_finding_ids_are_identical_across_formats(scanned: Path) -> None:
    """SC-001: one finding, one id, in JSON, Markdown and HTML alike."""
    payload = _report_payload(scanned)
    json_ids = {f["id"] for f in _all_findings(payload)}
    markdown = _report_paths(scanned)[".md"].read_text()
    md_ids = set(re.findall(r"^#### (SEC-\d+) —", markdown, re.M))
    html = _report_paths(scanned)[".html"].read_text()
    html_ids = {
        anchor[len("finding-"):]
        for anchor in re.findall(r'id="(finding-[^"]+)"', html)
    }
    assert json_ids and json_ids == md_ids == html_ids


def test_every_internal_reference_resolves_in_both_human_formats(scanned: Path) -> None:
    """SC-002: HTML anchors (belt-and-braces over the render-time raise) and
    Markdown recommendation pointers to band sections."""
    html = _report_paths(scanned)[".html"].read_text()
    emitted = set(re.findall(r'id="([^"]+)"', html))
    for href in set(re.findall(r'href="#([^"]+)"', html)):
        assert href in emitted, f"dangling HTML reference to #{href}"

    markdown = _report_paths(scanned)[".md"].read_text()
    sections = set(re.findall(r"^### (\w+) \(\d+\)$", markdown, re.M))
    for pointer in re.findall(r"see the ([\w, ]+) sections?\.", markdown):
        for band in re.findall(r"[A-Z]\w+", pointer):
            assert band in sections, f"recommendation points at missing section {band}"
