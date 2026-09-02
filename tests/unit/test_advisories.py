"""T031: offline bundled-advisory matching (FR-007, FR-008; contract D3).

The bundled snapshot is the always-on offline baseline: no native tool is
invoked, ranges are honored, each vulnerable package is its own finding, and a
stale snapshot reads could-not-check — never clean.
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.fixtures.missed_detection_sites import build_fixture


def _scan_site(tmp_path: Path, site: str):
    from pipeline.audits import offline

    root = build_fixture(site, tmp_path / site)
    return offline.run_offline({"demo": root})


def test_marked_redos_is_a_first_class_finding(tmp_path: Path) -> None:
    """D3/SC-004: the evidenced miss — marked@1.1.1 with its ReDoS advisories."""
    findings, outcomes = _scan_site(tmp_path, "advisory_npm_marked")
    marked = [f for f in findings if "marked" in json.dumps(f)]
    assert marked, "marked@1.1.1 produced no finding"
    finding = marked[0]
    assert finding["cwe"] == "CWE-1035"
    assert finding["location"]["file"].endswith("package.json")
    assert finding["location"]["symbol"] == "marked"
    rendered = json.dumps(finding)
    assert "CVE-2022-21680" in rendered or "CVE-2022-21681" in rendered
    assert "4.0.10" in rendered  # fixed version named
    assert "1.1.1" in rendered  # pinned version named
    assert not any(f["location"]["symbol"] == "react" for f in findings)


def test_every_ecosystem_matches_offline(tmp_path: Path) -> None:
    """D3/FR-007: npm, maven, pypi, go — pinned vulnerable versions all fire."""
    expected = {
        "advisory_maven": "org.apache.logging.log4j:log4j-core",
        "advisory_pypi": "urllib3",
        "advisory_go": "golang.org/x/text",
    }
    for site, package in expected.items():
        findings, _ = _scan_site(tmp_path, site)
        assert any(
            f["location"]["symbol"] == package for f in findings
        ), f"{site}: {package} not reported"


def test_fixed_versions_stay_silent(tmp_path: Path) -> None:
    """D3: packages at or above the fixed version produce no finding."""
    findings, _ = _scan_site(tmp_path, "advisory_npm_marked")
    assert not any(f["location"]["symbol"] == "react" for f in findings)


def test_two_vulnerable_packages_one_manifest_two_findings(tmp_path: Path) -> None:
    """D3: no dedupe collapse — marked and minimist are distinct findings."""
    findings, _ = _scan_site(tmp_path, "advisory_npm_two_vuln")
    symbols = {f["location"].get("symbol") for f in findings}
    assert {"marked", "minimist"} <= symbols


def test_stale_snapshot_is_could_not_check_never_clean(tmp_path: Path, monkeypatch) -> None:
    """D3/FR-008: a snapshot past its staleness threshold cannot read as clean."""
    from pipeline.audits import offline

    monkeypatch.setattr(offline, "_snapshot_age_days", lambda _eco: 10_000)
    root = build_fixture("advisory_npm_marked", tmp_path / "stale")
    findings, outcomes = offline.run_offline({"demo": root})
    stale = [o for o in outcomes if o["ecosystem"] == "npm"]
    assert stale and stale[0]["status"] == "could-not-check"
    assert "stale" in stale[0]["reason"].lower()


def test_baseline_invokes_no_native_tool(tmp_path: Path, monkeypatch) -> None:
    """D3: the offline baseline never shells out."""
    import subprocess

    def _forbid(*args, **kwargs):
        raise AssertionError("native tool invoked during offline baseline")

    monkeypatch.setattr(subprocess, "run", _forbid)
    monkeypatch.setattr(subprocess, "Popen", _forbid)
    findings, _ = _scan_site(tmp_path, "advisory_npm_marked")
    assert findings
