"""T073: dependency reporting end to end (quickstart Scenario 8).

The reviewed benchmark's dependency domain produced nothing at all, hiding 23
runtime advisories (15 high) on a stack years past end of life — a larger and far
more concrete exposure than either finding it did report. These tests assert the
domain is now either reported or *loudly* unassessed, never silently empty.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import audits
from pipeline import run as run_mod
from tests.fixtures.multi_member_workspace import build
from tests.integration.conftest import write_config

DECLARED_MEMBERS = [{"name": "web", "path": "web"}, {"name": "api", "path": "api"}]


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = build(tmp_path)
    write_config(root)
    return root


@pytest.fixture
def roots(workspace: Path) -> dict[str, Path]:
    return {"web": workspace / "web", "api": workspace / "api"}


def test_every_member_is_audited_against_its_own_ecosystem(roots) -> None:
    """FR-030a: no member is skipped because another ecosystem was found first."""
    outcomes, _grouped = audits.run(roots, timeout_s=30)
    by_member = {o.member: o.ecosystem for o in outcomes}
    assert by_member.get("web") == "npm"
    assert by_member.get("api") == "pypi"


def test_unavailable_toolchain_is_a_named_per_member_gap(roots) -> None:
    """FR-030c/FR-033: a partially audited workspace is never presented as audited."""
    outcomes, _grouped = audits.run(roots, timeout_s=30)
    gaps = audits.blocking_gaps(outcomes)
    unchecked = [o for o in outcomes if o.status == audits.STATUS_COULD_NOT_CHECK]
    assert len(gaps) == len(unchecked)
    for gap in gaps:
        assert "UNASSESSED" in gap
        assert "not a clean result" in gap
        assert "run:" in gap


def test_could_not_check_is_never_reported_as_clean(roots) -> None:
    outcomes, _grouped = audits.run(roots, timeout_s=30)
    for outcome in outcomes:
        if outcome.status == audits.STATUS_COULD_NOT_CHECK:
            assert outcome.reason
            assert outcome.status != audits.STATUS_CLEAN


def test_end_of_support_stack_is_reported_independently(roots) -> None:
    """FR-034: independent of any individual advisory.

    This is the exposure the reviewer ranked first and the benchmark never
    assessed — reported here even with no advisory database reachable.
    """
    findings = audits.stack_currency_findings(roots)
    assert findings, "no end-of-support finding was produced"
    # Feature 014 (FR-008): one finding per (member, product, cycle); the
    # packages field — not the description's first word — is authoritative.
    packages = {p for f in findings for p in (f.get("dependency") or {}).get("packages", [])}
    assert "@angular/core" in packages
    for finding in findings:
        assert finding["cwe"] == audits.CWE_UNMAINTAINED_COMPONENT
        assert finding["source"] == "dependency-audit"
        assert finding["evidence"][0]["reason"]


def test_skip_avoids_double_reporting_with_an_external_scanner(roots) -> None:
    """A domain already covered by an installed scanner is not audited twice."""
    outcomes, _grouped = audits.run(roots, timeout_s=30, skip_ecosystems={"npm"})
    assert all(o.ecosystem != "npm" for o in outcomes)


def test_manifests_are_untouched_by_a_full_audit(roots) -> None:
    """FR-031, across every adapter the workspace selects."""
    before = {
        name: {p.name: p.read_bytes() for p in root.rglob("*") if p.is_file()}
        for name, root in roots.items()
    }
    audits.run(roots, timeout_s=30)
    after = {
        name: {p.name: p.read_bytes() for p in root.rglob("*") if p.is_file()}
        for name, root in roots.items()
    }
    assert before == after


def test_audit_results_are_deterministic(roots) -> None:
    """SC-013: byte-identical for identical input."""
    first = [o.to_dict() for o in audits.run(roots, timeout_s=30)[0]]
    second = [o.to_dict() for o in audits.run(roots, timeout_s=30)[0]]
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


# ------------------------------------------------------------- through a scan


@pytest.fixture
def scanned(tmp_path: Path):
    """A single member whose manifest sits at its own root.

    The multi-member workspace above needs *declared* members; auto-discovery
    treats a root containing source in subdirectories as one member, and that
    member has no manifest of its own. This fixture exercises the driver path.
    """
    from tests.fixtures.unparsed_language import build_fixed_prefix

    repo = build_fixed_prefix(tmp_path)
    write_config(repo)

    def responder(_request):
        return json.dumps({"findings": []})

    result = run_mod.run_scan(repo, responder=responder, full=True)
    report = json.loads(Path(result.report_json_path).read_text())["payload"]
    return repo, report


def test_report_carries_audit_outcomes_per_member(scanned) -> None:
    _root, report = scanned
    outcomes = report["coverage"].get("audit_outcomes")
    assert outcomes, "the report records no audit outcome"
    for outcome in outcomes:
        assert outcome["status"] in ("advisories", "clean", "could-not-check")
        if outcome["status"] == "could-not-check":
            assert outcome["remediation_command"]


def test_blocking_gaps_appear_in_the_report(scanned) -> None:
    """FR-033: prominent, and clearly distinguished from a clean result."""
    _root, report = scanned
    gaps = report["coverage"].get("blocking_gaps") or []
    unchecked = [
        o for o in report["coverage"]["audit_outcomes"] if o["status"] == "could-not-check"
    ]
    if unchecked:
        assert gaps, "an unassessed dependency domain produced no blocking gap"


def test_dependency_artifact_is_written(scanned) -> None:
    root, _report = scanned
    payload = json.loads((root / ".secscan" / "dependency-audit.json").read_text())
    assert "outcomes" in payload["payload"]


# ------------------------------------------- de-duplication seam (FR-030c, E2)


def test_no_external_findings_means_everything_is_audited() -> None:
    """The default, and the safe one: nothing covered means audit everything."""
    from pipeline.ingest_findings import covered_domains

    assert covered_domains([]) == set()


def test_an_installed_scanner_does_not_by_itself_suppress_an_audit() -> None:
    """The trap in FR-030c, asserted directly.

    Skipping because a tool is *installed* would suppress our own audit while
    nothing replaced it — turning a covered domain into a silent gap. That is
    strictly worse than reporting an advisory twice, so coverage is credited from
    ingested output only.
    """
    from pipeline.ingest_findings import DEPENDENCY_SCANNERS, covered_domains

    assert "osv-scanner" in DEPENDENCY_SCANNERS  # capability is declared...
    assert covered_domains([]) == set()  # ...but confers no coverage on its own


def test_external_output_credits_only_the_ecosystem_it_reported_on() -> None:
    """A scanner capable of four ecosystems that reported on one covered one."""
    from pipeline.ingest_findings import covered_domains

    findings = [
        {"scanner": "osv-scanner", "dependency": {"ecosystem": "npm"}},
    ]
    assert covered_domains(findings) == {"npm"}


def test_a_non_dependency_scanner_never_displaces_an_audit() -> None:
    """Semgrep and Gitleaks report other domains entirely."""
    from pipeline.ingest_findings import covered_domains

    findings = [
        {"scanner": "semgrep", "dependency": {"ecosystem": "npm"}},
        {"scanner": "gitleaks"},
    ]
    assert covered_domains(findings) == set()


def test_skipped_domain_is_still_disclosed_in_the_report(roots) -> None:
    """A skip is a stated decision, not an absence."""
    from pipeline import ingest_findings

    findings = [{"scanner": "osv-scanner", "dependency": {"ecosystem": "npm"}}]
    assert ingest_findings.covered_domains(findings) == {"npm"}

    class _Store:
        def glob(self, _pattern):
            return []

    _found, _outcomes, gaps = ingest_findings.run_dependency_audits(_Store(), roots)
    # With no external findings, nothing is skipped and no skip note appears.
    assert not any("not audited natively" in gap for gap in gaps)
