"""T072: end-of-support assessment (FR-034).

The exposure the independent reviewer ranked **first** and the benchmark scan
never assessed at all: a stack years past end of support, receiving no security
fixes, independent of any individual advisory.

Two properties carry the weight here. `past_eol` is tri-state, so "we could not
tell" never reads as "supported". And staleness of the snapshot is itself
reportable, because presenting expired support data as current would be the same
unearned confidence this feature exists to remove.
"""

from __future__ import annotations

import pytest

from pipeline import stack_currency


def test_benchmark_stack_is_reported_past_support() -> None:
    """The concrete case: Angular 9.0.1, out of support since 2021-08-06."""
    status = stack_currency.status_for("@angular/core", "9.0.1")
    assert status.past_eol is True
    assert status.eol_date == "2021-08-06"
    assert status.cycle


@pytest.mark.parametrize(
    ("package", "version"),
    [("@angular/core", "9.0.1"), ("typescript", "3.7.5"), ("rxjs", "6.5.4"), ("django", "3.2.0")],
)
def test_known_end_of_support_versions_are_caught(package: str, version: str) -> None:
    status = stack_currency.status_for(package, version)
    assert status.past_eol is True, f"{package} {version} not reported past support"
    assert status.eol_date


def test_unknown_package_is_undetermined_not_supported() -> None:
    """FR-034 + Principle V: an unknown must never read as a clean result."""
    status = stack_currency.status_for("a-package-that-does-not-exist", "1.0.0")
    assert status.past_eol is None
    assert status.reason, "an undetermined result must say why"


def test_unknown_version_of_a_known_product_is_undetermined() -> None:
    status = stack_currency.status_for("@angular/core", "999.0.0")
    assert status.past_eol is not True
    if status.past_eol is None:
        assert status.reason


def test_manifest_identifier_maps_to_a_product_id() -> None:
    """Package-manager names and dataset product ids do not coincide."""
    assert stack_currency.product_for("@angular/core") == "angular"
    assert stack_currency.product_for("a-package-that-does-not-exist") is None


def test_staleness_is_reported_with_a_threshold() -> None:
    age, stale = stack_currency.staleness()
    assert age >= 0
    assert isinstance(stale, bool)
    assert stack_currency.staleness_threshold_days() > 0
    assert stale == (age > stack_currency.staleness_threshold_days())


def test_dataset_declares_its_version_and_date() -> None:
    """Required for the snapshot to be auditable and refreshable."""
    from datetime import date as date_type

    assert stack_currency.version()
    snapshot = stack_currency.dataset_date()
    assert isinstance(snapshot, date_type)
    assert snapshot.year >= 2024


def test_status_is_deterministic() -> None:
    first = stack_currency.status_for("@angular/core", "9.0.1")
    second = stack_currency.status_for("@angular/core", "9.0.1")
    assert first == second


def test_findings_are_generated_from_declared_versions(tmp_path) -> None:
    """FR-034 end to end: a manifest in, an end-of-support finding out."""
    from pipeline import audits

    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@angular/core": "9.0.1", "rxjs": "6.5.4"}}'
    )
    findings = audits.stack_currency_findings({"web": tmp_path})
    assert findings
    packages = {f["description"].split()[0] for f in findings}
    assert {"@angular/core", "rxjs"} <= packages
    for finding in findings:
        assert finding["cwe"] == audits.CWE_UNMAINTAINED_COMPONENT
        assert finding["source"] == "dependency-audit"
        assert finding["location"]["tier"] == "file"
        assert finding["evidence"][0]["reason"]
        assert "end of support" in finding["description"]


def _still_supported_angular_cycle() -> str:
    """A cycle the dataset says is still supported, found at run time.

    Hard-coding a version would quietly rot: Angular 17 was a reasonable "current"
    choice when written and is out of support as of this dataset. Deriving it from
    the same data the assertion is about keeps the test honest over time.
    """
    import json

    from pipeline import resources

    cycles = json.loads(resources.data_path("eol.json").read_text())["products"]["angular"]
    for entry in sorted(cycles, key=lambda c: int(c["cycle"]), reverse=True):
        if stack_currency.status_for("@angular/core", f"{entry['cycle']}.0.0").past_eol is False:
            return f"{entry['cycle']}.0.0"
    pytest.skip("the shipped snapshot lists no still-supported Angular cycle")


def test_a_supported_version_produces_no_finding(tmp_path) -> None:
    """Precision guard: this must not fire on every dependency."""
    from pipeline import audits

    version = _still_supported_angular_cycle()
    (tmp_path / "package.json").write_text(
        f'{{"dependencies": {{"@angular/core": "{version}"}}}}'
    )
    assert audits.stack_currency_findings({"web": tmp_path}) == [], (
        f"@angular/core {version} is still supported but was reported past end of support"
    )
