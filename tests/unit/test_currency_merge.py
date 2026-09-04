"""Feature 014 T020: currency signals roll up per (member, product, cycle).

FR-008/FR-009: one finding per `(member, product, cycle)` — never across members,
never merged with advisory (CVE) findings; IDs assigned after merging; evidence
preserved (no signal lost); highest contributing severity kept.
"""

from __future__ import annotations

import json
from pathlib import Path

from pipeline import audits


def _member(
    tmp_path: Path, name: str, package_block: dict, *, dev: dict | None = None
) -> None:
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    document = {"dependencies": package_block}
    if dev:
        document["devDependencies"] = dev
    (root / "package.json").write_text(json.dumps(document))


def test_same_product_cycle_collapses_to_one_finding(tmp_path: Path) -> None:
    _member(tmp_path, "web", {"@angular/core": "9.0.1", "@angular/platform-browser": "9.0.1"})
    findings = audits.stack_currency_findings({"web": tmp_path / "web"})
    assert len(findings) == 1
    finding = findings[0]
    dependency = finding["dependency"]
    assert dependency["packages"] == ["@angular/core", "@angular/platform-browser"]
    assert dependency["product"] == "angular"
    assert dependency["cycle"] == "9"
    assert dependency["signals"] == ["past-eol"]
    # No signal lost: one evidence entry per package.
    assert len(finding["evidence"]) == 2
    assert {e["reason"].split()[1] for e in finding["evidence"]} == set(dependency["packages"])


def test_distinct_products_stay_distinct(tmp_path: Path) -> None:
    _member(tmp_path, "web", {"@angular/core": "9.0.1", "rxjs": "6.5.4"})
    findings = audits.stack_currency_findings({"web": tmp_path / "web"})
    products = {f["dependency"]["product"] for f in findings}
    assert len(findings) == len(products) == 2


def test_merge_never_crosses_members(tmp_path: Path) -> None:
    _member(tmp_path, "web", {"@angular/core": "9.0.1"})
    _member(tmp_path, "mobile", {"@angular/core": "9.0.1"})
    findings = audits.stack_currency_findings(
        {"mobile": tmp_path / "mobile", "web": tmp_path / "web"}
    )
    assert len(findings) == 2
    assert {f["location"]["repo"] for f in findings} == {"mobile", "web"}
    assert all(f["dependency"]["affected_members"] == [f["location"]["repo"]] for f in findings)


def test_ids_are_assigned_after_merging(tmp_path: Path) -> None:
    _member(
        tmp_path,
        "web",
        {"@angular/core": "9.0.1", "@angular/platform-browser": "9.0.1", "rxjs": "6.5.4"},
    )
    findings = audits.stack_currency_findings({"web": tmp_path / "web"}, start=7)
    assert [f["id"] for f in findings] == ["SEC-0007", "SEC-0008"]


def test_currency_never_looks_like_an_advisory(tmp_path: Path) -> None:
    """FR-009: no advisory ids or ranges — the external-merge seam cannot match."""
    _member(tmp_path, "web", {"@angular/core": "9.0.1"})
    (finding,) = audits.stack_currency_findings({"web": tmp_path / "web"})
    dependency = finding["dependency"]
    assert "advisory_ids" not in dependency
    assert "affected_range" not in dependency
    assert "fixed_version" not in dependency


def test_exposure_reflects_the_merged_packages(tmp_path: Path) -> None:
    _member(tmp_path, "web", {"@angular/core": "9.0.1"}, dev={"rxjs": "6.5.4"})
    findings = audits.stack_currency_findings({"web": tmp_path / "web"})
    by_product = {f["dependency"]["product"]: f["dependency"]["exposure"] for f in findings}
    assert by_product["angular"] == "runtime"
    assert by_product["rxjs"] == "development"
