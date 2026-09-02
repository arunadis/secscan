"""005:T005-T007 — self-contained, navigable HTML rendering of the report.

Contract: specs/005-html-report-code-snippets/contracts/report-artifacts.md.
The HTML is a pure function of the report dict: constant inline CSS, no
JavaScript, every dynamic value escaped, and every internal href resolving to an
emitted anchor (FR-002-FR-006).
"""

from __future__ import annotations

import re

import pytest

from pipeline.render_html import anchor_for, render_html


def make_finding(
    finding_id: str,
    band: str = "High",
    description: str = "A description.",
    evidence_file: str = "src/app.py",
) -> dict:
    return {
        "id": finding_id,
        "cwe": "CWE-89",
        "severity_score": 8.0,
        "severity_band": band,
        "confidence": 0.9,
        "location": {
            "repo": "shop",
            "file": evidence_file,
            "symbol": "handler",
            "line_start": 10,
            "line_end": 12,
            "tier": "symbol",
        },
        "description": description,
        "evidence": [
            {"repo": "shop", "file": evidence_file, "symbol": "handler", "reason": "why"}
        ],
        "attack_scenario": "scenario",
        "impact": "impact",
        "recommendation": "fix it",
        "verification": {"status": "plausible"},
    }


def make_report(findings: list[dict]) -> dict:
    grouped: dict[str, list[dict]] = {}
    for finding in findings:
        grouped.setdefault(finding["severity_band"], []).append(finding)
    return {
        "scan_id": "20260901-000000-test",
        "workspace": {"id": "ws-test", "members": ["shop"]},
        "execution_mode": "endpoint-batch",
        "profile": {"name": "full"},
        "executive_summary": "Summary text.",
        "findings_by_band": grouped,
        "recommendations": [],
        "coverage": {"repos_analyzed": ["shop"], "segments_analyzed": 1, "clean": False},
        "usage": {
            "segments": [],
            "totals": {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0},
        },
    }


# ------------------------------------------------------------------ T005


def test_anchor_for_is_stable_and_sanitized() -> None:
    assert anchor_for("SEC-0001") == "finding-SEC-0001"
    assert anchor_for("SEC-0001") == anchor_for("SEC-0001")
    sanitized = anchor_for("shop:src/app.py#get /orders")
    assert re.fullmatch(r"finding-[A-Za-z0-9\-_]+", sanitized)


def test_anchor_collisions_are_rejected() -> None:
    """Two ids that sanitize to the same anchor must not silently collide."""
    report = make_report([make_finding("SEC 1"), make_finding("SEC-1")])
    with pytest.raises(ValueError, match="anchor"):
        render_html(report)


# ------------------------------------------------------------------ T006


def test_index_is_grouped_by_band_and_every_entry_resolves() -> None:
    findings = [
        make_finding("SEC-0001", band="Critical"),
        make_finding("SEC-0002", band="High"),
        make_finding("SEC-0003", band="High"),
        make_finding("SEC-0004", band="Low"),
    ]
    html = render_html(make_report(findings))

    index = html.split('id="index"', 1)[1].split("<main", 1)[0]
    assert index.index("Critical") < index.index("High") < index.index("Low")

    emitted_ids = set(re.findall(r'id="([^"]+)"', html))
    for finding in findings:
        anchor = anchor_for(finding["id"])
        assert anchor in emitted_ids
        assert f'href="#{anchor}"' in index  # index entry jumps to the finding
        # Back-link: the finding's own section links back to the index.
        section = html.split(f'id="{anchor}"', 1)[1]
        assert 'href="#index"' in section.split("</section>", 1)[0]


def test_every_internal_href_resolves() -> None:
    html = render_html(
        make_report([make_finding("SEC-0001"), make_finding("SEC-0002", band="Medium")])
    )
    emitted_ids = set(re.findall(r'id="([^"]+)"', html))
    for href in re.findall(r'href="#([^"]+)"', html):
        assert href in emitted_ids, f"dangling reference to #{href}"


# ------------------------------------------------------------------ T007


def test_html_is_self_contained_and_scriptless() -> None:
    html = render_html(make_report([make_finding("SEC-0001")]))
    assert "<script" not in html
    assert "<link" not in html
    assert "@import" not in html
    assert "http://" not in html and "https://" not in html
    assert "<style>" in html  # styling is inline, not external


def test_dynamic_content_is_escaped() -> None:
    hostile = '<script>alert("xss")</script><b>bold</b>'
    html = render_html(make_report([make_finding("SEC-0001", description=hostile)]))
    assert hostile not in html
    assert "&lt;script&gt;" in html


# ------------------------------------------------- feature 008 remediation


def test_external_tool_limitations_render_in_coverage() -> None:
    """E2: the External tooling section exists in HTML as in markdown (FR-009)."""
    report = make_report([])
    report["coverage"]["tool_limitations"] = [
        {
            "tool_id": "npm-audit",
            "status": "missing",
            "reason": "not installed; run init to provision",
            "affected_ecosystems": ["npm"],
        }
    ]
    html = render_html(report)
    assert "External tool: npm-audit" in html
    assert "not installed; run init to provision" in html


def test_suppressed_findings_render_section() -> None:
    """E2: the Suppressed findings section exists in HTML (FR-007)."""
    report = make_report([])
    report["suppressions"] = [
        {
            "finding": {
                "tool_ref": "osv-scanner",
                "description": "ghost-lib has a known advisory",
                "location": {"file": "package-lock.json"},
            },
            "tool_id": "osv-scanner",
            "disproof_ground": "package-absent",
            "evidence": ["no resolved pin for 'ghost-lib'"],
        }
    ]
    html = render_html(report)
    assert 'id="suppressions"' in html
    assert "Suppressed external findings (1)" in html
    assert "package-absent" in html and "no resolved pin" in html
