"""T011: deterministic misconfiguration detection (FR-001, FR-002; contract D1).

Every rule in misconfig_rules.json fires on its must-find fixture and never on
its must-not-find fixture; a redaction-blocked value elsewhere in the file
changes nothing; no matched text reaches a finding field.
"""

from __future__ import annotations

import pytest

from pipeline.redact import Redactor

#: rule id -> (site, file that must fire, file that must not)
CASES: dict[str, tuple[str, str, str]] = {
    "spring-csrf-disabled": (
        "misconfig_spring",
        "src/main/java/com/example/WebSecurityConfig.java",
        "src/main/java/com/example/TightSecurityConfig.java",
    ),
    "spring-cors-wildcard": (
        "misconfig_spring",
        "src/main/java/com/example/WebSecurityConfig.java",
        "src/main/java/com/example/TightSecurityConfig.java",
    ),
    "node-cors-wildcard-credentials": (
        "misconfig_node",
        "frontend/server.js",
        "frontend/api.js",
    ),
    "node-cookie-missing-secure": (
        "misconfig_node",
        "frontend/server.js",
        "frontend/api.js",
    ),
    "django-debug-enabled": (
        "misconfig_django",
        "config/settings.py",
        "config/prod_settings.py",
    ),
    "django-allowed-hosts-wildcard": (
        "misconfig_django",
        "config/settings.py",
        "config/prod_settings.py",
    ),
    "django-cors-allow-all": (
        "misconfig_django",
        "config/settings.py",
        "config/prod_settings.py",
    ),
    "django-csrf-exempt": (
        "misconfig_django",
        "config/views.py",
        "config/prod_settings.py",
    ),
    "go-insecure-skip-verify": (
        "misconfig_go",
        "main.go",
        "server.go",
    ),
}


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_fires_on_must_find_and_not_on_must_not_find(rule_id: str) -> None:
    from pipeline import misconfig
    from tests.fixtures.missed_detection_sites import SITES

    site, find_file, miss_file = CASES[rule_id]
    files = SITES[site]
    findings = misconfig.evaluate_files(files, repo="test")
    fired = [f for f in findings if f["tool_ref"] == f"misconfig:{rule_id}"]
    assert fired, f"{rule_id} did not fire on {find_file}"
    assert all(f["location"]["file"] == find_file for f in fired)
    assert all(f["location"]["file"] != miss_file for f in fired)
    assert all(f["location"]["line_start"] >= 1 for f in fired)


def test_evidenced_cases_carry_the_expected_cwes() -> None:
    """D1: the WebSecurityConfig misses are CWE-352 and CWE-942 at exact lines."""
    from pipeline import misconfig
    from tests.fixtures.missed_detection_sites import SITES

    findings = misconfig.evaluate_files(SITES["misconfig_spring"], repo="test")
    cwes = {f["cwe"] for f in findings}
    assert "CWE-352" in cwes
    assert "CWE-942" in cwes
    csrf = [f for f in findings if f["cwe"] == "CWE-352"][0]
    line = SITES["misconfig_spring"][
        "src/main/java/com/example/WebSecurityConfig.java"
    ].splitlines()[csrf["location"]["line_start"] - 1]
    assert "csrf" in line and "disable" in line


def test_blocked_value_elsewhere_in_file_changes_nothing() -> None:
    """FR-002: redaction blocks the comment's high-entropy value; rules still fire."""
    from pipeline import misconfig
    from tests.fixtures.missed_detection_sites import SITES

    files = SITES["misconfig_spring"]
    raw = files["src/main/java/com/example/WebSecurityConfig.java"]
    redaction = Redactor().redact(raw, origin="WebSecurityConfig.java")
    assert redaction.blocked >= 1, "fixture no longer exercises a blocked value"
    findings = misconfig.evaluate_files(files, repo="test")
    assert {f["cwe"] for f in findings} >= {"CWE-352", "CWE-942"}


def test_no_matched_text_in_finding_fields() -> None:
    """D1/Principle III: findings carry file, line, rule — never matched text."""
    import json

    from pipeline import misconfig
    from tests.fixtures.missed_detection_sites import SITES

    for site, files in SITES.items():
        if not site.startswith("misconfig_"):
            continue
        for finding in misconfig.evaluate_files(files, repo="test"):
            rendered = json.dumps(finding)
            assert "Zk3Lq9Xv2Bn7Rt4Wy8Pc1Md6Hj5Gf0Ds" not in rendered
            assert 'List.of("*")' not in rendered
