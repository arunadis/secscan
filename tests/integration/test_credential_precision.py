"""T018: credential precision end to end (feature 003, quickstart Scenario 5).

A full scan over a fixture workspace that reproduces the audited false-positive
classes (SEC-0085 identifier names, a heuristic-only properties secret, a
test-code credential) alongside a genuine format-matched credential. Asserts:
identifiers produce no finding, real credentials are found and graded honestly,
suppression decisions are inspectable in the packet artifacts, and no credential
value reaches any artifact (FR-004, FR-008, FR-010; SC-001, SC-002, SC-004).
"""

from __future__ import annotations

import json

import pytest

from pipeline import run as run_mod
from tests.integration.conftest import silent_responder, write_config

#: A real credential format seeded in production code (synthetic value).
GOOGLE_KEY = "AIzaSyD-1234567890abcdefghijklmnopqrstu"

_FILES = {
    # SEC-0085 class: camelCase identifiers embedding credential words — none of
    # these is a credential. The doc comment's "password" marks the file as
    # sensitive_data so the level-1 packet includes it.
    "src/main/java/com/example/TokenCosts.java": (
        "package com.example;\n"
        "\n"
        "/** Pricing for password-protected model calls. */\n"
        "public class TokenCosts {\n"
        "  private Double openaiModelInputTokenCostGpt51ChatLatest;\n"
        "  private Double openaiModelOutputTokenCostGpt51ChatLatest;\n"
        "}\n"
    ),
    # True positives: a format-matched credential and a heuristic-only
    # high-entropy value on a credential-named key, both in production code.
    "src/main/java/com/example/AuthConfig.java": (
        "package com.example;\n"
        "\n"
        "public class AuthConfig {\n"
        f'  private static final String apiKey = "{GOOGLE_KEY}";\n'
        '  private String jwtSecret = "nRvyYC4soFxBdZ5Nnzz5USXstR1YylsTd-mA0aKtI9HU'
        'lriGrtkfTiuDapkLiUCog";\n'
        "}\n"
    ),
    # Feature 010 (SEC-0080 class): credential-named variables assigned from
    # other environment variables. Runtime wiring, not credentials — and the
    # classification is path-agnostic (FR-000), so a migration script and a
    # compose file are both exercised.
    "migration/p0/verify-account.sh": (
        "#!/usr/bin/env bash\n"
        "use_prod() {\n"
        '  export AWS_ACCESS_KEY_ID="$AWS_DEVIN_PROD_ACCESS_KEY_ID"\n'
        '  export AWS_SECRET_ACCESS_KEY="$AWS_DEVIN_PROD_SECRET_ACCESS_KEY"\n'
        "  unset AWS_SESSION_TOKEN || true\n"
        "}\n"
        "\n"
        "use_dev() {\n"
        '  export AWS_ACCESS_KEY_ID="$AWS_DEVIN_READONLY_ACCESS_KEY_ID"\n'
        '  export AWS_SECRET_ACCESS_KEY="$AWS_DEVIN_READONLY_SECRET_ACCESS_KEY"\n'
        "  unset AWS_SESSION_TOKEN || true\n"
        "}\n"
    ),
    "deploy/docker-compose.yml": (
        "services:\n"
        "  api:\n"
        "    environment:\n"
        '      DB_PASSWORD: "${DB_PASSWORD:?DB_PASSWORD is required}"\n'
        '      API_TOKEN: "%API_TOKEN%"\n'
    ),
    # Test-code credential: reported, graded lower (FR-010).
    "src/test/java/com/example/AuthTest.java": (
        "package com.example;\n"
        "public class AuthTest {\n"
        '  private static final String SECRET = "testSigningKeyForUnitTestsOnly1234'
        '567890abcdefghij";\n'
        "}\n"
    ),
}


@pytest.fixture(scope="module")
def scanned(tmp_path_factory):
    root = tmp_path_factory.mktemp("credential-precision")
    for relpath, content in _FILES.items():
        target = root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    write_config(root)
    result = run_mod.run_scan(root, responder=silent_responder, full=True)
    correlated = json.loads((root / ".secscan" / "findings" / "correlated.json").read_text())[
        "payload"
    ]
    return root, result, [f for f in correlated["findings"] if f["cwe"] == "CWE-798"]


def _by_file(findings: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for finding in findings:
        out.setdefault(finding["location"]["file"], []).append(finding)
    return out


def test_identifier_false_positives_produce_no_finding(scanned) -> None:
    """SC-001: the SEC-0085 class is silent end to end."""
    _, _, findings = scanned
    assert "src/main/java/com/example/TokenCosts.java" not in _by_file(findings)


def test_format_credential_is_found_and_verified(scanned) -> None:
    _, _, findings = scanned
    finding = [
        f
        for f in _by_file(findings)["src/main/java/com/example/AuthConfig.java"]
        if f["detection"] == "format"
    ][0]
    assert finding["code_context"] == "production"
    # Calibration may cap the published confidence; the emitted value is 0.95.
    proposed = (finding.get("calibration") or {}).get("proposed_confidence")
    assert (proposed if proposed is not None else finding["confidence"]) == 0.95
    assert finding["verification"]["status"] == "verified"


def test_heuristic_finding_is_honestly_graded(scanned) -> None:
    """FR-008/FR-009: heuristic-only, lower confidence, never verified."""
    _, _, findings = scanned
    by_file = _by_file(findings)["src/main/java/com/example/AuthConfig.java"]
    finding = [f for f in by_file if f["detection"] == "heuristic"][0]
    format_finding = [f for f in by_file if f["detection"] == "format"][0]
    assert finding["confidence"] < format_finding["confidence"]
    assert finding["verification"]["status"] != "verified"
    assert "review" in finding["description"].lower()


def test_test_code_credential_is_reported_at_reduced_grading(scanned) -> None:
    """FR-010: reported — never suppressed — but calibrated."""
    _, _, findings = scanned
    by_file = _by_file(findings)
    prod = by_file["src/main/java/com/example/AuthConfig.java"][0]
    test = by_file["src/test/java/com/example/AuthTest.java"][0]
    assert test["code_context"] == "test"
    assert test["confidence"] < prod["confidence"]
    assert test["severity_score"] < prod["severity_score"]
    assert "test" in test["description"].lower()


def test_suppression_decisions_are_inspectable_in_artifacts(scanned) -> None:
    """FR-004/SC-004: every exemption recorded with origin, line, rule, reason."""
    root, _, _ = scanned
    packets = sorted((root / ".secscan" / "context-packets").glob("*.json"))
    assert packets
    exempted = [
        item
        for packet in packets
        for item in json.loads(packet.read_text())["payload"]["redaction"].get(
            "exempted_items", []
        )
    ]
    ours = [e for e in exempted if e["origin"].endswith("TokenCosts.java")]
    assert ours, "no exemption recorded for the identifier file"
    for entry in ours:
        assert entry["line"] >= 1
        assert entry["rule"] == "entropy-candidate"
        assert entry["reason"]
        assert entry["decision"] in ("exempt-identifier", "exempt-message")
        assert "value" not in entry  # values never appear in artifacts


def test_runtime_references_produce_no_finding(scanned) -> None:
    """Feature 010 SC-001 / FR-000: `"$VAR"` wiring is silent end to end, at any path."""
    _, _, findings = scanned
    by_file = _by_file(findings)
    assert not [f for f in by_file if f.startswith(("migration/", "deploy/"))], by_file.keys()
    # The genuine format-matched credential is unaffected.
    assert any(
        f["detection"] == "format"
        for f in by_file["src/main/java/com/example/AuthConfig.java"]
    )


def test_runtime_reference_exemptions_are_inspectable_in_artifacts(scanned) -> None:
    """Feature 010 FR-005 / SC-004: every reference exemption is recorded, never silent."""
    root, _, _ = scanned
    exempted = [
        item
        for packet in sorted((root / ".secscan" / "context-packets").glob("*.json"))
        for item in json.loads(packet.read_text())["payload"]["redaction"].get(
            "exempted_items", []
        )
        if item["decision"] == "exempt-reference"
    ]
    origins = {e["origin"] for e in exempted}
    assert any(o.endswith("verify-account.sh") for o in origins), origins
    for entry in exempted:
        assert entry["classification"].startswith("runtime-reference:")
        assert entry["rule"] in ("assigned-secret", "entropy-candidate")
        assert entry["reason"]
        assert "value" not in entry


def test_no_credential_value_reaches_any_artifact(scanned) -> None:
    """C5: the seeded production credential appears nowhere on disk."""
    root, _, _ = scanned
    for artifact in (root / ".secscan").rglob("*"):
        if artifact.is_file():
            assert GOOGLE_KEY not in artifact.read_text(errors="replace"), artifact
