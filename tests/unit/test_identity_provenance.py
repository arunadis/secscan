"""Feature 017 T005 (US1, FR-003): deterministic provenance fields — detection,
tool_ref, code_context — survive normalization untouched.

Probed provenance after the post-016 timesheet report dropped the pack finding's
record: normalization is clean, so the guarantee is pinned here.
"""

from __future__ import annotations

from pipeline.normalize_findings import FindingNormalizer

_RAW = [
    {
        "cwe": "CWE-290",
        "severity_score": 9.1,
        "confidence": 0.9,
        "detection": "format",
        "code_context": "production",
        "location": {
            "repo": "r",
            "file": "a.js",
            "symbol": "authenticateUser",
            "line_start": 4,
            "line_end": 42,
        },
        "description": "d",
        "evidence": [{"repo": "r", "file": "a.js", "symbol": "authenticateUser", "reason": "x"}],
        "attack_scenario": "a",
        "impact": "i",
        "recommendation": "rec",
        "tool_ref": "identity-archetype@1:node-header-identity-no-credential",
        "segment_id": "seg-1",
    }
]


def test_deterministic_provenance_fields_survive_normalization() -> None:
    result = FindingNormalizer().normalize(
        _RAW, source="analysis", status="local", default_repo="r", segment_id="seg-1"
    )
    assert not result.rejected
    (f,) = result.findings
    assert f["detection"] == "format"
    assert f["tool_ref"] == "identity-archetype@1:node-header-identity-no-credential"
    assert f["code_context"] == "production"
