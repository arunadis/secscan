"""T010: the CWE-798 auto-verify shortcut applies only to format detections.

Contract C4 / research R4: "presence in source is itself the finding" holds only
when presence is confirmed by a known credential format. A heuristic-only match
takes the standard trace path and cannot come out `verified` without one.
"""

from __future__ import annotations

from pipeline.verify import apply_verification

_GRAPH = {
    "nodes": [
        {"id": "repo:src/main/Auth.java", "repo": "repo", "path": "src/main/Auth.java",
         "type": "file"}
    ]
}


def _finding(detection: str | None) -> dict:
    finding = {
        "cwe": "CWE-798",
        "location": {"repo": "repo", "file": "src/main/Auth.java", "line_start": 10},
    }
    if detection is not None:
        finding["detection"] = detection
    return finding


def test_format_detection_auto_verifies() -> None:
    kept, _ = apply_verification([_finding("format")], _GRAPH, [])
    assert kept[0]["verification"]["status"] == "verified"


def test_heuristic_detection_cannot_auto_verify() -> None:
    kept, _ = apply_verification([_finding("heuristic")], _GRAPH, [])
    verdict = kept[0]["verification"]
    assert verdict["status"] == "plausible"
    assert verdict.get("gap")


def test_analysis_findings_without_provenance_auto_verify_as_before() -> None:
    """Backward compatibility: LLM-stage CWE-798 findings carry no `detection`."""
    kept, _ = apply_verification([_finding(None)], _GRAPH, [])
    assert kept[0]["verification"]["status"] == "verified"
