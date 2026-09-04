"""Feature 014 T015: template-aware framework control evaluation (FR-005–FR-007).

Pinned contract (clarification Q2, contracts/template-controls.md):
- sink in the control's sink list + zero member-wide bypasses + full parse
  coverage  => credited
- a control_bypass annotation anywhere in the member     => bypassed (with site)
- an unparsed source file in the member                  => unassessed
- sink NOT in the sink list                              => absent (never a candidate)
- finding not about a template                           => legacy path logic unchanged
"""

from __future__ import annotations

from pipeline import controls


def _file_node(
    repo: str, path: str, parsed: bool = True, annotations: list[str] | None = None
) -> dict:
    node = {
        "id": f"{repo}:{path}",
        "repo": repo,
        "type": "file",
        "path": path,
        "language": "typescript",
        "parsed": parsed,
        "file_class": "source",
    }
    if annotations:
        node["annotations"] = annotations
    return node


def _sink_node(repo: str, path: str, marker: str, framework: str = "angular") -> dict:
    return {
        "id": f"{repo}:{path}#{marker}@3",
        "repo": repo,
        "type": "template",
        "path": path,
        "symbol": f"{marker}@3",
        "language": "html",
        "format": framework,
        "file_class": "template",
        "parsed": True,
        "annotations": ["security_sink", "template_sink"],
    }


def _finding(repo: str = "web", file: str = "src/comment.html") -> dict:
    return {
        "id": "SEC-0001",
        "cwe": "CWE-79",
        "severity_score": 8.2,
        "confidence": 0.9,
        "location": {"repo": repo, "file": file, "line_start": 3},
        "verification": {"status": "plausible", "path": []},
    }


def _graph(*nodes: dict) -> dict:
    return {"nodes": list(nodes), "edges": []}


ANGULAR = {"angular"}


def test_escaped_sink_with_no_bypass_is_credited() -> None:
    graph = _graph(
        _file_node("web", "src/api.ts"),
        _sink_node("web", "src/comment.html", "[innerhtml]"),
    )
    result = controls.evaluate(_finding(), graph, ANGULAR)
    assert result == {"state": controls.STATE_CREDITED, "control": "angular-dom-sanitizer"}


def test_sink_binding_not_in_list_is_absent_never_candidate() -> None:
    """C1 resolution: an unmatched sink is not applicable, not a triage candidate."""
    # A made-up raw sink attribute the angular control does not list.
    graph = _graph(
        _file_node("web", "src/api.ts"),
        _sink_node("web", "src/x.html", "[outerhtml]", framework="vue"),
    )
    finding = _finding(file="src/x.html")
    result = controls.evaluate(finding, graph, {"vue"})
    # vue's control lists v-html, not [outerhtml] -> not applicable.
    assert result["state"] == controls.STATE_ABSENT


def test_member_wide_bypass_withholds_credit() -> None:
    graph = _graph(
        _file_node("web", "src/api.ts", annotations=["control_bypass"]),
        _sink_node("web", "src/comment.html", "[innerhtml]"),
    )
    result = controls.evaluate(_finding(), graph, ANGULAR)
    assert result["state"] == controls.STATE_BYPASSED
    assert result["bypass_site"]["file"] == "src/api.ts"


def test_unparsed_member_file_forces_unassessed() -> None:
    graph = _graph(
        _file_node("web", "src/legacy.rb", parsed=False),
        _file_node("web", "src/api.ts"),
        _sink_node("web", "src/comment.html", "[innerhtml]"),
    )
    # unparsed node needs language the loader marks; simulate directly
    graph["nodes"][0]["language"] = "ruby"
    result = controls.evaluate(_finding(), graph, ANGULAR)
    assert result["state"] == controls.STATE_UNASSESSED
    assert "no parser" in result.get("unassessed_reason", "")


def test_bypass_in_another_member_does_not_discredit() -> None:
    graph = _graph(
        _file_node("api", "src/other.ts", annotations=["control_bypass"]),
        _file_node("web", "src/api.ts"),
        _sink_node("web", "src/comment.html", "[innerhtml]"),
    )
    result = controls.evaluate(_finding(repo="web"), graph, ANGULAR)
    assert result["state"] == controls.STATE_CREDITED


def test_non_template_finding_uses_path_logic_unchanged() -> None:
    graph = _graph(_file_node("web", "src/api.ts"))
    finding = {
        "id": "SEC-0001",
        "cwe": "CWE-79",
        "severity_score": 8.2,
        "confidence": 0.9,
        "location": {"repo": "web", "file": "src/api.ts", "line_start": 5},
        "verification": {"status": "verified", "path": ["web:src/api.ts"]},
    }
    result = controls.evaluate(finding, graph, ANGULAR)
    assert result == {"state": controls.STATE_CREDITED, "control": "angular-dom-sanitizer"}


def test_template_sink_without_matching_framework_falls_back() -> None:
    """A template file with no sink node for a present framework: not template-gated."""
    graph = _graph(
        _file_node("web", "src/api.ts"),
        _sink_node("web", "src/x.html", "v-html", framework="vue"),  # vue sink
    )
    finding = _finding(file="src/x.html")
    result = controls.evaluate(finding, graph, {"angular"})
    # the only framework present (angular) has no documented claim on vue sinks
    # -> per contract rule 1 the control is not applicable to this sink.
    assert result["state"] == controls.STATE_ABSENT
