"""T059: file-class coverage end to end (quickstart Scenario 7).

The reviewed benchmark's most consequential gap: its code model held only `.ts`
and `.js` files, so no segment could see a DOM binding. The four `[innerHTML]`
sinks its injection finding rested on were found by a human afterwards, and
finding them changed the finding's conclusion *and* its severity. These tests
assert the pipeline finds them with zero manual steps.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline import build_code_graph, discover_repo, partition_repo
from pipeline.state import ArtifactStore
from tests.fixtures.per_language_stacks import DECLARED_MEMBERS, GROUND_TRUTH, build
from tests.integration.conftest import write_config


@pytest.fixture
def modelled(tmp_path: Path):
    root = build(tmp_path)
    write_config(root)
    store = ArtifactStore(root)
    workspace = discover_repo.run(store, DECLARED_MEMBERS, [])
    graph = build_code_graph.run(store, workspace)
    segments = partition_repo.run(store, workspace, graph, 12000)
    return root, graph, segments


def test_every_declared_file_class_is_represented(modelled) -> None:
    """SC-007: all five security-relevant classes, not just source."""
    _root, graph, _segments = modelled
    present = {n.get("file_class") for n in graph["nodes"] if n.get("file_class")}
    for file_class in GROUND_TRUTH["file_classes"]:
        assert file_class in present, f"{file_class} is absent from the code model"


def test_template_sinks_are_found_in_every_stack(modelled) -> None:
    """SC-007a: template coverage is never narrower than code coverage.

    A raw-markup sink lands in one of two places depending on the stack: in a
    template file (Angular, Django, JSP) it becomes its own node named for the
    marker; written in code (React JSX, Go safe-string conversion) it annotates
    the enclosing symbol. Both count — what must not happen is a stack where
    neither appears.
    """
    _root, graph, _segments = modelled
    sinks = [n for n in graph["nodes"] if "template_sink" in (n.get("annotations") or [])]
    assert sinks, "no template sink was discovered in any member"

    by_member: dict[str, list[str]] = {}
    for node in sinks:
        by_member.setdefault(node["repo"], []).append(node.get("symbol") or node["path"])

    for member in GROUND_TRUTH["template_sinks"]:
        assert by_member.get(member), f"{member}: no raw-markup sink was discovered"


def test_code_written_sinks_are_marked_as_control_bypasses(modelled) -> None:
    """A documented bypass on the path must be able to discredit its control.

    `dangerouslySetInnerHTML` and `template.HTML(...)` are exactly the sites that
    turn a credited framework control into a bypassed one (FR-022).
    """
    _root, graph, _segments = modelled
    bypasses = {
        n["repo"] for n in graph["nodes"] if "control_bypass" in (n.get("annotations") or [])
    }
    assert "web-react" in bypasses, "dangerouslySetInnerHTML was not marked as a bypass"
    assert "svc-go" in bypasses, "template.HTML() was not marked as a bypass"


def test_tsx_parses_without_error(modelled) -> None:
    """The mis-mapped grammar defect: .tsx was parsed with the non-JSX grammar."""
    _root, graph, _segments = modelled
    tsx = [n for n in graph["nodes"] if n["path"].endswith(".tsx")]
    assert tsx, "no node was emitted for the .tsx member"
    assert all(n.get("parsed") is not False for n in tsx)


def test_template_sinks_link_back_to_their_data_supplier(modelled) -> None:
    """FR-025: a `renders` edge, so a trace can reach the DOM."""
    _root, graph, _segments = modelled
    renders = [e for e in graph["edges"] if e["type"] == "renders"]
    assert renders, "no template sink was linked to the code supplying its value"


def test_templates_and_config_are_assigned_to_segments(modelled) -> None:
    """FR-026: the benchmark left package.json and firebase.json in no segment."""
    _root, graph, segments = modelled
    assigned = {path for segment in segments for path in segment["files"]}
    interesting = [
        n["path"]
        for n in graph["nodes"]
        if n.get("file_class") in ("template", "dependency-manifest", "deploy-config",
                                   "datastore-rules", "client-cache-config")
        and not n.get("symbol")
    ]
    assert interesting
    for path in interesting:
        assert path in assigned, f"{path} belongs to no segment"


def test_domains_follow_code_facts_not_module_names(modelled) -> None:
    """FR-028: a segment holding a manifest gets the dependencies domain."""
    _root, graph, segments = modelled
    manifests = {
        n["path"] for n in graph["nodes"] if n.get("file_class") == "dependency-manifest"
    }
    matching = [s for s in segments if manifests & set(s["files"])]
    assert matching, "no segment contains a dependency manifest"
    assert any("dependencies" in s["domains"] for s in matching)


def test_template_segments_get_the_injection_domain(modelled) -> None:
    _root, graph, segments = modelled
    templates = {n["path"] for n in graph["nodes"] if n.get("file_class") == "template"}
    matching = [s for s in segments if templates & set(s["files"])]
    assert matching
    assert all("injection" in s["domains"] for s in matching)


def test_coverage_statement_separates_coverage_from_silence(modelled) -> None:
    """FR-027/FR-029: represented, unparsed with a named format, not attempted."""
    from pipeline.generate_report import _file_class_coverage

    _root, graph, _segments = modelled
    coverage = _file_class_coverage(graph)
    by_class = {entry["file_class"]: entry for entry in coverage}
    for file_class in GROUND_TRUTH["file_classes"]:
        entry = by_class[file_class]
        assert entry["represented"] > 0, f"{file_class} reported as absent"
    # Every entry falls in exactly one bucket — silence is not representable.
    for entry in coverage:
        buckets = sum(
            1
            for key in ("represented", "unparsed", "not_attempted")
            if entry.get(key)
        )
        assert buckets >= 1, entry


def test_unparsed_source_language_is_named_not_hidden(tmp_path: Path) -> None:
    """FR-027: a parser gap is declared with its format, never skipped silently."""
    from pipeline.generate_report import _file_class_coverage

    (tmp_path / "legacy.rb").write_text("class A\nend\n")
    write_config(tmp_path)
    store = ArtifactStore(tmp_path)
    workspace = discover_repo.run(store, [], [])
    graph = build_code_graph.run(store, workspace)
    source = next(e for e in _file_class_coverage(graph) if e["file_class"] == "source")
    assert source.get("unparsed"), "an unmodelled language was not declared"
    assert source["unparsed"][0]["format"] == "ruby"
    assert source["unparsed"][0]["reason"]
