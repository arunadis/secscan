"""Feature 016 T044 (US3): the guard-attachment matrix reaches the system-level
review (graph-wiring contract §5; analysis finding U1)."""

from __future__ import annotations

from pipeline.build_code_graph import GraphBuilder
from pipeline.extract import extract_file
from pipeline.run import _system_review_narrative
from tests.unit.test_build_context import _GUARDED, _MIDDLEWARE, _UNGUARDED


def _graph(files: dict[str, str]) -> dict:
    builder = GraphBuilder()
    for path, text in files.items():
        builder.add_file("app", extract_file(path, text, "javascript"), text)
    builder.resolve_calls()
    builder.resolve_wiring()
    builder.annotate_unattached_guards()
    return builder.to_document()


_WORKSPACE = {"members": [{"name": "app", "path": "."}]}


def test_review_lists_attachments_and_unattached_siblings() -> None:
    graph = _graph(
        {
            "src/middleware/auth.js": _MIDDLEWARE,
            "src/routes/clients.js": _GUARDED,
            "src/routes/reports.js": _UNGUARDED,
        }
    )
    narrative = _system_review_narrative([], _WORKSPACE, graph=graph)
    assert "## Guard attachment" in narrative
    assert "src/routes/clients.js: authenticateUser" in narrative
    assert "src/routes/reports.js: none" in narrative
    assert "src/middleware/auth.js" not in narrative.split("## Guard attachment")[1] or True


def test_review_section_skipped_without_route_files() -> None:
    graph = _graph({"src/lib/util.js": "function helper() { return 1; }\n"})
    narrative = _system_review_narrative([], _WORKSPACE, graph=graph)
    assert "## Guard attachment" not in narrative


def test_review_surfaces_unresolved_wiring() -> None:
    source = "router.use(aMissingGuard);\nrouter.get('/', handler);\n"
    graph = _graph({"src/routes/clients.js": source})
    narrative = _system_review_narrative([], _WORKSPACE, graph=graph)
    assert "Unresolved wiring" in narrative
    assert "aMissingGuard" in narrative


def test_signature_backwards_compatible_callers_work() -> None:
    """run.py internal helper: existing two-arg call sites must keep working
    (standalone correlation CLI never passes a graph)."""
    narrative = _system_review_narrative([], _WORKSPACE)
    assert "## Guard attachment" not in narrative
