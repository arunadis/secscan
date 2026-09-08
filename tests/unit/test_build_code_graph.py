"""Feature 016 T010/T011/T043: wiring resolution and unattached-guard annotation
(graph-wiring contract §2/§3/§6)."""

from __future__ import annotations

from pipeline.build_code_graph import GraphBuilder
from pipeline.extract import extract_file

_REPO = "app"

_MIDDLEWARE = """function authenticateUser(req, res, next) {
  const e = req.headers['x-user-email'];
  req.userEmail = e;
  next();
}
"""

_ROUTES = """const { authenticateUser } = require('../middleware/auth');
const router = require('express').Router();

router.use(authenticateUser);

router.get('/', (req, res) => {
  res.json([]);
});

router.get('/me', authenticateUser, (req, res) => {
  res.json({});
});
"""

_ALT_ROUTES = """router.get('/public', (req, res) => {
  res.json({});
});
"""

_SCAFFOLD_TEST = """const { authenticateUser } = require('../../middleware/auth');
// tests exercise the middleware directly
"""


def _graph(files: dict[str, str]) -> dict:
    builder = GraphBuilder()
    for path, text in files.items():
        facts = extract_file(path, text, "javascript")
        builder.add_file(_REPO, facts, text)
    builder.resolve_calls()
    builder.resolve_wiring()
    builder.annotate_unattached_guards()
    return builder.to_document()


def _edges(graph: dict, kind: str) -> set[tuple[str, str]]:
    return {(e["from"], e["to"]) for e in graph["edges"] if e["type"] == kind}


def test_router_use_creates_calls_edge_to_the_guard() -> None:
    graph = _graph(
        {"src/middleware/auth.js": _MIDDLEWARE, "src/routes/clients.js": _ROUTES}
    )
    assert (
        f"{_REPO}:src/routes/clients.js",
        f"{_REPO}:src/middleware/auth.js#authenticateUser",
    ) in _edges(graph, "calls")


def test_module_scope_use_guards_every_endpoint_in_the_file() -> None:
    graph = _graph(
        {"src/middleware/auth.js": _MIDDLEWARE, "src/routes/clients.js": _ROUTES}
    )
    handlers = _edges(graph, "handler")
    guard = f"{_REPO}:src/middleware/auth.js#authenticateUser"
    assert (f"{_REPO}:src/routes/clients.js#@GET /", guard) in handlers


def test_route_argument_middleware_guards_that_route() -> None:
    graph = _graph(
        {"src/middleware/auth.js": _MIDDLEWARE, "src/routes/clients.js": _ROUTES}
    )
    handlers = _edges(graph, "handler")
    guard = f"{_REPO}:src/middleware/auth.js#authenticateUser"
    assert (f"{_REPO}:src/routes/clients.js#@GET /me", guard) in handlers


def test_route_scoped_wiring_does_not_leak_into_other_files() -> None:
    graph = _graph(
        {
            "src/middleware/auth.js": _MIDDLEWARE,
            "src/routes/clients.js": _ROUTES,
            "src/routes/public.js": _ALT_ROUTES,
        }
    )
    handlers = _edges(graph, "handler")
    assert not any("public.js" in source for source, _ in handlers)


def test_unknown_wiring_target_creates_no_edge_but_is_recorded() -> None:
    routes = "router.use(aMissingGuard);\nrouter.get('/', handler);\n"
    graph = _graph({"src/routes/clients.js": routes})
    assert _edges(graph, "handler") == set()
    uw = graph.get("unresolved_wiring") or []
    assert [e["name"] for e in uw] == ["aMissingGuard", "handler"]
    assert uw[0]["file"] == "src/routes/clients.js"
    assert uw[0]["reason"].startswith("no in-repo symbol")


def test_unresolved_wiring_present_even_when_empty() -> None:
    graph = _graph(
        {"src/middleware/auth.js": _MIDDLEWARE, "src/routes/clients.js": _ROUTES}
    )
    assert graph["unresolved_wiring"] == []


def test_guard_only_test_referenced_is_unattached() -> None:
    graph = _graph(
        {
            "src/middleware/auth.js": _MIDDLEWARE,
            "src/__tests__/auth.test.js": _SCAFFOLD_TEST,
        }
    )
    node = next(
        n for n in graph["nodes"]
        if n.get("symbol") == "authenticateUser" and n.get("type") == "function"
    )
    assert "unattached_security_guard" in node["annotations"]


def test_wired_guard_is_not_marked_unattached() -> None:
    graph = _graph(
        {"src/middleware/auth.js": _MIDDLEWARE, "src/routes/clients.js": _ROUTES}
    )
    node = next(
        n for n in graph["nodes"]
        if n.get("symbol") == "authenticateUser" and n.get("type") == "function"
    )
    assert "unattached_security_guard" not in node.get("annotations", [])


def test_non_guard_functions_never_carry_the_annotation() -> None:
    graph = _graph({"src/lib/list.js": "function listOrders(db) { return db.all; }\n"})
    node = next(n for n in graph["nodes"] if n.get("symbol") == "listOrders")
    assert "unattached_security_guard" not in node.get("annotations", [])
