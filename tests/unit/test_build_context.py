"""Feature 016 T025 (US3): role-digest and guard-attachment lines in the packet
call-graph summary (FR-013/FR-016; graph-wiring contract §5)."""

from __future__ import annotations

from pathlib import Path

from pipeline import build_context
from pipeline.budget import TokenBudget
from pipeline.build_code_graph import GraphBuilder
from pipeline.extract import extract_file
from pipeline.redact import Redactor
from pipeline.state import ArtifactStore

_MIDDLEWARE = """function authenticateUser(req, res, next) {
  const e = req.headers['x-user-email'];
  req.userEmail = e;
  next();
}
"""

_GUARDED = """const { authenticateUser } = require('../middleware/auth');
const router = require('express').Router();
router.use(authenticateUser);
router.get('/', (req, res) => { res.json([]); });
"""

_UNGUARDED = """const router = require('express').Router();
router.get('/plain', (req, res) => { res.json([]); });
"""

_ALL_SAFE = """const router = require('express').Router();
router.get('/a', (req, res) => { res.json([]); });
"""


def _graph(files: dict[str, str]) -> dict:
    builder = GraphBuilder()
    for path, text in files.items():
        builder.add_file("app", extract_file(path, text, "javascript"), text)
    builder.resolve_calls()
    builder.resolve_wiring()
    builder.annotate_unattached_guards()
    return builder.to_document()


def _summary(graph: dict, files: list[str], tmp_path: Path) -> str:
    segment = {
        "id": "seg-app-backend",
        "repos": ["app"],
        "files": files,
        "entrypoints": [],
        "domains": ["authentication"],
        "purpose": "p",
    }
    store = ArtifactStore(tmp_path)
    builder = build_context.ContextBuilder(
        store, {"members": [{"name": "app", "path": "."}]}, graph,
        TokenBudget.from_dict(
            {
                "max_context_tokens": 12000,
                "max_output_tokens": 3000,
                "escalation_threshold": 0.75,
            }
        ),
        Redactor(),
    )
    return builder._call_summary(segment)


def test_digest_names_inbound_referrers(tmp_path: Path) -> None:
    graph = _graph(
        {"src/middleware/auth.js": _MIDDLEWARE, "src/routes/clients.js": _GUARDED}
    )
    summary = _summary(
        graph, ["src/middleware/auth.js", "src/routes/clients.js"], tmp_path
    )
    assert "src/middleware/auth.js" in summary
    assert "referenced from" in summary
    assert "src/routes/clients.js#authenticateUser-wiring" not in summary  # stable text check


def test_guard_attachment_named_per_route_file(tmp_path: Path) -> None:
    graph = _graph(
        {"src/middleware/auth.js": _MIDDLEWARE, "src/routes/clients.js": _GUARDED}
    )
    summary = _summary(graph, ["src/routes/clients.js"], tmp_path)
    assert "guards: authenticateUser" in summary


def test_unguarded_module_called_out_only_when_siblings_are_guarded(tmp_path: Path) -> None:
    graph = _graph(
        {
            "src/middleware/auth.js": _MIDDLEWARE,
            "src/routes/clients.js": _GUARDED,
            "src/routes/reports.js": _UNGUARDED,
        }
    )
    summary = _summary(
        graph,
        ["src/middleware/auth.js", "src/routes/clients.js", "src/routes/reports.js"],
        tmp_path,
    )
    assert any(
        line.startswith("src/routes/reports.js ::")
        and "guards: none recorded" in line
        for line in summary.splitlines()
    )


def test_no_unguarded_callout_when_no_sibling_attaches_a_guard(tmp_path: Path) -> None:
    graph = _graph({"src/routes/a.js": _ALL_SAFE, "src/routes/b.js": _ALL_SAFE})
    files = ["src/routes/a.js", "src/routes/b.js"]
    # distinct endpoint symbols keep both route-bearing
    summary = _summary(graph, files, tmp_path)
    assert "none recorded" not in summary


def test_digest_marks_unattached_guard_files(tmp_path: Path) -> None:
    graph = _graph({"src/middleware/auth.js": _MIDDLEWARE})
    summary = _summary(graph, ["src/middleware/auth.js"], tmp_path)
    assert "unattached security guard" in summary
