"""Feature 016: unwired-connectivity fixture (FR-007 reachability gap).

A Flask-style Python service with real endpoints and real data access written in
conventions no recognizer covers (an invented `store.fetch(...)` driver and no
known wiring idioms), so flow tracing reproducibly connects zero of them.

    unwired-connectivity-app/
      requirements.txt
      src/app.py

Ground truth: zero findings expected; the FR-007 reachability declaration MUST
appear in coverage.
"""

from __future__ import annotations

import shutil
from pathlib import Path

APP_FILES: dict[str, str] = {
    "requirements.txt": "flask==3.0.0\n",
    "src/app.py": '''"""Endpoints + data access in unrecognized idioms only."""

from flask import Flask, request

app = Flask(__name__)


class Store:
    def fetch(self, statement, params):
        return []

    def mutate(self, statement, params):
        return 1


store = Store()


@app.route("/orders", methods=["GET"])
def list_orders():
    return {"orders": store.fetch("SELECT * FROM orders", ())}


@app.route("/orders", methods=["POST"])
def create_order():
    item = request.form["item"]
    store.mutate("INSERT INTO orders (item) VALUES (?)", (item,))
    return {"created": item}
''',
}

#: Declared ground truth.
GROUND_TRUTH = {
    "expected_findings": 0,
    # The exact zero-connectivity condition this fixture guarantees:
    "zero_traced_flows": True,
    # Coverage note the FR-007 declaration must produce (substring match).
    "coverage_note_contains": "reachability unconfirmed",
}


def build(root: Path) -> Path:
    """Materialize the fixture and return its root."""
    app_root = root / "unwired-connectivity-app"
    if app_root.exists():
        shutil.rmtree(app_root)
    for relative, content in APP_FILES.items():
        path = app_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return app_root
