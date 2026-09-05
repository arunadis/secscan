"""Feature 015: a seeded multi-repo business-flow workspace fixture.

Layout: three members, discovered automatically under the workspace root.

    flow-workspace/
      web/      browser client; calls the api member (declared integration)
      api/      order service; serves web and DISPATCHES to worker (undeclared hop)
      worker/   job executor with the privileged mutation

Declared integration (config workspace.integrations): web -> api, type sync-api.
Undeclared hop: api -> worker over HTTP. The business flow web->api is stitched; the
flow branch touching worker is explicitly partial (integration-undeclared), declared
in flow coverage, never inferred.
"""

from __future__ import annotations

import shutil
from pathlib import Path

WEB_FILES: dict[str, str] = {
    "package.json": '{\n  "name": "web"\n}\n',
    "src/client.ts": '''/** Calls the sibling api member. */
export async function submitOrder(item: string) {
  return fetch("https://api/v1/orders", {
    method: "POST",
    body: JSON.stringify({ item }),
  });
}
''',
}

API_FILES: dict[str, str] = {
    "requirements.txt": "flask==3.0.0\nrequests==2.31.0\n",
    "src/orders.py": '''"""Order service: entry for web; dispatches jobs to worker."""

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/v1/orders", methods=["POST"])
def create_order():
    """Transition step: records the order, then dispatches fulfillment."""
    item = request.json["item"]
    order_id = f"ord-{item}"
    # Undeclared cross-repo hop: worker is not a declared integration.
    requests.post("http://worker/jobs", json={"order_id": order_id})
    return {"order_id": order_id}
''',
}

WORKER_FILES: dict[str, str] = {
    "requirements.txt": "flask==3.0.0\n",
    "src/jobs.py": '''"""Job executor: privileged fulfillment mutation."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/jobs", methods=["POST"])
def run_job():
    """Terminal mutation: marks fulfillment complete. No auth boundary here."""
    order_id = request.json["order_id"]
    db = sqlite3.connect("jobs.db")
    db.execute("INSERT INTO jobs (order_id, status) VALUES (?, 'done')", (order_id,))
    return {"ok": True}
''',
}


def build(root: Path) -> Path:
    """Materialize the workspace and return its root."""
    workspace = root / "flow-workspace"
    if workspace.exists():
        shutil.rmtree(workspace)
    for member, files in (
        ("web", WEB_FILES),
        ("api", API_FILES),
        ("worker", WORKER_FILES),
    ):
        for relative, content in files.items():
            path = workspace / member / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    return workspace


#: Config fragment the tests merge into `.secscan/config.yaml` so the declared
#: web -> api integration is known (with its route surface) while api -> worker
#: stays undeclared.
DECLARED_INTEGRATIONS = [
    {
        "from": "web",
        "to": "api",
        "type": "sync-api",
        "endpoints": ["POST /v1/orders"],
    },
]

#: Declared ground truth, asserted by tests rather than restated inline.
GROUND_TRUTH = {
    "members": {"web", "api", "worker"},
    # web -> api is declared: those steps MUST stitch into one flow (FR-015).
    "stitched_repos_in_flow": {"web", "api"},
    # The api -> worker hop is undeclared: any flow touching it is partial (FR-016)
    # with this exact reason, declared in coverage.
    "partial_reason": "integration-undeclared",
    # Steps keep repo attribution.
    "step_repos": {"web", "api"},
}
