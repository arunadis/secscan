"""T037: a seeded multi-member workspace (FR-043a).

Multi-member behaviour cannot be observed on a single repository, and four of the
decisions this feature rests on only manifest with two or more members:

* **cross-member applicability** (FR-015a) — a browser-only client whose value
  reaches a sibling that *does* issue server-side requests must keep the
  server-side weakness class. Without this fixture, the applicability relation
  could introduce a false-negative class that does not exist today and no test
  would notice.
* **host ownership** (FR-024a) — a hard-coded host pointing at a sibling is
  internal; an unowned third-party host is not.
* **mixed ecosystems** (FR-030a) — one member on npm, another on PyPI.
* **path-scoped bypass detection** (FR-022) — a bypass in one member must not
  discredit a control in another.

Layout: the workspace root holds two members, discovered automatically.

    workspace/
      web/    browser-only Angular client, calls the api member
      api/    Flask service that issues outbound requests
"""

from __future__ import annotations

import shutil
from pathlib import Path

WEB_FILES: dict[str, str] = {
    "package.json": """{
  "name": "web",
  "dependencies": {
    "@angular/core": "9.0.1",
    "@angular/platform-browser": "9.0.1"
  }
}
""",
    "index.html": "<!doctype html>\n<html><body><app-root></app-root></body></html>\n",
    "src/api/client.ts": '''/** Talks to the sibling `api` member and to a third-party host. */
export class ApiClient {
  private baseUrl = "https://api/v1";
  private upstream = "https://feeds.thirdparty.example";

  fetchUser(id: string) {
    return fetch(`${this.baseUrl}/user/${id}`).then((r) => r.json());
  }

  fetchUpstream(topic: string) {
    return fetch(`${this.upstream}/topics/${topic}`).then((r) => r.json());
  }
}
''',
    "src/render/comment.component.ts": '''/** Renders comment bodies supplied by the API. */
export class CommentComponent {
  content = "";

  update(body: string) {
    this.content = body;
  }
}
''',
}

API_FILES: dict[str, str] = {
    "requirements.txt": "flask==3.0.0\nrequests==2.31.0\n",
    "src/app.py": '''"""Sibling service: issues server-side requests on behalf of callers."""

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/v1/user/<user_id>", methods=["GET"])
def get_user(user_id):
    """Fetches from an upstream chosen partly by the caller."""
    return requests.get(f"https://directory.internal/users/{user_id}").json()
''',
}


def build(root: Path) -> Path:
    """Materialize the workspace and return its root."""
    workspace = root / "multi-member-workspace"
    if workspace.exists():
        shutil.rmtree(workspace)
    for member, files in (("web", WEB_FILES), ("api", API_FILES)):
        for relative, content in files.items():
            path = workspace / member / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    return workspace


#: Declared ground truth, asserted by tests rather than restated inline.
GROUND_TRUTH = {
    "members": {"web": "browser-client", "api": "server-request-issuer"},
    "internal_hosts": ["api"],
    "external_hosts": ["feeds.thirdparty.example"],
    "ecosystems": {"web": "npm", "api": "pypi"},
    # A request-forgery finding located in `web` must be RETAINED, because `api`
    # is reachable from it and does issue server-side requests (FR-015a).
    "retain_cwe_918_in": "web",
}
