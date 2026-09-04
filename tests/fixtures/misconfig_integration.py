"""Feature 014 T008: misconfiguration finding for an unintegrated technology.

Reproduces the cross-check's stale-Firebase-rules shape in deterministic form:
a Flask-only member carrying a wildcard-CORS Express-style snippet with no
`cors` package declared — the configuration governs middleware that is not
integrated.

    workspace/
      api/  Flask service; stray cors() snippet; no cors dependency
"""

from __future__ import annotations

import shutil
from pathlib import Path

API_FILES: dict[str, str] = {
    "requirements.txt": "flask==3.0.0\n",
    "src/app.py": '''"""Flask service — the only actually integrated stack."""

from flask import Flask

app = Flask(__name__)


@app.route("/health")
def health():
    return {"ok": True}
''',
    # A leftover middleware snippet from the starter template; the cors package
    # it configures is not declared anywhere.
    "src/snippets.ts": '''export function stale() {
  return { origin: true, credentials: true };
}

const corsConfig = cors({ origin: true });
''',
}


def build(root: Path) -> Path:
    workspace = root / "misconfig-integration"
    if workspace.exists():
        shutil.rmtree(workspace)
    for relative, content in API_FILES.items():
        path = workspace / "api" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return workspace
