"""Feature 014 T006: seeded workspace for dependency usage evidence.

Two members pin known-vulnerable packages from the bundled npm snapshot:

    workspace/
      stale/     pins marked 1.1.1, never imports it (bundled advisory <4.0.10)
      consumer/  pins minimist 1.2.5 AND imports it (bundled advisory <1.2.6)

Declared ground truth is asserted by the benchmark gate, not restated inline.
"""

from __future__ import annotations

import shutil
from pathlib import Path

STALE_FILES: dict[str, str] = {
    "package.json": """{
  "name": "stale",
  "dependencies": {
    "marked": "1.1.1",
    "unfetch": "5.0.0"
  }
}
""",
    "index.html": "<!doctype html>\n<html><body></body></html>\n",
    "src/api.ts": """/** Fetches data without touching the declared `marked` package. */
import { fetch } from 'unfetch';

export function loadUser(id: string) {
  return fetch(`/api/user/${id}`).then((r) => r.json());
}
""",
}

CONSUMER_FILES: dict[str, str] = {
    "package.json": """{
  "name": "consumer",
  "dependencies": {
    "minimist": "1.2.5"
  }
}
""",
    "src/cli.ts": """/** Parses CLI arguments with the declared (vulnerable) minimist. */
import parseArgs from 'minimist';

export function parse(argv: string[]) {
  return parseArgs(argv);
}
""",
}


def build(root: Path) -> Path:
    """Materialize the workspace and return its root."""
    workspace = root / "dependency-usage"
    if workspace.exists():
        shutil.rmtree(workspace)
    for member, files in (("stale", STALE_FILES), ("consumer", CONSUMER_FILES)):
        for relative, content in files.items():
            path = workspace / member / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    return workspace


#: Declared ground truth, asserted by tests rather than restated inline.
GROUND_TRUTH = {
    "advisory_packages": {"stale": "marked", "consumer": "minimist"},
    "expected_usage_state": {"stale": "none-found", "consumer": "found"},
}
