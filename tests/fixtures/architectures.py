"""T036: the same smell in five architectures (FR-013, FR-014, FR-016).

Every member below contains **byte-identical** unsafe code — a URL built by
interpolating an unvalidated value — differing only in the manifests and entry
points that determine its execution shape.

That identical-input/different-verdict property is the sharpest available test of
the applicability relation, and nothing else in the suite provides it. Tests that
vary the code alongside the architecture cannot distinguish "the classifier
worked" from "the finding differed anyway".

Expected verdicts for a `CWE-918` finding located in `client.ts`, with no other
member reachable:

| member          | shape                  | CWE-918 verdict           |
|-----------------|------------------------|---------------------------|
| `svc-server`    | server-request-issuer  | retained                  |
| `spa-browser`   | browser-client         | remapped (impossible)     |
| `tool-cli`      | cli                    | remapped (impossible)     |
| `lib-package`   | library                | remapped (impossible)     |
| `mystery`       | undetermined           | retained — never suppress |

`mystery` is the important one: an unknown architecture must behave like the
server case, not like the browser case (FR-013a).
"""

from __future__ import annotations

import shutil
from pathlib import Path

#: Byte-identical across every member. This is the point of the fixture.
SHARED_SMELL = """export class ApiClient {
  fetchUser(host, id) {
    return fetch(host + "/user/" + id).then((r) => r.json());
  }
}
"""

MEMBERS: dict[str, dict[str, str]] = {
    "svc-server": {
        "package.json": '{\n  "name": "svc-server",\n'
        '  "dependencies": {"express": "4.18.2"}\n}\n',
        "src/client.ts": SHARED_SMELL,
        "src/server.ts": """import express from "express";
const app = express();
app.get("/user/:id", (req, res) => res.json({}));
""",
    },
    "spa-browser": {
        "package.json": '{\n  "name": "spa-browser",\n'
        '  "dependencies": {"@angular/core": "17.0.0"}\n}\n',
        "index.html": "<!doctype html>\n<html><body><app-root></app-root></body></html>\n",
        "src/client.ts": SHARED_SMELL,
    },
    "tool-cli": {
        "pyproject.toml": "[project]\nname = 'tool-cli'\n\n[project.scripts]\ntool = 'tool:main'\n",
        "src/client.ts": SHARED_SMELL,
    },
    "lib-package": {
        "pyproject.toml": "[project]\nname = 'lib-package'\nversion = '1.0.0'\n",
        "src/client.ts": SHARED_SMELL,
    },
    "mystery": {
        # No manifest, no entry point, no build marker — nothing decides the shape.
        "src/client.ts": SHARED_SMELL,
    },
}

EXPECTED_SHAPES: dict[str, str] = {
    "svc-server": "server-request-issuer",
    "spa-browser": "browser-client",
    "tool-cli": "cli",
    "lib-package": "library",
    "mystery": "undetermined",
}

#: Shapes on which CWE-918 must be RETAINED when nothing else is reachable.
#: `undetermined` appears here deliberately: an unknown never buys suppression.
RETAINS_REQUEST_FORGERY = frozenset({"server-request-issuer", "undetermined"})

DECLARED_MEMBERS = [{"name": name, "path": name} for name in sorted(MEMBERS)]


def build(root: Path) -> Path:
    workspace = root / "architectures"
    if workspace.exists():
        shutil.rmtree(workspace)
    for member, files in MEMBERS.items():
        for relative, content in files.items():
            path = workspace / member / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    return workspace
