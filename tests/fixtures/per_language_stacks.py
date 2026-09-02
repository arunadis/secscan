"""T056/T057: one member per grammar-backed language, each with a template.

Proves SC-007a — that template and ecosystem coverage is never narrower than code
coverage for the same stack — and covers all five security-relevant file classes
so SC-007 cannot pass on a single stack.

The `.tsx` member exists specifically because it was broken: `.tsx` was parsed
with the non-JSX TypeScript grammar, so React's `dangerouslySetInnerHTML` produced
a parse error instead of a sink (research.md A1).
"""

from __future__ import annotations

import shutil
from pathlib import Path

MEMBERS: dict[str, dict[str, str]] = {
    # --------------------------------------------------- JavaScript / TypeScript
    "web-angular": {
        "package.json": '{\n  "name": "web-angular",\n'
        '  "dependencies": {"@angular/core": "17.0.0"}\n}\n',
        "firebase.json": '{\n  "hosting": {"public": "dist"}\n}\n',
        "database.rules.json": '{\n  "rules": {".read": "auth != null"}\n}\n',
        "ngsw-config.json": '{\n  "index": "/index.html"\n}\n',
        "src/comment.component.html": '<p class="body" [innerHTML]="comment.content"></p>\n',
        "src/api.service.ts": """export class Comment {
  content = "";
}

export class ApiService {
  fetchComment(id: string) {
    return fetch(`https://api.example.com/item/${id}`).then((r) => r.json());
  }
}
""",
    },
    "web-react": {
        "package.json": '{\n  "name": "web-react",\n  "dependencies": {"react-dom": "18.2.0"}\n}\n',
        "src/Comment.tsx": """export function Comment({body}: {body: string}) {
  return <p dangerouslySetInnerHTML={{__html: body}} />;
}
""",
    },
    # ------------------------------------------------------------------- Python
    "svc-django": {
        "requirements.txt": "django==5.0\n",
        "templates/profile.djhtml": "<div>{{ about|safe }}</div>\n",
        "app/views.py": '''"""Renders a profile page."""


def profile(request, about):
    return render(request, "profile.djhtml", {"about": about})
''',
    },
    # --------------------------------------------------------------------- Java
    "svc-spring": {
        "pom.xml": "<project><artifactId>svc-spring</artifactId></project>\n",
        "src/main/webapp/user.jsp": '<c:out value="${user.about}" escapeXml="false" />\n',
        "src/main/java/App.java": """public class App {
  public String about(String value) {
    return value;
  }
}
""",
    },
    # ----------------------------------------------------------------------- Go
    "svc-go": {
        "go.mod": "module svc-go\n\ngo 1.22\n",
        "web/page.gohtml": "<div>{{ .Body }}</div>\n",
        "main.go": """package main

import "html/template"

func render(body string) template.HTML {
	return template.HTML(body)
}
""",
    },
}

#: Declared ground truth (SC-007, SC-007a).
GROUND_TRUTH = {
    "file_classes": [
        "source",
        "template",
        "dependency-manifest",
        "deploy-config",
        "datastore-rules",
        "client-cache-config",
    ],
    "template_sinks": {
        "web-angular": "[innerHTML]",
        "web-react": "dangerouslySetInnerHTML",
        "svc-django": "|safe filter",
        "svc-spring": 'escapeXml="false"',
        "svc-go": "safe-string type conversion",
    },
    "ecosystems": {
        "web-angular": "npm",
        "web-react": "npm",
        "svc-django": "pypi",
        "svc-spring": "maven",
        "svc-go": "go",
    },
}

DECLARED_MEMBERS = [{"name": name, "path": name} for name in sorted(MEMBERS)]


def build(root: Path) -> Path:
    workspace = root / "per-language-stacks"
    if workspace.exists():
        shutil.rmtree(workspace)
    for member, files in MEMBERS.items():
        for relative, content in files.items():
            path = workspace / member / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    return workspace
