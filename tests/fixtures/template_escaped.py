"""Feature 014 T016: escaped template binding, with and without a bypass.

Reproduces the 20260904 cross-check failure: a stored-XSS claim through
``[innerHTML]`` although Angular's DomSanitizer escapes the binding and no
``bypassSecurityTrustHtml`` exists in the member.

    <root>/
      package.json       @angular/core 9.0.1
      src/comment.component.ts
      src/comment.component.html   [innerHTML] binding
      src/dom.service.ts           (bypass variant only) bypassSecurityTrustHtml

Ground truth is asserted by the benchmark gate, not restated inline.
"""

from __future__ import annotations

import shutil
from pathlib import Path

FILES: dict[str, str] = {
    "package.json": """{
  "name": "escaped-template",
  "dependencies": {
    "@angular/core": "9.0.1",
    "@angular/platform-browser": "9.0.1"
  }
}
""",
    "src/comment.component.ts": """import { Component, Input } from '@angular/core';

@Component({ selector: 'app-comment', templateUrl: './comment.component.html' })
export class CommentComponent {
  @Input() content = '';
}
""",
    "src/comment.component.html": """<div class="comment">
  <h2>Comment</h2>
  <p [innerHTML]="content"></p>
</div>
""",
}

BYPASS_FILE = """import { Injectable } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Injectable()
export class DomService {
  constructor(private sanitizer: DomSanitizer) {}

  trust(html: string): SafeHtml {
    return this.sanitizer.bypassSecurityTrustHtml(html);
  }
}
"""


def build(root: Path, *, with_bypass: bool = False) -> Path:
    """Materialize the member and return its root."""
    if root.exists():
        shutil.rmtree(root)
    for relative, content in FILES.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    if with_bypass:
        path = root / "src/dom.service.ts"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(BYPASS_FILE)
    return root
