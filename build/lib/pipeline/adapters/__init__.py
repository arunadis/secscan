"""External-tool report adapters (feature 008; completes 001 US3's seam).

Dispatch by registry tool id. Adding a tool's parser is a module change plus a
registry data entry — the pipeline never names tools directly.
"""

from __future__ import annotations

from typing import Any

from pipeline.adapters import (
    dependency_check,
    gitleaks,
    govulncheck,
    npm_audit,
    osv,
    pip_audit,
    semgrep,
    trivy,
)
from pipeline.adapters.common import AdapterError

_ADAPTERS = {
    "semgrep": semgrep.normalize,
    "gitleaks": gitleaks.normalize,
    "osv-scanner": osv.normalize,
    "trivy": trivy.normalize,
    "npm-audit": npm_audit.normalize,
    "pip-audit": pip_audit.normalize,
    "govulncheck": govulncheck.normalize,
    "owasp-dependency-check": dependency_check.normalize,
}


def normalize(tool_id: str, report_text: str, member: str) -> list[dict[str, Any]]:
    """Parse one tool's report into normalized findings; AdapterError on drift."""
    adapter = _ADAPTERS.get(tool_id)
    if adapter is None:
        raise AdapterError(f"no adapter registered for tool '{tool_id}'")
    return adapter(report_text, member)


__all__ = ["AdapterError", "normalize"]
