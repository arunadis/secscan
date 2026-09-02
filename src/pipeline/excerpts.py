"""Redacted code excerpts for report findings (feature 005, FR-007-FR-013).

Each admitted finding gets a ``code_excerpt``: the cited lines plus a bounded
window of context, sourced from the scanned file and passed through the
Redactor — the report shows exactly the redacted view the pipeline analyzed, and
a window the redactor blocks is withheld with a stated reason (Constitution
III/V). Extraction never raises: any failure becomes ``status="unavailable"``
with a reason, so one unreadable file cannot sink report generation (FR-010).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pipeline import discover_repo, stacks
from pipeline.redact import Redactor
from pipeline.state import ArtifactStore

BLOCKED_REASON = (
    "the excerpt window contains a value that could not be confirmed as a "
    "non-credential, so it is withheld rather than shown"
)


def member_roots(store: ArtifactStore, workspace: dict[str, Any]) -> dict[str, Path]:
    """Member name -> absolute path, resolved once per report build."""
    return discover_repo.member_paths(store, workspace)


def build_excerpt(
    finding: dict[str, Any],
    *,
    roots: dict[str, Path],
    settings: Any,
    redactor: Redactor,
) -> dict[str, Any]:
    """Build the ``code_excerpt`` for one finding; never raises."""
    location = finding.get("location") or {}
    repo = str(location.get("repo", ""))
    file = str(location.get("file", ""))
    cited_start = int(location.get("line_start") or 1)
    cited_end = max(int(location.get("line_end") or cited_start), cited_start)

    base: dict[str, Any] = {
        "repo": repo,
        "file": file,
        "cited_start": cited_start,
        "cited_end": cited_end,
        "window_start": cited_start,
        "window_end": cited_end,
        "truncated": False,
    }

    root = roots.get(repo)
    if root is None:
        return {**base, "status": "unavailable",
                "reason": f"repository '{repo}' is not a workspace member on disk"}
    path = root / file
    if not path.is_file():
        return {**base, "status": "unavailable",
                "reason": "source file not found at report time"}
    try:
        text = path.read_text(errors="replace")
    except OSError as exc:
        return {**base, "status": "unavailable",
                "reason": f"source file could not be read at report time ({exc.strerror or exc})"}

    all_lines = text.splitlines()
    if not all_lines:
        return {**base, "status": "unavailable", "reason": "source file is empty"}

    cited_start = min(cited_start, len(all_lines))
    cited_end = min(cited_end, len(all_lines))
    window_start = max(1, cited_start - settings.context_lines)
    window_end = min(len(all_lines), cited_end + settings.context_lines)

    truncated = False
    if window_end - window_start + 1 > settings.max_lines:
        # Context shrinks first; the cited range is always fully included.
        truncated = True
        budget = settings.max_lines - (cited_end - cited_start + 1)
        if budget >= 0:
            before = min(cited_start - window_start, budget // 2)
            after = min(window_end - cited_end, budget - before)
            before = min(cited_start - window_start, budget - after)
            window_start = cited_start - before
            window_end = cited_end + after
        else:
            window_start, window_end = cited_start, cited_end

    window_text = "\n".join(all_lines[window_start - 1 : window_end])
    result = redactor.redact(window_text, origin=file)
    if result.blocked > 0:
        return {
            **base,
            "window_start": window_start,
            "window_end": window_end,
            "status": "unavailable",
            "reason": BLOCKED_REASON,
        }

    redacted_lines = result.text.split("\n")
    if len(redacted_lines) != window_end - window_start + 1:
        return {
            **base,
            "window_start": window_start,
            "window_end": window_end,
            "status": "unavailable",
            "reason": "excerpt lines could not be aligned after redaction",
        }

    lines: list[dict[str, Any]] = []
    for offset, line_text in enumerate(redacted_lines):
        number = window_start + offset
        line_truncated = len(line_text) > settings.max_line_length
        if line_truncated:
            line_text = line_text[: settings.max_line_length]
            truncated = True
        lines.append(
            {
                "number": number,
                "text": line_text,
                "cited": cited_start <= number <= cited_end,
                "truncated": line_truncated,
            }
        )

    excerpt: dict[str, Any] = {
        **base,
        "cited_start": cited_start,
        "cited_end": cited_end,
        "window_start": window_start,
        "window_end": window_end,
        "truncated": truncated,
        "status": "ok",
        "lines": lines,
    }
    language = _language_for(file)
    if language:
        excerpt["language"] = language
    return excerpt


def _language_for(file: str) -> str | None:
    suffix = Path(file).suffix.lower()
    language = discover_repo.any_language_for(suffix)
    if language:
        return language
    if suffix in stacks.template_suffixes():
        return "html"
    return None
