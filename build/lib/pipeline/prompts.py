"""Prompt assembly with per-segment domain filtering (FR-011).

FR-011 requires loading *only* the guidance relevant to each segment rather than
every rule for every analysis. The segment prompt therefore ships all domain
guidance between markers, and this module emits only the bullets a segment's
domains call for — so a `quick` scan of a config module does not pay for
deserialization, SSRF, and rate-limiting guidance it will never use.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Iterable

from pipeline import resources

START_MARKER = "<!-- DOMAIN-GUIDANCE:START -->"
END_MARKER = "<!-- DOMAIN-GUIDANCE:END -->"

_BULLET = re.compile(r"^- \*\*(?P<name>[^*]+)\*\*")


@functools.cache
def _raw_prompt(name: str) -> str:
    path = resources.prompts_dir() / name
    return path.read_text() if path.exists() else ""


@functools.cache
def _parse(name: str) -> tuple[str, dict[str, str], str]:
    """Split a prompt into (head, {domain: bullet}, tail)."""
    text = _raw_prompt(name)
    if START_MARKER not in text or END_MARKER not in text:
        return text, {}, ""

    head, remainder = text.split(START_MARKER, 1)
    block, tail = remainder.split(END_MARKER, 1)

    bullets: dict[str, str] = {}
    current: str | None = None
    lines: dict[str, list[str]] = {}
    for line in block.strip("\n").splitlines():
        match = _BULLET.match(line)
        if match:
            current = match.group("name").strip()
            lines[current] = [line]
        elif current and line.strip():
            lines[current].append(line)
    for domain, collected in lines.items():
        bullets[domain] = "\n".join(collected)
    return head, bullets, tail


def available_domains(name: str = "segment_scan.md") -> list[str]:
    return sorted(_parse(name)[1])


def render_segment_prompt(
    domains: Iterable[str] | None = None, name: str = "segment_scan.md"
) -> str:
    """Return the prompt carrying guidance for ``domains`` only.

    Unknown or empty domain sets fall back to the full guidance rather than
    silently shipping a prompt with no rules at all.
    """
    head, bullets, tail = _parse(name)
    if not bullets:
        return _raw_prompt(name)

    requested = [d for d in (domains or []) if d in bullets]
    selected = requested or list(bullets)
    block = "\n".join(bullets[domain] for domain in selected)
    return f"{head}{block}\n{tail}"


def render_prompt(name: str) -> str:
    """Unfiltered prompt (system review, discovery, partition review)."""
    return _raw_prompt(name)
