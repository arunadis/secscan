"""Agent adapter registry (FR-021).

Adding support for a new coding agent means adding an :class:`Adapter` subclass
here — the core skill payload never changes.
"""

from __future__ import annotations

from installer.agents.agents import AgentsAdapter
from installer.agents.base import Adapter
from installer.agents.claude import ClaudeAdapter
from installer.agents.copilot import CopilotAdapter
from installer.agents.cursor import CursorAdapter
from installer.agents.devin import DevinAdapter
from installer.agents.gemini import GeminiAdapter
from installer.agents.windsurf import WindsurfAdapter

_ADAPTER_CLASSES: tuple[type[Adapter], ...] = (
    ClaudeAdapter,
    CopilotAdapter,
    CursorAdapter,
    WindsurfAdapter,
    DevinAdapter,
    AgentsAdapter,
    GeminiAdapter,
)

ADAPTERS: dict[str, Adapter] = {cls.key: cls() for cls in _ADAPTER_CLASSES}


def get_adapter(key: str) -> Adapter:
    try:
        return ADAPTERS[key]
    except KeyError as exc:
        raise KeyError(key) from exc


def supported() -> list[str]:
    return sorted(ADAPTERS)


def describe() -> list[tuple[str, str, str]]:
    """(key, label, skills path) for help output."""
    return [
        (adapter.key, adapter.label, "/".join(adapter.skills_subdir))
        for adapter in sorted(ADAPTERS.values(), key=lambda a: a.key)
    ]


__all__ = ["ADAPTERS", "Adapter", "describe", "get_adapter", "supported"]
