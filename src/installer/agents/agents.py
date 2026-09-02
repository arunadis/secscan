"""Cross-vendor adapter — `.agents/skills/<name>/SKILL.md`.

The `.agents/` path is the vendor-neutral location honoured by several clients, so
it doubles as the fallback target for agents without a dedicated adapter.
"""

from __future__ import annotations

from installer.agents.base import Adapter


class AgentsAdapter(Adapter):
    key = "agents"
    label = "Cross-vendor (.agents)"
    skills_subdir = (".agents", "skills")
    invocation = "/{name}"
