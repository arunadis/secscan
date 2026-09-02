"""Cross-repository integration points (FR-001b, FR-001c).

v1 (US1) normalizes operator-declared integrations. Discovery/typing of inferred
integrations and dependent-segment invalidation land with US4/US5; the shapes are
fixed here so those stages layer on without schema changes.
"""

from __future__ import annotations

from typing import Any

VALID_TYPES = ("sync-api", "async-messaging", "shared-datastore", "identity-propagation")


def normalize_declared(declared: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn config-shaped integration entries into workspace-schema entries."""
    out: list[dict[str, Any]] = []
    for entry in declared or []:
        kind = str(entry.get("type", ""))
        if kind not in VALID_TYPES:
            continue
        channels = entry.get("endpoints") or entry.get("channels") or []
        out.append(
            {
                "from_repo": str(entry.get("from", "")),
                "to_repo": str(entry.get("to", "")),
                "type": kind,
                "endpoints_or_channels": [str(c) for c in channels],
                "trust_boundary": bool(entry.get("trust_boundary", True)),
                "declared": True,
                "confidence": 1.0,
            }
        )
    return sorted(out, key=lambda i: (i["from_repo"], i["to_repo"], i["type"]))


def integration_id(integration: dict[str, Any]) -> str:
    return f"{integration['from_repo']}->{integration['to_repo']}:{integration['type']}"


def segments_touching(
    integrations: list[dict[str, Any]], segments: list[dict[str, Any]], repo: str
) -> list[str]:
    """Segments in *other* repos that participate in an integration with ``repo``.

    Used by incremental scans (FR-017) so a change on one side of a boundary
    invalidates conclusions on the other.
    """
    partners: set[str] = set()
    for integration in integrations:
        if integration["from_repo"] == repo:
            partners.add(integration["to_repo"])
        elif integration["to_repo"] == repo:
            partners.add(integration["from_repo"])
    return sorted(
        segment["id"]
        for segment in segments
        if any(member in partners for member in segment["repos"])
    )
