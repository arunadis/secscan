"""Host ownership: workspace-internal vs genuinely third-party (FR-024–FR-024b).

The reviewed benchmark's real top risk behind its injection finding was trust in
an unowned third-party host hard-coded as the application's only data source —
reported, but as a secondary note on a weakness class that did not apply. This
module exists so that trust boundary can be minted as a finding in its own right.

The asymmetry with the applicability relation is deliberate and worth naming. There,
an unknown retains a finding by *not suppressing*. Here, an unknown retains it by
*defaulting to external*. Both directions serve the same rule: an unknown never
buys silence. What must never happen is a genuinely unowned host being silently
exempted because ownership could not be worked out.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

INTERNAL = "internal"
EXTERNAL = "external"
UNDETERMINED = "undetermined"

#: Hosts that are never a third-party trust boundary.
_LOCAL = ("localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal")

#: Absolute URLs appearing in source. Deliberately narrow: a bare domain in prose
#: is not a trust boundary, an actual request target is.
_URL = re.compile(r"""(?:['"`])(https?://[^\s'"`<>]+)(?:['"`])""")


@dataclass(frozen=True)
class HostVerdict:
    host: str
    ownership: str
    reason: str

    @property
    def reportable(self) -> bool:
        """Internal hosts raise no third-party trust finding (FR-024a)."""
        return self.ownership != INTERNAL


def extract_hosts(text: str) -> set[str]:
    """Absolute-URL hosts referenced in ``text``."""
    found: set[str] = set()
    for match in _URL.finditer(text):
        host = (urlparse(match.group(1)).hostname or "").lower()
        if host:
            found.add(host)
    return found


def _member_identifiers(workspace: dict[str, Any] | None) -> set[str]:
    """Names and declared hosts that identify a workspace member."""
    identifiers: set[str] = set()
    for member in (workspace or {}).get("members") or []:
        name = str(member.get("name") or "").lower()
        if name:
            identifiers.add(name)
    for integration in (workspace or {}).get("integrations") or []:
        for key in ("from_repo", "to_repo"):
            value = str(integration.get(key) or "").lower()
            if value:
                identifiers.add(value)
        for endpoint in integration.get("endpoints_or_channels") or []:
            host = (urlparse(str(endpoint)).hostname or "").lower()
            if host:
                identifiers.add(host)
    return identifiers


def classify(host: str, workspace: dict[str, Any] | None) -> HostVerdict:
    """Is ``host`` workspace-internal, third-party, or undetermined?

    Ownership is derived from the workspace model alone — no new operator
    configuration is introduced (FR-024a).
    """
    lowered = host.lower()
    if lowered in _LOCAL:
        return HostVerdict(host, INTERNAL, "local or loopback address")

    identifiers = _member_identifiers(workspace)
    if not identifiers:
        return HostVerdict(
            host,
            EXTERNAL,
            (
                "the workspace model lists no members or integration points, so ownership "
                "could not be determined; treated as external so an unowned host is never "
                "silently exempted"
            ),
        )

    if lowered in identifiers:
        return HostVerdict(host, INTERNAL, f"'{host}' matches a workspace member or integration")

    label = lowered.split(".")[0]
    if label in identifiers:
        return HostVerdict(
            host, INTERNAL, f"'{label}' matches a workspace member or declared integration"
        )

    return HostVerdict(host, EXTERNAL, f"'{host}' matches no workspace member or integration")


def third_party_hosts(
    graph: dict[str, Any],
    workspace: dict[str, Any] | None,
    roots: dict[str, Any] | None = None,
) -> dict[str, HostVerdict]:
    """Every externally-owned host referenced by the workspace's source."""
    verdicts: dict[str, HostVerdict] = {}
    for node in graph.get("nodes") or []:
        if node.get("type") != "file" or not (roots or {}).get(node["repo"]):
            continue
        try:
            text = (roots[node["repo"]] / node["path"]).read_text(errors="replace")
        except OSError:
            continue
        for host in extract_hosts(text):
            if host in verdicts:
                continue
            verdict = classify(host, workspace)
            if verdict.reportable:
                verdicts[host] = verdict
    return dict(sorted(verdicts.items()))
