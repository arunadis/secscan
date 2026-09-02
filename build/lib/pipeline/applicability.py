"""Weakness-class applicability per architecture (FR-015, FR-016).

This module owns the *relation* — the shipped data and the questions you can ask
of it. Evaluating it over a finding's traced workspace path, and remapping as a
result, lands with User Story 2.

The relation may only encode impossibility that holds **by construction**. It is
deliberately small: a wrong suppression is a false negative, and the review that
motivated this feature showed that to be the more damaging direction.
"""

from __future__ import annotations

import functools
import json
from typing import Any

from pipeline import cwe, resources

DATA_FILE = "applicability.json"

#: Architecture shapes (data-model.md "Architecture Profile").
SHAPES = (
    "server-request-issuer",
    "browser-client",
    "cli",
    "library",
    "undetermined",
)

#: The shape that means "we could not tell" — never a basis for suppression.
UNDETERMINED = "undetermined"


class InvalidApplicabilityData(ValueError):
    """Raised when the shipped relation is malformed."""


@functools.lru_cache(maxsize=1)
def _data() -> dict[str, Any]:
    document = json.loads(resources.data_path(DATA_FILE).read_text())
    for rule in document["rules"]:
        cwe.validate_cwe(rule["cwe"])
        for alternative in rule["alternatives"]:
            cwe.validate_cwe(alternative)
        unknown = set(rule["requires_any"]) - set(SHAPES)
        if unknown:
            raise InvalidApplicabilityData(
                f"{rule['cwe']}: unknown architecture shape(s) {sorted(unknown)}"
            )
        if UNDETERMINED in rule["requires_any"]:
            raise InvalidApplicabilityData(
                f"{rule['cwe']}: 'undetermined' may not appear in requires_any — an "
                "unknown architecture must never satisfy a structural requirement"
            )
        if not rule["alternatives"]:
            raise InvalidApplicabilityData(
                f"{rule['cwe']}: a rule must name at least one defensible alternative "
                "class, because suppression without a replacement discards a real code fact"
            )
    return document


def version() -> str:
    return str(_data()["version"])


def governed_cwes() -> tuple[str, ...]:
    """Weakness classes the relation has an opinion about."""
    return tuple(sorted(rule["cwe"] for rule in _data()["rules"]))


def rule_for(cwe_id: str) -> dict[str, Any] | None:
    for rule in _data()["rules"]:
        if rule["cwe"] == cwe_id:
            return dict(rule)
    return None


def requires_any(cwe_id: str) -> tuple[str, ...]:
    """Shapes on which ``cwe_id`` is structurally possible; empty when ungoverned."""
    rule = rule_for(cwe_id)
    return tuple(rule["requires_any"]) if rule else ()


def alternatives_for(cwe_id: str) -> tuple[str, ...]:
    rule = rule_for(cwe_id)
    return tuple(rule["alternatives"]) if rule else ()


def reachable_members(
    origin_repo: str,
    graph: dict[str, Any],
    workspace: dict[str, Any] | None = None,
) -> set[str]:
    """Members reachable *from* ``origin_repo``, following direction.

    Reachability is a deterministic traversal of the code model's cross-member
    edges plus the workspace's declared integration points (FR-015b). It costs no
    analysis context, which is why it is in scope even though supplying
    cross-segment source to an analysis step (escalation level 4) is not.

    Direction is respected. A sibling that calls *in* does not lend this location
    its architecture — otherwise every member in a workspace would inherit every
    other member's shape and the relation would stop suppressing anything.
    """
    nodes = {node["id"]: node for node in graph.get("nodes") or []}
    reachable = {origin_repo}
    frontier = {origin_repo}

    #: repo -> repos it can reach directly
    outgoing: dict[str, set[str]] = {}
    for edge in graph.get("edges") or []:
        source = nodes.get(edge.get("from"))
        target = nodes.get(edge.get("to"))
        if not source or not target or source["repo"] == target["repo"]:
            continue
        outgoing.setdefault(source["repo"], set()).add(target["repo"])

    # All four declared integration classes count as reachability: coupling
    # through a shared datastore or a queue is no less real than a direct call.
    for integration in (workspace or {}).get("integrations") or []:
        source = integration.get("from_repo")
        target = integration.get("to_repo")
        if source and target:
            outgoing.setdefault(source, set()).add(target)

    while frontier:
        current = frontier.pop()
        for neighbour in outgoing.get(current, ()):
            if neighbour not in reachable:
                reachable.add(neighbour)
                frontier.add(neighbour)
    return reachable


def is_possible_on(cwe_id: str, shapes: set[str] | frozenset[str]) -> bool | str:
    """Is ``cwe_id`` structurally possible given the reachable ``shapes``?

    Returns ``True``, ``False``, or the string ``"undetermined"``. The three-way
    result is the point: only a definite ``False`` may drive a remap, so an unknown
    architecture and unknown reachability both preserve the finding (FR-013a,
    FR-015c).
    """
    rule = rule_for(cwe_id)
    if rule is None:
        # The relation has no opinion, so nothing is disproved.
        return True
    if not shapes or UNDETERMINED in shapes:
        return UNDETERMINED
    return bool(set(shapes) & set(rule["requires_any"]))


# ------------------------------------------------------------- evaluation


def origin_shape(
    finding: dict[str, Any],
    graph: dict[str, Any],
    profiles: dict[str, Any],
    segments: list[dict[str, Any]] | None,
) -> str | None:
    """The shape governing the finding's own location, or ``None`` for the member's.

    A hybrid repository — a browser application and its own server in one tree —
    needs a server-side class to apply to the server portion and *not* to the
    browser portion (spec Edge Cases, FR-014). Member scope alone cannot express
    that, so a segment carrying its own profile overrides its member's here.

    The override is withheld when the segment has an **outgoing** cross-segment
    edge to differently-shaped code in the same member. Direction is what makes
    that correct: a server-side weakness needs a path *out* to something that
    issues server-side requests, so an inbound edge (server code rendering into a
    template) does not make the template a server. Narrowing regardless would
    suppress a class whose path genuinely reaches the server portion, which is
    FR-015a's whole point and a false negative.
    """
    if not segments:
        return None

    location = finding.get("location") or {}
    repo, path = location.get("repo", ""), location.get("file", "")

    by_file: dict[tuple[str, str], dict[str, Any]] = {}
    for segment in segments:
        for member in segment.get("repos") or []:
            for relative in segment.get("files") or []:
                by_file[(member, relative)] = segment

    origin_segment = by_file.get((repo, path))
    if origin_segment is None:
        return None
    profile = origin_segment.get("architecture")
    if not profile:
        return None  # segment matches its member; nothing to override

    member_shape = getattr(profiles.get(repo), "shape", None)
    own_files = {(repo, f) for f in origin_segment.get("files") or []}
    nodes = {node["id"]: node for node in graph.get("nodes") or []}

    for edge in graph.get("edges") or []:
        source, target = nodes.get(edge.get("from")), nodes.get(edge.get("to"))
        if not source or not target:
            continue
        if (source["repo"], source["path"]) not in own_files:
            continue
        if (target["repo"], target["path"]) in own_files:
            continue
        neighbour = by_file.get((target["repo"], target["path"]))
        neighbour_shape = (neighbour or {}).get("architecture", {}).get("shape") or member_shape
        if neighbour_shape and neighbour_shape != profile["shape"]:
            return None  # reaches differently-shaped code: do not narrow

    return str(profile["shape"])


def evaluate(
    finding: dict[str, Any],
    graph: dict[str, Any],
    profiles: dict[str, Any],
    workspace: dict[str, Any] | None = None,
    requested_cwes: set[str] | None = None,
    segments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Applicability conclusion for one finding (FR-015a–FR-015c, FR-019).

    Returns the ``applicability`` block recorded on the finding. Only a definite
    ``applicable: false`` may drive a remap; ``true`` and ``"undetermined"`` both
    retain the finding exactly as analysis classified it.
    """
    from pipeline import architecture

    cwe_id = finding["cwe"]
    origin = (finding.get("location") or {}).get("repo", "")

    if rule_for(cwe_id) is None:
        return {"applicable": True, "reason": "no applicability rule governs this weakness class"}

    members = sorted(reachable_members(origin, graph, workspace))
    shapes = architecture.shapes_for(profiles, members)

    # Segment scope overrides member scope for the finding's own location, which
    # is what makes a hybrid repository representable (data-model.md).
    narrowed = origin_shape(finding, graph, profiles, segments)
    if narrowed is not None:
        member_shape = getattr(profiles.get(origin), "shape", None)
        shapes = (shapes - {member_shape}) | {narrowed} if member_shape else shapes | {narrowed}

    verdict = is_possible_on(cwe_id, shapes)

    block: dict[str, Any] = {
        "applicable": verdict,
        "reachable_shapes": sorted(shapes),
    }
    if narrowed is not None:
        block["origin_scope"] = "segment"

    if verdict is True:
        enabling = _enabling_member(cwe_id, members, profiles, origin)
        if enabling:
            block["enabling_member"] = enabling
            block["reason"] = (
                f"reachable member '{enabling}' has an architecture on which this class "
                "is structurally possible"
            )
    elif verdict == UNDETERMINED:
        block["reason"] = (
            "architecture or reachability could not be determined for every reachable "
            "member, so this class cannot be ruled out"
        )
    else:
        block["reason"] = (
            f"no reachable member has an architecture that can exhibit {cwe_id} "
            f"(reachable shapes: {', '.join(sorted(shapes))})"
        )
        if requested_cwes and cwe_id in requested_cwes:
            # FR-019: an explicit operator request outranks suppression, but the
            # doubt is recorded rather than discarded.
            block["applicable"] = True
            block["reason"] = (
                f"{block['reason']}; retained because the active profile explicitly "
                "requested this weakness class"
            )
            block["operator_override"] = True
    return block


def _enabling_member(
    cwe_id: str, members: list[str], profiles: dict[str, Any], origin: str
) -> str | None:
    """The member whose architecture makes ``cwe_id`` possible, preferring a sibling."""
    required = set(requires_any(cwe_id))
    matches = [
        name
        for name in members
        if name in profiles and getattr(profiles[name], "shape", None) in required
    ]
    siblings = [name for name in matches if name != origin]
    return (siblings or matches or [None])[0]


def remap(finding: dict[str, Any], conclusion: dict[str, Any]) -> dict[str, Any] | None:
    """Remap a structurally impossible weakness class (FR-016, FR-017).

    Suppression is not deletion: the finding survives with the defensible class for
    the same code fact, its severity recomputed, and the original decision recorded
    so it stays auditable even when the result falls below the reporting threshold.
    """
    from pipeline import cwe as cwe_mod

    if conclusion.get("applicable") is not False:
        return None

    original = finding["cwe"]
    alternatives = alternatives_for(original)
    if not alternatives:
        return None

    replacement = alternatives[0]
    original_severity = float(finding.get("severity_score", cwe_mod.default_severity(original)))
    new_severity = min(original_severity, cwe_mod.default_severity(replacement))

    record = {
        "original_cwe": original,
        "new_cwe": replacement,
        "original_severity": round(original_severity, 1),
        "new_severity": round(new_severity, 1),
        "reason": conclusion.get(
            "reason", "structurally impossible for the reachable architectures"
        ),
    }

    finding["cwe"] = replacement
    finding["severity_score"] = round(new_severity, 1)
    finding["severity_band"] = cwe_mod.band_for(new_severity)
    owasp = cwe_mod.owasp_for(replacement)
    if owasp:
        finding["owasp_top10"] = owasp
    else:
        finding.pop("owasp_top10", None)
    finding["compliance_refs"] = cwe_mod.compliance_refs(replacement)
    if not finding["compliance_refs"]:
        finding.pop("compliance_refs")
    finding["reclassification"] = record
    return record


def apply_applicability(
    findings: list[dict[str, Any]],
    graph: dict[str, Any],
    profiles: dict[str, Any],
    workspace: dict[str, Any] | None = None,
    requested_cwes: set[str] | None = None,
    segments: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Attach conclusions and remap where structurally disproved (in place).

    Returns the reclassification records, which are retained in the scan artifacts
    even for findings later filtered out by profile thresholds (FR-017).
    """
    records: list[dict[str, Any]] = []
    for finding in findings:
        conclusion = evaluate(finding, graph, profiles, workspace, requested_cwes, segments)
        finding["applicability"] = conclusion
        record = remap(finding, conclusion)
        if record:
            records.append({"id": finding["id"], **record})
    return records
