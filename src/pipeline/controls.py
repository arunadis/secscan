"""Framework default controls and their bypasses (FR-021, FR-022–FR-022d).

This module owns the shipped catalogue. Evaluating a control's state against a
finding's traced path — deciding `credited` / `bypassed` / `absent` /
`unassessed` — lands with User Story 2.

The one thing worth stating loudly: **presence of a framework is not evidence of a
control.** Jinja2 autoescaping is off unless configured, and JSP `<%= %>` is raw.
`escapes_by_default` is per framework, and a framework carrying
`requires_config` may only be credited once that configuration is found.
"""

from __future__ import annotations

import functools
import json
from typing import Any

from pipeline import cwe, resources

DATA_FILE = "framework_controls.json"

#: Evaluation states. `absent` is a determined answer; `unassessed` is not.
STATE_CREDITED = "credited"
STATE_BYPASSED = "bypassed"
STATE_ABSENT = "absent"
STATE_UNASSESSED = "unassessed"
STATES = (STATE_CREDITED, STATE_BYPASSED, STATE_ABSENT, STATE_UNASSESSED)


class InvalidControlData(ValueError):
    """Raised when the shipped catalogue is malformed."""


@functools.lru_cache(maxsize=1)
def _data() -> dict[str, Any]:
    document = json.loads(resources.data_path(DATA_FILE).read_text())
    for framework in document["frameworks"]:
        if "escapes_by_default" not in framework:
            raise InvalidControlData(
                f"{framework['id']}: escapes_by_default must be stated explicitly — "
                "defaulting it either way is exactly the guess this feature forbids"
            )
        for control in framework["controls"]:
            for cwe_id in control["mitigates"]:
                cwe.validate_cwe(cwe_id)
            if not control.get("bypasses"):
                raise InvalidControlData(
                    f"{control['id']}: a control with no known bypass cannot be "
                    "discredited, so its bypass syntaxes must be listed"
                )
    return document


def version() -> str:
    return str(_data()["version"])


def frameworks() -> tuple[dict[str, Any], ...]:
    return tuple(dict(f) for f in sorted(_data()["frameworks"], key=lambda f: f["id"]))


def framework(framework_id: str) -> dict[str, Any] | None:
    for entry in _data()["frameworks"]:
        if entry["id"] == framework_id:
            return dict(entry)
    return None


def escapes_by_default(framework_id: str) -> bool | None:
    """``None`` when the framework is unrecognized — which is *not* ``False``."""
    entry = framework(framework_id)
    return None if entry is None else bool(entry["escapes_by_default"])


def controls_for(framework_id: str, cwe_id: str) -> tuple[dict[str, Any], ...]:
    """Controls in ``framework_id`` that mitigate ``cwe_id``."""
    entry = framework(framework_id)
    if entry is None:
        return ()
    return tuple(
        dict(control)
        for control in sorted(entry["controls"], key=lambda c: c["id"])
        if cwe_id in control["mitigates"]
    )


def detection_markers() -> dict[str, str]:
    """Dependency/import marker -> framework id, for deterministic detection."""
    out: dict[str, str] = {}
    for entry in _data()["frameworks"]:
        for marker in entry.get("detect") or ():
            out[marker] = entry["id"]
    return dict(sorted(out.items()))


def sink_syntaxes() -> dict[str, tuple[str, ...]]:
    """Framework id -> unsafe sink syntaxes across its controls."""
    out: dict[str, set[str]] = {}
    for entry in _data()["frameworks"]:
        for control in entry["controls"]:
            out.setdefault(entry["id"], set()).update(control.get("sinks") or ())
    return {k: tuple(sorted(v)) for k, v in sorted(out.items())}


def bypass_syntaxes() -> dict[str, tuple[str, ...]]:
    """Framework id -> documented bypass syntaxes across its controls."""
    out: dict[str, set[str]] = {}
    for entry in _data()["frameworks"]:
        for control in entry["controls"]:
            out.setdefault(entry["id"], set()).update(control.get("bypasses") or ())
    return {k: tuple(sorted(v)) for k, v in sorted(out.items())}


def all_bypass_syntaxes() -> tuple[str, ...]:
    """Every bypass syntax, for the path-scoped bypass search (FR-022, FR-022a)."""
    found: set[str] = set()
    for syntaxes in bypass_syntaxes().values():
        found.update(syntaxes)
    return tuple(sorted(found))


# ------------------------------------------------------------- evaluation


def detect_frameworks(manifest: dict[str, Any] | None, graph: dict[str, Any]) -> set[str]:
    """Frameworks present, from dependency markers, imports, and node paths."""
    markers = detection_markers()
    found: set[str] = set()
    haystack = " ".join(
        sorted(
            {str(f) for f in (manifest or {}).get("frameworks") or ()}
            | {str(n.get("path", "")) for n in graph.get("nodes") or []}
            # Feature 014 R1: imports now persist on file nodes — they are the
            # authoritative "is this framework actually pulled in" signal.
            | {
                str(import_text)
                for n in graph.get("nodes") or []
                for import_text in n.get("imports") or []
            }
        )
    )
    for marker, framework_id in markers.items():
        if marker in haystack:
            found.add(framework_id)
    return found


def evaluate(
    finding: dict[str, Any],
    graph: dict[str, Any],
    frameworks_present: set[str],
) -> dict[str, Any]:
    """Framework-control state for one finding (contracts/accuracy-contracts.md §3).

    The states are deliberately four, not two. `absent` means "this framework has
    no such default control" — a determined answer. `unassessed` means "we could
    not establish the control's state", which caps confidence and inflates
    nothing. Collapsing the two would force a guess in one direction or the other,
    and both directions are wrong: assume-absent recreates the over-alarming this
    feature exists to remove, assume-present silently under-scores a real finding.
    """
    cwe_id = finding["cwe"]
    path = list((finding.get("verification") or {}).get("path") or [])
    nodes = {node["id"]: node for node in graph.get("nodes") or []}

    if not frameworks_present:
        return {
            "state": STATE_UNASSESSED,
            "unassessed_reason": (
                "no framework was recognized for this segment, so whether a default "
                "output control applies could not be established"
            ),
        }

    candidates = [
        (framework_id, control)
        for framework_id in sorted(frameworks_present)
        for control in controls_for(framework_id, cwe_id)
    ]
    if not candidates:
        # The framework is recognized and simply has no default control for this
        # weakness class. That is a determined answer, so it is `absent`, not
        # `unassessed`, and it produces no coverage gap.
        return {"state": STATE_ABSENT}

    framework_id, control = candidates[0]

    # Feature 014 (FR-005-FR-007, clarification Q2): a sink in a markup template
    # is gated by the control's sink list and a member-wide bypass scan, not by
    # the traced path alone. A sink the control does not list is not applicable
    # (`absent`), never a hedge.
    location = finding.get("location") or {}
    template_sink = _template_sink_for(location, nodes)
    if template_sink is not None:
        return _evaluate_template_sink(
            template_sink, candidates, nodes, repo=str(location.get("repo") or "")
        )

    # A control that only applies when configured cannot be credited on presence
    # alone. Jinja2 autoescaping is the canonical case: off unless switched on.
    if control.get("requires_config") and escapes_by_default(framework_id) is False:
        return {
            "state": STATE_UNASSESSED,
            "control": control["id"],
            "unassessed_reason": (
                f"{framework_id} does not escape by default; whether "
                f"{', '.join(control['requires_config'])} is configured could not be "
                "established from the analyzed files"
            ),
        }

    # Crediting requires full parse coverage of the path: a bypass hiding in a file
    # the model could not read must not be mistaken for the absence of a bypass.
    unparsed = [
        nodes[node_id]["path"]
        for node_id in path
        if node_id in nodes and nodes[node_id].get("parsed") is False
    ]
    if unparsed:
        return {
            "state": STATE_UNASSESSED,
            "control": control["id"],
            "unassessed_reason": (
                "the traced path includes file(s) with no parser "
                f"({', '.join(sorted(set(unparsed)))}), so a bypass there could not be ruled out"
            ),
        }

    bypass = _bypass_on_path(path, nodes)
    if bypass is not None:
        return {
            "state": STATE_BYPASSED,
            "control": control["id"],
            "bypass_site": bypass,
        }

    return {"state": STATE_CREDITED, "control": control["id"]}


def _template_sink_for(location: dict[str, Any], nodes: dict[str, Any]) -> dict[str, Any] | None:
    """The template sink at the finding's location, when one exists (FR-005).

    Sink sub-nodes carry ``symbol = "<marker>@<line>"`` and ``format =
    <framework id>``; the presence of such a node in the located template file
    is what turns control evaluation into the template branch.
    """
    repo, file = str(location.get("repo") or ""), str(location.get("file") or "")
    for node in nodes.values():
        if (
            node.get("type") == "template"
            and node.get("symbol")
            and node.get("repo") == repo
            and node.get("path") == file
        ):
            marker = str(node["symbol"]).rsplit("@", 1)[0]
            return {
                "marker": marker,
                "framework": str(node.get("format") or ""),
                "line_start": int(node.get("line_start") or 1),
            }
    return None


def _evaluate_template_sink(
    sink: dict[str, Any],
    candidates: list[tuple[str, dict[str, Any]]],
    nodes: dict[str, Any],
    *,
    repo: str,
) -> dict[str, Any]:
    """Hybrid control decision for a sink living in a markup template.

    deterministic credit requires the sink in the control's shipped sink list,
    zero bypasses member-wide, and full member parse coverage; bypass present or
    coverage incomplete yields bypassed/unassessed (the triage round may still
    judge it via candidate controls); a sink outside the sink list is `absent`.
    """
    matched = [
        (framework_id, control)
        for framework_id, control in candidates
        if not sink["framework"] or framework_id == sink["framework"]
    ]
    if not matched:
        return {"state": STATE_ABSENT}
    framework_id, control = matched[0]
    sinks = {str(s).lower() for s in control.get("sinks") or ()}
    if sink["marker"].lower() not in sinks:
        return {"state": STATE_ABSENT}

    if control.get("requires_config") and escapes_by_default(framework_id) is False:
        return {
            "state": STATE_UNASSESSED,
            "control": control["id"],
            "unassessed_reason": (
                f"{framework_id} does not escape by default; whether "
                f"{', '.join(control['requires_config'])} is configured could not be "
                "established from the analyzed files"
            ),
        }

    unparsed = sorted(
        {
            str(node["path"])
            for node in nodes.values()
            if node.get("repo") == repo
            and node.get("type") == "file"
            and node.get("parsed") is False
        }
    )
    if unparsed:
        return {
            "state": STATE_UNASSESSED,
            "control": control["id"],
            "unassessed_reason": (
                f"member '{repo}' has file(s) with no parser ({', '.join(unparsed)}), so a "
                "bypass there could not be ruled out"
            ),
        }

    bypass_node = next(
        (
            nodes[node_id]
            for node_id in sorted(nodes)
            if nodes[node_id].get("repo") == repo
            and "control_bypass" in (nodes[node_id].get("annotations") or [])
        ),
        None,
    )
    if bypass_node is not None:
        return {
            "state": STATE_BYPASSED,
            "control": control["id"],
            "bypass_site": {
                "repo": bypass_node["repo"],
                "file": bypass_node["path"],
                "line_start": int(bypass_node.get("line_start") or 1),
                "line_end": int(
                    bypass_node.get("line_end") or bypass_node.get("line_start") or 1
                ),
                **(
                    {"symbol": bypass_node["symbol"]}
                    if bypass_node.get("symbol")
                    else {}
                ),
            },
        }

    return {"state": STATE_CREDITED, "control": control["id"]}


def _bypass_on_path(path: list[str], nodes: dict[str, Any]) -> dict[str, Any] | None:
    """The first annotated bypass sitting on the traced path, if any (FR-022).

    Only the path matters. A bypass elsewhere in the target is real and is
    reported as its own hygiene finding (FR-022b), but it says nothing about
    whether *this* sink is protected.
    """
    for node_id in path:
        node = nodes.get(node_id)
        if node and "control_bypass" in (node.get("annotations") or []):
            return {
                "repo": node["repo"],
                "file": node["path"],
                "line_start": int(node.get("line_start") or 1),
                "line_end": int(node.get("line_end") or node.get("line_start") or 1),
                **({"symbol": node["symbol"]} if node.get("symbol") else {}),
            }
    return None


def residual_impact(framework_id: str, control_id: str) -> str:
    """What a credited control still permits — used to reframe the narrative."""
    entry = framework(framework_id)
    for control in (entry or {}).get("controls", ()):
        if control["id"] == control_id:
            return str(control.get("residual_impact", ""))
    return ""
