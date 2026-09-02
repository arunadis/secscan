"""T039: the applicability relation over a traced workspace path (FR-015a–FR-019).

The asymmetry these tests pin down: suppression requires positive structural
disproof, while *every* unknown — unknown architecture, unknown reachability,
an unresolved far side — retains the finding as classified.
"""

from __future__ import annotations

from pipeline import applicability
from pipeline.architecture import BROWSER, SERVER, UNDETERMINED, ArchitectureProfile


def profile(shape: str) -> ArchitectureProfile:
    if shape == UNDETERMINED:
        return ArchitectureProfile("member", shape, undetermined_reason="no markers")
    return ArchitectureProfile("member", shape, ("evidence",))


def graph(*edges: tuple[str, str]) -> dict:
    nodes, seen = [], set()
    for source, target in edges:
        for repo in (source, target):
            if repo not in seen:
                seen.add(repo)
                nodes.append(
                    {"id": f"{repo}:a.ts#f", "repo": repo, "type": "function", "path": "a.ts"}
                )
    return {
        "nodes": nodes,
        "edges": [{"from": f"{s}:a.ts#f", "to": f"{t}:a.ts#f", "type": "calls"} for s, t in edges],
    }


def finding(repo="web", cwe="CWE-918") -> dict:
    return {
        "id": "SEC-0001",
        "cwe": cwe,
        "severity_score": 4.3,
        "confidence": 0.65,
        "location": {"repo": repo, "file": "a.ts", "symbol": "f", "line_start": 1, "line_end": 2},
        "evidence": [],
    }


# --------------------------------------------------------------- reachability


def test_reachability_follows_direction() -> None:
    """A sibling that calls *in* does not lend this location its architecture."""
    g = graph(("api", "web"))  # api -> web
    assert applicability.reachable_members("web", g) == {"web"}
    assert applicability.reachable_members("api", g) == {"api", "web"}


def test_reachability_is_transitive() -> None:
    g = graph(("web", "api"), ("api", "worker"))
    assert applicability.reachable_members("web", g) == {"web", "api", "worker"}


def test_declared_integrations_count_as_reachability() -> None:
    """All four integration classes, not just direct calls (Edge Cases)."""
    workspace = {
        "integrations": [
            {"from_repo": "web", "to_repo": "api", "type": "shared-datastore"},
        ]
    }
    assert applicability.reachable_members("web", graph(), workspace) == {"web", "api"}


# ----------------------------------------------------------------- suppression


def test_browser_only_target_suppresses_request_forgery() -> None:
    """The benchmark's misclassification, now caught."""
    conclusion = applicability.evaluate(finding(), graph(), {"web": profile(BROWSER)})
    assert conclusion["applicable"] is False
    assert conclusion["reachable_shapes"] == [BROWSER]


def test_reachable_sibling_server_retains_the_class() -> None:
    """FR-015a/SC-005a: the false-negative class this rule could have introduced."""
    g = graph(("web", "api"))
    profiles = {"web": profile(BROWSER), "api": profile(SERVER)}
    conclusion = applicability.evaluate(finding(), g, profiles)
    assert conclusion["applicable"] is True
    assert conclusion["enabling_member"] == "api"
    assert SERVER in conclusion["reachable_shapes"]


def test_undetermined_architecture_never_suppresses() -> None:
    """FR-013a."""
    conclusion = applicability.evaluate(finding(), graph(), {"web": profile(UNDETERMINED)})
    assert conclusion["applicable"] == applicability.UNDETERMINED
    assert "could not be determined" in conclusion["reason"]


def test_unclassified_member_never_suppresses() -> None:
    """A member with no profile at all is an unknown, not an empty set."""
    conclusion = applicability.evaluate(finding(), graph(), {})
    assert conclusion["applicable"] == applicability.UNDETERMINED


def test_unresolved_far_side_never_suppresses() -> None:
    """FR-015c: an integration whose target was never classified."""
    workspace = {"integrations": [{"from_repo": "web", "to_repo": "ghost"}]}
    conclusion = applicability.evaluate(
        finding(), graph(), {"web": profile(BROWSER)}, workspace
    )
    assert conclusion["applicable"] == applicability.UNDETERMINED


def test_ungoverned_class_is_never_suppressed() -> None:
    conclusion = applicability.evaluate(
        finding(cwe="CWE-89"), graph(), {"web": profile(BROWSER)}
    )
    assert conclusion["applicable"] is True


def test_operator_request_beats_suppression_and_records_the_doubt() -> None:
    """FR-019: the operator wins, but the applicability doubt is not discarded."""
    conclusion = applicability.evaluate(
        finding(), graph(), {"web": profile(BROWSER)}, requested_cwes={"CWE-918"}
    )
    assert conclusion["applicable"] is True
    assert conclusion["operator_override"] is True
    assert "explicitly requested" in conclusion["reason"]


# --------------------------------------------------------------------- remap


def test_remap_rewrites_class_severity_and_records_everything() -> None:
    """FR-016/FR-017: suppression is not deletion."""
    doc = finding()
    conclusion = applicability.evaluate(doc, graph(), {"web": profile(BROWSER)})
    record = applicability.remap(doc, conclusion)
    assert record is not None
    assert doc["cwe"] == "CWE-20"
    assert doc["reclassification"]["original_cwe"] == "CWE-918"
    assert doc["reclassification"]["reason"]
    assert doc["severity_band"]


def test_remap_does_not_fire_on_true_or_undetermined() -> None:
    doc = finding()
    assert applicability.remap(doc, {"applicable": True}) is None
    assert applicability.remap(doc, {"applicable": applicability.UNDETERMINED}) is None
    assert doc["cwe"] == "CWE-918"


def test_apply_returns_records_for_the_audit_trail() -> None:
    docs = [finding(), finding(cwe="CWE-89")]
    docs[1]["id"] = "SEC-0002"
    records = applicability.apply_applicability(
        docs, graph(), {"web": profile(BROWSER)}
    )
    assert len(records) == 1
    assert records[0]["id"] == "SEC-0001"
    assert all("applicability" in d for d in docs)
