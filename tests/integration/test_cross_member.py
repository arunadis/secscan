"""T044: cross-member applicability and host ownership (quickstart Scenario 5).

This is the guard against the applicability relation introducing a false-negative
class that does not exist today. On a lone browser-only member, request forgery is
structurally impossible and gets remapped. Put a reachable sibling that *does*
issue server-side requests next to it and the same finding must be retained.

Getting this wrong in the safe-looking direction — suppressing whenever the
finding's own member is browser-only — would trade the reviewed benchmark's false
positive for a silent false negative in every real multi-service workspace.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import architecture, discover_repo, hosts
from pipeline.state import ArtifactStore
from tests.fixtures.multi_member_workspace import GROUND_TRUTH, build
from tests.integration.conftest import write_config


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = build(tmp_path)
    write_config(root)
    return root


#: Members are *declared* rather than auto-discovered. Auto-discovery treats a
#: root whose subdirectories contain source as a single member, so a declared
#: manifest is the documented way to describe a multi-member workspace (FR-001c).
DECLARED_MEMBERS = [{"name": "web", "path": "web"}, {"name": "api", "path": "api"}]
DECLARED_INTEGRATIONS = [
    {
        "from_repo": "web",
        "to_repo": "api",
        "type": "sync-api",
        "endpoints_or_channels": ["https://api/v1"],
        "trust_boundary": True,
        "confidence": 1.0,
    }
]


@pytest.fixture
def discovered(workspace: Path):
    store = ArtifactStore(workspace)
    document = discover_repo.run(store, DECLARED_MEMBERS, DECLARED_INTEGRATIONS)
    manifests = {
        m["name"]: store.read(f"repository/{m['name']}.manifest.json")
        for m in document["members"]
    }
    return workspace, document, manifests


def test_both_members_are_discovered(discovered) -> None:
    _root, document, _manifests = discovered
    assert {m["name"] for m in document["members"]} == {"web", "api"}


def test_each_member_gets_its_own_architecture(discovered) -> None:
    """FR-013: shapes are per member, not per workspace."""
    _root, _document, manifests = discovered
    shapes = {name: m["architecture"]["shape"] for name, m in manifests.items()}
    assert shapes == GROUND_TRUTH["members"], shapes


def test_reachable_sibling_server_retains_request_forgery(discovered) -> None:
    """SC-005a: the class suppressed on a lone browser member survives here."""
    from pipeline import applicability

    _root, document, manifests = discovered
    profiles = {
        name: architecture.ArchitectureProfile.from_dict(m["architecture"])
        for name, m in manifests.items()
    }
    # `web` reaches `api` through a declared integration point.
    workspace_model = {
        "members": document["members"],
        "integrations": [{"from_repo": "web", "to_repo": "api", "type": "sync-api"}],
    }
    finding = {
        "id": "SEC-0001",
        "cwe": "CWE-918",
        "severity_score": 4.3,
        "confidence": 0.6,
        "location": {"repo": "web", "file": "src/api/client.ts", "symbol": "fetchUser",
                     "line_start": 6, "line_end": 8},
        "evidence": [],
    }
    empty_graph = {"nodes": [], "edges": []}
    conclusion = applicability.evaluate(finding, empty_graph, profiles, workspace_model)
    assert conclusion["applicable"] is True, (
        "a reachable sibling issues server-side requests, so the class must be retained"
    )
    assert conclusion["enabling_member"] == "api"
    assert applicability.remap(finding, conclusion) is None
    assert finding["cwe"] == "CWE-918"


def test_lone_browser_member_still_suppresses(discovered) -> None:
    """The contrast case: no sibling reachable, so the remap fires as before."""
    from pipeline import applicability

    _root, _document, manifests = discovered
    profiles = {
        "web": architecture.ArchitectureProfile.from_dict(manifests["web"]["architecture"])
    }
    finding = {
        "id": "SEC-0001",
        "cwe": "CWE-918",
        "severity_score": 4.3,
        "confidence": 0.6,
        "location": {"repo": "web", "file": "src/api/client.ts", "symbol": "fetchUser",
                     "line_start": 6, "line_end": 8},
        "evidence": [],
    }
    conclusion = applicability.evaluate(finding, {"nodes": [], "edges": []}, profiles, {})
    assert conclusion["applicable"] is False
    assert applicability.remap(finding, conclusion) is not None


def test_sibling_host_is_internal_and_third_party_host_is_not(discovered) -> None:
    """FR-024a/FR-024b on a real workspace model."""
    _root, document, _manifests = discovered
    model = {
        "members": document["members"],
        "integrations": [{"from_repo": "web", "to_repo": "api", "type": "sync-api"}],
    }
    for host in GROUND_TRUTH["internal_hosts"]:
        assert hosts.classify(host, model).ownership == hosts.INTERNAL, host
    for host in GROUND_TRUTH["external_hosts"]:
        verdict = hosts.classify(host, model)
        assert verdict.ownership == hosts.EXTERNAL, host
        assert verdict.reportable is True


def test_members_use_different_ecosystems(discovered) -> None:
    """Groundwork for FR-030a: per-member audits against the member's own stack."""
    root, _document, _manifests = discovered
    assert (root / "web" / "package.json").exists()
    assert (root / "api" / "requirements.txt").exists()


def test_architecture_profiles_are_written_to_disk(discovered) -> None:
    """Applicability reads these; if they are not persisted it cannot decide."""
    root, _document, _manifests = discovered
    for name in ("web", "api"):
        payload = json.loads(
            (root / ".secscan" / "repository" / f"{name}.manifest.json").read_text()
        )["payload"]
        assert payload["architecture"]["shape"] in architecture.SHAPES
