"""T043–T045: architecture-aware classification end to end (quickstart 4–6).

The headline case is the one the independent reviewer called the most damaging
defect in the benchmark scan: a browser-only application with a request-forgery
finding filed against it. These tests assert the pipeline now catches it — and,
just as importantly, that it does *not* catch it when a reachable sibling makes
the class genuinely applicable.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import run as run_mod
from tests.fixtures.unparsed_language import build_fixed_prefix
from tests.integration.conftest import write_config


def ssrf_responder(request) -> str:
    """Reports the finding the reviewer said should never have been filed."""
    payload = request.payload
    findings = []
    for path in sorted(payload.get("source") or {}):
        if "client.ts" not in path:
            continue
        findings.append(
            {
                "cwe": "CWE-918",
                "severity_score": 4.3,
                "confidence": 0.65,
                "location": {
                    "repo": "fixed-prefix-sink",
                    "file": path,
                    "symbol": "fetchUser",
                    "line_start": 5,
                    "line_end": 8,
                },
                "description": "The id is interpolated into a request URL without encoding.",
                "evidence": [
                    {
                        "repo": "fixed-prefix-sink",
                        "file": path,
                        "symbol": "fetchUser",
                        "reason": "template-literal interpolation with no encodeURIComponent",
                    }
                ],
                "attack_scenario": "An attacker distributes a link steering the request.",
                "impact": "The request is steered to an unintended endpoint.",
                "recommendation": "Encode the value and validate it against a grammar.",
                "segment_id": payload.get("segment_id"),
            }
        )
    return json.dumps({"findings": findings})


@pytest.fixture
def spa_scan(tmp_path: Path):
    repo = build_fixed_prefix(tmp_path)
    write_config(repo)
    result = run_mod.run_scan(repo, responder=ssrf_responder, full=True)
    correlated = json.loads(
        (repo / ".secscan" / "findings" / "correlated.json").read_text()
    )["payload"]
    return repo, result, correlated


def test_browser_only_member_is_classified_as_such(spa_scan) -> None:
    repo, _result, _correlated = spa_scan
    manifest = json.loads(
        (repo / ".secscan" / "repository" / "fixed-prefix-sink.manifest.json").read_text()
    )["payload"]
    assert manifest["architecture"]["shape"] == "browser-client"
    assert manifest["architecture"]["evidence"]


def test_request_forgery_on_a_browser_only_target_is_remapped(spa_scan) -> None:
    """SC-005: the benchmark's misclassification, now impossible to file."""
    _repo, _result, correlated = spa_scan
    findings = correlated["findings"]
    assert findings, "the fixture produced no findings"
    assert all(f["cwe"] != "CWE-918" for f in findings), (
        "a browser-only target still carries a server-side request forgery finding"
    )
    # Scoped to analysis output: the fixture pins Angular 9.0.1 and rxjs 6.5.4, so
    # the scan legitimately also reports end-of-support findings (FR-034).
    from_analysis = [f for f in findings if f["source"] == "analysis"]
    assert from_analysis
    assert all(f["cwe"] in ("CWE-20", "CWE-116") for f in from_analysis)


def test_the_remap_is_recorded_with_its_reason(spa_scan) -> None:
    """FR-016/FR-017: an auditable decision, not a silent rewrite."""
    _repo, _result, correlated = spa_scan
    records = correlated.get("reclassifications")
    assert records, "no reclassification was recorded"
    record = records[0]
    assert record["original_cwe"] == "CWE-918"
    assert record["new_cwe"] in ("CWE-20", "CWE-116")
    assert "no reachable member" in record["reason"]

    finding = next(f for f in correlated["findings"] if f["source"] == "analysis")
    assert finding["reclassification"]["original_cwe"] == "CWE-918"
    assert finding["applicability"]["applicable"] is False
    assert finding["applicability"]["reachable_shapes"] == ["browser-client"]


def test_owasp_label_follows_the_remapped_class(spa_scan) -> None:
    """Routing keys off this label; leaving A10 attached would misroute the work."""
    _repo, _result, correlated = spa_scan
    finding = next(f for f in correlated["findings"] if f["source"] == "analysis")
    assert "A10" not in finding.get("owasp_top10", "")


def test_unproven_finding_is_calibrated(spa_scan) -> None:
    """FR-020: confidence reflects what was established, not what was proposed."""
    _repo, _result, correlated = spa_scan
    finding = next(f for f in correlated["findings"] if f["source"] == "analysis")
    assert finding["verification"]["status"] != "verified"
    assert finding["confidence"] <= 0.5
    assert finding["calibration"]["proposed_confidence"] == 0.65


def test_framework_control_state_is_recorded(spa_scan) -> None:
    """Every finding says whether a control was credited, absent, or unassessed."""
    _repo, _result, correlated = spa_scan
    for finding in correlated["findings"]:
        state = finding["framework_control"]["state"]
        assert state in ("credited", "bypassed", "absent", "unassessed")
        if state == "unassessed":
            assert finding["framework_control"]["unassessed_reason"]


def test_reproduction_stays_honest_after_the_remap(spa_scan) -> None:
    """The infeasible localhost probe is gone; a canary probe is now appropriate.

    Once the class is improper encoding rather than request forgery, a probe no
    longer has to control the scheme and host — so a trigger is emitted, and it is
    an achievable one. The two mechanisms compose rather than fight.
    """
    _repo, _result, correlated = spa_scan
    repro = next(f for f in correlated["findings"] if f["source"] == "analysis")["reproduction"]
    assert repro["mode"] == "hypothesis"
    assert "127.0.0.1:9" not in json.dumps(repro)
    if repro.get("trigger"):
        assert "CANARY" in repro["trigger"].upper()


# --------------------------------------- segment-scope architecture (FR-014, F1)


HYBRID = {
    "requirements.txt": "django==5.0\nrequests==2.31.0\n",
    "templates/profile.djhtml": "<div>{{ about|safe }}</div>\n",
    "api/views.py": '''"""Server-side API that issues outbound requests."""

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/v1/fetch", methods=["GET"])
def fetch():
    return requests.get(f"https://upstream.internal/{request.args.get('p')}").json()
''',
}


@pytest.fixture
def hybrid(tmp_path: Path):
    from pipeline import build_code_graph, discover_repo, partition_repo
    from pipeline.state import ArtifactStore

    for name, content in HYBRID.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    write_config(tmp_path)
    store = ArtifactStore(tmp_path)
    workspace = discover_repo.run(store, [], [])
    graph = build_code_graph.run(store, workspace)
    segments = partition_repo.run(store, workspace, graph, 12000)
    manifest = store.read(f"repository/{tmp_path.name}.manifest.json")
    return manifest, {s["id"]: s for s in segments}


def test_one_repository_can_carry_two_architectures(hybrid) -> None:
    """FR-014: a Django project whose templates are browser-delivered."""
    manifest, segments = hybrid
    assert manifest["architecture"]["shape"] == "server-request-issuer"

    templates = next(s for k, s in segments.items() if "template" in k)
    assert templates["architecture"]["shape"] == "browser-client"
    assert templates["architecture"]["scope"] == "segment"
    assert templates["architecture"]["evidence"]


def test_segment_profile_is_recorded_only_on_difference(hybrid) -> None:
    """Writing the member's shape onto every segment would be noise.

    Recording only divergence is what the schema states, and it makes a genuine
    difference visible instead of buried.
    """
    _manifest, segments = hybrid
    api = next(s for k, s in segments.items() if "api" in k)
    assert "architecture" not in api, "a matching segment should inherit, not restate"


def test_a_segment_with_its_own_entry_point_is_not_reclassified(hybrid) -> None:
    """Conservative by construction: templates alone are not enough."""
    from pipeline.partition_repo import segment_architecture

    member = {"shape": "server-request-issuer", "evidence": ["depends on 'flask'"]}
    segment = {"id": "seg-x", "repos": ["r"], "entrypoints": ["GET /x"]}
    assert segment_architecture(segment, member, {"template"}, {"trust_boundary"}) is None


def _ssrf_at(repo: str, path: str) -> dict:
    return {
        "id": "SEC-0001",
        "cwe": "CWE-918",
        "severity_score": 4.3,
        "confidence": 0.6,
        "location": {"repo": repo, "file": path, "line_start": 1, "line_end": 2},
        "evidence": [],
    }


def test_server_side_class_applies_to_the_server_portion_only(hybrid, tmp_path) -> None:
    """The Edge Case, stated as it is written: applies to the server portion and
    *not* to the browser portion of one hybrid repository (FR-014).

    Member scope alone cannot express this — the member is a server, so both
    findings would be retained. Segment scope is what makes the distinction.
    """
    from pipeline import applicability, build_code_graph, partition_repo
    from pipeline.architecture import ArchitectureProfile
    from pipeline.state import ArtifactStore

    manifest, _segments = hybrid
    store = ArtifactStore(tmp_path)
    workspace = store.read("workspace.json")
    graph = build_code_graph.run(store, workspace)
    segments = partition_repo.run(store, workspace, graph, 12000)
    name = tmp_path.name
    profiles = {name: ArchitectureProfile.from_dict(manifest["architecture"])}

    browser = applicability.evaluate(
        _ssrf_at(name, "templates/profile.djhtml"), graph, profiles, {}, None, segments
    )
    server = applicability.evaluate(
        _ssrf_at(name, "api/views.py"), graph, profiles, {}, None, segments
    )

    assert browser["applicable"] is False, "the browser portion still carries a server-side class"
    assert browser["origin_scope"] == "segment"
    assert server["applicable"] is True, "the server portion lost its server-side class"


def test_segment_scope_does_not_narrow_across_a_boundary_it_can_reach() -> None:
    """FR-015a: the safety half, which the Edge Case must not be allowed to break.

    A browser-shaped segment with an **outgoing** edge into server-shaped code can
    genuinely cause a server-side request, so narrowing to its own shape would be
    a false negative. Direction decides: an inbound edge (server code rendering
    into a template) does not make the template a server.
    """
    from pipeline import applicability

    nodes = [
        {"id": "r:ui/page.html", "repo": "r", "type": "template", "path": "ui/page.html"},
        {"id": "r:api/s.py#call", "repo": "r", "type": "function", "path": "api/s.py",
         "symbol": "call"},
    ]
    segments = [
        {"id": "seg-ui", "repos": ["r"], "files": ["ui/page.html"],
         "architecture": {"scope": "segment", "shape": "browser-client", "evidence": ["x"]}},
        {"id": "seg-api", "repos": ["r"], "files": ["api/s.py"]},
    ]

    class _Server:
        shape = "server-request-issuer"

    profiles = {"r": _Server()}
    finding = _ssrf_at("r", "ui/page.html")

    outgoing = {"nodes": nodes,
                "edges": [{"from": "r:ui/page.html", "to": "r:api/s.py#call", "type": "calls"}]}
    assert applicability.evaluate(finding, outgoing, profiles, {}, None, segments)[
        "applicable"
    ] is True, "a segment that reaches server code was narrowed to browser-only"

    inbound = {"nodes": nodes,
               "edges": [{"from": "r:api/s.py#call", "to": "r:ui/page.html", "type": "renders"}]}
    assert applicability.evaluate(finding, inbound, profiles, {}, None, segments)[
        "applicable"
    ] is False, "an inbound render edge must not make a template a server"
