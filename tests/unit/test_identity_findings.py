"""Feature 016 T029 (US4): archetype finding shape reaches the pipeline as a
format detection with model-resolvable locations (contracts/identity-archetype-rules)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline import build_code_graph, discover_repo, identity_rules
from pipeline.normalize_findings import FindingNormalizer
from pipeline.state import ArtifactStore
from tests.fixtures import header_identity_app


@pytest.fixture()
def substrate(tmp_path: Path) -> dict:
    app_root = header_identity_app.build(tmp_path)
    store = ArtifactStore(tmp_path)
    workspace = discover_repo.run(
        store, [{"name": app_root.name, "path": app_root.name}], []
    )
    graph = build_code_graph.run(store, workspace)
    # version 1 content for US4 (T032); until it ships, the test injects the v1 rule
    return {
        "store": store,
        "roots": discover_repo.member_paths(store, workspace),
        "graph": graph,
        "workspace": workspace,
    }


_RULE = {
    "id": "node-header-identity-no-credential",
    "stacks": ["node"],
    "file_globs": ["**/*.js"],
    "scope": "function",
    "identity_read": "req\\.(?:headers|cookies)[\\[.]",
    "requires_absent": ["jwt\\.verify", "passport\\.authenticate",
                        "bcrypt\\.(?:compare|checkpw)", "verify\\w*Token\\s*\\(",
                        "compare(?:Password)?\\s*\\("],
    "dispatch": "\\bnext\\s*\\(",
    "cwe": "CWE-290",
    "severity_score": 9.1,
    "title": "Identity asserted from client-controlled header without any credential",
    "description": (
        "The function reads identity from a request header/cookie and dispatches "
        "with no credential, signature, or token verification — holder-asserted "
        "identity is attackers' to choose."
    ),
    "recommendation": (
        "Replace the asserted value with a verified credential (signed token, "
        "session, mTLS) before dispatch."
    ),
}

_RULES_DOC = {
    "version": "1",
    "dataset_date": "2026-09-07",
    "guard_names": ["authenticat\\w+"],
    "rules": [_RULE],
}


def test_archetype_produces_exactly_the_anchor_finding(substrate) -> None:
    rules = identity_rules.load_identity_rules(_RULES_DOC)
    segment = {
        "id": "seg-x",
        "repos": ["header-identity-app"],
        "files": sorted(
            {n["path"] for n in substrate["graph"]["nodes"] if n.get("path")}
        ),
    }
    raw = identity_rules.evaluate_segment(
        substrate["roots"], substrate["graph"], segment, rules,
        identity_rules.rules_version(_RULES_DOC), segment_id="seg-x",
    )
    truth = header_identity_app.GROUND_TRUTH["anchor_finding"]
    assert len(raw) == 1
    finding = raw[0]
    assert finding["location"]["symbol"] == truth["symbol"]
    assert finding["location"]["file"] == truth["file"]
    assert finding["cwe"] == truth["cwe"]
    assert finding["detection"] == "format"
    assert finding["tool_ref"] == "identity-archetype@1:node-header-identity-no-credential"


def test_safe_jwt_guard_is_never_reported(substrate) -> None:
    rules = identity_rules.load_identity_rules(_RULES_DOC)
    segment = {
        "id": "seg-x",
        "repos": ["header-identity-app"],
        "files": sorted(
            {n["path"] for n in substrate["graph"]["nodes"] if n.get("path")}
        ),
    }
    raw = identity_rules.evaluate_segment(
        substrate["roots"], substrate["graph"], segment, rules, "1"
    )
    assert not any(
        f["location"]["symbol"] in header_identity_app.GROUND_TRUTH["safe_symbols"]
        for f in raw
    )


def test_archetype_finding_normalizes_and_resolves(substrate) -> None:
    rules = identity_rules.load_identity_rules(_RULES_DOC)
    segment = {
        "id": "seg-x",
        "repos": ["header-identity-app"],
        "files": sorted(
            {n["path"] for n in substrate["graph"]["nodes"] if n.get("path")}
        ),
    }
    raw = identity_rules.evaluate_segment(
        substrate["roots"], substrate["graph"], segment, rules, "1"
    )
    normalizer = FindingNormalizer()
    result = normalizer.normalize(
        raw, source="analysis", status="local",
        default_repo="header-identity-app", segment_id="seg-x",
    )
    assert not result.rejected
    assert len(result.findings) == 1
    normalized = result.findings[0]
    assert normalized["id"]
    assert normalized["severity_band"] == "Critical"
    from pipeline.normalize_findings import resolve_and_dedupe

    kept, rejected = resolve_and_dedupe(result.findings, substrate["graph"])
    assert not rejected
    assert kept[0]["location"]["line_start"]
