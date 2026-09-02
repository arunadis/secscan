"""T038: architecture classification (FR-013–FR-014).

The rule under test throughout: a recorded shape reflects positive evidence, and
an unknown is a state rather than a default.
"""

from __future__ import annotations

from pathlib import Path

from pipeline.architecture import (
    BROWSER,
    CLI,
    LIBRARY,
    SERVER,
    UNDETERMINED,
    ArchitectureProfile,
    classify_member,
    shapes_for,
)


def write(root: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root


def test_browser_only_client_is_recognized(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "package.json": '{"dependencies": {"@angular/core": "9.0.1"}}',
            "index.html": "<app-root></app-root>",
        },
    )
    profile = classify_member(tmp_path)
    assert profile.shape == BROWSER
    assert profile.evidence
    assert any("no server-side entry point" in e for e in profile.evidence)


def test_http_client_dependency_does_not_make_a_spa_a_server(tmp_path: Path) -> None:
    """`axios` in a single-page app issues requests from the victim's browser.

    Treating that as a server-side request issuer would resurrect exactly the
    misclassification this feature exists to prevent.
    """
    write(
        tmp_path,
        {
            "package.json": '{"dependencies": {"react-dom": "18.2.0", "axios": "1.6.0"}}',
            "index.html": "<div id=root></div>",
        },
    )
    assert classify_member(tmp_path).shape == BROWSER


def test_server_framework_is_recognized(tmp_path: Path) -> None:
    write(tmp_path, {"requirements.txt": "flask==3.0.0\npsycopg2-binary==2.9.9\n"})
    profile = classify_member(tmp_path)
    assert profile.shape == SERVER
    assert any("flask" in e for e in profile.evidence)


def test_discovered_http_entry_point_outranks_browser_markers(tmp_path: Path) -> None:
    """A member that answers HTTP requests is a server, whatever else it ships."""
    write(tmp_path, {"package.json": '{"dependencies": {"react-dom": "18.2.0"}}'})
    manifest = {"entrypoints": [{"symbol": "get_order", "kind": "http"}]}
    assert classify_member(tmp_path, manifest).shape == SERVER


def test_cli_is_recognized(tmp_path: Path) -> None:
    write(tmp_path, {"pyproject.toml": "[project.scripts]\nmytool = 'mytool:main'\n"})
    assert classify_member(tmp_path).shape == CLI


def test_package_with_no_entry_point_is_a_library(tmp_path: Path) -> None:
    write(tmp_path, {"pyproject.toml": "[project]\nname = 'helpers'\n"})
    assert classify_member(tmp_path).shape == LIBRARY


def test_nothing_decisive_yields_undetermined_with_a_reason(tmp_path: Path) -> None:
    """FR-013a: unknown is a state, and it says why."""
    write(tmp_path, {"notes.txt": "no manifest here"})
    profile = classify_member(tmp_path)
    assert profile.shape == UNDETERMINED
    assert profile.determined is False
    assert profile.undetermined_reason
    assert "suppression is disabled" in profile.undetermined_reason


def test_undetermined_carries_no_fabricated_evidence(tmp_path: Path) -> None:
    """FR-013b: never substitute an assumed shape for one that was not determined."""
    write(tmp_path, {"README": "x"})
    payload = classify_member(tmp_path).to_dict()
    assert payload["shape"] == UNDETERMINED
    assert "evidence" not in payload
    assert payload["undetermined_reason"]


def test_determined_profile_always_carries_evidence(tmp_path: Path) -> None:
    write(tmp_path, {"requirements.txt": "django==5.0\n"})
    payload = classify_member(tmp_path).to_dict()
    assert payload["evidence"]
    assert "undetermined_reason" not in payload


def test_round_trips_through_its_dict_form(tmp_path: Path) -> None:
    write(tmp_path, {"requirements.txt": "flask==3.0.0\n"})
    profile = classify_member(tmp_path)
    assert ArchitectureProfile.from_dict(profile.to_dict()) == profile


def test_missing_profile_contributes_undetermined_not_nothing() -> None:
    """A classification gap must never silently narrow the reachable set."""
    profiles = {"web": ArchitectureProfile("member", BROWSER, ("x",))}
    assert shapes_for(profiles, ["web", "api"]) == {BROWSER, UNDETERMINED}
    assert shapes_for({}, []) == {UNDETERMINED}


# ------------------------ the same smell in five architectures (T036 fixture)


def test_identical_code_yields_different_shapes(tmp_path: Path) -> None:
    """FR-013: the classifier reads the architecture, not the code.

    Every member holds byte-identical unsafe code. If shapes still differ, the
    classification is genuinely driven by manifests and entry points — which no
    other test in the suite can demonstrate, because they vary the code too.
    """
    from tests.fixtures.architectures import EXPECTED_SHAPES, MEMBERS, SHARED_SMELL, build

    root = build(tmp_path)
    bodies = {(root / m / "src/client.ts").read_text() for m in MEMBERS}
    assert bodies == {SHARED_SMELL}, "the fixture's code is not identical across members"

    actual = {name: classify_member(root / name).shape for name in MEMBERS}
    assert actual == EXPECTED_SHAPES, actual


def test_the_same_finding_is_suppressed_or_retained_by_architecture_alone(tmp_path: Path) -> None:
    """FR-016 + FR-013a, the property the whole applicability relation rests on."""
    from pipeline import applicability
    from tests.fixtures.architectures import MEMBERS, RETAINS_REQUEST_FORGERY, build

    root = build(tmp_path)
    for name in sorted(MEMBERS):
        profile = classify_member(root / name)
        finding = {
            "id": "SEC-0001",
            "cwe": "CWE-918",
            "severity_score": 4.3,
            "confidence": 0.6,
            "location": {"repo": name, "file": "src/client.ts", "line_start": 2, "line_end": 4},
            "evidence": [],
        }
        conclusion = applicability.evaluate(
            finding, {"nodes": [], "edges": []}, {name: profile}, {}
        )
        remapped = applicability.remap(finding, conclusion) is not None
        should_retain = profile.shape in RETAINS_REQUEST_FORGERY
        assert remapped is not should_retain, (
            f"{name} ({profile.shape}): "
            f"{'suppressed but should be retained' if should_retain else 'retained but impossible'}"
        )


def test_undetermined_member_behaves_like_the_server_case(tmp_path: Path) -> None:
    """FR-013a stated as a comparison, which is the form that catches regressions.

    An unknown architecture must land on the retain side with the server, not on
    the suppress side with the browser. Getting this backwards is silent: the
    finding simply disappears.
    """
    from pipeline import applicability
    from tests.fixtures.architectures import build

    root = build(tmp_path)
    verdicts = {}
    for name in ("svc-server", "mystery", "spa-browser"):
        profile = classify_member(root / name)
        finding = {
            "id": "SEC-0001",
            "cwe": "CWE-918",
            "severity_score": 4.3,
            "confidence": 0.6,
            "location": {"repo": name, "file": "src/client.ts", "line_start": 2, "line_end": 4},
            "evidence": [],
        }
        verdicts[name] = applicability.evaluate(
            finding, {"nodes": [], "edges": []}, {name: profile}, {}
        )["applicable"]

    assert verdicts["svc-server"] is True
    assert verdicts["mystery"] != False  # noqa: E712 - `undetermined` is not `False`
    assert verdicts["spa-browser"] is False
