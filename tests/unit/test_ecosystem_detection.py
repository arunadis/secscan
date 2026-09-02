"""Ecosystem detection from manifests and build files (feature 008, FR-001)."""

from __future__ import annotations

from pathlib import Path

from pipeline.tooling.ecosystem import detect_ecosystems


def _evidence(detection, ecosystem: str) -> list[str]:
    return sorted(d.evidence for d in detection if d.ecosystem == ecosystem)


def test_multi_ecosystem_fixture(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "package.json").write_text("{}")
    (root / "pom.xml").write_text("<project/>")

    detections = detect_ecosystems({"proj": root})

    assert {d.ecosystem for d in detections} == {"npm", "maven"}
    assert _evidence(detections, "npm") == ["package.json"]
    assert _evidence(detections, "maven") == ["pom.xml"]
    assert all(d.member == "proj" for d in detections)


def test_gradle_build_files_detect_maven_ecosystem(tmp_path: Path) -> None:
    root = tmp_path / "jvm"
    root.mkdir()
    (root / "build.gradle.kts").write_text("plugins { java }")

    detections = detect_ecosystems({"jvm": root})

    assert {d.ecosystem for d in detections} == {"maven"}
    assert _evidence(detections, "maven") == ["build.gradle.kts"]


def test_python_and_go_manifests(tmp_path: Path) -> None:
    root = tmp_path / "poly"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.32.0\n")
    (root / "go.mod").write_text("module example.com/poly\n\ngo 1.22\n")

    detections = detect_ecosystems({"poly": root})

    assert {d.ecosystem for d in detections} == {"pypi", "go"}


def test_no_manifests_detects_nothing_honestly(tmp_path: Path) -> None:
    root = tmp_path / "plain"
    root.mkdir()
    (root / "main.py").write_text("print('hello')\n")

    assert detect_ecosystems({"plain": root}) == []


def test_monorepo_members_are_attributed(tmp_path: Path) -> None:
    web = tmp_path / "web"
    api = tmp_path / "api"
    web.mkdir()
    api.mkdir()
    (web / "package.json").write_text("{}")
    (api / "pom.xml").write_text("<project/>")

    detections = detect_ecosystems({"web": web, "api": api})

    by_member = {d.member: d.ecosystem for d in detections}
    assert by_member == {"web": "npm", "api": "maven"}


def test_detections_are_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "package.json").write_text("{}")
    (root / "nested").mkdir()
    (root / "nested" / "requirements.txt").write_text("requests==2.32.0\n")

    first = detect_ecosystems({"proj": root})
    assert first == detect_ecosystems({"proj": root})
    assert _evidence(first, "pypi") == ["nested/requirements.txt"]


def test_skipped_directories_do_not_evidence_ecosystems(tmp_path: Path) -> None:
    """Manifests inside skipped dirs (node_modules, .secscan) don't count."""
    root = tmp_path / "proj"
    (root / "node_modules" / "left-pad-again").mkdir(parents=True)
    (root / "node_modules" / "left-pad-again" / "package.json").write_text("{}")
    (root / ".secscan" / "tooling").mkdir(parents=True)
    (root / ".secscan" / "tooling" / "requirements.txt").write_text("x==1\n")

    assert detect_ecosystems({"proj": root}) == []
