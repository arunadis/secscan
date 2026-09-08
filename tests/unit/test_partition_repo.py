"""Feature 016 T024 (US3): subdivided segments never lose reachability context
(FR-011/FR-012): every part carries the route enumeration, production files order
ahead of test files, and test-only endpoints are attributed test-scoped."""

from __future__ import annotations

from pathlib import Path

from pipeline.partition_repo import _subdivide

_FILLER = "x = 1\n" * 30  # comfortably over a small usable budget per file


def _segment() -> dict:
    return {
        "id": "seg-app-backend",
        "name": "Backend",
        "repos": ["app"],
        "purpose": "Handles backend functionality.",
        "domains": ["authentication"],
        "entrypoints": ["GET /api/clients", "POST /api/clients", "GET /api/clients/999 [test]"],
        "files": [
            "backend/src/__tests__/clients.test.js",  # alphabetically first, prod-last by rule
            "backend/src/routes/clients.js",
            "backend/src/routes/work_entries.js",
            "backend/src/middleware/auth.js",
        ],
        "dependencies": [],
        "data_stores": [],
        "estimated_tokens": 1000,
    }


def _materialize(root: Path, files: list[str]) -> None:
    for relative in files:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_FILLER)


def test_every_part_carries_the_route_enumeration(tmp_path: Path) -> None:
    segment = _segment()
    _materialize(tmp_path, segment["files"])
    parts = _subdivide(segment, tmp_path, 120)  # usable 84 tokens → forces splits
    assert len(parts) > 1
    for part in parts:
        assert part["entrypoints"] == segment["entrypoints"]


def test_enumeration_is_bounded_with_an_explicit_remainder(tmp_path: Path) -> None:
    """Scale guard (the 10x slow test drives 734 routes through every part):
    a part carries a bounded head plus an explicit remainder, never the full
    unbounded list."""
    from pipeline.partition_repo import _MAX_PART_ENTRYPOINTS

    segment = _segment()
    segment["entrypoints"] = [f"GET /r{i}" for i in range(_MAX_PART_ENTRYPOINTS + 25)]
    _materialize(tmp_path, segment["files"])
    parts = _subdivide(segment, tmp_path, 120)
    assert len(parts) > 1
    for part in parts:
        assert len(part["entrypoints"]) == _MAX_PART_ENTRYPOINTS + 1
        assert part["entrypoints"][-1].startswith("+25 more")
        assert part["entrypoints"][-1].endswith(segment["id"] + ".json)")


def test_single_part_keeps_enumeration_too(tmp_path: Path) -> None:
    segment = _segment()
    segment["files"] = ["backend/src/routes/clients.js"]
    _materialize(tmp_path, segment["files"])
    parts = _subdivide(segment, tmp_path, 12000)
    assert len(parts) == 1
    assert parts[0]["entrypoints"] == segment["entrypoints"]


def test_production_files_precede_test_files_in_part_assignment(tmp_path: Path) -> None:
    segment = _segment()
    _materialize(tmp_path, segment["files"])
    parts = _subdivide(segment, tmp_path, 120)
    test_first_part = next(
        p for p in parts if any("__tests__" in f for f in p["files"])
    )
    assert parts.index(test_first_part) == len(parts) - 1  # tests land last


def test_part_marker_identity_unchanged(tmp_path: Path) -> None:
    segment = _segment()
    _materialize(tmp_path, segment["files"])
    parts = _subdivide(segment, tmp_path, 120)
    for index, part in enumerate(parts, start=1):
        assert part["id"].endswith(f"-p{index}")
        assert part["subdivided_from"] == segment["id"]
