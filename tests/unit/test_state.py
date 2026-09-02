"""T016/T017: artifact store, checkpoints, resume, and change detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline.schemas import SchemaError
from pipeline.state import ArtifactStore, SchemaVersionMismatch, canonical_json, hash_document
from tests.contract.test_schemas import valid_manifest, valid_segment


def test_artifact_roundtrip_with_envelope(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    store.write("repository/shop.manifest.json", "discover_repo", valid_manifest(), "manifest")
    payload = store.read("repository/shop.manifest.json")
    assert payload == valid_manifest()

    raw = (store.dir / "repository/shop.manifest.json").read_text()
    assert '"schema_version"' in raw
    assert '"stage": "discover_repo"' in raw


def test_schema_validation_blocks_bad_artifacts(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    bad = valid_segment()
    bad["estimated_tokens"] = -1
    with pytest.raises(SchemaError):
        store.write("segments/x.json", "partition_repo", bad, "segment")


def test_artifacts_are_byte_identical_for_identical_input(tmp_path: Path) -> None:
    """artifact-schemas.md invariant 1: determinism."""
    a = ArtifactStore(tmp_path / "a", scan_id="fixed")
    b = ArtifactStore(tmp_path / "b", scan_id="fixed")
    doc = {"z": 1, "a": [3, 2, 1], "m": {"k": "v"}}
    pa = a.write("x.json", "stage", doc)
    pb = b.write("x.json", "stage", doc)
    assert pa.read_text() == pb.read_text()
    assert canonical_json(doc) == canonical_json(dict(reversed(list(doc.items()))))


def test_resume_skips_completed_stage(tmp_path: Path) -> None:
    """FR-016a: completed stages are skipped when the resume key matches."""
    store = ArtifactStore(tmp_path)
    key = hash_document({"input": "v1"})
    assert not store.should_skip("discover_repo", key)
    store.mark_done("discover_repo", key)
    assert store.should_skip("discover_repo", key)
    # Different input -> must re-run.
    assert not store.should_skip("discover_repo", hash_document({"input": "v2"}))


def test_state_survives_process_restart(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    store.mark_done("discover_repo", "key-1")
    scan_id = store.scan_id

    reopened = ArtifactStore(tmp_path)
    assert reopened.scan_id == scan_id
    assert reopened.stage("discover_repo").status == "done"
    assert reopened.should_skip("discover_repo", "key-1")


def test_failed_stage_records_error(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    store.mark_running("build_code_graph")
    assert store.stage("build_code_graph").status == "running"
    store.mark_failed("build_code_graph", "tree-sitter grammar missing")
    record = store.stage("build_code_graph")
    assert record.status == "failed"
    assert "grammar" in record.error


def test_invalidate_forces_rerun(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    store.mark_done("partition_repo", "k")
    store.invalidate("partition_repo")
    assert not store.should_skip("partition_repo", "k")


def test_change_detection_across_members(tmp_path: Path) -> None:
    """FR-017: per-file hashes drive incremental scans."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_text("print('a')\n")
    (repo / "src" / "b.py").write_text("print('b')\n")

    store = ArtifactStore(tmp_path)
    first = store.snapshot_files({"repo": repo})
    assert set(first) == {"repo:src/a.py", "repo:src/b.py"}
    store.record_files(first)

    (repo / "src" / "a.py").write_text("print('a modified')\n")
    (repo / "src" / "c.py").write_text("print('c')\n")
    (repo / "src" / "b.py").unlink()

    changes = store.changed_files(store.snapshot_files({"repo": repo}))
    assert changes["modified"] == ["repo:src/a.py"]
    assert changes["added"] == ["repo:src/c.py"]
    assert changes["removed"] == ["repo:src/b.py"]


def test_snapshot_ignores_noise_directories(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "node_modules" / "pkg").mkdir(parents=True)
    (repo / "node_modules" / "pkg" / "index.js").write_text("noise")
    (repo / ".venv").mkdir()
    (repo / ".venv" / "x.py").write_text("noise")
    (repo / "app.py").write_text("real")

    store = ArtifactStore(tmp_path)
    snapshot = store.snapshot_files({"repo": repo})
    assert list(snapshot) == ["repo:app.py"]


def test_schema_version_mismatch_is_flagged(tmp_path: Path) -> None:
    """FR-020: upgrades surface required re-runs instead of misreading artifacts."""
    store = ArtifactStore(tmp_path)
    path = store.write("x.json", "stage", {"a": 1})
    path.write_text(path.read_text().replace('"schema_version": "1"', '"schema_version": "99"'))
    with pytest.raises(SchemaVersionMismatch) as exc:
        store.read("x.json")
    assert "Re-run the affected stages" in str(exc.value)


def test_stage_summary_covers_all_stages(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    summary = store.stage_summary()
    assert summary["generate_report"] == "pending"
    assert len(summary) >= 10


def test_meta_roundtrip(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    store.set_meta("profile_depth_key", "all|L4|sys=1")
    assert ArtifactStore(tmp_path).get_meta("profile_depth_key") == "all|L4|sys=1"
