"""T029: disabled-by-default parity (feature 015, FR-001/FR-005, SC-001).

Re-running a scan in place with the feature off must reproduce byte-identical
artifacts, and the scan must contain no flow artifacts at all — the feature is
invisible until enabled. Parity against the pre-feature tool is additionally
guarded structurally: no stage of the new feature writes anything while disabled.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from pipeline import run as run_mod
from tests.fixtures.single_repo_shop import build as build_shop
from tests.integration.conftest import oracle_responder, silent_responder, write_config


def _snapshot(store_dir: Path) -> dict[str, str]:
    return {
        path.relative_to(store_dir).as_posix(): path.read_text()
        for path in sorted(store_dir.rglob("*.json"))
    }


def test_disabled_scan_is_byte_identical_across_full_reruns(tmp_path: Path):
    root = build_shop(tmp_path / "repo")
    write_config(root)
    store_dir = root / ".secscan"

    run_mod.run_scan(root, responder=oracle_responder, full=True)
    first = _snapshot(store_dir)

    # Wipe analysis state but keep config, then re-run everything from scratch.
    config_text = (store_dir / "config.yaml").read_text()
    shutil.rmtree(store_dir)
    store_dir.mkdir(parents=True)
    (store_dir / "config.yaml").write_text(config_text)
    run_mod.run_scan(root, responder=oracle_responder, full=True)
    second = _snapshot(store_dir)

    scan_ids = (
        json.loads(first["state.json"])["scan_id"],
        json.loads(second["state.json"])["scan_id"],
    )

    def normalize(artifacts: dict[str, str], scan_id: str) -> dict[str, str]:
        out = {
            name.replace(scan_id, "<scan-id>"): text.replace(scan_id, "<scan-id>")
            for name, text in artifacts.items()
        }
        # state.json carries wall-clock bookkeeping (stage updated_at), which the
        # constitution explicitly keeps out of artifacts; only content is compared.
        state = json.loads(out["state.json"])
        for record in state.get("stages", {}).values():
            record["updated_at"] = 0
        out["state.json"] = json.dumps(state, indent=2, sort_keys=True)
        return out

    assert normalize(first, scan_ids[0]) == normalize(second, scan_ids[1])


def test_disabled_scan_has_no_flow_artifacts(tmp_path: Path):
    root = build_shop(tmp_path / "repo")
    write_config(root)
    result = run_mod.run_scan(root, responder=oracle_responder, full=True)
    store_dir = root / ".secscan"
    artifacts = _snapshot(store_dir)
    assert "business-flows.json" not in artifacts
    assert "findings/flows.json" not in artifacts
    report_json = next(
        k for k in artifacts if k.startswith("reports/") and k.endswith(".json")
    )
    report = json.loads(artifacts[report_json])
    assert "flow_coverage" not in report
    assert not any(f.get("flow_ref") for f in result.findings)


def test_unset_enabled_key_never_blocks_non_interactive(tmp_path: Path):
    # FR-004: unset preference in a direct run ⇒ disabled, no prompting, no pause.
    root = build_shop(tmp_path / "repo")
    write_config(root)  # no business_flow.enabled key at all
    result = run_mod.run_scan(root, responder=silent_responder, full=True)
    assert result.report["coverage"]["segments_analyzed"] >= 0
    assert not (root / ".secscan" / "business-flows.json").exists()
