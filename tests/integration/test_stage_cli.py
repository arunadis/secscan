"""Stage-level CLIs (contracts/cli-contracts.md).

The contract promises every pipeline stage is runnable standalone as
``python -m pipeline.<stage> --workdir <scan-root>``. These tests hold that
promise honest — and check the standalone path produces the *same* result as the
driver, so the two cannot drift.
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from pipeline import run as run_mod
from pipeline.state import ArtifactStore
from tests.integration.conftest import oracle_responder

#: Stages the contract lists as standalone-runnable and that exist today.
STAGE_MODULES = (
    "discover_repo",
    "build_code_graph",
    "partition_repo",
    "build_context",
    "normalize_findings",
    "correlate_findings",
    "generate_report",
)


@pytest.mark.parametrize("module", STAGE_MODULES)
def test_every_documented_stage_exposes_a_cli(module: str) -> None:
    """contracts/cli-contracts.md: uniform `python -m pipeline.<stage>` surface."""
    imported = importlib.import_module(f"pipeline.{module}")
    assert callable(getattr(imported, "main", None)), f"pipeline.{module} has no main()"


def run_stage(module: str, workdir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", f"pipeline.{module}", "--workdir", str(workdir)],
        capture_output=True,
        text=True,
        cwd=workdir,
        timeout=300,
    )


@pytest.mark.parametrize("module", ["discover_repo", "build_code_graph", "partition_repo"])
def test_early_stages_run_standalone(configured_shop: Path, module: str) -> None:
    """Discovery through partitioning can be driven stage by stage."""
    for stage in ("discover_repo", "build_code_graph", "partition_repo"):
        proc = run_stage(stage, configured_shop)
        assert proc.returncode == 0, f"{stage}: {proc.stderr}"
        if stage == module:
            assert proc.stdout.strip()
            break

    store = ArtifactStore(configured_shop)
    assert store.exists("workspace.json")


def identity(finding: dict) -> tuple:
    """Semantic identity of a finding — ids are allocation artifacts."""
    location = finding["location"]
    return (
        finding["cwe"],
        location["repo"],
        location["file"],
        location.get("symbol"),
        location["line_start"],
    )


def test_full_stage_chain_reproduces_the_driver_result(configured_shop: Path) -> None:
    """Running the stages by hand yields the same findings as `run_scan`."""
    # 1. Reference result from the driver.
    reference = run_mod.run_scan(configured_shop, responder=oracle_responder, full=True)
    reference_ids = sorted(identity(f) for f in reference.reported_findings)
    assert reference_ids

    # 2. Reset findings/report artifacts, keep the model + handoff answers.
    store = ArtifactStore(configured_shop)
    for relative in ("findings/correlated.json",):
        store.path_for(relative).unlink(missing_ok=True)
    for path in store.glob("reports/*"):
        path.unlink()

    # 3. Drive the back half of the pipeline by hand.
    for stage in ("correlate_findings", "generate_report"):
        proc = run_stage(stage, configured_shop)
        assert proc.returncode == 0, f"{stage}: {proc.stderr}"

    correlated = store.read("findings/correlated.json")["findings"]
    reports = store.glob("reports/*.json")
    assert reports, "generate_report must write a report"

    rebuilt = json.loads(reports[-1].read_text())["payload"]
    rebuilt_ids = sorted(
        identity(f) for band in rebuilt["findings_by_band"].values() for f in band
    )
    assert rebuilt_ids == reference_ids
    assert all(f.get("verification") for f in correlated)
    assert all(f.get("reproduction") for f in correlated)


def test_normalize_stage_consumes_agent_responses(configured_shop: Path) -> None:
    """`normalize_findings` turns handoff answers into local findings."""
    from pipeline.llm_client import AgentHandoff

    with pytest.raises(AgentHandoff):
        run_mod.run_scan(configured_shop, full=True)

    handoff = configured_shop / ".secscan" / "handoff"
    responses = handoff / "responses"
    responses.mkdir(parents=True, exist_ok=True)
    for path in sorted((handoff / "requests").glob("*.json")):
        request = json.loads(path.read_text())

        class _Shim:
            payload = request["context_packet"]

        (responses / f"{request['request_id']}.json").write_text(oracle_responder(_Shim()))

    proc = run_stage("normalize_findings", configured_shop)
    assert proc.returncode == 0, proc.stderr
    assert "normalized" in proc.stdout

    store = ArtifactStore(configured_shop)
    local = store.glob("findings/local/*.json")
    assert local
    findings = [
        f
        for path in local
        for f in store.read(f"findings/local/{path.name}")["findings"]
    ]
    assert findings
    for finding in findings:
        assert finding["id"].startswith("SEC-")
        assert finding["cwe"].startswith("CWE-")


def test_request_id_maps_back_to_its_segment() -> None:
    from pipeline.normalize_findings import segment_id_for

    assert segment_id_for("seg-shop-orders-l1") == "seg-shop-orders"
    assert segment_id_for("seg-shop-orders-l4") == "seg-shop-orders"
    assert segment_id_for("seg-shop-orders") == "seg-shop-orders"


def test_stage_cli_reports_missing_prerequisites(tmp_path: Path) -> None:
    """A stage run out of order fails loudly, not silently."""
    from tests.integration.conftest import write_config

    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("x = 1\n")
    write_config(project)

    proc = run_stage("correlate_findings", project)
    assert proc.returncode != 0
    assert "code-graph" in (proc.stderr + proc.stdout)
