"""Contract tests for feature-008 tooling artifacts.

Schemas pinned in specs/008/contracts/data-contracts.md §2/§3/§5. The
constitution merge gate requires contract tests for every schema; these run
before the writers do (T038→T016, T039→T021, T040→T031).
"""

from __future__ import annotations

import json

from pipeline.init_cmd import run_init

VALID_SOURCES = {"project-provided", "system-installed", "missing"}
VALID_DECISIONS = {
    "use",
    "skipped-by-user",
    "skipped-no-consent",
    "not-applicable",
    "missing-declared",
    "installed",
    "skipped-no-key",  # feature 009 (contracts/init-nvd-credential.md §4)
}
VALID_CREDENTIAL_STATES = {  # feature 009: closed four-value enum
    "available",
    "awaiting-key",
    "degraded-no-key",
    "skipped-no-key",
}
VALID_RUN_STATUS = {"ran", "skipped", "failed"}
VALID_DISPROOF_GROUNDS = {
    "package-absent",
    "version-outside-range",
    "location-unresolvable",
    "component-absent",
}


def test_availability_artifact_schema(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    root = tmp_path / "proj"
    root.mkdir()
    (root / "package.json").write_text('{"name": "p"}\n')

    run_init(root, environ={}, no_input=True)

    artifact = root / ".secscan" / "tooling" / "availability.json"
    assert artifact.exists(), "init must persist tooling/availability.json"
    envelope = json.loads(artifact.read_text())
    payload = envelope.get("payload", envelope)
    records = payload["tools"]
    assert records, "an npm project must produce at least one record"
    for record in records:
        assert record["tool_id"]
        assert isinstance(record["applicable"], bool)
        assert record["source"] in VALID_SOURCES
        assert record["decision"] in VALID_DECISIONS
        assert record["network"] in {"none", "on-first-use", "per-run"}
        # optional fields are tolerated absent, null, or a string
        for optional in ("version", "invocation"):
            assert record.get(optional) is None or isinstance(record[optional], str)
        # feature 009 §4: the additive credential object, when present, is
        # exactly {variable, state} with the closed state enum; readers tolerate
        # absence
        credential = record.get("credential")
        if credential is not None:
            assert set(credential) == {"variable", "state"}
            assert credential["variable"].isupper()
            assert credential["state"] in VALID_CREDENTIAL_STATES


def test_runs_artifact_schema(tmp_path) -> None:
    """contracts §3: failed runs carry a reason; tripped guard implies failed."""
    from pipeline.tooling.runner import write_run_records  # T039/T021

    store_records = [
        {
            "scan_id": "s1",
            "tool_id": "npm-audit",
            "tool_version": "9.9.9",
            "db_version": None,
            "status": "failed",
            "reason": "exited without usable output",
            "invocation": "npm audit --json",
            "read_only_guard": "passed",
            "finding_count": 0,
        }
    ]
    write_run_records(tmp_path, store_records)
    payload = json.loads((tmp_path / "tooling" / "runs.json").read_text())
    payload = payload.get("payload", payload)
    for record in payload["runs"]:
        assert record["status"] in VALID_RUN_STATUS
        if record["status"] == "failed":
            assert record["reason"], "failed runs must carry a reason"
        if record["read_only_guard"] == "tripped":
            assert record["status"] == "failed"


def test_suppressions_artifact_schema(tmp_path) -> None:
    """contracts §5: closed disproof ground enum, non-empty evidence."""
    from pipeline.crosscheck import write_suppressions  # T040/T031

    suppressions = [
        {
            "scan_id": "s1",
            "finding": {"tool_ref": "osv-scanner", "description": "ghost advisory"},
            "tool_id": "osv-scanner",
            "disproof_ground": "package-absent",
            "evidence": ["no 'ghost-lib' in resolved npm pins"],
        }
    ]
    write_suppressions(tmp_path, suppressions)
    payload = json.loads((tmp_path / "tooling" / "suppressions.json").read_text())
    payload = payload.get("payload", payload)
    for record in payload["suppressions"]:
        assert record["disproof_ground"] in VALID_DISPROOF_GROUNDS
        assert record["evidence"], "every suppression must carry evidence"
        assert record["tool_id"] and record["finding"]
