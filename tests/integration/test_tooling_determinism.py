"""Two-run byte-identity across tooling artifacts (feature 008, Principle I).

Mirrors tests/integration/test_determinism.py's comparison, pinning the new
artifacts this feature writes: availability.json, runs.json, suppressions.json,
ingested external findings, and the report set.
"""

from __future__ import annotations

import json
from pathlib import Path

from pipeline import run as run_mod
from tests.helpers.tool_shims import copy_fixture, install_shims
from tests.integration.conftest import silent_responder, write_config


def _artifacts(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted((root / ".secscan").rglob("*")):
        # JSON only, matching the established determinism test's scope: the
        # markdown/html renders embed the scan id by design (feature 005).
        if not path.is_file() or path.suffix != ".json":
            continue
        if path.name in ("state.json",):
            continue
        document = json.loads(path.read_text(errors="replace"))
        document.pop("scan_id", None)
        payload = document.get("payload")
        if isinstance(payload, dict):
            payload.pop("scan_id", None)
        relative = str(path.relative_to(root))
        if relative.startswith(".secscan/reports/"):
            relative = ".secscan/reports/<scan-id>.json"
        out[relative] = json.dumps(document, sort_keys=True).replace(str(root), "<root>")
    return out


def test_two_scans_with_same_tools_are_byte_identical(tmp_path, monkeypatch) -> None:
    shims = {"osv-scanner": "osv_crosscheck.json", "semgrep": "semgrep_crosscheck.json"}
    results: list[dict[str, str]] = []
    for name in ("a", "b"):
        root = copy_fixture("crosscheck", tmp_path / name)
        bin_dir = install_shims(tmp_path / name, shims)
        monkeypatch.setenv("PATH", str(bin_dir))
        write_config(root)
        run_mod.run_scan(root, responder=silent_responder, full=True)
        results.append(_artifacts(root))

    first, second = results
    assert set(first) == set(second), "two runs produced different artifact sets"
    for name in sorted(first):
        assert first[name] == second[name], f"{name} differs between identical runs"


def test_two_inits_with_identical_environment_are_byte_identical(
    tmp_path, monkeypatch
) -> None:
    """Feature 009: the credential annotation keeps availability.json
    byte-identical across identical input+environment (Principle I), in both
    the key-present and keyless variants."""
    from pipeline.init_cmd import run_init

    for variant, environ in enumerate(({}, {"NVD_API_KEY": "any-presence-marker"})):
        artifacts: list[str] = []
        for name in (f"{variant}a", f"{variant}b"):
            root = copy_fixture("multi_eco", tmp_path / name)
            install_shims(tmp_path / name, {})
            monkeypatch.setenv("PATH", str(tmp_path / name / "shim-bin"))
            run_init(root, environ=environ, no_input=True, allow_keyless_nvd=True)
            artifacts.append(
                json.dumps(
                    json.loads(
                        (root / ".secscan" / "tooling" / "availability.json").read_text()
                    ),
                    sort_keys=True,
                )
            )
        assert artifacts[0] == artifacts[1], (
            f"availability.json differs between identical init runs (env {environ!r})"
        )
