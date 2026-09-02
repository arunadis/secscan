"""External tool output passes the redactor before any artifact (FR-011, T028).

The gitleaks recording embeds a credential-shaped value in ``Match``/``Secret``
fields. The finding is reportable; the value must not survive anywhere.
"""

from __future__ import annotations

from config.loader import Config
from pipeline.redact import Redactor
from pipeline.state import ArtifactStore
from pipeline.tooling import execute
from tests.helpers.tool_shims import copy_fixture, install_shims

SECRET = "AKIAIOSFODNN7EXAMPL3"


def test_secret_in_tool_output_never_reaches_artifacts(tmp_path, monkeypatch) -> None:
    root = copy_fixture("crosscheck", tmp_path)
    install_shims(tmp_path, {"gitleaks": "gitleaks_secret.json"})
    monkeypatch.setenv("PATH", str(tmp_path / "shim-bin"))

    store = ArtifactStore(root)
    limitations = execute.run_external_scans(
        store, {"crosscheck": root}, Config(path=None), redactor=Redactor()
    )

    payload = store.read_optional("findings/external/gitleaks.json") or {"findings": []}
    assert len(payload["findings"]) == 1, "the secret finding itself is reportable"
    assert "value redacted" in payload["findings"][0]["description"]

    # the value is absent from every artifact written this run
    for artifact in sorted((root / ".secscan").rglob("*")):
        if artifact.is_file():
            assert SECRET not in artifact.read_text(errors="replace"), artifact

    assert all(t["tool_id"] != "gitleaks" for t in limitations), (
        "the tool ran; no limitation declared for it"
    )
