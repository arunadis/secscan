"""T070/T071: audit adapter guarantees and advisory attribution.

Each guarantee here exists because its violation would be worse than reporting
nothing at all. In particular `clean` must mean *audited and clean* — conflating
it with "could not check" converts an unknown into a reassurance, which is the
single worst outcome available to this module.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.audits import attribution
from pipeline.audits.base import (
    DEFAULT_TIMEOUT_S,
    STATUS_ADVISORIES,
    STATUS_CLEAN,
    STATUS_COULD_NOT_CHECK,
    Advisory,
    AuditAdapter,
)
from pipeline.audits.go import GovulncheckAudit
from pipeline.audits.java import MavenCoordinateAudit
from pipeline.audits.node import NpmAudit, PnpmAudit, YarnAudit
from pipeline.audits.python import PipAudit

ADAPTERS = (NpmAudit, PnpmAudit, YarnAudit, PipAudit, GovulncheckAudit, MavenCoordinateAudit)


# ------------------------------------------------------------------ contract


@pytest.mark.parametrize("adapter_cls", ADAPTERS)
def test_adapter_declares_its_contract(adapter_cls) -> None:
    adapter = adapter_cls()
    assert adapter.ecosystem
    assert adapter.tool
    assert adapter.manifests
    assert adapter.capability in ("native-advisory", "coordinates-plus-offline-match")


@pytest.mark.parametrize("adapter_cls", ADAPTERS)
def test_command_is_read_only(adapter_cls) -> None:
    """FR-031: no install, no upgrade, no write. Asserted on the argv itself."""
    command = " ".join(adapter_cls()._command())
    forbidden = ("install", "update", "upgrade", "add ", "fix", "--write", "-w ")
    for token in forbidden:
        assert token not in command, f"{adapter_cls.__name__}: '{token}' in {command!r}"


@pytest.mark.parametrize("adapter_cls", ADAPTERS)
def test_detect_never_executes_anything(adapter_cls, tmp_path: Path) -> None:
    """Detection is manifest presence only."""
    assert adapter_cls().detect(tmp_path) is False


@pytest.mark.parametrize("adapter_cls", ADAPTERS)
def test_missing_toolchain_is_could_not_check_with_a_command(adapter_cls, tmp_path: Path) -> None:
    """FR-033: never `clean`, and always actionable."""
    adapter = adapter_cls()
    adapter.tool = "definitely-not-a-real-tool"
    outcome = adapter.audit(tmp_path, "m", timeout_s=5)
    assert outcome.status == STATUS_COULD_NOT_CHECK
    assert outcome.reason
    assert outcome.remediation_command
    assert outcome.checked is False


@pytest.mark.parametrize("adapter_cls", ADAPTERS)
def test_audit_never_raises(adapter_cls, tmp_path: Path) -> None:
    outcome = adapter_cls().audit(tmp_path, "m", timeout_s=5)
    assert outcome.status in (STATUS_ADVISORIES, STATUS_CLEAN, STATUS_COULD_NOT_CHECK)


def test_manifest_and_lockfile_are_unchanged_by_an_audit(tmp_path: Path) -> None:
    """FR-031, checked rather than trusted."""
    (tmp_path / "package.json").write_text('{"dependencies":{}}')
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion":3}')
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    NpmAudit().audit(tmp_path, "m", timeout_s=30)
    after = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    assert before == after


class _StubAdapter(AuditAdapter):
    ecosystem = "npm"
    tool = "sh"
    manifests = ("package.json",)

    def __init__(self, payload: str, exit_code: int = 0) -> None:
        self._payload = payload
        self._exit = exit_code

    def _command(self) -> list[str]:
        return ["sh", "-c", f"printf '%s' '{self._payload}'; exit {self._exit}"]

    def _parse(self, stdout: str, root: Path) -> list[Advisory]:
        return NpmAudit()._parse(stdout, root)


def test_clean_means_audited_and_clean(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    outcome = _StubAdapter('{"vulnerabilities":{}}').audit(tmp_path, "m", timeout_s=10)
    assert outcome.status == STATUS_CLEAN


def test_nonzero_exit_without_output_is_not_clean(tmp_path: Path) -> None:
    """The ambiguous case. Ambiguity is never a reassurance."""
    (tmp_path / "package.json").write_text("{}")
    outcome = _StubAdapter("", exit_code=1).audit(tmp_path, "m", timeout_s=10)
    assert outcome.status == STATUS_COULD_NOT_CHECK
    assert "exited 1" in outcome.reason


def test_unparseable_output_is_could_not_check(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    outcome = _StubAdapter("not json at all").audit(tmp_path, "m", timeout_s=10)
    assert outcome.status == STATUS_COULD_NOT_CHECK
    assert "could not be parsed" in outcome.reason


def test_timeout_is_could_not_check(tmp_path: Path) -> None:
    class _Slow(_StubAdapter):
        def _command(self) -> list[str]:
            return ["sh", "-c", "sleep 5"]

    (tmp_path / "package.json").write_text("{}")
    outcome = _Slow("").audit(tmp_path, "m", timeout_s=1)
    assert outcome.status == STATUS_COULD_NOT_CHECK
    assert "did not finish" in outcome.reason


def test_output_is_normalized_not_verbatim(tmp_path: Path) -> None:
    """`npm audit --json` varies between runs; volatile fields must not survive."""
    payload = json.dumps(
        {
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "high",
                    "range": "<4.17.21",
                    "via": [{"source": 1065, "url": "https://example/GHSA-x"}],
                    "effects": ["a", "b"],
                    "fixAvailable": {"name": "lodash", "version": "4.17.21"},
                }
            }
        }
    ).replace("'", "")
    advisories = NpmAudit()._parse(payload, tmp_path)
    assert len(advisories) == 1
    advisory = advisories[0]
    assert advisory.package == "lodash"
    assert advisory.affected_range == "<4.17.21"
    assert advisory.fixed_version == "4.17.21"
    assert advisory.severity == "high"
    assert advisory.exposure == "runtime"
    # `effects` is volatile and must not appear anywhere in the normalized form.
    assert "effects" not in str(advisory)


def test_java_without_an_advisory_export_refuses_to_report_clean(tmp_path: Path) -> None:
    """Enumerating coordinates without matching them is not an assessment."""
    (tmp_path / "pom.xml").write_text("<project/>")
    outcome = MavenCoordinateAudit().audit(tmp_path, "m", timeout_s=10)
    assert outcome.status == STATUS_COULD_NOT_CHECK
    assert "not assessed" in outcome.reason or "advisory export" in outcome.reason


# -------------------------------------------------------------- attribution


def advisory(package="lodash", ecosystem="npm", exposure="runtime") -> Advisory:
    return Advisory(
        package=package,
        ecosystem=ecosystem,
        affected_range="<4.17.21",
        fixed_version="4.17.21",
        advisory_ids=("GHSA-x",),
        severity="high",
        exposure=exposure,
    )


def test_one_advisory_across_members_yields_one_finding(tmp_path: Path) -> None:
    """FR-030b: grouped by identity, attributing every affected member."""
    grouped = attribution.group({"web": [advisory()], "admin": [advisory()]})
    assert len(grouped) == 1
    assert set(grouped[0].members) == {"web", "admin"}
    assert grouped[0].attribution == attribution.ATTRIBUTION_PER_MEMBER


def test_runtime_exposure_wins_over_development(tmp_path: Path) -> None:
    """FR-032: the exposure that ships is the one that matters."""
    grouped = attribution.group(
        {"web": [advisory(exposure="development")], "admin": [advisory(exposure="runtime")]}
    )
    assert grouped[0].advisory.exposure == "runtime"


def test_hoisted_lockfile_attributes_by_declaring_manifest(tmp_path: Path) -> None:
    """FR-030e: fallback 2, when native per-member output is unavailable."""
    for member, deps in (("web", {"lodash": "4.17.20"}), ("admin", {})):
        root = tmp_path / member
        root.mkdir()
        (root / "package.json").write_text(json.dumps({"dependencies": deps}))
    grouped = attribution.group(
        {"web": [advisory()], "admin": [advisory()]},
        roots={"web": tmp_path / "web", "admin": tmp_path / "admin"},
        lockfile_shared=True,
    )
    assert grouped[0].members == ("web",)
    assert grouped[0].attribution == attribution.ATTRIBUTION_PER_MEMBER


def test_undeAerivable_attribution_is_stated_not_guessed(tmp_path: Path) -> None:
    """FR-030f: neither guessed nor broadened to every member."""
    for member in ("web", "admin"):
        root = tmp_path / member
        root.mkdir()
        (root / "package.json").write_text('{"dependencies":{}}')
    grouped = attribution.group(
        {"web": [advisory()]},
        roots={"web": tmp_path / "web", "admin": tmp_path / "admin"},
        lockfile_shared=True,
    )
    assert grouped[0].attribution == attribution.ATTRIBUTION_NOT_DERIVABLE
    assert grouped[0].members == ()


def test_missing_lockfile_marks_version_ambiguity(tmp_path: Path) -> None:
    """FR-035: stated on the finding rather than resolved by guessing."""
    grouped = attribution.group({"web": [advisory()]}, version_ambiguous={"web": True})
    payload = attribution.to_finding_payload(grouped[0], "native:npm")
    assert payload["version_ambiguous"] is True


def test_grouping_is_deterministic() -> None:
    per_member = {"b": [advisory("lodash"), advisory("axios")], "a": [advisory("lodash")]}
    first = [g.advisory.package for g in attribution.group(per_member)]
    second = [g.advisory.package for g in attribution.group(per_member)]
    assert first == second == sorted(first)


def test_finding_payload_carries_required_fields() -> None:
    grouped = attribution.group({"web": [advisory()]})
    payload = attribution.to_finding_payload(grouped[0], "native:npm")
    for key in ("package", "ecosystem", "exposure", "attribution", "audit_source"):
        assert key in payload


def test_default_timeout_is_bounded() -> None:
    assert 0 < DEFAULT_TIMEOUT_S <= 600
