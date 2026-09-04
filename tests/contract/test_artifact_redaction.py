"""001:T075 / 002:T100 — no credential reaches any artifact, not just packets.

This sweep exists because the assertion it makes was previously claimed and not
checked. Before it, the only credential assertion in the suite covered *context
packets* (`test_full_scan.py`), on the reasoning that packets are the only thing a
model ever sees. That reasoning is sound for Principle III and wrong for the
Safety Invariant actually written down, which is that no credential reaches any
**output**. Artifacts are read by humans, committed to repositories, and attached
to tickets.

Feature 002 widened the exposure: five artifact families now carry text derived
from source that a packet-only check never looked at — dependency audit outcomes,
dependency findings, correlated findings, the rendered report, and repository
manifests (which now hold architecture evidence strings).

Every scan artifact is swept, so a *new* artifact family is covered the day it is
added rather than the day someone remembers to extend a list.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from pipeline import progress
from pipeline import run as run_mod
from pipeline.redact import BLOCKED, Redactor
from pipeline.state import LOG_FILE_NAME
from tests.fixtures.single_repo_shop import FIXTURE
from tests.integration.conftest import oracle_responder, write_config

#: Prefix of a redaction marker. Finding one in an artifact is the system working.
REDACTED_PREFIX = "[REDACTED:"

#: Every literal secret seeded into the shop fixture. Taken from the fixture's own
#: source so the two cannot drift apart.
SEEDED_SECRETS: tuple[str, ...] = ("Pr0d-Sh0p-DB-2024!",)


@pytest.fixture(scope="module")
def scanned(tmp_path_factory) -> Path:
    root = FIXTURE.write(tmp_path_factory.mktemp("redaction-sweep"))
    write_config(root)
    # Feature 011: the progress trace is an output too, so the scan is driven with
    # a (quiet) reporter and its scan.log is swept like every other file.
    reporter = progress.build_reporter(
        progress.OutputLevel.QUIET, log_path=root / ".secscan" / LOG_FILE_NAME
    )
    try:
        run_mod.run_scan(root, responder=oracle_responder, full=True, progress=reporter)
    finally:
        reporter.close()
    return root


@pytest.fixture(scope="module")
def scanned_batch(tmp_path_factory, monkeypatch_module) -> Path:
    """The same fixture scanned under the batch policy against the fake provider (012)."""
    from tests.helpers.fake_provider import FakeProvider

    monkeypatch_module.setenv("REDACTION_SWEEP_KEY", "sk-fake")
    root = FIXTURE.write(tmp_path_factory.mktemp("redaction-sweep-batch"))
    write_config(
        root,
        {
            "llm": {
                "endpoint": {
                    "provider": "anthropic",
                    "api_key_env": "REDACTION_SWEEP_KEY",
                    "model_map": {"local": "m-local", "segment": "m-segment"},
                }
            }
        },
    )
    reporter = progress.build_reporter(
        progress.OutputLevel.QUIET, log_path=root / ".secscan" / LOG_FILE_NAME
    )
    try:
        run_mod.run_scan(
            root, transport=FakeProvider("anthropic"), full=True, progress=reporter,
            clock=lambda: 1_700_000_000.0, sleep=lambda s: None,
        )
    finally:
        reporter.close()
    return root


@pytest.fixture(scope="module")
def monkeypatch_module():
    from _pytest.monkeypatch import MonkeyPatch

    patcher = MonkeyPatch()
    yield patcher
    patcher.undo()


def _artifacts(root: Path) -> list[Path]:
    scan_dir = root / ".secscan"
    return sorted(
        p
        for p in scan_dir.rglob("*")
        if p.is_file()
        and (p.suffix in (".json", ".md", ".html") or p.name == LOG_FILE_NAME)
        and "__pycache__" not in p.parts
    )


def test_scan_log_is_seen_by_the_sweep(scanned: Path) -> None:
    """Feature 011 (FR-015/SC-006): the progress trace is swept like any artifact."""
    names = {p.name for p in _artifacts(scanned)}
    assert LOG_FILE_NAME in names, "scan.log was not produced or not swept"


def test_answers_and_ledger_are_seen_by_the_sweep(scanned_batch: Path) -> None:
    """Feature 012 (SC-008): persisted answers and the batch ledger are outputs too."""
    from pipeline.state import BATCH_LEDGER_META

    artifacts = _artifacts(scanned_batch)
    answers = [p for p in artifacts if p.parent.name == "answers"]
    assert answers, "no persisted answers were produced or swept"
    state = json.loads((scanned_batch / ".secscan" / "state.json").read_text())
    ledger = json.dumps(state["meta"][BATCH_LEDGER_META])
    assert ledger and "batch_" in ledger
    redactor = Redactor([])
    for text in [ledger] + [p.read_text() for p in answers]:
        for secret in SEEDED_SECRETS:
            assert secret not in text
        assert not redactor.redact(text).hits, "redactor flagged batch state"


def test_the_sweep_actually_sees_the_artifacts(scanned: Path) -> None:
    """Guard against the sweep silently passing because it found nothing.

    A sweep that iterates an empty list is worse than no sweep: it reports a
    safety property it never examined, which is exactly the defect this file
    was written to correct.
    """
    artifacts = _artifacts(scanned)
    assert len(artifacts) >= 10, f"only {len(artifacts)} artifacts found"

    names = {p.name for p in artifacts}
    # The families feature 002 added or changed. Each must be present, so this
    # test fails if a family stops being written rather than silently skipping it.
    for expected in ("dependency-audit.json", "code-graph.json", "usage.json"):
        assert expected in names, f"{expected} was not produced"
    assert any(p.parent.name == "reports" for p in artifacts), "no report was written"
    assert any(p.suffix == ".html" for p in artifacts), "no HTML report was written"
    assert any("manifest" in p.name for p in artifacts), "no repository manifest"
    assert any(p.parent.name == "context-packets" for p in artifacts)


def test_no_seeded_secret_appears_in_any_artifact(scanned: Path) -> None:
    """The literal check: a known credential, swept across every output."""
    offenders: list[str] = []
    for path in _artifacts(scanned):
        text = path.read_text(errors="replace")
        for secret in SEEDED_SECRETS:
            if secret in text:
                offenders.append(f"{path.relative_to(scanned)} leaks {secret!r}")
    assert not offenders, "\n".join(offenders)


def test_no_artifact_contains_anything_the_redactor_would_flag(scanned: Path) -> None:
    """The general check: the redactor's own detector, applied to its own outputs.

    Stronger than the literal check because it catches credentials this fixture
    does not seed. Redaction markers are excluded — finding `[REDACTED:...]` in an
    artifact is the system working.
    """
    redactor = Redactor()
    offenders: list[str] = []
    marker = re.compile(r"\[(?:REDACTED|BLOCKED):[^\]]*\]")
    for path in _artifacts(scanned):
        text = path.read_text(errors="replace")
        # Strip whole markers first: they are the redactor's own output, and
        # leaving them in would make the detector argue with itself. The
        # replacement is a placeholder token so the *remainder* of the line is
        # evaluated in its real shape (feature 005 embeds markers mid-line in
        # code excerpts, e.g. `DB_PASSWORD = "[REDACTED:...]"`).
        cleaned = marker.sub("***", text)
        if redactor.scan(cleaned):
            offenders.append(str(path.relative_to(scanned)))
    assert not offenders, "artifacts still containing detectable secrets: " + ", ".join(offenders)


def _strings(value: Any, key: str = "value") -> list[tuple[str, str]]:
    """Every ``(key, string)`` pair in a nested JSON document.

    The key is carried so each value can be re-evaluated in the `key: value` form
    it actually has on disk — the field name is part of what makes a value a
    credential or not.
    """
    if isinstance(value, str):
        return [(key, value)]
    if isinstance(value, dict):
        return [pair for k, v in value.items() for pair in _strings(v, str(k))]
    if isinstance(value, list):
        return [pair for v in value for pair in _strings(v, key)]
    return []


def test_no_finding_field_carries_a_credential(scanned: Path) -> None:
    """Field-level sweep over findings, including the blocks 002 added.

    `dependency`, `calibration`, `applicability`, `framework_control` and
    `reclassification` are all new, and several interpolate source-derived text
    into prose a reader will see.
    """
    redactor = Redactor()
    findings_dir = scanned / ".secscan" / "findings"
    documents = list(findings_dir.rglob("*.json")) if findings_dir.exists() else []
    assert documents, "no finding artifacts were produced"

    for path in documents:
        payload = json.loads(path.read_text()).get("payload") or {}
        for finding in payload.get("findings") or []:
            for key, text in _strings(finding):
                for secret in SEEDED_SECRETS:
                    assert secret not in text, f"{path.name}/{finding.get('id')}: {text[:80]}"
                if REDACTED_PREFIX in text or BLOCKED in text:
                    continue
                # Evaluate the value as it actually appears on disk — a JSON
                # key/value line. Feeding a bare token strips the context the
                # redactor legitimately uses, and would flag ordinary field
                # values like a kebab-case rule name.
                serialized = f'  "{key}": {json.dumps(text)}'
                assert not redactor.scan(serialized), (
                    f"{path.name}/{finding.get('id')}.{key} carries a credential: {text[:80]}"
                )


def test_audit_outcomes_carry_no_credential_and_no_local_path(scanned: Path) -> None:
    """FR-031/SC-013: subprocess output is normalized, not passed through.

    Audit tools print absolute paths and, in unlucky cases, registry tokens from
    a project's own configuration. Neither may survive into an artifact.
    """
    payload = json.loads(
        (scanned / ".secscan" / "dependency-audit.json").read_text()
    )["payload"]
    text = json.dumps(payload)
    for secret in SEEDED_SECRETS:
        assert secret not in text
    assert not Redactor().scan(text)
    assert str(scanned) not in text, "an absolute local path reached the artifact"
    assert "_authToken" not in text
    assert "-debug-" not in text, "a per-run tool log path reached the artifact"


def test_report_renderings_carry_no_credential(scanned: Path) -> None:
    """Both renderings, since the markdown is what a human actually reads."""
    reports = sorted((scanned / ".secscan" / "reports").iterdir())
    assert reports, "no report was written"
    redactor = Redactor()
    for path in reports:
        text = path.read_text(errors="replace")
        for secret in SEEDED_SECRETS:
            assert secret not in text, path.name
        assert not redactor.scan(text), path.name


def test_hardcoded_credential_is_still_reported_as_a_finding(scanned: Path) -> None:
    """The counterpart guard: redaction must not delete the finding itself.

    A sweep that passes because the credential finding vanished would be a
    regression dressed as a success, so the value is absent *and* the finding
    that a credential exists is present.
    """
    findings_dir = scanned / ".secscan" / "findings"
    documents = list(findings_dir.rglob("*.json"))
    cwes = {
        finding.get("cwe")
        for path in documents
        for finding in (json.loads(path.read_text()).get("payload") or {}).get("findings") or []
    }
    assert "CWE-798" in cwes, "the hard-coded credential is no longer reported at all"
