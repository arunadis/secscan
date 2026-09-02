"""Init provisioning flows for external tools (feature 008, US1).

quickstart.md Scenarios 1-3: applicability-driven offers, project-provided
discovery, and the confirmed install list. Everything runs offline against
PATH shims; fixture trees are copied into tmp_path because init creates
``.secscan/`` in the project root.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.init_cmd import run_init
from pipeline.tooling import provision
from tests.helpers.tool_shims import copy_fixture, install_brew_shim, install_shims

RECORDED = {
    "npm": "npm_audit.json",
    "semgrep": "semgrep.json",
    "osv-scanner": "osv_crosscheck.json",
    "trivy": "trivy.json",
    "gitleaks": "gitleaks.json",
}


def _init(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    shims: dict[str, str] | None = None,
    **kwargs,
):
    if shims is not False:
        bin_dir = install_shims(root.parent, shims or dict(RECORDED))
    else:
        bin_dir = root.parent
    monkeypatch.setenv("PATH", str(bin_dir))
    return run_init(root, environ={}, **kwargs)


def _tooling(report) -> dict[str, dict]:
    return {record["tool_id"]: record for record in report.tooling}


# ------------------------------------------------------- Scenario 1 (T009)


def test_applicability_offers_only_detected_ecosystems(tmp_path, monkeypatch) -> None:
    root = copy_fixture("multi_eco", tmp_path)
    report = _init(root, monkeypatch, no_input=True)

    offered = _tooling(report)
    assert set(offered) == {
        "semgrep", "gitleaks", "osv-scanner", "trivy", "npm-audit", "owasp-dependency-check",
    }
    # pypi and go tools are never offered: the project has neither ecosystem
    assert "pip-audit" not in offered and "govulncheck" not in offered
    # per-tool network requirement is declared (FR-002)
    assert offered["npm-audit"]["network"] == "per-run"
    assert report.ready


def test_python_only_project_offers_no_jvm_or_node_tools(tmp_path, monkeypatch) -> None:
    root = tmp_path / "pypi_project"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.32.0\n")

    report = _init(root, monkeypatch, no_input=True)

    offered = _tooling(report)
    assert "pip-audit" in offered
    assert "npm-audit" not in offered and "owasp-dependency-check" not in offered


# ------------------------------------------------------- Scenario 2 (T010)


def test_project_provided_plugin_is_used_directly(tmp_path, monkeypatch) -> None:
    root = copy_fixture("project_provided", tmp_path)
    report = _init(root, monkeypatch, no_input=True)

    record = _tooling(report)["owasp-dependency-check"]
    assert record["source"] == "project-provided"
    assert "mvnw" in record["invocation"]
    # never offered for installation
    assert record["decision"] != "missing-declared"
    assert "owasp-dependency-check" not in report.install_plan


def test_project_provided_wins_over_system_copy(tmp_path, monkeypatch) -> None:
    root = copy_fixture("project_provided", tmp_path)
    # system copy also present
    _init(root, monkeypatch, shims={**RECORDED, "dependency-check.sh": "odc.json"}, no_input=True)
    report = run_init(root, environ={}, no_input=True)

    record = _tooling(report)["owasp-dependency-check"]
    assert record["source"] == "project-provided"


# ------------------------------------------------------- Scenario 3 (T011)


def test_nothing_installs_before_confirmation(tmp_path, monkeypatch) -> None:
    root = copy_fixture("multi_eco", tmp_path)
    bin_dir = tmp_path / "brew-bin"
    install_brew_shim(bin_dir, mapping=RECORDED)

    monkeypatch.setenv("PATH", str(bin_dir))
    report = run_init(root, environ={}, prompt=lambda _text: "none")

    assert report.install_plan, "missing tools must be enumerated before consent"
    assert not (bin_dir / "npm").exists()
    decisions = {r["tool_id"]: r["decision"] for r in report.tooling if r["source"] == "missing"}
    assert decisions
    # "none" to the credential question is not an explicit provide/proceed, so
    # the NVD-backed tool is skipped honestly; non-credential tools follow the
    # existing skipped-by-user path (feature 009, FR-010)
    assert decisions["owasp-dependency-check"] == "skipped-no-key"
    assert all(
        d == "skipped-by-user"
        for tool, d in decisions.items() if tool != "owasp-dependency-check"
    )


def test_selective_deselection_installs_only_confirmed_subset(tmp_path, monkeypatch) -> None:
    root = copy_fixture("multi_eco", tmp_path)
    bin_dir = tmp_path / "brew-bin"
    install_brew_shim(bin_dir, mapping=RECORDED)

    presented: list[str] = []
    monkeypatch.setenv("PATH", str(bin_dir))
    report = run_init(
        root,
        environ={},
        prompt=lambda text: (presented.append(text), "npm-audit")[1],
    )

    assert (bin_dir / "npm").exists()
    assert not (bin_dir / "semgrep").exists()
    decisions = {r["tool_id"]: r["decision"] for r in report.tooling}
    assert decisions["npm-audit"] == "installed"
    assert decisions["osv-scanner"] == "skipped-by-user"
    assert presented  # the exact list was presented before installing


def test_install_flag_all_and_subset(tmp_path, monkeypatch) -> None:
    root = copy_fixture("multi_eco", tmp_path)
    bin_dir = tmp_path / "brew-bin"
    install_brew_shim(bin_dir, mapping=RECORDED)

    monkeypatch.setenv("PATH", str(bin_dir))
    report = run_init(root, environ={}, install="npm-audit,osv-scanner")

    assert (bin_dir / "npm").exists() and (bin_dir / "osv-scanner").exists()
    assert not (bin_dir / "semgrep").exists()
    listed = "\n".join(report.install_plan)
    assert "npm-audit" in listed and "osv-scanner" in listed


def test_no_input_and_declined_runs_report_limitation(tmp_path, monkeypatch) -> None:
    root = copy_fixture("multi_eco", tmp_path)
    bin_dir = tmp_path / "brew-bin"
    install_brew_shim(bin_dir, mapping=RECORDED)

    monkeypatch.setenv("PATH", str(bin_dir))
    report = run_init(root, environ={}, no_input=True)

    decisions = {r["tool_id"]: r["decision"] for r in report.tooling if r["source"] == "missing"}
    assert decisions
    # non-credential tools: skipped-no-consent; the NVD-backed tool records the
    # honest keyless decision (feature 009, FR-009)
    assert decisions["owasp-dependency-check"] == "skipped-no-key"
    assert all(
        d == "skipped-no-consent"
        for tool, d in decisions.items() if tool != "owasp-dependency-check"
    )
    assert report.ready, "missing optional tools never block readiness (contracts/cli.md)"


def test_failed_installation_is_reported_not_fatal(tmp_path, monkeypatch) -> None:
    root = copy_fixture("multi_eco", tmp_path)
    bin_dir = tmp_path / "brew-bin"
    install_brew_shim(bin_dir, mapping=RECORDED)
    monkeypatch.setenv("SECSCAN_SHIM_BREW_FAIL", "1")  # brew shim exits 1, creates nothing
    monkeypatch.setenv("PATH", str(bin_dir))

    report = run_init(root, environ={}, yes=True)

    decisions = {r["tool_id"]: r["decision"] for r in report.tooling}
    assert decisions["owasp-dependency-check"] == "skipped-no-key"  # feature 009
    assert all(d != "installed" for d in decisions.values())
    assert any(d == "missing-declared" for d in decisions.values())
    assert report.ready


# =============================================================== feature 009
# US1: NVD_API_KEY presence handling at init time (spec 009, FR-001..FR-007).


def _availability(root: Path) -> dict[str, dict]:
    payload = json.loads(
        (root / ".secscan" / "tooling" / "availability.json").read_text()
    )
    return {record["tool_id"]: record for record in payload["tools"]}


def test_key_present_records_available_without_credential_prompt(
    tmp_path, monkeypatch
) -> None:
    """T007: key set ⇒ no credential prompt, record annotated available, and
    only credential-declaring tools carry the credential object."""
    root = copy_fixture("multi_eco", tmp_path)
    bin_dir = install_shims(tmp_path, dict(RECORDED))
    monkeypatch.setenv("PATH", str(bin_dir))

    prompts: list[str] = []
    report = run_init(
        root,
        environ={"NVD_API_KEY": "qs-test-sentinel-0001"},
        # interactive (prompt stub present) but the credential question must never fire
        prompt=lambda text: (prompts.append(text), "none")[1],
    )

    assert not any("NVD_API_KEY" in p or "API key" in p for p in prompts), (
        f"credential prompt fired despite key: {prompts}"
    )
    record = _tooling(report)["owasp-dependency-check"]
    assert record["credential"] == {"variable": "NVD_API_KEY", "state": "available"}
    # only the NVD-backed record is annotated
    assert all(
        "credential" not in r
        for tool, r in _tooling(report).items()
        if tool != "owasp-dependency-check"
    )
    # persisted artifact carries the same annotation (FR-007)
    persisted = _availability(root)["owasp-dependency-check"]
    assert persisted["credential"]["state"] == "available"
    # report states presence, never validity (FR-003) and never the value (FR-011)
    rendered = report.render()
    assert "presence checked, key not validated" in rendered
    assert "qs-test-sentinel-0001" not in rendered


def test_provide_key_choice_installs_wired_and_awaits_key(tmp_path, monkeypatch) -> None:
    """T008: interactive keyless + 'provide' ⇒ guidance echoes the obtain URL,
    the tool installs wired-by-name, the record is awaiting-key; re-run with
    the key set upgrades to available without reinstalling (FR-005c, FR-007)."""
    root = copy_fixture("multi_eco", tmp_path)
    bin_dir = tmp_path / "brew-bin"
    install_brew_shim(bin_dir, mapping={**RECORDED, "dependency-check.sh": "odc.json"})
    monkeypatch.setenv("PATH", str(bin_dir))

    echo_lines: list[str] = []
    # credential prompt fires BEFORE the install-consent prompt (FR-004/R7)
    answers = iter(["provide", "owasp-dependency-check"])
    report = run_init(
        root,
        environ={},
        prompt=lambda _text: next(answers),
        echo=echo_lines.append,
    )

    assert (bin_dir / "dependency-check.sh").exists(), "tool must be installed"
    record = _tooling(report)["owasp-dependency-check"]
    assert record["decision"] == "installed"
    assert record["credential"] == {"variable": "NVD_API_KEY", "state": "awaiting-key"}
    assert "awaiting key" in report.render()
    assert "https://nvd.nist.gov/developers/request-an-api-key" in "\n".join(echo_lines)

    mtime_before = (bin_dir / "dependency-check.sh").stat().st_mtime_ns
    rerun = run_init(
        root,
        environ={"NVD_API_KEY": "qs-test-sentinel-0002"},
        no_input=True,
    )
    record2 = _tooling(rerun)["owasp-dependency-check"]
    assert record2["credential"]["state"] == "available"
    assert record2["decision"] == "use"  # already present: upgraded, not reinstalled
    assert (bin_dir / "dependency-check.sh").stat().st_mtime_ns == mtime_before


# --------------------------------------------------------------- US2 (feature 009)
# Keyless interactive flows: warned first, explicit choice, honestly recorded.


def test_keyless_skip_choice_installs_nothing_and_stays_ready(tmp_path, monkeypatch) -> None:
    """T011: interactive keyless + 'skip' ⇒ no install attempt for the NVD tool,
    skipped-no-key recorded with the how-to-add-later note, init still ready
    (FR-006, FR-008)."""
    root = copy_fixture("multi_eco", tmp_path)
    bin_dir = tmp_path / "brew-bin"
    install_brew_shim(bin_dir, mapping=RECORDED)
    monkeypatch.setenv("PATH", str(bin_dir))

    answers = iter(["skip", "none"])
    report = run_init(root, environ={}, prompt=lambda _t: next(answers))

    assert not (bin_dir / "dependency-check.sh").exists(), (
        "skipped tool must not be installed"
    )
    record = _tooling(report)["owasp-dependency-check"]
    assert record["decision"] == "skipped-no-key"
    assert record["credential"] == {"variable": "NVD_API_KEY", "state": "skipped-no-key"}
    assert report.ready, "a credential skip never blocks readiness (FR-006)"
    rendered = report.render()
    assert "skipped — no NVD key" in rendered
    assert "re-run init" in rendered  # FR-008: how to add the tool later


def test_keyless_proceed_warns_before_install_and_records_degraded(
    tmp_path, monkeypatch
) -> None:
    """T012: interactive keyless + 'proceed' ⇒ the implication warning is
    emitted BEFORE any installation runs, then the tool installs and records
    degraded-no-key (FR-004, FR-005b)."""
    root = copy_fixture("multi_eco", tmp_path)
    bin_dir = tmp_path / "brew-bin"
    install_brew_shim(bin_dir, mapping={**RECORDED, "dependency-check.sh": "odc.json"})
    monkeypatch.setenv("PATH", str(bin_dir))

    events: list[str] = []
    original_install = provision.install_selected

    def recording_install(missing, selection):
        # the warning MUST have been emitted before any installation runs
        assert any("rate-limited" in line for line in events), (
            f"install proceeded before the keyless warning: {events}"
        )
        return original_install(missing, selection)

    monkeypatch.setattr(
        "pipeline.tooling.provision.install_selected", recording_install
    )

    answers = iter(["proceed", "owasp-dependency-check"])
    report = run_init(
        root,
        environ={},
        prompt=lambda _t: next(answers),
        echo=events.append,
    )

    assert (bin_dir / "dependency-check.sh").exists()
    record = _tooling(report)["owasp-dependency-check"]
    assert record["decision"] == "installed"
    assert record["credential"] == {"variable": "NVD_API_KEY", "state": "degraded-no-key"}
    warning = "\n".join(events)
    assert "rate-limited" in warning and "nvd.nist.gov" in warning
    assert "rate-limited (explicit choice)" in report.render()


def test_already_installed_keyless_tool_reports_degraded_without_prompt(
    tmp_path, monkeypatch
) -> None:
    """T012 edge case: system-installed ODC + no key ⇒ presence check still
    runs, no install-side prompt is issued, informational degraded line."""
    root = copy_fixture("multi_eco", tmp_path)
    install_shims(tmp_path, {**RECORDED, "dependency-check.sh": "odc.json"})
    monkeypatch.setenv("PATH", str(tmp_path / "shim-bin"))

    prompts: list[str] = []
    report = run_init(
        root,
        environ={},
        no_input=True,
        prompt=lambda text: (prompts.append(text), "none")[1],
    )

    assert not any("NVD" in p or "key" in p for p in prompts), (
        f"credential prompt fired for an already-installed tool: {prompts}"
    )
    record = _tooling(report)["owasp-dependency-check"]
    assert record["source"] == "system-installed"
    assert record["credential"] == {"variable": "NVD_API_KEY", "state": "degraded-no-key"}
    assert "rate-limited" in report.render()


# --------------------------------------------------------------- US3 (feature 009)
# Non-interactive determinism: never prompt, default skip, explicit opt-in only.


def test_no_input_never_prompts_and_skips_keyless_nvd_tool(tmp_path, monkeypatch) -> None:
    """T015: headless keyless run ⇒ zero credential interaction, skipped-no-key
    recorded with declared reason, report ready (FR-009)."""
    root = copy_fixture("multi_eco", tmp_path)
    bin_dir = tmp_path / "brew-bin"
    install_brew_shim(bin_dir, mapping=RECORDED)
    monkeypatch.setenv("PATH", str(bin_dir))

    prompts: list[str] = []
    # prompt callable present but must never be invoked in no_input mode
    report = run_init(
        root,
        environ={},
        no_input=True,
        prompt=lambda text: (prompts.append(text), "all")[1],
    )

    assert not prompts, f"no_input run prompted: {prompts}"
    record = _tooling(report)["owasp-dependency-check"]
    assert record["decision"] == "skipped-no-key"
    assert record["credential"]["state"] == "skipped-no-key"
    assert "no NVD key" in record["detail"]
    assert "re-run init" in report.render()
    assert report.ready


def test_non_tty_stdin_keyless_skips_without_waiting(tmp_path, monkeypatch) -> None:
    """T015 (cont.): when stdin is not a TTY and no prompt callable exists, the
    run completes unattended with the keyless NVD tool skipped (FR-009)."""
    root = copy_fixture("multi_eco", tmp_path)
    bin_dir = tmp_path / "brew-bin"
    install_brew_shim(bin_dir, mapping=RECORDED)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    report = run_init(root, environ={})

    record = _tooling(report)["owasp-dependency-check"]
    assert record["decision"] == "skipped-no-key"
    assert report.ready


def test_blanket_consent_keyless_filters_nvd_tool_unless_flagged(tmp_path, monkeypatch) -> None:
    """T016: --yes / --install=all keyless ⇒ NVD tool excluded (skipped-no-key);
    allow_keyless_nvd=True installs degraded-no-key; the flag NEVER widens the
    tool selection (FR-010)."""
    root = copy_fixture("multi_eco", tmp_path)
    bin_dir = tmp_path / "brew-bin"
    install_brew_shim(bin_dir, mapping={**RECORDED, "dependency-check.sh": "odc.json"})
    monkeypatch.setenv("PATH", str(bin_dir))

    report = run_init(root, environ={}, yes=True)
    assert not (bin_dir / "dependency-check.sh").exists(), (
        "blanket --yes must not install keyless NVD-backed tools"
    )
    record = _tooling(report)["owasp-dependency-check"]
    assert record["decision"] == "skipped-no-key"

    flagged = run_init(root, environ={}, yes=True, allow_keyless_nvd=True)
    record2 = _tooling(flagged)["owasp-dependency-check"]
    assert record2["decision"] == "installed"
    assert record2["credential"]["state"] == "degraded-no-key"

    # the flag widens nothing by itself: no consent, nothing installs
    # (fresh brew shim dir: installs from the runs above must not leak in)
    bin_dir2 = tmp_path / "brew-bin-2"
    install_brew_shim(bin_dir2, mapping=RECORDED)
    monkeypatch.setenv("PATH", str(bin_dir2))
    plain = run_init(root, environ={}, no_input=True, allow_keyless_nvd=True)
    assert _tooling(plain)["npm-audit"]["decision"] == "skipped-no-consent"
    assert _tooling(plain)["owasp-dependency-check"]["decision"] == "skipped-no-consent"
    assert (
        _tooling(plain)["owasp-dependency-check"]["credential"]["state"]
        == "skipped-no-key"
    )
