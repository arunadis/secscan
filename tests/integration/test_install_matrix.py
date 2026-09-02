"""T037: installation matrix across supported coding agents (quickstart Scenario 0).

Covers FR-020 (installer + per-project pinning + in-place upgrade), FR-021
(agent-agnostic core + adapters), FR-022 (registered invocable command),
FR-024 (init + environment checks), and the `.secscan/` ignore default.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from installer import core as installer
from installer.agents import ADAPTERS, get_adapter

AGENT_KEYS = sorted(ADAPTERS)


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "demo-project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("def main():\n    return 1\n")
    return root


# --------------------------------------------------------------- matrix tests


@pytest.mark.parametrize("agent", AGENT_KEYS)
def test_install_scaffolds_skill_for_every_agent(project: Path, agent: str) -> None:
    result = installer.install(project, agent)
    adapter = get_adapter(agent)

    assert result.action == "installed"
    assert result.skill_dir.is_dir()
    assert result.skill_dir.is_relative_to(project)
    # The adapter decides where the agent looks for skills.
    assert adapter.skills_dir(project) in result.skill_dir.parents


@pytest.mark.parametrize("agent", AGENT_KEYS)
def test_installed_entrypoint_declares_name_and_description(project: Path, agent: str) -> None:
    """FR-021/FR-022: every adapter emits a valid, invocable entrypoint."""
    result = installer.install(project, agent)
    adapter = get_adapter(agent)
    entry = result.entrypoint

    assert entry.exists()
    assert entry.suffix in (".md", ".toml")

    meta = adapter.parse_entrypoint(entry)
    assert meta["name"] == installer.SKILL_NAME
    assert meta["description"].strip()
    # The scan workflow must survive the transformation.
    assert "security" in meta["body"].lower()
    assert "context" in meta["body"].lower()


@pytest.mark.parametrize("agent", AGENT_KEYS)
def test_payload_is_complete_and_self_contained(project: Path, agent: str) -> None:
    """Per-project install pins this project's scanner version (FR-020)."""
    result = installer.install(project, agent)
    skill = result.skill_dir

    assert (skill / "prompts" / "segment_scan.md").exists()
    assert (skill / "prompts" / "final_review.md").exists()
    assert (skill / "schemas" / "finding.json").exists()
    assert (skill / "cwe_map.json").exists()
    assert (skill / "profiles" / "builtin.yaml").exists()
    # Deterministic scripts travel with the skill so the agent can run them.
    assert (skill / "scripts" / "pipeline" / "run.py").exists()
    assert (skill / "scripts" / "config" / "loader.py").exists()


@pytest.mark.parametrize("agent", AGENT_KEYS)
def test_install_records_a_manifest_with_pinned_version(project: Path, agent: str) -> None:
    result = installer.install(project, agent)
    manifest = json.loads((result.skill_dir / installer.MANIFEST_NAME).read_text())

    assert manifest["agent"] == agent
    assert manifest["tool_version"] == installer.TOOL_VERSION
    assert manifest["config_schema_version"] == installer.CONFIG_SCHEMA_VERSION
    assert manifest["files"], "manifest must inventory installed files for upgrades"


def test_gemini_adapter_emits_toml_not_markdown(project: Path) -> None:
    """research.md R1: Gemini CLI uses flat TOML commands, so translate."""
    result = installer.install(project, "gemini")
    assert result.entrypoint.suffix == ".toml"
    text = result.entrypoint.read_text()
    assert "prompt = " in text
    assert "description = " in text
    # The YAML frontmatter must not leak into the TOML.
    assert not text.lstrip().startswith("---")
    # Argument placeholder is translated to Gemini's syntax.
    assert "$ARGUMENTS" not in text


@pytest.mark.parametrize("agent", ["claude", "copilot", "cursor", "windsurf", "devin", "agents"])
def test_skill_md_agents_keep_yaml_frontmatter(project: Path, agent: str) -> None:
    result = installer.install(project, agent)
    text = result.entrypoint.read_text()
    assert text.startswith("---\n")
    front = yaml.safe_load(text.split("---", 2)[1])
    assert front["name"] == installer.SKILL_NAME
    assert front["description"]


def test_devin_adapter_sets_user_trigger(project: Path) -> None:
    """Adapters may add agent-specific frontmatter the core does not carry."""
    result = installer.install(project, "devin")
    front = yaml.safe_load(result.entrypoint.read_text().split("---", 2)[1])
    assert front.get("triggers") == ["user", "model"]


# ------------------------------------------------------------------ behaviour


def test_unknown_agent_lists_supported_agents(project: Path) -> None:
    with pytest.raises(installer.InstallError) as exc:
        installer.install(project, "clippy")
    assert "clippy" in str(exc.value)
    for key in ("claude", "gemini"):
        assert key in str(exc.value)


def test_install_adds_scan_dir_to_gitignore(project: Path) -> None:
    """T047: artifacts are gitignored by default, opt-in to commit."""
    installer.install(project, "claude")
    ignore = (project / ".gitignore").read_text()
    assert ".secscan/" in ignore

    # Idempotent: installing again must not duplicate the entry.
    installer.install(project, "claude")
    assert (project / ".gitignore").read_text().count(".secscan/") == 1


def test_commit_artifacts_opt_out_of_ignore(project: Path) -> None:
    installer.install(project, "claude", commit_artifacts=True)
    ignore_path = project / ".gitignore"
    if ignore_path.exists():
        assert ".secscan/" not in ignore_path.read_text()


def test_install_is_idempotent(project: Path) -> None:
    first = installer.install(project, "claude")
    second = installer.install(project, "claude")
    assert second.action == "upgraded"
    assert second.skill_dir == first.skill_dir


# -------------------------------------------------------------------- upgrade


def test_upgrade_preserves_config_and_artifacts(project: Path) -> None:
    """FR-020: re-running the installer replaces skill files, keeps state."""
    installer.install(project, "claude")
    from pipeline.init_cmd import run_init

    run_init(project)

    config_path = project / ".secscan" / "config.yaml"
    config_path.write_text(config_path.read_text() + "\n# operator's own note\n")
    artifact = project / ".secscan" / "reports" / "old-scan.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text('{"kept": true}')

    result = installer.install(project, "claude")

    assert result.action == "upgraded"
    assert "operator's own note" in config_path.read_text()
    assert json.loads(artifact.read_text()) == {"kept": True}


def test_upgrade_flags_config_schema_change(project: Path) -> None:
    """FR-020: schema changes are surfaced, not silently applied."""
    installer.install(project, "claude")
    from pipeline.init_cmd import run_init

    run_init(project)

    manifest_path = project / ".claude" / "skills" / installer.SKILL_NAME / installer.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    manifest["config_schema_version"] = 0  # pretend the project is on an older schema
    manifest_path.write_text(json.dumps(manifest))

    result = installer.install(project, "claude")
    assert result.config_schema_changed
    assert any("schema" in note.lower() for note in result.notes)


def test_upgrade_removes_stale_payload_files(project: Path) -> None:
    result = installer.install(project, "claude")
    stale = result.skill_dir / "prompts" / "obsolete_prompt.md"
    stale.write_text("from an older version")

    installer.install(project, "claude")
    assert not stale.exists()


def test_downgrade_requires_force(project: Path) -> None:
    result = installer.install(project, "claude")
    manifest_path = result.skill_dir / installer.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    manifest["tool_version"] = "99.0.0"
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(installer.InstallError) as exc:
        installer.install(project, "claude")
    assert "--force" in str(exc.value)

    assert installer.install(project, "claude", force=True).action == "upgraded"


def test_switching_agents_installs_alongside(project: Path) -> None:
    claude = installer.install(project, "claude")
    devin = installer.install(project, "devin")
    assert claude.skill_dir != devin.skill_dir
    assert claude.entrypoint.exists() and devin.entrypoint.exists()


# ----------------------------------------------------------------------- init


def test_init_generates_config_and_reports_environment(project: Path) -> None:
    """FR-024: init generates the default config and checks the environment."""
    installer.install(project, "claude")
    from pipeline.init_cmd import run_init

    report = run_init(project, environ={})

    config_path = project / ".secscan" / "config.yaml"
    assert config_path.exists()
    assert yaml.safe_load(config_path.read_text())["version"] == 1

    assert report.execution_mode == "agent-mediated"
    assert report.config_created is True
    names = {check.name for check in report.checks}
    assert {"configuration", "analysis model", "credentials"} <= names
    # feature 008 (FR-001): tooling checks are registry-driven and gated on
    # detected ecosystems; this fixture has no manifests, so init must honestly
    # declare that no external tools apply rather than probe a fixed list
    assert "external tooling" in names
    assert report.ready is True  # zero-config must be ready to scan
    assert "agent-mediated" in report.render()


def test_init_is_idempotent_and_does_not_clobber_config(project: Path) -> None:
    installer.install(project, "claude")
    from pipeline.init_cmd import run_init

    run_init(project)
    config_path = project / ".secscan" / "config.yaml"
    config_path.write_text(config_path.read_text() + "\n# keep me\n")

    report = run_init(project)
    assert report.config_created is False
    assert "# keep me" in config_path.read_text()


def test_init_reports_missing_credential_for_configured_endpoint(project: Path) -> None:
    installer.install(project, "claude")
    from pipeline.init_cmd import run_init

    scan_dir = project / ".secscan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "llm": {
                    "mode": "endpoint",
                    "endpoint": {"provider": "anthropic", "api_key_env": "ABSENT_KEY"},
                },
            }
        )
    )

    report = run_init(project, environ={})
    assert report.ready is False
    credential = next(c for c in report.checks if c.name == "credentials")
    assert credential.ok is False
    assert "ABSENT_KEY" in credential.detail


def test_init_surfaces_invalid_configuration(project: Path) -> None:
    """FR-026: problems are reported up front, not at scan time."""
    installer.install(project, "claude")
    from pipeline.init_cmd import run_init

    scan_dir = project / ".secscan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "config.yaml").write_text(
        yaml.safe_dump({"version": 1, "execution_policy": {"mode": "batch-offpeak"}})
    )

    report = run_init(project, environ={})
    assert report.ready is False
    config_check = next(c for c in report.checks if c.name == "configuration")
    assert "offpeak_window" in config_check.detail


# --------------------------------------------------- installed skill can scan


def test_installed_skill_runs_a_real_scan(project: Path) -> None:
    """The end goal: after install + init, the pipeline actually scans."""
    from tests.fixtures.single_repo_shop import build
    from tests.integration.conftest import oracle_responder

    repo = build(project.parent)
    installer.install(repo, "devin")

    from pipeline import run as run_mod
    from pipeline.init_cmd import run_init

    report = run_init(repo, environ={})
    assert report.ready

    result = run_mod.run_scan(repo, responder=oracle_responder, full=True)
    assert result.reported_findings
    assert result.report["execution_mode"] == "agent-mediated"


def test_scan_without_config_directs_user_to_init(project: Path) -> None:
    """FR-024: no config -> clear message naming init, not a low-level error."""
    from config.loader import ConfigNotFound
    from pipeline import run as run_mod

    installer.install(project, "claude")
    with pytest.raises(ConfigNotFound) as exc:
        run_mod.run_scan(project)
    assert "init" in str(exc.value)
