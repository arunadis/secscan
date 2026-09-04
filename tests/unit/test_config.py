"""T016/T017: config validation, profiles, budgets, and execution-mode resolution."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from config import mode as mode_mod
from config import profiles as profiles_mod
from config.loader import (
    Config,
    ConfigError,
    ConfigNotFound,
    apply_env_overrides,
    default_config_yaml,
    load,
    validate_config,
)
from config.mode import ExecutionMode, MissingCredential
from pipeline.budget import BudgetExceeded, TokenBudget, estimate_tokens


def write_config(tmp_path: Path, raw: dict | str) -> Path:
    scan_dir = tmp_path / ".secscan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    path = scan_dir / "config.yaml"
    path.write_text(raw if isinstance(raw, str) else yaml.safe_dump(raw))
    return scan_dir


# ------------------------------------------------------------------- loading


def test_default_config_is_valid() -> None:
    parsed = yaml.safe_load(default_config_yaml())
    assert validate_config(parsed) == []


def test_missing_config_points_user_to_init(tmp_path: Path) -> None:
    """FR-024: a scan without config directs the user to init, not a low-level error."""
    with pytest.raises(ConfigNotFound) as exc:
        load(tmp_path / ".secscan")
    assert "secscan init" in str(exc.value)


def test_load_valid_config(tmp_path: Path) -> None:
    scan_dir = write_config(tmp_path, default_config_yaml())
    config = load(scan_dir, environ={})
    assert config.llm_mode == "auto"
    assert config.execution_mode == "auto"  # batch when an endpoint is configured (012)
    assert config.budgets["max_context_tokens"] == 12000


# ---------------------------------------------------------------- validation


def test_strict_validation_reports_all_problems_at_once() -> None:
    """FR-026: every problem is reported in one pass."""
    problems = validate_config(
        {
            "version": 1,
            "llm": {"mode": "nonsense"},
            "budgets": {"max_context_tokens": -5, "escalation_threshold": 4},
            "scanners": {"unknown-tool": {"enabled": True}},
        }
    )
    assert len(problems) >= 4
    joined = "\n".join(problems)
    assert "llm.mode" in joined
    assert "budgets.max_context_tokens" in joined
    assert "budgets.escalation_threshold" in joined
    assert "unknown-tool" in joined


def test_batch_offpeak_without_window_is_a_conflict() -> None:
    """The documented conflicting-settings example must be rejected."""
    problems = validate_config(
        {"version": 1, "execution_policy": {"mode": "batch-offpeak"}}
    )
    assert any("offpeak_window" in p and "required" in p for p in problems)


def test_unknown_keys_are_rejected_with_expected_names() -> None:
    problems = validate_config({"version": 1, "budgets": {"max_contxt_tokens": 100}})
    assert any("max_contxt_tokens" in p and "expected one of" in p for p in problems)


def test_endpoint_requires_api_key_env_name() -> None:
    problems = validate_config(
        {"version": 1, "llm": {"mode": "endpoint", "endpoint": {"provider": "anthropic"}}}
    )
    assert any("api_key_env" in p for p in problems)


def test_config_rejects_inline_secret_values() -> None:
    """FR-025: the config file must never hold a secret."""
    problems = validate_config(
        {
            "version": 1,
            "llm": {
                "endpoint": {
                    "api_key_env": "ANTHROPIC_API_KEY",
                    "api_key": "sk-ant-do-not-store-me",
                }
            },
        }
    )
    assert any("must not hold a secret" in p for p in problems)


def test_batch_requires_endpoint() -> None:
    problems = validate_config(
        {
            "version": 1,
            "execution_policy": {"mode": "interactive", "batch": {"enabled": True}},
        }
    )
    assert any("batch APIs are unavailable in agent-mediated mode" in p for p in problems)


def test_workspace_integration_must_reference_declared_members() -> None:
    problems = validate_config(
        {
            "version": 1,
            "workspace": {
                "members": [{"name": "orders", "path": "../orders"}],
                "integrations": [{"from": "orders", "to": "ghost", "type": "sync-api"}],
            },
        }
    )
    assert any("unknown member" in p for p in problems)


def test_invalid_redaction_regex_is_reported() -> None:
    problems = validate_config({"version": 1, "redaction": {"extra_patterns": ["([unclosed"]}})
    assert any("invalid regex" in p for p in problems)


def test_config_error_message_lists_problems(tmp_path: Path) -> None:
    scan_dir = write_config(tmp_path, {"version": 1, "llm": {"mode": "bogus"}})
    with pytest.raises(ConfigError) as exc:
        load(scan_dir, environ={})
    assert "refusing to start the scan" in str(exc.value)


# ------------------------------------------------------------ env overrides


def test_env_overrides_apply_without_editing_the_file() -> None:
    raw = {"budgets": {"max_context_tokens": 12000}}
    applied = apply_env_overrides(raw, {"SECSCAN_BUDGETS_MAX_CONTEXT_TOKENS": "4000"})
    assert raw["budgets"]["max_context_tokens"] == 4000
    assert "budgets.max_context_tokens" in applied


def test_env_override_coerces_types() -> None:
    raw: dict = {}
    apply_env_overrides(
        raw,
        {
            "SECSCAN_BUDGETS_ESCALATION_THRESHOLD": "0.5",
            "SECSCAN_EXECUTION_POLICY_MODE": "batch-offpeak",
        },
    )
    assert raw["budgets"]["escalation_threshold"] == 0.5
    assert raw["execution_policy"]["mode"] == "batch-offpeak"


# ------------------------------------------------------------------ profiles


@pytest.mark.parametrize("name", ["quick", "full", "audit"])
def test_builtin_profiles_resolve(name: str) -> None:
    profile = profiles_mod.resolve(name)
    assert profile.name == name
    assert profile.description
    assert 1 <= profile.analysis_depth.max_escalation_level <= 4


def test_profile_thresholds_match_spec_defaults() -> None:
    """FR-028 default report-inclusion thresholds."""
    quick = profiles_mod.resolve("quick")
    assert quick.report_thresholds.min_severity_band == "High"

    full = profiles_mod.resolve("full")
    assert full.report_thresholds.min_severity_band == "Medium"
    assert full.report_thresholds.min_confidence == 0.5

    audit = profiles_mod.resolve("audit")
    assert audit.report_thresholds.min_severity_band == "None"
    assert audit.report_thresholds.min_confidence == 0.0


def test_profiles_control_analysis_depth_not_just_reporting() -> None:
    """FR-028: quick is genuinely cheaper; audit is genuinely exhaustive."""
    quick = profiles_mod.resolve("quick")
    audit = profiles_mod.resolve("audit")
    assert quick.analysis_depth.max_escalation_level < audit.analysis_depth.max_escalation_level
    assert len(quick.analysis_depth.domains) < len(audit.analysis_depth.domains)
    assert audit.analysis_depth.all_domains
    assert not quick.analysis_depth.system_review
    assert quick.depth_key != audit.depth_key


def test_verified_findings_bypass_confidence_floor() -> None:
    """FR-029: a traced path outweighs the heuristic confidence score."""
    thresholds = profiles_mod.resolve("full").report_thresholds
    assert not thresholds.admits("High", confidence=0.2, verified=False)
    assert thresholds.admits("High", confidence=0.2, verified=True)
    # Severity floor still applies even when verified.
    assert not thresholds.admits("Low", confidence=1.0, verified=True)


def test_custom_profile_inherits_from_builtin() -> None:
    custom = {
        "ci-triage": {
            "base": "quick",
            "report_thresholds": {"min_severity_band": "Critical", "min_confidence": 0.6},
        }
    }
    profile = profiles_mod.resolve("ci-triage", custom=custom)
    assert profile.report_thresholds.min_severity_band == "Critical"
    # inherited from quick
    assert profile.analysis_depth.max_escalation_level == 2


def test_per_scan_overrides_are_recorded() -> None:
    profile = profiles_mod.resolve(
        "full", overrides={"report_thresholds": {"min_confidence": 0.9}}
    )
    assert profile.report_thresholds.min_confidence == 0.9
    assert profile.overrides == {"report_thresholds": {"min_confidence": 0.9}}


def test_unknown_profile_lists_available() -> None:
    with pytest.raises(profiles_mod.ProfileError) as exc:
        profiles_mod.resolve("turbo")
    assert "audit" in str(exc.value)


def test_unknown_domain_is_rejected() -> None:
    with pytest.raises(profiles_mod.ProfileError):
        profiles_mod.resolve("x", custom={"x": {"analysis_depth": {"domains": ["telepathy"]}}})


# -------------------------------------------------------------------- budget


def test_budget_enforcement() -> None:
    budget = TokenBudget(1000, 500, 0.75)
    budget.check(900)
    with pytest.raises(BudgetExceeded) as exc:
        budget.check(1200, "segment/seg-1")
    assert "seg-1" in str(exc.value)


def test_budget_escalation_threshold() -> None:
    budget = TokenBudget(1000, 500, 0.75)
    assert budget.should_escalate(500)
    assert not budget.should_escalate(800)


def test_budget_trims_whole_files_and_reports_drops() -> None:
    budget = TokenBudget(60, 100, 0.75)
    mapping = {"big.py": "x" * 1000, "small.py": "y" * 20}
    retained, dropped = budget.trim_to_fit(mapping)
    assert "big.py" in dropped
    assert "small.py" in retained
    assert budget.fits(sum(estimate_tokens(v) for v in retained.values()))


# ------------------------------------------------------------ execution mode


def test_agent_mediated_is_default_without_endpoint() -> None:
    """FR-027: no key required to scan."""
    config = Config(path=None, raw={"llm": {"mode": "auto"}})
    resolution = mode_mod.resolve(config, environ={})
    assert resolution.mode is ExecutionMode.AGENT_MEDIATED
    assert resolution.tier_for("local") == "agent"
    assert resolution.unavailable_features  # endpoint-only features reported


def test_endpoint_config_takes_precedence() -> None:
    config = Config(
        path=None,
        raw={
            "llm": {
                "mode": "auto",
                "endpoint": {
                    "provider": "anthropic",
                    "api_key_env": "TEST_KEY",
                    "model_map": {"local": "haiku", "segment": "sonnet", "system": "opus"},
                },
            }
        },
    )
    resolution = mode_mod.resolve(config, environ={"TEST_KEY": "secret"})
    # An endpoint with no explicit policy is batch by default (feature 012, FR-023).
    assert resolution.mode is ExecutionMode.ENDPOINT_BATCH
    assert resolution.policy_source == "default"
    assert resolution.tier_for("local") == "haiku"
    assert resolution.tier_for("system") == "opus"
    assert not resolution.unavailable_features


def test_missing_credential_for_configured_endpoint_stops_clearly() -> None:
    config = Config(
        path=None,
        raw={"llm": {"endpoint": {"api_key_env": "ABSENT_KEY", "provider": "anthropic"}}},
    )
    with pytest.raises(MissingCredential) as exc:
        mode_mod.resolve(config, environ={})
    assert "ABSENT_KEY" in str(exc.value)
    assert "agent-mediated" in str(exc.value)


def test_explicit_agent_mode_ignores_endpoint() -> None:
    config = Config(
        path=None,
        raw={"llm": {"mode": "agent", "endpoint": {"api_key_env": "X", "provider": "anthropic"}}},
    )
    resolution = mode_mod.resolve(config, environ={})
    assert resolution.mode is ExecutionMode.AGENT_MEDIATED


def test_credential_status_never_exposes_the_value() -> None:
    config = Config(
        path=None, raw={"llm": {"endpoint": {"api_key_env": "TEST_KEY", "provider": "anthropic"}}}
    )
    status = mode_mod.credential_status(config, environ={"TEST_KEY": "super-secret"})
    assert status == {"required": True, "variable": "TEST_KEY", "present": True}
    assert "super-secret" not in str(status)
