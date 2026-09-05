"""T028/T032: business_flow config validation, precedence, and --set plumbing
(feature 015, FR-001/FR-002/FR-004/FR-022)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from config import profiles as profiles_mod
from config.loader import (
    ConfigError,
    default_config_yaml,
    load,
    validate_config,
)
from pipeline import business_flow


def _write_config(tmp_path: Path, data: dict) -> Path:
    scan_dir = tmp_path / ".secscan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "config.yaml").write_text(yaml.safe_dump(data, sort_keys=False))
    return scan_dir


def _base() -> dict:
    return yaml.safe_load(default_config_yaml())


class TestValidation:
    def test_unknown_business_flow_key_rejected(self, tmp_path: Path):
        raw = _base()
        raw["business_flow"] = {"enabled": True, "surprise": 1}
        problems = validate_config(raw)
        assert any("unknown setting 'surprise'" in p for p in problems)

    def test_enabled_must_be_boolean(self):
        raw = _base()
        raw["business_flow"] = {"enabled": "yes"}
        problems = validate_config(raw)
        assert any("business_flow.enabled must be a boolean" in p for p in problems)

    def test_applicability_mode_vocabulary(self):
        raw = _base()
        raw["business_flow"] = {"applicability_mode": "sometimes"}
        problems = validate_config(raw)
        assert any("applicability_mode" in p for p in problems)

    def test_unknown_declared_regime_rejected(self):
        raw = _base()
        raw["business_flow"] = {"declared_regimes": ["bogus-regime"]}
        problems = validate_config(raw)
        assert any("unknown regime" in p for p in problems)

    def test_default_template_is_valid(self):
        assert validate_config(_base()) == []


class TestUnsetVersusFalse:
    def test_absent_enabled_is_unset(self, tmp_path: Path):
        scan_dir = _write_config(tmp_path, _base())
        config = load(scan_dir)
        assert config.business_flow_enabled is None  # unset, not False

    def test_explicit_false_is_set(self, tmp_path: Path):
        raw = _base()
        raw["business_flow"] = {"enabled": False}
        config = load(_write_config(tmp_path, raw))
        assert config.business_flow_enabled is False


class TestPrecedence:
    def _profile(self, **overrides):
        raw = _base()
        return profiles_mod.resolve(overrides=overrides, custom=raw.get("profiles"))

    def test_default_off_everywhere(self, tmp_path: Path):
        config = load(_write_config(tmp_path, _base()))
        for name in ("quick", "full", "audit"):
            profile = profiles_mod.resolve(name, custom=config.custom_profiles)
            assert profile.analysis_depth.business_flow is None
            assert business_flow.enabled_for(profile, config) is False

    def test_config_enables_when_profile_silent(self, tmp_path: Path):
        raw = _base()
        raw["business_flow"] = {"enabled": True}
        config = load(_write_config(tmp_path, raw))
        profile = profiles_mod.resolve(custom=config.custom_profiles)
        assert business_flow.enabled_for(profile, config) is True

    def test_profile_flag_beats_config(self, tmp_path: Path):
        raw = _base()
        raw["business_flow"] = {"enabled": True}
        config = load(_write_config(tmp_path, raw))
        profile = profiles_mod.resolve(
            overrides={"analysis_depth": {"business_flow": False}},
            custom=config.custom_profiles,
        )
        assert business_flow.enabled_for(profile, config) is False

    def test_set_override_enables(self, tmp_path: Path):
        """--set analysis_depth.business_flow=true reaches the round (T032)."""
        config = load(_write_config(tmp_path, _base()))
        profile = profiles_mod.resolve(
            overrides={"analysis_depth": {"business_flow": True}},
            custom=config.custom_profiles,
        )
        assert business_flow.enabled_for(profile, config) is True


class TestEnvOverrides:
    def test_env_enabled_and_mode(self, tmp_path: Path):
        scan_dir = _write_config(tmp_path, _base())
        config = load(
            scan_dir,
            environ={
                "SECSCAN_BUSINESS_FLOW_ENABLED": "true",
                "SECSCAN_BUSINESS_FLOW_APPLICABILITY_MODE": "declared-only",
            },
        )
        assert config.business_flow_enabled is True
        assert config.business_flow_applicability_mode == "declared-only"

    def test_env_declared_regimes_commas(self, tmp_path: Path):
        scan_dir = _write_config(tmp_path, _base())
        # Unknown ids still fail validation — env cannot smuggle a regime in.
        with pytest.raises(ConfigError):
            load(scan_dir, environ={"SECSCAN_BUSINESS_FLOW_DECLARED_REGIMES": "nope"})
