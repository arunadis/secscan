"""Feature 012 T007: execution-policy resolution table, new keys, and env overrides.

Rows follow contracts/batch-execution.md §1.
"""

from __future__ import annotations

import pytest
import yaml

from config import loader
from config.loader import Config, apply_env_overrides, default_config_yaml, validate_config
from config.mode import ExecutionMode, resolve

ENDPOINT = {
    "provider": "anthropic", "api_key_env": "K", "model_map": {"local": "h", "segment": "s"},
}
ENV = {"K": "set"}


def _config(endpoint: bool, mode: str | None = None, enabled: bool | None = None, **extra):
    raw: dict = {"version": 1, "llm": {}}
    if endpoint:
        raw["llm"]["endpoint"] = dict(ENDPOINT)
    policy: dict = {}
    if mode is not None:
        policy["mode"] = mode
    if enabled is not None:
        policy["batch"] = {"enabled": enabled}
    if policy:
        raw["execution_policy"] = policy
    raw.update(extra)
    return raw


@pytest.mark.parametrize(
    ("endpoint", "mode", "enabled", "expected", "source"),
    [
        (False, None, None, ExecutionMode.AGENT_MEDIATED, "explicit"),
        (False, "batch", None, ExecutionMode.AGENT_MEDIATED, "explicit"),
        (True, None, None, ExecutionMode.ENDPOINT_BATCH, "default"),
        (True, "auto", None, ExecutionMode.ENDPOINT_BATCH, "default"),
        (True, "auto", True, ExecutionMode.ENDPOINT_BATCH, "explicit"),
        (True, "auto", False, ExecutionMode.ENDPOINT_INTERACTIVE, "explicit"),
        (True, "interactive", None, ExecutionMode.ENDPOINT_INTERACTIVE, "explicit"),
        (True, "interactive", False, ExecutionMode.ENDPOINT_INTERACTIVE, "explicit"),
        (True, "batch", None, ExecutionMode.ENDPOINT_BATCH, "explicit"),
        (True, "batch", True, ExecutionMode.ENDPOINT_BATCH, "explicit"),
        (True, "batch-offpeak", None, ExecutionMode.ENDPOINT_BATCH, "explicit"),
    ],
)
def test_resolution_table(endpoint, mode, enabled, expected, source) -> None:
    raw = _config(endpoint, mode, enabled)
    if mode == "batch-offpeak":
        raw["execution_policy"]["offpeak_window"] = "02:00-06:00"
    resolution = resolve(Config(path=None, raw=raw), ENV)
    assert resolution.mode is expected
    assert resolution.policy_source == source
    if expected is ExecutionMode.ENDPOINT_BATCH:
        assert resolution.batch_window_hours == 24.0
        assert resolution.retry_attempts == 5 and resolution.retry_max_wait_s == 60


def test_resolution_reads_window_and_retry_settings() -> None:
    raw = _config(True, "batch")
    raw["execution_policy"]["batch"] = {"window_hours": 2.5}
    raw["llm"]["retry"] = {"attempts": 2, "max_wait_s": 5}
    resolution = resolve(Config(path=None, raw=raw), ENV)
    assert resolution.batch_window_hours == 2.5
    assert (resolution.retry_attempts, resolution.retry_max_wait_s) == (2, 5)
    assert "(default policy)" not in resolution.describe().splitlines()[0]
    default = resolve(Config(path=None, raw=_config(True)), ENV)
    assert "(default policy)" in default.describe().splitlines()[0]


def test_mode_enum_and_new_key_validation() -> None:
    problems = validate_config(_config(True, "sometimes"))
    assert any("execution_policy.mode must be one of auto, interactive, batch, batch-offpeak" in p
               for p in problems)
    raw = _config(True, "batch")
    raw["execution_policy"]["batch"] = {"window_hours": 0}
    raw["llm"]["retry"] = {"attempts": 0, "max_wait_s": 0}
    problems = validate_config(raw)
    assert any("execution_policy.batch.window_hours must be a positive number" in p
               for p in problems)
    assert any("llm.retry.attempts must be a positive integer" in p for p in problems)
    assert any("llm.retry.max_wait_s must be a positive integer" in p for p in problems)
    assert len(problems) >= 3  # reported together


def test_conflicting_mode_and_enabled_are_rejected() -> None:
    problems = validate_config(_config(True, "batch", False))
    assert any("execution_policy.mode is 'batch' but execution_policy.batch.enabled is false" in p
               for p in problems)
    problems = validate_config(_config(True, "interactive", True))
    assert any(
        "execution_policy.mode is 'interactive' but execution_policy.batch.enabled is true" in p
        for p in problems
    )
    assert validate_config(_config(True, "batch", True)) == []
    assert validate_config(_config(True, "auto", False)) == []


def test_batch_enabled_without_endpoint_still_rejected() -> None:
    problems = validate_config(_config(False, None, True))
    assert any("requires llm.endpoint" in p for p in problems)


def test_unknown_retry_key_rejected_and_known_keys_allowed() -> None:
    raw = _config(True)
    raw["llm"]["retry"] = {"bogus": 1}
    assert any("unknown setting 'bogus' under llm.retry" in p for p in validate_config(raw))
    raw["llm"]["retry"] = {"attempts": 3, "max_wait_s": 10}
    raw["execution_policy"] = {"batch": {"window_hours": 12}}
    assert validate_config(raw) == []


def test_config_accessor_defaults() -> None:
    config = Config(path=None, raw=_config(True))
    assert config.execution_mode == "auto"
    assert config.batch_enabled_explicit is None
    assert config.batch_window_hours == 24.0
    assert config.retry_attempts == 5 and config.retry_max_wait_s == 60
    explicit = Config(path=None, raw=_config(True, "auto", False))
    assert explicit.batch_enabled_explicit is False


def test_env_overrides_land_on_nested_keys() -> None:
    raw = _config(True)
    applied = apply_env_overrides(
        raw,
        {
            "SECSCAN_EXECUTION_POLICY_BATCH_WINDOW_HOURS": "1",
            "SECSCAN_LLM_RETRY_ATTEMPTS": "2",
            "SECSCAN_LLM_RETRY_MAX_WAIT_S": "5",
            "SECSCAN_EXECUTION_POLICY_MODE": "interactive",
        },
    )
    assert raw["execution_policy"]["batch"]["window_hours"] == 1
    assert raw["llm"]["retry"] == {"attempts": 2, "max_wait_s": 5}
    assert raw["execution_policy"]["mode"] == "interactive"
    assert set(applied) == {
        "execution_policy.batch.window_hours", "llm.retry.attempts", "llm.retry.max_wait_s",
        "execution_policy.mode",
    }
    assert validate_config(raw) == []


def test_default_template_declares_auto_mode_and_window() -> None:
    text = default_config_yaml()
    assert "mode: auto" in text and "window_hours: 24" in text
    parsed = yaml.safe_load(text)
    assert parsed["execution_policy"]["mode"] == "auto"
    assert "enabled" not in parsed["execution_policy"]["batch"]
    assert validate_config(parsed) == []
    assert loader.VALID_EXECUTION_MODES == ("auto", "interactive", "batch", "batch-offpeak")
