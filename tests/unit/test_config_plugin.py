"""`plugin.run_bound_s` configuration key and `SECSCAN_PLUGIN_RUN_BOUND_S` (feature 018)."""

from __future__ import annotations

from pathlib import Path

import pytest

from config import loader


def _write(tmp_path: Path, body: str) -> Path:
    (tmp_path / "config.yaml").write_text("version: 1\n" + body)
    return tmp_path


def test_run_bound_defaults_to_45(tmp_path: Path) -> None:
    config = loader.load(_write(tmp_path, ""), environ={})
    assert config.plugin_run_bound_s == 45


@pytest.mark.parametrize("value", [5, 45, 3600])
def test_run_bound_accepts_range(tmp_path: Path, value: int) -> None:
    config = loader.load(_write(tmp_path, f"plugin:\n  run_bound_s: {value}\n"), environ={})
    assert config.plugin_run_bound_s == value


@pytest.mark.parametrize("value", ["4", "3601", "'45'", "true", "4.5"])
def test_run_bound_rejects_out_of_range_or_non_int(tmp_path: Path, value: str) -> None:
    with pytest.raises(loader.ConfigError) as exc:
        loader.load(_write(tmp_path, f"plugin:\n  run_bound_s: {value}\n"), environ={})
    assert "plugin.run_bound_s must be an integer between 5 and 3600" in str(exc.value)


def test_unknown_key_under_plugin_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(loader.ConfigError) as exc:
        loader.load(_write(tmp_path, "plugin:\n  bound: 1\n"), environ={})
    assert "unknown setting 'bound' under plugin" in str(exc.value)


def test_env_override(tmp_path: Path) -> None:
    config = loader.load(_write(tmp_path, ""), environ={"SECSCAN_PLUGIN_RUN_BOUND_S": "120"})
    assert config.plugin_run_bound_s == 120
