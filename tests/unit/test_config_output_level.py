"""`output.level` configuration key and `SECSCAN_OUTPUT_LEVEL` (feature 011, FR-011)."""

from __future__ import annotations

from pathlib import Path

import pytest

from config import loader


def _write(tmp_path: Path, body: str) -> Path:
    (tmp_path / "config.yaml").write_text("version: 1\n" + body)
    return tmp_path


@pytest.mark.parametrize("level", ["quiet", "default", "verbose"])
def test_output_level_accepts_the_three_values(tmp_path: Path, level: str) -> None:
    config = loader.load(_write(tmp_path, f"output:\n  level: {level}\n"), environ={})
    assert config.output_level == level


def test_output_level_defaults_when_section_absent(tmp_path: Path) -> None:
    config = loader.load(_write(tmp_path, ""), environ={})
    assert config.output_level == "default"


def test_unknown_output_level_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(loader.ConfigError) as exc:
        loader.load(_write(tmp_path, "output:\n  level: loud\n"), environ={})
    assert "output.level must be one of: quiet, default, verbose" in str(exc.value)
    assert "'loud'" in str(exc.value)


def test_unknown_key_under_output_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(loader.ConfigError) as exc:
        loader.load(_write(tmp_path, "output:\n  colour: never\n"), environ={})
    assert "unknown setting 'colour' under output" in str(exc.value)


def test_env_override_beats_config(tmp_path: Path) -> None:
    root = _write(tmp_path, "output:\n  level: quiet\n")
    config = loader.load(root, environ={"SECSCAN_OUTPUT_LEVEL": "verbose"})
    assert config.output_level == "verbose"


def test_env_override_is_validated(tmp_path: Path) -> None:
    with pytest.raises(loader.ConfigError):
        loader.load(_write(tmp_path, ""), environ={"SECSCAN_OUTPUT_LEVEL": "shout"})


def test_loader_and_progress_agree_on_the_level_names() -> None:
    from pipeline.progress import OutputLevel

    assert loader.VALID_OUTPUT_LEVELS == OutputLevel.names()
