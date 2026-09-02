"""Unit tests for the pure credential-decision module (feature 009, FR-002/004/005).

The module is deliberately pure: presence is read from an injected ``environ``
mapping (never ``os.environ`` directly), so these tests run hermetically.
"""

from __future__ import annotations

from pipeline.tooling.credentials import (
    KEYLESS_STATE_DEGRADED,
    STATE_AVAILABLE,
    STATE_AWAITING_KEY,
    STATE_SKIPPED_NO_KEY,
    guidance_text,
    key_present,
    warning_text,
)
from pipeline.tooling.registry import CredentialSpec

SPEC = CredentialSpec(
    env_var="NVD_API_KEY",
    obtain_url="https://nvd.nist.gov/developers/request-an-api-key",
    absence_impact=(
        "without an NVD API key the NVD data download is heavily rate-limited:"
        " the first sync can take many times longer, and rate-limiting can"
        " cause intermittent sync failures"
    ),
)


def test_state_constants_are_the_closed_four_value_enum() -> None:
    assert {STATE_AVAILABLE, STATE_AWAITING_KEY, STATE_SKIPPED_NO_KEY, KEYLESS_STATE_DEGRADED} == {
        "available",
        "awaiting-key",
        "degraded-no-key",
        "skipped-no-key",
    }


def test_key_present_requires_a_non_empty_value() -> None:
    assert key_present(SPEC, {"NVD_API_KEY": "abc123"})
    assert not key_present(SPEC, {})
    assert not key_present(SPEC, {"NVD_API_KEY": ""})
    # whitespace-only is operationally absent (spec edge case)
    assert not key_present(SPEC, {"NVD_API_KEY": "   \n\t "})


def test_key_present_reads_the_declared_variable_name_only() -> None:
    assert not key_present(SPEC, {"NOT_THE_KEY": "abc123"})


def test_warning_text_states_impact_and_where_to_obtain() -> None:
    text = warning_text(SPEC)
    assert SPEC.absence_impact in text
    assert SPEC.obtain_url in text
    assert SPEC.env_var in text


def test_guidance_text_instructs_by_name_and_never_solicits_a_value() -> None:
    text = guidance_text(SPEC)
    assert SPEC.env_var in text
    assert SPEC.obtain_url in text
    # the guidance must not ask the user to type/paste the key value anywhere:
    # the shell environment is the only supply route (research.md R1)
    assert "paste" not in text.lower()
    assert "enter the key" not in text.lower()
