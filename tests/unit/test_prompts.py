"""FR-011: only the guidance relevant to a segment is loaded."""

from __future__ import annotations

from pipeline import cwe, prompts
from pipeline.budget import estimate_tokens


def test_all_domains_are_documented() -> None:
    """Every domain the partitioner can assign must have guidance."""
    documented = set(prompts.available_domains())
    assert documented, "domain guidance block not found in segment_scan.md"
    missing = sorted(set(cwe.domains()) - documented)
    assert not missing, f"domains without prompt guidance: {missing}"


def test_filtered_prompt_contains_only_requested_domains() -> None:
    rendered = prompts.render_segment_prompt(["injection", "authorization"])
    assert "**injection**" in rendered
    assert "**authorization**" in rendered
    for absent in ("deserialization", "ssrf", "rate-limiting", "dependencies"):
        assert f"**{absent}**" not in rendered, absent


def test_filtering_preserves_the_surrounding_instructions() -> None:
    """The output/rules sections must survive filtering."""
    rendered = prompts.render_segment_prompt(["secrets"])
    assert "JSON only" in rendered
    assert "needs_escalation" in rendered
    assert "Two levels of reasoning" in rendered
    assert prompts.START_MARKER not in rendered
    assert prompts.END_MARKER not in rendered


def test_filtering_materially_reduces_prompt_size() -> None:
    """The point of FR-011: fewer tokens per invocation."""
    full = prompts.render_prompt("segment_scan.md")
    narrow = prompts.render_segment_prompt(["secrets"])
    assert estimate_tokens(narrow) < estimate_tokens(full) * 0.8


def test_unknown_or_empty_domains_fall_back_to_full_guidance() -> None:
    """Never ship a prompt with no rules at all."""
    for domains in ([], ["telepathy"], None):
        rendered = prompts.render_segment_prompt(domains)
        assert "**injection**" in rendered
        assert "**authorization**" in rendered


def test_unfiltered_prompts_are_returned_intact() -> None:
    review = prompts.render_prompt("final_review.md")
    assert "cross-boundary" in review.lower()
    assert prompts.render_prompt("does_not_exist.md") == ""
