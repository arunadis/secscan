"""Feature 012 T019: batch token share and the estimated-saving figure (FR-013)."""

from __future__ import annotations

from pipeline.usage import UsageTracker

ASSUMPTION = "provider's published 50% batch discount"


def test_batch_tokens_are_tracked_separately() -> None:
    usage = UsageTracker()
    usage.record("segment_analysis", 100, 20, batch=True)
    usage.record("segment_analysis", 50, 10, batch=False)
    assert usage.batch_input_tokens == 100 and usage.batch_output_tokens == 20
    assert usage.total_input_tokens == 150 and usage.total_output_tokens == 30


def test_estimated_saving_percent_formula() -> None:
    assert UsageTracker().estimated_saving_percent == 0.0
    all_batch = UsageTracker()
    all_batch.record("s", 100, 100, batch=True)
    assert all_batch.estimated_saving_percent == 50.0
    none = UsageTracker()
    none.record("s", 100, 100)
    assert none.estimated_saving_percent == 0.0
    half = UsageTracker()
    half.record("s", 100, 0, batch=True)
    half.record("s", 100, 0)
    assert half.estimated_saving_percent == 25.0


def test_serialisation_carries_the_new_fields_and_round_trips() -> None:
    usage = UsageTracker()
    usage.record("s", 100, 100, batch=True)
    doc = usage.to_dict()
    share = doc["batch_share"]
    assert share["batch_input_tokens"] == 100 and share["batch_output_tokens"] == 100
    assert share["estimated_saving_percent"] == 50.0
    assert share["assumption"] == ASSUMPTION
    assert UsageTracker.from_dict(doc).to_dict() == doc


def test_markdown_shows_labelled_saving_row() -> None:
    usage = UsageTracker()
    usage.record("s", 100, 100, batch=True)
    assert (
        f"| Estimated saving vs interactive pricing | 50.0% (assumes the {ASSUMPTION}) |"
        in usage.render_markdown()
    )
