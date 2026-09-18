"""Cooperative deadline for `run_scan` (feature 018, FR-007; research R4).

The plugin form must return to its host before the host's tool-call limit. The
driver therefore accepts a ``deadline`` in the injected clock's domain and raises
``ScanPaused`` at the next boundary the pipeline already persists behind. The CLI
never passes a deadline, so nothing changes for it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import run as run_mod
from pipeline.llm_client import AgentHandoff, ScanPaused
from tests.fixtures.single_repo_shop import build as build_shop
from tests.helpers.fake_provider import FakeProvider
from tests.integration.conftest import oracle_responder, write_config

FAKE_KEY = "FAKE_ENDPOINT_KEY_018"


class Clock:
    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def shop(tmp_path: Path) -> Path:
    root = build_shop(tmp_path / "shop")
    write_config(root, {"triage": {"enabled": "off"}})
    return root


def _json_artifacts(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted((root / ".secscan").rglob("*.json")):
        if path.name == "state.json":
            continue
        out[str(path.relative_to(root))] = path.read_text()
    return out


def test_no_deadline_never_pauses(shop: Path) -> None:
    result = run_mod.run_scan(shop, responder=oracle_responder, deadline=None)
    assert result.report_path.exists()


def test_expired_deadline_still_completes_one_unit_then_pauses(shop: Path) -> None:
    """Every call advances the scan by at least one unit of new work, so a resume
    whose pre-checkpoint work alone exceeds the bound can never livelock."""
    clock = Clock()
    with pytest.raises(ScanPaused) as exc:
        run_mod.run_scan(shop, responder=oracle_responder, clock=clock, deadline=clock() - 1)
    paused = exc.value
    assert paused.reason == "deadline"
    assert paused.stage == "build_code_graph", "paused before the *second* stage"
    assert paused.subject is None
    # state.json is saved before the raise so `status` can report the checkpoint.
    assert (shop / ".secscan" / "state.json").exists()
    # The first stage's artifact exists; the second's does not.
    assert (shop / ".secscan" / "workspace.json").exists()
    assert not (shop / ".secscan" / "code-graph.json").exists()

    # A resume with the same expired deadline advances exactly one more stage
    # (the reused first stage does not count as progress).
    with pytest.raises(ScanPaused) as exc:
        run_mod.run_scan(shop, responder=oracle_responder, clock=clock, deadline=clock() - 1)
    assert exc.value.stage != "build_code_graph"
    assert (shop / ".secscan" / "code-graph.json").exists()


def test_no_pause_between_segments_stage_boundaries_only(tmp_path: Path) -> None:
    """Analysis stages re-drive from their first unit on resume, so a pause between
    segments would persist nothing; the driver pauses only at stage checkpoints —
    here the next one after segment analysis is the (checkpointed) triage round."""
    shop = build_shop(tmp_path / "shop")
    write_config(shop, {"triage": {"enabled": "on"}})
    clock = Clock()
    seen: list[str] = []

    def responder(request):
        seen.append(request.payload.get("segment_id", request.payload.get("finding_id")))
        clock.now += 100  # every answer overruns the bound
        return oracle_responder(request)

    with pytest.raises(ScanPaused) as exc:
        run_mod.run_scan(shop, responder=responder, clock=clock, deadline=clock() + 50)
    paused = exc.value
    assert paused.subject is None, "never a per-segment pause"
    assert paused.stage == "finding_triage"
    assert len(seen) >= 2, "all segments of the stage were analysed in one call"
    partial = _json_artifacts(shop)
    assert any(p.startswith(".secscan/findings/local/") for p in partial)

    # Resume with no deadline: completes, and the pre-pause artifacts are unchanged.
    result = run_mod.run_scan(shop, responder=oracle_responder)
    assert result.report_path.exists()
    final = _json_artifacts(shop)
    for path, content in partial.items():
        if "/findings/local/" in path or path.endswith(("workspace.json", "code-graph.json")):
            assert final[path] == content, f"{path} changed across the pause"


def test_reference_run_equals_paused_run(tmp_path: Path) -> None:
    """Artifacts of pause+resume equal a single uninterrupted run (FR-020 parity)."""
    a = build_shop(tmp_path / "a")
    b = build_shop(tmp_path / "b")
    for root in (a, b):
        write_config(root, {"triage": {"enabled": "off"}})

    run_mod.run_scan(a, responder=oracle_responder)

    # An already-expired deadline pauses after every checkpointed stage: the scan
    # settles only through several resumes.
    clock = Clock()
    for _ in range(12):
        try:
            run_mod.run_scan(b, responder=oracle_responder, clock=clock, deadline=clock() - 1)
            break
        except ScanPaused:
            continue
    else:
        raise AssertionError("paused run did not settle")

    def normalised(root: Path) -> dict[str, str]:
        out = {}
        for rel, text in _json_artifacts(root).items():
            doc = json.loads(text)
            if isinstance(doc, dict):
                doc.pop("scan_id", None)
            # The two roots differ only by name; tool invocations record absolute paths.
            text = json.dumps(doc, sort_keys=True)
            for prefix in (str(root.resolve()), str(root)):
                text = text.replace(prefix, "<ROOT>")
            out[rel] = text
        return out

    left, right = normalised(a), normalised(b)
    # Report filenames carry the scan id; compare by directory-relative shape.
    assert {k for k in left if "/reports/" not in k} == {k for k in right if "/reports/" not in k}
    for key in left:
        if "/reports/" in key:
            continue
        assert left[key] == right[key], f"{key} differs between paused and uninterrupted runs"


def test_handoff_takes_precedence_over_deadline(shop: Path) -> None:
    """Without a responder the agent handoff fires; a deadline never masks it."""
    clock = Clock()
    with pytest.raises(AgentHandoff):
        run_mod.run_scan(shop, clock=clock, deadline=clock() + 10_000)


def test_endpoint_interactive_mode_does_not_pause_between_segments(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv(FAKE_KEY, "sk-fake")
    root = build_shop(tmp_path / "shop")
    write_config(
        root,
        {
            "llm": {
                "endpoint": {
                    "provider": "anthropic",
                    "api_key_env": FAKE_KEY,
                    "model_map": {"local": "m-local", "segment": "m-segment"},
                }
            },
            "execution_policy": {"mode": "interactive"},
            "triage": {"enabled": "on"},
        },
    )
    clock = Clock()
    provider = FakeProvider("anthropic")

    def transport(method, url, headers, body, *, timeout):
        clock.now += 100  # every provider call overruns the bound
        return provider(method, url, headers, body, timeout=timeout)

    with pytest.raises(ScanPaused) as exc:
        run_mod.run_scan(
            root, transport=transport, clock=clock, sleep=lambda s: None,
            deadline=clock() + 50,
        )
    paused = exc.value
    # Every segment was answered in one go; the pause landed at the next *stage*
    # boundary (the checkpointed triage round), never between segments (research R4).
    assert paused.subject is None
    assert paused.stage == "finding_triage"
    assert provider.interactive_calls >= 2
