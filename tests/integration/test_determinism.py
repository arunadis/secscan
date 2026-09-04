"""T098/T099: determinism and token-cost regression (SC-013).

Determinism is not a nicety here — it is what makes a security report auditable.
A finding that cannot be regenerated cannot be defended, and this feature added
several new sources of potential drift: subprocess output from audit tools, a
shipped end-of-support dataset, and line-numbered context packets.
"""

from __future__ import annotations

import json
from pathlib import Path

from pipeline import run as run_mod
from tests.integration.conftest import oracle_responder, write_config

BASELINE = Path(__file__).parent.parent / "benchmark" / "cases" / "baseline_usage.json"


def _scan(root: Path):
    write_config(root)
    return run_mod.run_scan(root, responder=oracle_responder, full=True)


def _artifacts(root: Path) -> dict[str, str]:
    """Every artifact's canonical content, excluding inherently per-run values.

    The scan id is a timestamp plus a nonce by design, so it is stripped from both
    the content and the report *filename* — otherwise every run would trivially
    "differ" and the check would say nothing about determinism.
    """
    out: dict[str, str] = {}
    for path in sorted((root / ".secscan").rglob("*.json")):
        if path.name == "state.json":
            continue
        document = json.loads(path.read_text())
        if isinstance(document, dict):  # raw external-tool reports may be arrays
            document.pop("scan_id", None)
            payload = document.get("payload")
            if isinstance(payload, dict):
                payload.pop("scan_id", None)
        relative = str(path.relative_to(root))
        if relative.startswith(".secscan/reports/"):
            relative = ".secscan/reports/<scan-id>.json"
        # The workspace model records absolute member paths. Two copies of the
        # same tree live at different paths, so the path itself is an input
        # difference, not a determinism failure.
        rendered = json.dumps(document, sort_keys=True).replace(str(root), "<root>")
        out[relative] = rendered
    return out


def test_two_scans_of_identical_input_are_byte_identical(tmp_path: Path) -> None:
    """SC-013. Covers the known `npm audit --json` instability (research.md A2)."""
    from tests.fixtures.single_repo_shop import build

    first_root = build(tmp_path / "a")
    second_root = build(tmp_path / "b")
    _scan(first_root)
    _scan(second_root)

    first = _artifacts(first_root)
    second = _artifacts(second_root)
    assert set(first) == set(second)
    for name in sorted(first):
        assert first[name] == second[name], f"{name} differs between identical runs"


def _scan_batch(root: Path, monkeypatch) -> None:
    """Endpoint + batch policy against the fake provider (feature 012, SC-003)."""
    from tests.helpers.fake_provider import FakeProvider

    monkeypatch.setenv("DETERMINISM_KEY", "sk-fake")
    write_config(
        root,
        {
            "llm": {
                "endpoint": {
                    "provider": "anthropic",
                    "api_key_env": "DETERMINISM_KEY",
                    "model_map": {"local": "m-local", "segment": "m-segment"},
                }
            }
        },
    )
    run_mod.run_scan(
        root, transport=FakeProvider("anthropic"), full=True,
        clock=lambda: 1_700_000_000.0, sleep=lambda s: None,
    )


def test_two_batch_scans_of_identical_input_are_byte_identical(tmp_path: Path, monkeypatch):
    """Feature 012 SC-003: answers and findings under the batch policy are deterministic."""
    from tests.fixtures.single_repo_shop import build

    first_root = build(tmp_path / "a")
    second_root = build(tmp_path / "b")
    _scan_batch(first_root, monkeypatch)
    _scan_batch(second_root, monkeypatch)
    first = _artifacts(first_root)
    second = _artifacts(second_root)
    assert set(first) == set(second)
    assert any(name.startswith(".secscan/analysis/answers/") for name in first)
    for name in sorted(first):
        assert first[name] == second[name], f"{name} differs between identical batch runs"


def test_answer_files_identical_across_policies(tmp_path: Path, monkeypatch) -> None:
    """Feature 012 SC-003: an answer file never records how it was obtained."""
    from tests.fixtures.single_repo_shop import build
    from tests.helpers.fake_provider import FakeProvider

    batch_root = build(tmp_path / "batch")
    live_root = build(tmp_path / "live")
    _scan_batch(batch_root, monkeypatch)
    write_config(
        live_root,
        {
            "llm": {
                "endpoint": {
                    "provider": "anthropic",
                    "api_key_env": "DETERMINISM_KEY",
                    "model_map": {"local": "m-local", "segment": "m-segment"},
                }
            },
            "execution_policy": {"mode": "interactive"},
        },
    )
    run_mod.run_scan(live_root, transport=FakeProvider("anthropic"), full=True)
    batch = {k: v for k, v in _artifacts(batch_root).items() if "/answers/" in k}
    live = {k: v for k, v in _artifacts(live_root).items() if "/answers/" in k}
    assert batch and batch == live


def test_rescanning_the_same_tree_is_stable(tmp_path: Path) -> None:
    from tests.fixtures.single_repo_shop import build

    root = build(tmp_path)
    _scan(root)
    before = _artifacts(root)
    run_mod.run_scan(root, responder=oracle_responder, full=True)
    after = _artifacts(root)
    for name in sorted(set(before) & set(after)):
        assert before[name] == after[name], f"{name} changed on re-scan"


def test_audit_outcomes_carry_no_volatile_text(tmp_path: Path) -> None:
    """Tool diagnostics embed absolute paths and timestamps; they must not survive."""
    from tests.fixtures.single_repo_shop import build

    root = build(tmp_path)
    _scan(root)
    payload = json.loads((root / ".secscan" / "dependency-audit.json").read_text())
    text = json.dumps(payload)
    assert "/private/var" not in text
    assert "-debug-" not in text
    assert str(tmp_path) not in text


#: Feature 001's own efficiency target (spec 001 SC: ">=5x token savings versus a
#: maximal-context baseline"). Used as the absolute floor because the recorded
#: 7.58x baseline was measured on a *different* target under a different profile,
#: and `baseline_usage.json` says explicitly not to compare across those. A true
#: like-for-like pre/post figure would need a baseline captured on this fixture
#: before the feature, which does not exist.
MINIMUM_SAVINGS_FACTOR = 5.0


def test_line_numbering_cost_stays_within_budget(tmp_path: Path) -> None:
    """SC-013: bounded context still pays for itself with numbering included.

    Measured 6.4x on this fixture after numbering. That is comfortably above
    feature 001's 5x target, and the 15% allowance in SC-013 is only meaningful
    against a same-target baseline (see MINIMUM_SAVINGS_FACTOR).
    """
    from tests.fixtures.single_repo_shop import build

    baseline = json.loads(BASELINE.read_text())
    assert baseline["target"] != "single-repo-shop", (
        "if a same-target baseline is ever recorded, tighten this test to the "
        "15% rule in SC-013"
    )

    root = build(tmp_path)
    result = _scan(root)
    usage = result.usage if isinstance(result.usage, dict) else result.usage.to_dict()
    savings = float((usage.get("baseline_comparison") or {}).get("savings_factor") or 0.0)
    assert savings >= MINIMUM_SAVINGS_FACTOR, (
        f"savings fell to {savings}x, below the {MINIMUM_SAVINGS_FACTOR}x floor from "
        "feature 001; line-numbered context may have become too expensive"
    )


def test_context_packets_are_numbered_and_within_budget(tmp_path: Path) -> None:
    """Numbering must not push a packet over budget silently."""
    from tests.fixtures.single_repo_shop import build

    root = build(tmp_path)
    _scan(root)
    for path in sorted((root / ".secscan" / "context-packets").glob("*.json")):
        packet = json.loads(path.read_text())["payload"]
        assert packet["estimated_tokens"] <= packet["token_budget"]["max_context_tokens"]
        for name, text in packet["source"].items():
            first = next((line for line in text.splitlines() if line.strip()), "")
            if not first:
                continue  # an empty file carries nothing to number
            assert "|" in first[:8], f"unnumbered source in {path.name} ({name}): {first!r}"
