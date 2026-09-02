"""Accuracy-fixture helpers (feature 002).

Extends :mod:`tests.fixtures.build_fixture` with the ground truth the accuracy work
needs to assert, which the original `SeededVuln` cannot express:

* the **exact** symbol line range, so location drift is measurable rather than
  eyeballed (FR-001, SC-001);
* the resolution **tier** a finding is expected to reach, so a language the code
  model cannot parse is asserted to still be *reported* at file tier rather than
  dropped (FR-003, SC-001a);
* whether a sink interpolates the untrusted value after a **fixed prefix**, which
  decides whether a concrete reproduction probe is achievable at all (FR-009);
* the architecture shape a member is expected to classify as, and the weakness
  class it is expected to be remapped to, if any (FR-013, FR-016).

Ground truth is written next to the generated tree as ``ACCURACY_TRUTH.json`` so
tests read declared expectations instead of restating them inline.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path

#: Resolution tiers a finding may legitimately reach (contracts/accuracy-contracts.md §1).
TIER_SYMBOL = "symbol"
TIER_FILE = "file"
TIER_REJECTED = "rejected"

#: Architecture shapes (data-model.md "Architecture Profile").
SHAPES = (
    "server-request-issuer",
    "browser-client",
    "cli",
    "library",
    "undetermined",
)


@dataclass
class ExpectedLocation:
    """The authoritative location a finding must resolve to."""

    file: str
    symbol: str | None
    line_start: int
    line_end: int
    #: `symbol` where the language is parsed, `file` where it is not
    tier: str = TIER_SYMBOL
    #: False at file tier even when a symbol name was reported (Edge Cases)
    symbol_confirmed: bool = True

    def __post_init__(self) -> None:
        if self.tier not in (TIER_SYMBOL, TIER_FILE, TIER_REJECTED):
            raise ValueError(f"unknown tier: {self.tier}")
        if self.line_end < self.line_start:
            raise ValueError(f"{self.file}: line_end precedes line_start")
        if self.tier != TIER_SYMBOL and self.symbol_confirmed:
            raise ValueError(f"{self.file}: symbol cannot be confirmed at {self.tier} tier")


@dataclass
class ExpectedSink:
    """How a sink builds its value — decides probe feasibility (FR-009/FR-010)."""

    file: str
    symbol: str
    #: True when the untrusted value is interpolated after a prefix the attacker
    #: does not control (e.g. `${baseUrl}/user/${id}`), which makes any probe whose
    #: success criterion requires controlling that prefix unachievable.
    fixed_prefix: bool = False
    #: Expected reproduction mode: "observed" only when a full path is traced.
    expect_mode: str = "hypothesis"
    #: When no achievable probe exists, the trigger must be omitted entirely.
    expect_trigger: bool = True


@dataclass
class ExpectedClassification:
    """Architecture-aware classification expectations (FR-013–FR-016)."""

    member: str
    shape: str
    #: Weakness class analysis is expected to propose.
    proposed_cwe: str | None = None
    #: Class it must be remapped to, or None when it must be retained as proposed.
    remapped_cwe: str | None = None
    #: Member that makes the class applicable via reachability, if any.
    enabling_member: str | None = None

    def __post_init__(self) -> None:
        if self.shape not in SHAPES:
            raise ValueError(f"unknown architecture shape: {self.shape}")
        if self.remapped_cwe and self.enabling_member:
            raise ValueError(
                f"{self.member}: a finding cannot be both remapped and kept applicable "
                "by a sibling — see FR-015a"
            )


@dataclass
class AccuracyFixture:
    """A generated tree carrying accuracy ground truth."""

    name: str
    files: dict[str, str] = field(default_factory=dict)
    locations: list[ExpectedLocation] = field(default_factory=list)
    sinks: list[ExpectedSink] = field(default_factory=list)
    classifications: list[ExpectedClassification] = field(default_factory=list)
    #: Values that must NOT produce a coverage gap (redaction precision, FR-036).
    exempt_identifiers: list[str] = field(default_factory=list)
    #: Credentials that MUST still be detected — recall guard (FR-037).
    seeded_credentials: list[str] = field(default_factory=list)

    def write(self, root: Path) -> Path:
        target = root / self.name
        if target.exists():
            shutil.rmtree(target)
        for rel, content in self.files.items():
            path = target / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        truth = {
            "fixture": self.name,
            "locations": [asdict(x) for x in self.locations],
            "sinks": [asdict(x) for x in self.sinks],
            "classifications": [asdict(x) for x in self.classifications],
            "exempt_identifiers": sorted(self.exempt_identifiers),
            "seeded_credentials": sorted(self.seeded_credentials),
        }
        rendered = json.dumps(truth, indent=2, sort_keys=True) + "\n"
        (target / "ACCURACY_TRUTH.json").write_text(rendered)
        return target

    def verify_declared_lines(self, target: Path) -> None:
        """Assert every declared line range actually exists in the written tree.

        Ground truth that has drifted from the fixture is worse than no ground
        truth, because tests then assert a fiction. Fixture builders call this.
        """
        for loc in self.locations:
            path = target / loc.file
            if not path.exists():
                raise AssertionError(f"declared location {loc.file} was not written")
            total = len(path.read_text().splitlines())
            if loc.line_end > total:
                raise AssertionError(
                    f"{loc.file}: declared line_end {loc.line_end} exceeds file length {total}"
                )


def load_accuracy_truth(fixture_root: Path) -> dict:
    return json.loads((fixture_root / "ACCURACY_TRUTH.json").read_text())
