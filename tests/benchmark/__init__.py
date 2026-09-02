"""Accuracy benchmark harness (FR-043, FR-043a, FR-043b).

A benchmark *case* pairs a scan target with the expected outcome **per accuracy
defect class**, so a regression in one class fails the check without being masked
by another class improving (FR-043b). That per-class structure is the whole point:
a single aggregate score would let the injection fix hide a dependency regression.

Two kinds of case exist (data-model.md "Accuracy Benchmark Case"):

``reviewed-real``
    A real target whose expected outcomes come from an independent human review.
    The reviewer is the source of truth; if the reviewer disputes something the
    case accepts, the case is wrong.

``seeded-workspace``
    A generated workspace whose expected outcomes are declared when the fixture is
    built. Needed because multi-member behaviour cannot be observed on a
    single-repository target.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

CASES_DIR = Path(__file__).parent / "cases"

#: The accuracy defect classes the review identified. Assertions are grouped by
#: these, and every case must state an expectation for each class it exercises.
DEFECT_CLASSES = (
    "evidence-integrity",
    "classification",
    "calibration",
    "coverage",
    "dependency-coverage",
    "redaction-precision",
    "report-consistency",
    "credential-precision",
    "missed-detection",
    "llm-detection",
    "supply-chain-detection",
)

KINDS = ("reviewed-real", "seeded-workspace")

#: Data files in cases/ that are not benchmark cases: the usage baseline, the
#: audited credential ground truth (consumed directly by the credential-precision
#: defect-class test), and the must-find corpus (consumed by missed-detection).
NON_CASE_FILES = (
    "baseline_usage.json",
    "audited_credential_baseline.json",
    "must_find.json",
)


@dataclass(frozen=True)
class Expectation:
    """One asserted outcome within a defect class."""

    defect_class: str
    assertion: str
    baseline: str

    def __post_init__(self) -> None:
        if self.defect_class not in DEFECT_CLASSES:
            raise ValueError(f"unknown defect class: {self.defect_class}")


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    kind: str
    target: str
    source_of_truth: str
    expectations: tuple[Expectation, ...]

    @property
    def classes_covered(self) -> tuple[str, ...]:
        return tuple(sorted({e.defect_class for e in self.expectations}))

    @classmethod
    def load(cls, path: Path) -> BenchmarkCase:
        raw = json.loads(path.read_text())
        kind = raw["kind"]
        if kind not in KINDS:
            raise ValueError(f"{path.name}: unknown kind {kind}")
        return cls(
            case_id=raw["case_id"],
            kind=kind,
            target=raw["target"],
            source_of_truth=raw["source_of_truth"],
            expectations=tuple(
                Expectation(
                    defect_class=e["defect_class"],
                    assertion=e["assertion"],
                    baseline=e["baseline"],
                )
                for e in raw["expectations"]
            ),
        )


def load_cases(directory: Path | None = None) -> list[BenchmarkCase]:
    """All benchmark cases, deterministically ordered."""
    directory = directory or CASES_DIR
    return [
        BenchmarkCase.load(p)
        for p in sorted(directory.glob("*.json"))
        if p.name not in NON_CASE_FILES
    ]
