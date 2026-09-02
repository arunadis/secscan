"""Helpers for building seeded-vulnerability fixture repositories.

Fixtures are generated on demand (not committed as sprawling trees) so that the
seeded ground truth stays declarative and reviewable. Each fixture declares its
expected findings, which integration tests assert against.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SeededVuln:
    """A vulnerability deliberately planted in a fixture."""

    key: str
    cwe: str
    file: str
    symbol: str
    note: str
    cross_repo: bool = False
    expect_reported: bool = True


@dataclass
class Fixture:
    """A generated repository (or workspace member) with known ground truth."""

    name: str
    files: dict[str, str] = field(default_factory=dict)
    seeded: list[SeededVuln] = field(default_factory=list)

    def write(self, root: Path) -> Path:
        target = root / self.name
        if target.exists():
            shutil.rmtree(target)
        for rel, content in self.files.items():
            path = target / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        ground_truth = {
            "fixture": self.name,
            "seeded": [
                {
                    "key": v.key,
                    "cwe": v.cwe,
                    "file": v.file,
                    "symbol": v.symbol,
                    "note": v.note,
                    "cross_repo": v.cross_repo,
                    "expect_reported": v.expect_reported,
                }
                for v in self.seeded
            ],
        }
        (target / "GROUND_TRUTH.json").write_text(json.dumps(ground_truth, indent=2) + "\n")
        return target


def load_ground_truth(fixture_root: Path) -> dict:
    return json.loads((fixture_root / "GROUND_TRUTH.json").read_text())
