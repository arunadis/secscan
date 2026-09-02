"""Pre-write report consistency gate (FR-040–FR-042).

A **gate**, not a warning. The whole point is that a self-inconsistent report never
reaches a reader — the reviewed benchmark told its reader to see a Medium finding
"in the High section" of a report with no High section, and printed a reproduction
step whose precondition its own impact paragraph denied. Both are the kind of
defect that costs a report its credibility even when every technical claim in it
is sound.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pipeline import controls


@dataclass(frozen=True)
class Contradiction:
    """One internal inconsistency, and where it was found."""

    rule: str
    where: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.rule}] {self.where}: {self.detail}"


def _sections(report: dict[str, Any]) -> set[str]:
    """Severity sections that actually exist in this report."""
    return {band for band, findings in (report.get("findings_by_band") or {}).items() if findings}


def check(report: dict[str, Any]) -> list[Contradiction]:
    """Every internal contradiction in ``report``, deterministically ordered."""
    problems: list[Contradiction] = []
    present = _sections(report)
    findings = [f for items in (report.get("findings_by_band") or {}).values() for f in items]

    # 1. Dangling section references (FR-040).
    for index, line in enumerate(report.get("recommendations") or []):
        for band in ("Critical", "High", "Medium", "Low", "None"):
            if f"{band} section" in line and band not in present:
                problems.append(
                    Contradiction(
                        rule="dangling-section-reference",
                        where=f"recommendations[{index}]",
                        detail=(
                            f"points at the {band} section, which this report does not "
                            f"contain (present: {', '.join(sorted(present)) or 'none'})"
                        ),
                    )
                )

    for finding in findings:
        identifier = finding.get("id", "<unknown>")
        band = finding.get("severity_band")
        if band and band not in present:
            problems.append(
                Contradiction(
                    rule="finding-outside-its-band",
                    where=identifier,
                    detail=f"declares band {band} but is rendered under a different section",
                )
            )

        verification = (finding.get("verification") or {}).get("status")
        repro = finding.get("reproduction") or {}

        # 2. An observation claimed without verification (FR-008/FR-042).
        if repro.get("mode") == "observed" and verification != "verified":
            problems.append(
                Contradiction(
                    rule="unearned-observation",
                    where=identifier,
                    detail=(
                        f"reproduction claims mode 'observed' while verification is "
                        f"'{verification}' — nothing observed this"
                    ),
                )
            )
        if repro.get("observed_behavior") and verification != "verified":
            problems.append(
                Contradiction(
                    rule="unearned-observation",
                    where=identifier,
                    detail="carries observed_behavior without an end-to-end verification",
                )
            )

        # 3. A trail rendered as a path that is not one (FR-005).
        trail = repro.get("traced_trail") or []
        path = (finding.get("verification") or {}).get("path") or []
        if trail and not path:
            problems.append(
                Contradiction(
                    rule="trail-without-a-path",
                    where=identifier,
                    detail="renders a traced trail although no path was traced",
                )
            )
        for entry in trail:
            if entry not in path:
                problems.append(
                    Contradiction(
                        rule="trail-entry-off-path",
                        where=identifier,
                        detail=f"trail entry '{entry}' is not on the traced path",
                    )
                )

        # 4. A narrative describing an impact a credited control prevents (FR-023).
        control = finding.get("framework_control") or {}
        if control.get("state") == controls.STATE_CREDITED:
            impact = str(finding.get("impact", "")).lower()
            for phrase in ("script execution", "arbitrary script", "execute arbitrary"):
                if phrase in impact:
                    problems.append(
                        Contradiction(
                            rule="impact-contradicts-credited-control",
                            where=identifier,
                            detail=(
                                f"impact claims '{phrase}' while control "
                                f"'{control.get('control')}' is credited as preventing it"
                            ),
                        )
                    )

        # 5. A reproduction depending on a precondition the finding denies
        #    (FR-011) — the benchmark's self-contradiction.
        trigger = str(repro.get("trigger") or "")
        narrative = " ".join(
            str(finding.get(key, "")) for key in ("impact", "description", "attack_scenario")
        ).lower()
        fixed_origin = (
            "scheme and host are fixed" in narrative or "cannot be forced" in narrative
        )
        if trigger and fixed_origin:
            if "127.0.0.1" in trigger or "localhost" in trigger:
                problems.append(
                    Contradiction(
                        rule="repro-contradicts-narrative",
                        where=identifier,
                        detail=(
                            "trigger targets another origin while the narrative states the "
                            "scheme and host are fixed"
                        ),
                    )
                )

        # 6. A trigger present with no achievable criterion, or absent with no
        #    reason (FR-009/FR-010).
        if not trigger and not repro.get("trigger_omitted_reason") and repro:
            problems.append(
                Contradiction(
                    rule="trigger-omitted-without-reason",
                    where=identifier,
                    detail="no trigger and no stated reason for its absence",
                )
            )

    # 7. Read-guidance when nothing was verified end to end (FR-041).
    if findings:
        verified = sum(
            1 for f in findings if (f.get("verification") or {}).get("status") == "verified"
        )
        summary = str(report.get("executive_summary", ""))
        if verified == 0 and "read" not in summary.lower():
            problems.append(
                Contradiction(
                    rule="missing-read-guidance",
                    where="executive_summary",
                    detail=(
                        "no finding was verified end to end, and the summary does not say "
                        "how the findings should be read in light of that"
                    ),
                )
            )

    return sorted(problems, key=lambda p: (p.rule, p.where, p.detail))


class ReportInconsistent(RuntimeError):
    """Raised when a report would be written while contradicting itself."""

    def __init__(self, problems: list[Contradiction]) -> None:
        self.problems = problems
        listing = "\n  - ".join(str(p) for p in problems)
        super().__init__(
            f"report withheld: {len(problems)} internal contradiction(s):\n  - {listing}"
        )


def enforce(report: dict[str, Any], strict: bool = True) -> list[Contradiction]:
    """Gate the report. Raises when ``strict`` and any contradiction remains.

    ``strict=False`` exists for callers re-rendering historical artifacts, which
    may predate these rules and cannot be regenerated.
    """
    problems = check(report)
    if problems and strict:
        raise ReportInconsistent(problems)
    return problems
