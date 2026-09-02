"""Finding ingestion: the single seam where non-analysis findings enter (FR-030c).

Two producers feed findings that did not come from segment analysis:

* **External scanners** — Semgrep, Gitleaks, OSV-Scanner, Trivy. Adapters live in
  `pipeline/adapters/` and are part of `001-hierarchical-security-scan` US3, not
  yet built.
* **Native dependency audits** — `pipeline/audits/`, built by
  `002-scan-accuracy-hardening` US4.

They overlap: OSV-Scanner and Trivy both report dependency advisories, and so does
`npm audit`. Reporting the same advisory twice is a precision failure, so this
module owns the de-duplication decision and nothing else does.

**The rule that matters, and the trap in it.** A domain may be skipped only when an
external scanner has *actually produced findings* for it in this scan — never
because a scanner happens to be installed. Skipping on installation would suppress
our own audit while nothing replaced it, converting a covered domain into a silent
gap. That is strictly worse than reporting an advisory twice, and it is the exact
failure mode this feature exists to remove, so the check is on ingested output.

Until 001's adapters land, `covered_domains()` returns an empty set and every
domain is audited natively. The seam is here so that stays true by construction
when they arrive, rather than depending on someone remembering.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


#: Ecosystem ids that an external scanner can fully cover, keyed by the scanner's
#: normalized `source` value. Only scanners whose remit *is* dependency advisories
#: appear here: Semgrep and Gitleaks report other domains and never displace an
#: ecosystem audit.
#: Derived from the shipped tool registry (feature 008, FR-001) — the hard-coded
#: fallback stays for the day the registry cannot load, so a data failure can
#: never silently widen coverage claims.
def _dependency_scanners() -> dict[str, tuple[str, ...]]:
    try:
        from pipeline.tooling.registry import load_registry

        return {
            tool.id: tool.covers_ecosystems
            for tool in load_registry()
            if tool.kind == "dependency-audit"
        }
    except Exception:
        return {
            "osv-scanner": ("npm", "pypi", "go", "maven"),
            "trivy": ("npm", "pypi", "go", "maven"),
        }


#: Backward-compatible snapshot for existing callers/tests; the authoritative
#: source at run time is the registry via ``_dependency_scanners()``.
DEPENDENCY_SCANNERS: dict[str, tuple[str, ...]] = _dependency_scanners()


def load_external_findings(store: Any) -> list[dict[str, Any]]:
    """Findings ingested from external scanners, if any adapter ran."""
    findings: list[dict[str, Any]] = []
    for path in store.glob("findings/external/*.json"):
        payload = store.read(f"findings/external/{path.name}")
        findings.extend(payload.get("findings") or [])
    return findings


def covered_domains(external_findings: list[dict[str, Any]]) -> set[str]:
    """Ecosystems already covered by external scanner *output* (FR-030c).

    Derived from findings that exist, not from tools that exist. An empty set —
    the current state, with no adapters built — means audit everything.
    """
    covered: set[str] = set()
    scanners = _dependency_scanners()
    for finding in external_findings:
        scanner = str(finding.get("scanner") or finding.get("tool") or "")
        ecosystems = scanners.get(scanner)
        if not ecosystems:
            continue
        declared = (finding.get("dependency") or {}).get("ecosystem")
        # Credit only the ecosystem actually reported on. A scanner capable of
        # four ecosystems that reported on one has not covered the other three.
        if declared:
            covered.add(str(declared))
        else:
            covered.update(ecosystems)
    return covered


def _advisory_key(finding: dict[str, Any]) -> tuple[str, str] | None:
    dep = finding.get("dependency") or {}
    package = str(dep.get("package") or "")
    ecosystem = str(dep.get("ecosystem") or "")
    if not package or not ecosystem:
        return None
    return ecosystem, package


def merge_external_findings(
    store: Any,
    findings: list[dict[str, Any]],
    *,
    start_id: int,
    roots: dict[str, Path] | None = None,
) -> list[dict[str, Any]]:
    """Fold ingested external findings into the stream (FR-006).

    Advisory-identity dedupe: an external dependency finding matching a native
    one on (ecosystem, package) with a shared advisory id or equal affected
    range merges into the native finding, whose ``sources`` records every
    contributor. Unmatched external findings get stable ids appended after the
    native sequence. Non-dependency external findings (SAST/secrets/IaC) pass
    through unchanged — code findings dedupe is location dedupe downstream (D3).

    Cross-check (FR-007/008) runs before merging: structurally disproven
    findings are diverted to the auditable suppression list instead of merging;
    reachability doubts keep their finding (suppression never happens on them).
    """
    external = load_external_findings(store)
    if not external:
        return findings
    if roots:
        from pipeline import crosscheck

        external, suppressions = crosscheck.evaluate(roots, external)
        if suppressions or store.exists("tooling/suppressions.json"):
            crosscheck.write_suppressions(store.dir, suppressions)
    external = sorted(
        external,
        key=lambda f: (
            str(f.get("scanner") or f.get("tool") or ""),
            str((f.get("location") or {}).get("file") or ""),
            str(f.get("description") or ""),
        ),
    )

    native_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for finding in findings:
        key = _advisory_key(finding)
        if key:
            native_by_key.setdefault(key, []).append(finding)

    next_id = start_id
    for finding in external:
        scanner = str(finding.get("scanner") or finding.get("tool") or "external")
        finding.setdefault("sources", [scanner])
        key = _advisory_key(finding)
        candidates = native_by_key.get(key, []) if key else []
        merged = False
        for native in candidates:
            native_dep = native.get("dependency") or {}
            shared_ids = set(native_dep.get("advisory_ids") or []) & set(
                finding["dependency"].get("advisory_ids") or []
            )
            same_range = (
                native_dep.get("affected_range")
                and native_dep.get("affected_range") == finding["dependency"].get("affected_range")
            )
            if shared_ids or same_range:
                native["sources"] = sorted(
                    set(native.get("sources") or [str(native.get("source", "dependency-audit"))])
                    | set(finding["sources"])
                )
                merged = True
                break
        if not merged:
            finding["id"] = f"SEC-{next_id:04d}"
            next_id += 1
            findings.append(finding)
    return findings


def run_dependency_audits(
    store: Any,
    roots: dict[str, Path],
    start_id: int = 1,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Run native audits for every domain no external scanner has covered.

    Returns ``(findings, audit_outcome_dicts, blocking_gaps)``.
    """
    from pipeline import audits
    from pipeline.audits import offline

    skip = covered_domains(load_external_findings(store))

    # Bundled-snapshot baseline: always on, fully offline (feature 004, R4).
    # Native tools augment it when available; where the baseline assessed a
    # domain, a native could-not-check no longer reads as a blocking gap.
    bundled_findings, bundled_outcomes = offline.run_offline(roots)
    assessed = {
        (o["member"], o["ecosystem"])
        for o in bundled_outcomes
        if o["status"] in ("advisories", "clean")
    }

    outcomes, grouped = audits.run(roots, skip_ecosystems=skip)
    outcomes = [
        o
        for o in outcomes
        if not (o.status == "could-not-check" and (o.member, o.ecosystem) in assessed)
    ]
    outcome_dicts = [o.to_dict() for o in outcomes]
    outcome_dicts.extend(bundled_outcomes)

    dependency_findings = audits.to_findings(grouped, start=start_id)
    # Bundled-baseline findings get stable ids in the same sequence.
    for offset, finding in enumerate(bundled_findings):
        finding["id"] = f"SEC-{start_id + len(dependency_findings) + offset:04d}"
    dependency_findings.extend(bundled_findings)
    currency_findings = audits.stack_currency_findings(
        roots, start=start_id + len(dependency_findings)
    )
    findings = [*dependency_findings, *currency_findings]
    # External (feature 008) findings merge through this seam last: identity
    # ids come after the native sequence, dedupe merges contributors (FR-006),
    # and the cross-check diverts structural false positives to the audible
    # suppression list (FR-007).
    findings = merge_external_findings(
        store, findings, start_id=start_id + len(findings), roots=roots
    )

    gaps = audits.blocking_gaps(outcomes)
    gaps.extend(
        f"Dependency domain UNASSESSED for member '{o['member']}' "
        f"({o['ecosystem']}): {o['reason']}. This is not a clean result — "
        "refresh the bundled snapshot or run the native auditor."
        for o in bundled_outcomes
        if o["status"] == "could-not-check"
    )
    for ecosystem in sorted(skip):
        gaps.append(
            f"Dependency domain '{ecosystem}' was not audited natively because an "
            "external scanner already reported on it in this scan."
        )
    return findings, outcome_dicts, gaps
