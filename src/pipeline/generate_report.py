"""Final stage: unified security report (FR-018, FR-019, FR-029).

Produces both renderings from one data set: machine-readable JSON and a
human-readable Markdown document. Findings are grouped by severity band and
ranked verification-aware (verified above plausible within a band), with the
reproduction block inline in both renderings.
"""

from __future__ import annotations

import re
from typing import Any

from config.profiles import ScanProfile
from pipeline import cwe
from pipeline.state import ArtifactStore
from pipeline.usage import UsageTracker

BANDS = ("Critical", "High", "Medium", "Low", "None")

_VERIFICATION_RANK = {"verified": 0, "plausible": 1, "disproven": 2}


def rank_key(finding: dict[str, Any]) -> tuple:
    """Verification-aware ranking within a severity band (FR-029)."""
    status = (finding.get("verification") or {}).get("status", "plausible")
    return (
        _VERIFICATION_RANK.get(status, 9),
        -float(finding.get("severity_score", 0.0)),
        -float(finding.get("confidence", 0.0)),
        finding["id"],
    )


def admitted(findings: list[dict[str, Any]], profile: ScanProfile) -> list[dict[str, Any]]:
    """Apply the profile's report thresholds (verification-aware)."""
    thresholds = profile.report_thresholds
    kept: list[dict[str, Any]] = []
    for finding in findings:
        verification = (finding.get("verification") or {}).get("status")
        if verification == "disproven" or finding.get("status") == "rejected":
            continue
        if thresholds.admits(
            finding["severity_band"],
            float(finding.get("confidence", 0.0)),
            verified=verification == "verified",
        ):
            kept.append(finding)
    return kept


def group_by_band(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for band in BANDS:
        subset = [f for f in findings if f["severity_band"] == band]
        if subset:
            grouped[band] = sorted(subset, key=rank_key)
    return grouped


def admitted_ids(report: dict[str, Any]) -> set[str]:
    """Finding identifiers admitted to this report (FR-010 reference target)."""
    ids: set[str] = set()
    for items in (report.get("findings_by_band") or {}).values():
        for finding in items:
            if isinstance(finding, dict) and finding.get("id"):
                ids.add(str(finding["id"]))
    return ids


_REFERENCE = re.compile(r"SEC-\d{4,}")


def resolve_narrative_references(
    report: dict[str, Any], system_review: str
) -> tuple[str, list[dict[str, Any]]]:
    """Quarantine narrative sections whose finding references do not resolve.

    Returns ``(clean system review, quarantined_sections)`` (feature 014,
    FR-010, clarification Q5). ANY identifier-shaped token in a scanned section
    is treated as a reference — deterministic validation, no intent inference.
    Sections named: system review text, cross-system findings, attack paths,
    recommendations. Findings' own fields are built from admitted ids and are
    out of scope.
    """
    admitted = admitted_ids(report)
    quarantined: list[dict[str, Any]] = []

    def dangling(text: str) -> list[str]:
        return sorted(set(_REFERENCE.findall(text)) - admitted)

    if system_review.strip():
        bad = dangling(system_review)
        for identifier in bad:
            quarantined.append(
                {
                    "section": "system_review",
                    "dangling_id": identifier,
                    "reason": "identifier not admitted to the report",
                }
            )
        if bad:
            system_review = ""

    cross = report.get("cross_system_findings")
    if cross:
        bad = sorted(set(str(i) for i in cross) - admitted)
        if bad:
            report["cross_system_findings"] = sorted(set(map(str, cross)) & admitted)
            if not report["cross_system_findings"]:
                del report["cross_system_findings"]
            for identifier in bad:
                quarantined.append(
                    {
                        "section": "cross_system_findings",
                        "dangling_id": identifier,
                        "reason": "identifier not admitted to the report",
                    }
                )

    paths = report.get("attack_paths")
    if paths:
        kept = []
        for entry in paths:
            ids = [str(i) for i in entry.get("finding_ids") or []]
            text = " ".join([*ids, str(entry.get("description") or "")])
            bad = dangling(text)
            if bad:
                for identifier in bad:
                    quarantined.append(
                        {
                            "section": "attack_paths",
                            "dangling_id": identifier,
                            "reason": "identifier not admitted to the report",
                        }
                    )
                continue
            kept.append(entry)
        if len(kept) != len(paths):
            if kept:
                report["attack_paths"] = kept
            else:
                del report["attack_paths"]

    recommendations = report.get("recommendations")
    if recommendations:
        kept = []
        for item in recommendations:
            bad = dangling(str(item))
            if bad:
                for identifier in bad:
                    quarantined.append(
                        {
                            "section": "recommendations",
                            "dangling_id": identifier,
                            "reason": "identifier not admitted to the report",
                        }
                    )
                continue
            kept.append(item)
        if len(kept) != len(recommendations):
            if kept:
                report["recommendations"] = kept
            else:
                del report["recommendations"]

    quarantined.sort(key=lambda q: (q["section"], q["dangling_id"]))
    return system_review, quarantined


def cross_system_ids(findings: list[dict[str, Any]]) -> list[str]:
    """Findings whose evidence spans two or more repos or segments (FR-015)."""
    out: list[str] = []
    for finding in findings:
        repos = {e.get("repo") for e in finding.get("evidence") or [] if e.get("repo")}
        segments = {
            e.get("segment_id") for e in finding.get("evidence") or [] if e.get("segment_id")
        }
        if len(repos) > 1 or len(segments) > 1:
            out.append(finding["id"])
    return sorted(out)


def _resolution_tiers(
    reported: list[dict[str, Any]], rejected: list[dict[str, Any]] | None
) -> dict[str, int]:
    """How strongly each reported location is known, plus how many were dropped.

    Makes FR-003a legible: a reader can see at a glance whether the scan's
    locations carry symbol-level or only file-level guarantees, and that findings
    with unresolvable locations were removed rather than published with a caveat.
    """
    counts = {"symbol": 0, "file": 0, "rejected": 0}
    for finding in reported:
        tier = (finding.get("location") or {}).get("tier")
        if tier in counts:
            counts[tier] += 1
    for finding in rejected or []:
        if str(finding.get("rejection_reason", "")).startswith("location could not be resolved"):
            counts["rejected"] += 1
    return counts


_SECURITY_ANNOTATIONS = frozenset(
    {
        "security_sink",
        "sensitive_data",
        "trust_boundary",
        "authentication_required",
        "authorization_required",
    }
)

#: impact statements per gap cause (FR-010: concrete, not generic)
_IMPACT = {
    "blocked-value": (
        "a value that could not be confirmed as a non-credential was blocked"
        "{line_note}; security-config and credential rules could not fully assess "
        "this file's content"
    ),
    "budget-dropped": (
        "the file exceeded the token budget and was deferred; segment analysis "
        "may not have seen its content"
    ),
    "unparsed-format": "the file's format is not parsed; only file-tier facts exist",
}


def _gap_details(
    records: list[dict[str, Any]], graph: dict[str, Any] | None
) -> list[dict[str, Any]]:
    """Structured coverage-gap records with criticality and impact (FR-010).

    Criticality is deterministic: the file carries a security annotation in the
    code model, belongs to a configuration file class, or is named like
    security configuration.
    """
    import re

    from pipeline import stacks

    annotations_by_file: dict[str, set[str]] = {}
    for node in (graph or {}).get("nodes", []):
        annotations_by_file.setdefault(node["path"], set()).update(
            node.get("annotations") or []
        )
    config_classes = set(stacks.file_class_names()) - {"source", "template"}
    security_name = re.compile(r"(?i)security|firewall|acl|auth")

    details: list[dict[str, Any]] = []
    for record in records:
        path = record["file"]
        name = path.rsplit("/", 1)[-1]
        critical = bool(
            annotations_by_file.get(path, set()) & _SECURITY_ANNOTATIONS
            or stacks.file_class_for(name) in config_classes
            or security_name.search(name)
        )
        line_note = f" at line {record['line']}" if record.get("line") else ""
        impact = _IMPACT[record["cause"]].format(line_note=line_note)
        details.append(
            {
                "cause": record["cause"],
                "file": path,
                "segment_id": record["segment_id"],
                "security_critical": critical,
                "impact": impact,
            }
        )
    return sorted(details, key=lambda d: (not d["security_critical"], d["file"], d["cause"]))


def _file_class_coverage(graph: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Per-file-class coverage, derived from the code model (FR-027, FR-029).

    Lets a reader tell coverage from silence. Every enumerated security-relevant
    file lands in exactly one bucket: represented, or unparsed with its format
    named. Silent exclusion — the benchmark's actual failure, where five whole
    file classes were simply absent — is not representable here.
    """
    from pipeline import stacks

    buckets: dict[str, dict[str, Any]] = {
        name: {"file_class": name, "represented": 0, "unparsed": []}
        for name in stacks.file_class_names()
    }
    for node in (graph or {}).get("nodes") or []:
        file_class = node.get("file_class")
        if not file_class or node.get("symbol"):
            continue  # count files, not the symbols inside them
        bucket = buckets.setdefault(
            file_class, {"file_class": file_class, "represented": 0, "unparsed": []}
        )
        if node.get("parsed") is False and file_class == "source":
            # Config files are represented-but-unparsed by design; an unmodelled
            # *source* language is a genuine parser gap and is named as one.
            bucket["unparsed"].append(
                {
                    "path": node["path"],
                    "format": str(node.get("language") or node.get("format") or "unknown"),
                    "reason": "no grammar is available for this language",
                }
            )
        else:
            bucket["represented"] += 1

    out = []
    for name in sorted(buckets):
        bucket = buckets[name]
        bucket["unparsed"] = sorted(bucket["unparsed"], key=lambda item: item["path"])
        if not bucket["unparsed"]:
            bucket.pop("unparsed")
        if bucket["represented"] == 0 and "unparsed" not in bucket:
            bucket["not_attempted"] = [f"no {name} file was found in the workspace"]
        out.append(bucket)
    return out


def build_report(
    *,
    scan_id: str,
    workspace: dict[str, Any],
    execution_mode: str,
    profile: ScanProfile,
    findings: list[dict[str, Any]],
    usage: UsageTracker,
    segments_analyzed: int,
    policy_source: str = "explicit",
    coverage_gaps: list[str] | None = None,
    unavailable_features: list[str] | None = None,
    attack_paths: list[dict[str, Any]] | None = None,
    system_review: str = "",
    rejected: list[dict[str, Any]] | None = None,
    graph: dict[str, Any] | None = None,
    audit_outcomes: list[dict[str, Any]] | None = None,
    blocking_gaps: list[str] | None = None,
    gap_records: list[dict[str, Any]] | None = None,
    tool_limitations: list[dict[str, Any]] | None = None,
    suppressions: list[dict[str, Any]] | None = None,
    scan_root: Any | None = None,
    triage_summary: dict[str, Any] | None = None,
    flow_coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reported = admitted(findings, profile)
    for finding in reported:
        finding["status"] = "reported"
    if scan_root is not None:
        # Feature 005: every admitted finding carries a redacted code excerpt
        # (status ok or unavailable with reason — never omitted, FR-010).
        from pipeline import excerpts as excerpts_mod
        from pipeline.redact import Redactor

        roots = excerpts_mod.member_roots(ArtifactStore(scan_root), workspace)
        redactor = Redactor()
        for finding in reported:
            finding["code_excerpt"] = excerpts_mod.build_excerpt(
                finding, roots=roots, settings=profile.excerpts, redactor=redactor
            )
    grouped = group_by_band(reported)

    members = [m["name"] for m in workspace["members"]]
    coverage: dict[str, Any] = {
        "repos_analyzed": members,
        "segments_analyzed": segments_analyzed,
        "clean": not reported,
    }
    if coverage_gaps:
        coverage["gaps"] = sorted(set(coverage_gaps))
    if gap_records:
        coverage["gap_details"] = _gap_details(gap_records, graph)
    coverage["resolution_tiers"] = _resolution_tiers(reported, rejected)
    if graph is not None:
        coverage["file_classes"] = _file_class_coverage(graph)
    if audit_outcomes:
        coverage["audit_outcomes"] = sorted(
            audit_outcomes, key=lambda o: (o["member"], o["ecosystem"])
        )
    if blocking_gaps:
        # Rendered at the top of the report: an unassessed domain must not read
        # like a clean one (FR-033).
        coverage["blocking_gaps"] = sorted(set(blocking_gaps))
    if tool_limitations:
        # Feature 008 (FR-009): each external tool that did not run is a named
        # coverage declaration — its absence must never read as a clean result.
        coverage["tool_limitations"] = sorted(tool_limitations, key=lambda t: t["tool_id"])
    # Feature 008 (FR-007): every suppression is visible with its ground and
    # evidence — exclusion is never silent, and the list needs no re-scan.
    if suppressions:
        report_suppressions = sorted(
            suppressions,
            key=lambda s: (s["tool_id"], s["disproof_ground"], s["finding"].get("tool_ref", "")),
        )
    if workspace.get("unavailable_members"):
        coverage["unavailable_members"] = list(workspace["unavailable_members"])
    if triage_summary is not None:
        # Feature 013 (FR-006/FR-009): methodology note — the consultation
        # boundary in effect and how many candidates were adjudicated.
        coverage["triage"] = triage_summary

    # Feature 013 (FR-012): flagged findings render in a distinct section with
    # their open question — derived from ALL correlated findings (not only the
    # threshold-admitted ones), so a low-severity flag is never lost.
    awaiting = [
        {
            "finding_id": f["id"],
            "location": {
                "repo": (f.get("location") or {}).get("repo", ""),
                "file": (f.get("location") or {}).get("file", ""),
                **(
                    {"symbol": f["location"]["symbol"]}
                    if (f.get("location") or {}).get("symbol")
                    else {}
                ),
            },
            "question": f["awaiting_verification"]["question"],
            **(
                {
                    "settling_evidence_hint": f["awaiting_verification"][
                        "settling_evidence_hint"
                    ]
                }
                if f["awaiting_verification"].get("settling_evidence_hint")
                else {}
            ),
            "provenance": f["awaiting_verification"].get("provenance", "triage"),
        }
        for f in findings
        if f.get("awaiting_verification")
    ]

    report: dict[str, Any] = {
        "scan_id": scan_id,
        "workspace": {"id": workspace["id"], "members": members},
        "execution_mode": execution_mode,
        # "default" when the batch policy came from `mode: auto` (feature 012, FR-023).
        "execution_policy_source": policy_source,
        "profile": {"name": profile.name, "overrides": profile.overrides},
        "executive_summary": _executive_summary(reported, grouped, members, profile, system_review),
        "findings_by_band": grouped,
        "recommendations": _recommendations(reported),
        "coverage": coverage,
        "usage": usage.to_dict(),
    }
    if suppressions:
        report["suppressions"] = report_suppressions
    if awaiting:
        report["awaiting_verification"] = sorted(awaiting, key=lambda a: a["finding_id"])
    if flow_coverage:
        # Feature 015 (FR-014): when the business-flow round ran, its coverage
        # ledger is declared in the report — analyzed flows, partial flows with
        # reasons, and candidate regimes never read as clean by omission.
        report["flow_coverage"] = flow_coverage
    cross = cross_system_ids(reported)
    if cross:
        report["cross_system_findings"] = cross
    if attack_paths:
        report["attack_paths"] = attack_paths
    if unavailable_features:
        report["unavailable_features"] = sorted(unavailable_features)
    return report


def _executive_summary(
    reported: list[dict[str, Any]],
    grouped: dict[str, list[dict[str, Any]]],
    members: list[str],
    profile: ScanProfile,
    system_review: str,
) -> str:
    scope = f"{len(members)} repository/-ies ({', '.join(members)})"
    if not reported:
        return (
            f"Scanned {scope} under the '{profile.name}' profile and found no issues meeting "
            "the profile's reporting thresholds. The workspace was analyzed successfully; "
            "this is a clean result, not a failed scan."
        )
    counts = ", ".join(f"{len(v)} {k}" for k, v in grouped.items())
    verified = sum(
        1 for f in reported if (f.get("verification") or {}).get("status") == "verified"
    )
    lead = (
        f"Scanned {scope} under the '{profile.name}' profile. "
        f"{len(reported)} finding(s): {counts}. "
        f"{verified} were statically verified with a complete source-to-sink path."
    )
    if verified == 0:
        # FR-041. Stating the count without saying what it means invites the
        # reader to treat plausible findings as confirmed ones — which is how the
        # reviewed benchmark's honest caveats still produced an over-alarming read.
        lead += (
            " Read these as leads to confirm, not as confirmed vulnerabilities: no"
            " finding here has a traced path from an external entry point, so each"
            " reproduction block states what to check rather than what was observed."
        )
    if system_review.strip():
        lead += " Cross-boundary analysis notes are included below."
    return lead


def _recommendations(reported: list[dict[str, Any]]) -> list[str]:
    """Ranked remediation, each pointing at a section that exists (FR-040).

    The section pointer comes from the bands the findings were *published* in.
    Deriving it from the weakness class's default severity — as this did before —
    told the reader to see a Medium finding "in the High section" of a report with
    no High section.
    """
    by_cwe: dict[str, int] = {}
    bands: dict[str, set[str]] = {}
    for finding in reported:
        identifier = finding["cwe"]
        by_cwe[identifier] = by_cwe.get(identifier, 0) + 1
        bands.setdefault(identifier, set()).add(finding["severity_band"])

    ordered = sorted(by_cwe.items(), key=lambda kv: (-kv[1], kv[0]))
    out: list[str] = []
    for identifier, count in ordered[:8]:
        plural = "s" if count > 1 else ""
        present = sorted(bands[identifier], key=cwe.band_rank)
        where = (
            f"see the {present[0]} section"
            if len(present) == 1
            else f"see the {', '.join(present)} sections"
        )
        out.append(
            f"Address {count} {cwe.name_for(identifier)} finding{plural} ({identifier}); "
            f"{where}."
        )
    return out


# ------------------------------------------------------------------ markdown


def _render_excerpt_markdown(add, finding: dict[str, Any]) -> None:
    """Redacted code block for the finding (FR-007, FR-010; research.md R4).

    Lines are verbatim redacted source — no inline markers — so the excerpt
    matches the source at the cited location byte-for-byte (SC-003).
    """
    excerpt = finding.get("code_excerpt")
    if not excerpt:
        return
    label = (
        f"{excerpt['repo']}:{excerpt['file']}:"
        f"L{excerpt['cited_start']}-L{excerpt['cited_end']}"
    )
    if excerpt["status"] != "ok":
        add(f"*Code excerpt unavailable: {excerpt.get('reason', '')}* (`{label}`)")
        add("")
        return
    add(f"**Code** — `{label}`" + (" (truncated)" if excerpt.get("truncated") else ""))
    add("")
    language = excerpt.get("language") or ""
    fence = "````" if any("```" in line["text"] for line in excerpt["lines"]) else "```"
    add(f"{fence}{language}")
    for line in excerpt["lines"]:
        marker = "  … [truncated]" if line.get("truncated") else ""
        add(f"{line['text']}{marker}")
    add(fence)
    add("")


def mode_label(report: dict[str, Any]) -> str:
    """Execution mode plus the default-policy marker (feature 012, FR-023)."""
    suffix = " (default policy)" if report.get("execution_policy_source") == "default" else ""
    return f"{report['execution_mode']}{suffix}"


def render_markdown(report: dict[str, Any], system_review: str = "") -> str:
    lines: list[str] = []
    add = lines.append

    add(f"# Security Report — {report['workspace']['id']}")
    add("")
    add(f"**Scan**: `{report['scan_id']}`  ")
    add(f"**Execution mode**: {mode_label(report)}  ")
    profile = report["profile"]
    overrides = f" (overrides: {profile['overrides']})" if profile.get("overrides") else ""
    add(f"**Profile**: {profile['name']}{overrides}  ")
    add(f"**Repositories**: {', '.join(report['workspace']['members'])}")
    add("")
    add("## Executive Summary")
    add("")
    add(report["executive_summary"])
    add("")

    grouped = report["findings_by_band"]
    if grouped:
        add("## Findings by Severity")
        add("")
        for band in BANDS:
            findings = grouped.get(band)
            if not findings:
                continue
            add(f"### {band} ({len(findings)})")
            add("")
            for finding in findings:
                _render_finding(add, finding)
    else:
        add("## Findings")
        add("")
        add(
            "No issues met the reporting thresholds for this profile. "
            "The workspace was scanned successfully."
        )
        add("")

    if report.get("cross_system_findings"):
        add("## Cross-System Findings")
        add("")
        add(
            "These findings carry evidence from more than one segment or repository: "
            + ", ".join(f"`{i}`" for i in report["cross_system_findings"])
        )
        add("")

    if report.get("attack_paths"):
        add("## Attack Paths")
        add("")
        for path in report["attack_paths"]:
            ids = ", ".join(f"`{i}`" for i in path.get("finding_ids", []))
            add(f"- {path['description']} ({ids})")
        add("")

    if system_review.strip():
        add("## System-Level Review")
        add("")
        add(system_review.strip())
        add("")

    if report.get("quarantined_sections"):
        add("## Report Integrity")
        add("")
        add(
            "The following narrative content was quarantined: it referenced finding "
            "identifiers that are not part of this report. The omission is declared "
            "rather than hidden; the scan exit status signals the defect."
        )
        add("")
        for entry in report["quarantined_sections"]:
            add(
                f"- Section `{entry['section']}` omitted: referenced "
                f"`{entry['dangling_id']}` — {entry['reason']}"
            )
        add("")

    if report.get("recommendations"):
        add("## Recommendations")
        add("")
        for item in report["recommendations"]:
            add(f"- {item}")
        add("")

    if report.get("awaiting_verification"):
        add(f"## Awaiting Verification ({len(report['awaiting_verification'])})")
        add("")
        add(
            "The triage round could not settle these findings from repository "
            "evidence alone; each carries the concrete question that would settle "
            "it. They remain in the findings above, graded by what was proven. "
            "Answer a question in `.secscan/triage/declarations.json` and re-run "
            "the scan to resolve it."
        )
        add("")
        for item in report["awaiting_verification"]:
            location = item.get("location") or {}
            add(f"- **{item['finding_id']}** (`{location.get('repo')}:{location.get('file')}`)")
            add(f"  - Question: {item['question']}")
            if item.get("settling_evidence_hint"):
                add(f"  - Settling evidence: {item['settling_evidence_hint']}")
        add("")

    coverage = report["coverage"]
    add("## Coverage")
    add("")
    add(f"- Repositories analyzed: {', '.join(coverage['repos_analyzed'])}")
    add(f"- Segments analyzed: {coverage['segments_analyzed']}")
    if coverage.get("unavailable_members"):
        members = ", ".join(coverage["unavailable_members"])
        add(f"- **Unavailable members** (coverage gap): {members}")
    # Structured gap details first, security-critical before the rest (FR-010).
    details = coverage.get("gap_details") or []
    for detail in sorted(details, key=lambda d: (not d["security_critical"], d["file"])):
        marker = "**SECURITY-CRITICAL**" if detail["security_critical"] else "Gap"
        add(
            f"- {marker}: {detail['file']} ({detail['cause']}, segment "
            f"{detail['segment_id']}) — {detail['impact']}"
        )
    for gap in coverage.get("gaps", []):
        add(f"- Gap: {gap}")
    for outcome in coverage.get("audit_outcomes", []):
        line = (
            f"- Dependency audit: {outcome['member']} ({outcome['ecosystem']}) — "
            f"{outcome['status']}"
        )
        if outcome.get("reason"):
            line += f": {outcome['reason']}"
        add(line)
    for gap in coverage.get("blocking_gaps", []):
        add(f"- Blocking gap: {gap}")
    triage_cov = coverage.get("triage")
    if triage_cov is not None:
        if triage_cov.get("enabled"):
            add(
                "- Finding triage: ran "
                f"({triage_cov.get('candidates', 0)} candidates, "
                f"{triage_cov.get('adjudicated', 0)} adjudicated); "
                f"{triage_cov.get('mode_note', '')}".rstrip()
            )
    flow_cov = report.get("flow_coverage")
    if flow_cov:
        add("")
        add("### Business Flows")
        add("")
        applicability = flow_cov.get("applicability") or {}
        add(
            f"- Flows reconstructed: {len(flow_cov.get('reconstructed') or [])} · "
            f"analyzed: {len(flow_cov.get('analyzed') or [])} · "
            f"partial: {len(flow_cov.get('partial') or [])} · "
            f"unanalyzed: {len(flow_cov.get('unanalyzed') or [])}"
        )
        add(
            "- Regime applicability: "
            f"{applicability.get('mode', 'hybrid')} mode; "
            "evaluated: "
            f"{', '.join(applicability.get('evaluated_regimes') or []) or 'none'}"
        )
        if applicability.get("skipped_reason"):
            add(f"- Obligation evaluation skipped: {applicability['skipped_reason']}")
        for entry in flow_cov.get("partial") or []:
            reasons = ", ".join(entry["gap_reasons"])
            add(f"- Partial flow `{entry['flow_id']}`: {reasons}")
        for entry in flow_cov.get("unanalyzed") or []:
            add(f"- Unanalyzed flow `{entry['flow_id']}`: {entry['reason']}")
        for entry in flow_cov.get("undetermined") or []:
            add(
                f"- Undetermined flow `{entry['flow_id']}`: "
                + "; ".join(entry["reasons"])
            )
        for entry in flow_cov.get("candidate_regimes") or []:
            cats = ", ".join(entry["detected_categories"])
            add(
                f"- Candidate regime (suggested, not evaluated): "
                f"`{entry['regime']}` — detected {cats}; declare it in "
                "business_flow.declared_regimes to evaluate"
            )
        else:
            add("- Finding triage: disabled (profile/config)")
    for limitation in coverage.get("tool_limitations", []):
        # External tooling the report implicitly lacks (feature 008, FR-009).
        add(
            f"- External tool: {limitation['tool_id']} — {limitation['status']}"
            + (f": {limitation['reason']}" if limitation.get("reason") else "")
            + (
                f" (coverage: {', '.join(limitation['affected_ecosystems'])})"
                if limitation.get("affected_ecosystems")
                else ""
            )
        )
    if report.get("suppressions"):
        add("")
        add(f"## Suppressed external findings ({len(report['suppressions'])})")
        add("")
        add(
            "The cross-check deterministically disproved these tool findings; "
            "each is excluded with its ground and evidence. None of these is "
            "silently dropped — re-run not required to review them."
        )
        for record in report["suppressions"]:
            location = (record["finding"].get("location") or {}).get("file") or "manifest"
            add(
                f"- [{record['disproof_ground']}] {record['tool_id']}: "
                f"{record['finding']['description'][:160]} ({location})"
            )
            for evidence in record["evidence"]:
                add(f"  - {evidence}")
    if report.get("unavailable_features"):
        add("- Unavailable in this execution mode:")
        for feature in report["unavailable_features"]:
            add(f"  - {feature}")
    add("")

    add("## Usage & Cost")
    add("")
    add(UsageTracker.from_dict(report["usage"]).render_markdown())
    add("")
    return "\n".join(lines)


def _render_finding(add, finding: dict[str, Any]) -> None:
    location = finding["location"]
    where = f"{location['file']}"
    if location.get("symbol"):
        where += f"#{location['symbol']}"
    where += f":{location['line_start']}"

    # A file-tier location was verified, but only to file granularity. Saying so
    # is the difference between a reader trusting the line and knowing not to.
    tier = location.get("tier")
    if tier == "file":
        where += " (file-level location; symbol unconfirmed)"

    verification = finding.get("verification") or {}
    badge = verification.get("status", "unverified")

    add(f"#### {finding['id']} — {cwe.name_for(finding['cwe'])} [{badge}]")
    add("")
    add(
        f"- **CWE**: {finding['cwe']}"
        + (f" · **OWASP**: {finding['owasp_top10']}" if finding.get("owasp_top10") else "")
    )
    add(
        f"- **Severity**: {finding['severity_score']} ({finding['severity_band']})"
        f" · **Confidence**: {finding['confidence']}"
        + (
            f" · **Detection**: {finding['detection']}"
            + (" (review required)" if finding["detection"] == "heuristic" else "")
            if finding.get("detection")
            else ""
        )
        + (
            f" · **Context**: {finding['code_context']} code"
            if finding.get("code_context") == "test"
            else ""
        )
    )
    add(f"- **Location**: `{location['repo']}` → `{where}`")
    triage_block = finding.get("triage")
    if triage_block:
        previous = triage_block.get("previous_severity")
        change = (
            f" (was {previous})"
            if triage_block.get("verdict") == "downgraded" and previous is not None
            else ""
        )
        provenance = (
            " — resolved from a user-declared answer"
            if triage_block.get("user_declaration")
            else ""
        )
        add(f"- **Triage**: {triage_block['verdict']}{change}{provenance}")
    if finding.get("awaiting_verification"):
        add(f"- **Awaiting verification**: {finding['awaiting_verification']['question']}")
    if finding.get("triage_unresolved"):
        add(f"- **Triage incomplete**: {finding['triage_unresolved']['reason']}")
    if finding.get("compliance_refs"):
        add(f"- **Compliance**: {', '.join(finding['compliance_refs'])}")
    if finding.get("flow_category"):
        # Feature 015 (FR-008/FR-014): the flow narrative rides inside the finding
        # — steps as ordered evidence, never dressed as a source-to-sink trace.
        narrative = finding.get("flow_narrative") or {}
        label = (
            "Regulatory breach in business flow"
            if finding["flow_category"] == "regulatory-violation"
            else "Business-flow gap"
        )
        add(f"- **{label}**: `{finding.get('flow_ref', '?')}` — {narrative.get('name', '')}")
        for index, step in enumerate(narrative.get("steps") or [], start=1):
            detail = f" — {step['detail']}" if step.get("detail") else ""
            add(f"  - step {index}: `{step['node_id']}`{detail}")
        add(f"- **Missing/violated check**: {narrative.get('missing_check', '')}")
        add(f"- **How security is compromised**: {narrative.get('compromise', '')}")
        if finding.get("regulatory_refs"):
            refs = ", ".join(
                f"{ref['regime']}: {ref['obligation']}"
                + (f" (detected via: {ref['basis']})" if ref.get("basis") else "")
                for ref in finding["regulatory_refs"]
            )
            add(f"- **Regulations (potential compliance risk, not legal advice)**: {refs}")
    if finding.get("tool_ref"):
        add(f"- **Reported by**: `{finding['tool_ref']}`")
    usage = finding.get("usage") or {}
    usage_state = usage.get("state")
    if usage_state == "found":
        locations = ", ".join(
            f"`{loc['repo']}:{loc['file']}`"
            + (f":{loc['line_start']}" if loc.get("line_start") else "")
            + f" ({loc['kind']})"
            for loc in usage.get("locations") or []
        )
        role = usage.get("role", "runtime")
        suffix = " — development tooling only" if role == "development" else ""
        add(f"- **Dependency usage**: found ({role}){suffix}: {locations}")
    elif usage_state == "none-found":
        add(
            "- **Dependency usage**: no import, config reference, or literal dynamic "
            "use of this package was found in the affected member's source — the "
            "finding stands, but the exposure is conditional on the package being "
            "exercised"
        )
    elif usage_state == "undetermined":
        add(f"- **Dependency usage**: undetermined — {usage.get('reason', '')}")
    integration = finding.get("integration") or {}
    integration_state = integration.get("state")
    if integration_state == "integrated":
        hits = "; ".join(
            f"`{e['file']}` ({e['reason']})" for e in integration.get("evidence") or []
        )
        add(f"- **Integration**: the configured technology is in use — {hits}")
    elif integration_state == "no-integration-found":
        add(
            "- **Integration**: no SDK, dependency, import, or config integration with "
            "the technology this rule governs was found — if unused, remove the "
            "configuration rather than hardening it"
        )
    elif integration_state == "undetermined":
        add(f"- **Integration**: undetermined — {integration.get('reason', '')}")
    add("")
    _render_excerpt_markdown(add, finding)
    add(finding["description"])
    add("")
    add(f"**Attack scenario.** {finding['attack_scenario']}")
    add("")
    add(f"**Impact.** {finding['impact']}")
    add("")

    if verification.get("path"):
        add(f"**Traced path.** {' → '.join(verification['path'])}")
        add("")
    if verification.get("gap"):
        add(f"**Verification gap.** {verification['gap']}")
        add("")

    repro = finding.get("reproduction")
    if repro:
        hypothesis = repro.get("mode") == "hypothesis"
        add("#### Reproduction" + (" (hypothesis — not observed)" if hypothesis else ""))
        add("")
        step = 1
        add(f"{step}. **Preconditions**: {repro['preconditions']}")
        step += 1
        if repro.get("trigger"):
            add(f"{step}. **Trigger**: {repro['trigger']}")
        else:
            add(f"{step}. **No achievable trigger**: {repro.get('trigger_omitted_reason', '')}")
        step += 1
        add(f"{step}. **Expected**: {repro['expected_behavior']}")
        step += 1
        if repro.get("observed_behavior"):
            add(f"{step}. **Observed**: {repro['observed_behavior']}")
        else:
            add(f"{step}. **To check**: {repro.get('outcome_to_check', '')}")
        if repro.get("traced_trail"):
            step += 1
            add(f"{step}. **Traced path**: {' → '.join(repro['traced_trail'])}")
        add("")

    add("**Evidence.**")
    add("")
    for item in finding["evidence"]:
        symbol = f"#{item['symbol']}" if item.get("symbol") else ""
        add(f"- `{item['repo']}:{item['file']}{symbol}` — {item['reason']}")
    add("")
    add(f"**Recommendation.** {finding['recommendation']}")
    add("")


def main() -> None:  # pragma: no cover - CLI wrapper
    """Re-render the report from persisted artifacts (no analysis re-run)."""
    import argparse
    from pathlib import Path

    from config import mode as mode_mod
    from config import profiles as profiles_mod
    from config.loader import load

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--profile", default=None)
    args = parser.parse_args()

    store = ArtifactStore(args.workdir)
    config = load(store.dir)
    workspace = store.read("workspace.json")
    correlated = (store.read("findings/correlated.json") or {}).get("findings") or []
    usage_payload = store.read_optional("usage.json") or {}
    usage = UsageTracker.from_dict(usage_payload) if usage_payload else UsageTracker()
    profile = profiles_mod.resolve(args.profile, custom=config.custom_profiles)
    resolution = mode_mod.resolve(config)

    system_review_path = store.path_for("system-review.md")
    system_review = system_review_path.read_text() if system_review_path.exists() else ""

    report = build_report(
        scan_id=store.scan_id,
        workspace=workspace,
        execution_mode=resolution.mode.value,
        policy_source=resolution.policy_source,
        profile=profile,
        findings=correlated,
        usage=usage,
        segments_analyzed=len(store.glob("segments/*.json")),
        unavailable_features=list(resolution.unavailable_features),
        system_review=system_review,
        scan_root=args.workdir,
    )
    markdown_path, _json_path, html_path = write(store, report, system_review)
    reported = sum(len(v) for v in report["findings_by_band"].values())
    print(f"report: {markdown_path} ({reported} finding(s)) · html: {html_path}")


def write(
    store: ArtifactStore, report: dict[str, Any], system_review: str = "", strict: bool = True
) -> tuple[Any, Any, Any]:
    """Write all three renderings, gated on internal consistency (FR-042).

    Narrative reference resolution runs first (feature 014, FR-010): a section
    referencing a finding id that is not admitted is quarantined — removed from
    what publishes, declared in the report, and signalled via exit status. The
    consistency gate then holds the residual invariant strictly: a reference
    that survives quarantine is a pipeline bug, not publishable user data.
    ``strict=False`` is for re-rendering historical artifacts that predate these
    rules and cannot be regenerated.
    """
    from pipeline import consistency, render_html

    if strict:
        system_review, quarantined = resolve_narrative_references(report, system_review)
        if quarantined:
            report["quarantined_sections"] = quarantined
    consistency.enforce(report, strict=strict, system_review=system_review)
    json_path = store.write(
        f"reports/{report['scan_id']}.json", "generate_report", report, "report"
    )
    markdown_path = store.write_text(
        f"reports/{report['scan_id']}.md", render_markdown(report, system_review)
    )
    html_path = store.write_text(
        f"reports/{report['scan_id']}.html", render_html.render_html(report, system_review)
    )
    return markdown_path, json_path, html_path


if __name__ == "__main__":  # pragma: no cover
    main()
