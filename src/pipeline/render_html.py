"""HTML rendering of the unified security report (feature 005, FR-001-FR-006).

A pure function of the report dict: one constant inline stylesheet, no
JavaScript, no external assets, and every dynamic value passed through
``html.escape``. Navigation is plain anchors — an index grouped by severity
band, a stable ``finding-<id>`` anchor per finding, back-links, and a
referenced-files section so evidence and coverage-gap file references are
clickable. Before returning, every emitted ``href="#..."`` is checked against
the emitted ids: a report with a dangling internal reference raises rather than
reaching a reader (Constitution IV).
"""

from __future__ import annotations

import html
import re
from typing import Any

from pipeline import cwe, generate_report
from pipeline.generate_report import BANDS
from pipeline.usage import SAVING_ASSUMPTION, UsageTracker

_UNSAFE = re.compile(r"[^A-Za-z0-9\-_]")

_CSS = """
:root { color-scheme: light dark; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       margin: 0; display: flex; min-height: 100vh; }
nav#index { width: 19rem; flex-shrink: 0; padding: 1rem; overflow-y: auto;
            max-height: 100vh; position: sticky; top: 0;
            border-right: 1px solid #8884; font-size: 0.9rem; }
nav#index details { margin-bottom: 0.4rem; }
nav#index summary { cursor: pointer; font-weight: 600; }
nav#index ul { list-style: none; padding-left: 0.8rem; margin: 0.3rem 0; }
nav#index li { margin: 0.15rem 0; overflow-wrap: anywhere; }
main { flex: 1; padding: 1rem 2rem; max-width: 72rem; }
header h1 { margin-bottom: 0.2rem; }
.meta { color: #666; font-size: 0.9rem; }
.badge { display: inline-block; padding: 0 0.4em; border-radius: 0.4em;
         font-size: 0.8em; border: 1px solid #888; }
.badge.verified { border-color: #2a7; color: #2a7; }
.badge.plausible { border-color: #c80; color: #c80; }
section.finding { border-top: 2px solid #8884; margin-top: 1.5rem; }
.band-count { margin-right: 0.8rem; }
pre.excerpt { background: #8881; padding: 0.6rem; overflow-x: auto;
              border-radius: 0.4rem; line-height: 1.35; }
pre.excerpt .ln { display: inline-block; min-width: 3em; text-align: right;
                  margin-right: 0.8em; color: #888; user-select: none; }
pre.excerpt .cited { background: #c804; display: block; }
pre.excerpt .row { display: block; white-space: pre; }
.back { font-size: 0.85rem; }
table { border-collapse: collapse; }
td, th { border: 1px solid #8884; padding: 0.2rem 0.6rem; text-align: left; }
""".strip()


def _sanitize(text: str) -> str:
    return _UNSAFE.sub("-", text)


def anchor_for(finding_id: str) -> str:
    """Stable document anchor for a finding (FR-004)."""
    return "finding-" + _sanitize(finding_id)


def _file_anchor(repo: str, path: str) -> str:
    return "file-" + _sanitize(f"{repo}:{path}")


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_html(report: dict[str, Any], system_review: str = "") -> str:
    """Render the report as a self-contained HTML document."""
    grouped: dict[str, list[dict[str, Any]]] = report.get("findings_by_band") or {}
    all_findings = [f for band in BANDS for f in grouped.get(band) or []]

    anchors = [anchor_for(f["id"]) for f in all_findings]
    if len(set(anchors)) != len(anchors):
        raise ValueError("anchor collision: two findings sanitize to the same anchor")

    parts: list[str] = []
    add = parts.append

    add("<!DOCTYPE html>")
    add('<html lang="en"><head><meta charset="utf-8">')
    add('<meta name="viewport" content="width=device-width, initial-scale=1">')
    add(f"<title>Security Report — {_esc(report['workspace']['id'])}</title>")
    add(f"<style>{_CSS}</style></head><body>")

    _render_index(add, report, grouped)
    add("<main>")
    _render_header(add, report, grouped)
    add('<section id="summary"><h2>Executive Summary</h2>')
    add(f"<p>{_esc(report['executive_summary'])}</p></section>")

    if grouped:
        add('<section id="findings"><h2>Findings by Severity</h2>')
        for band in BANDS:
            findings = grouped.get(band)
            if not findings:
                continue
            add(f'<section id="band-{_esc(band.lower())}">')
            add(f"<h2>{_esc(band)} ({len(findings)})</h2>")
            for finding in findings:
                _render_finding(add, finding)
            add("</section>")
        add("</section>")
    else:
        add('<section id="findings"><h2>Findings</h2><p>No issues met the reporting '
            "thresholds for this profile. The workspace was scanned successfully.</p></section>")

    _render_cross_references(add, report)
    if system_review.strip():
        add('<section id="system-review"><h2>System-Level Review</h2>')
        add(f"<p>{_esc(system_review.strip())}</p></section>")
    if report.get("quarantined_sections"):
        add('<section id="report-integrity"><h2>Report Integrity</h2>')
        add("<p>Narrative content was quarantined because it referenced finding "
            "identifiers not admitted to this report; the omission is declared, "
            "not hidden.</p><ul>")
        for entry in report["quarantined_sections"]:
            add(f"<li>Section <code>{_esc(entry['section'])}</code> omitted: referenced "
                f"<code>{_esc(entry['dangling_id'])}</code> — {_esc(entry['reason'])}</li>")
        add("</ul></section>")
    if report.get("recommendations"):
        add('<section id="recommendations"><h2>Recommendations</h2><ul>')
        for item in report["recommendations"]:
            add(f"<li>{_esc(item)}</li>")
        add("</ul></section>")
    _render_coverage(add, report)
    _render_files(add, report, all_findings)
    _render_usage(add, report)
    add("</main></body></html>")

    document = "\n".join(parts)
    _check_links(document)
    return document


def _render_index(
    add, report: dict[str, Any], grouped: dict[str, list[dict[str, Any]]]
) -> None:
    add('<nav id="index"><h2>Index</h2>')
    add('<p><a href="#summary">Summary</a> · <a href="#coverage">Coverage</a> · '
        '<a href="#files">Files</a> · <a href="#usage">Usage</a></p>')
    for band in BANDS:
        findings = grouped.get(band)
        if not findings:
            continue
        add(f"<details open><summary>{_esc(band)} ({len(findings)})</summary><ul>")
        for finding in findings:
            badge = (finding.get("verification") or {}).get("status", "unverified")
            add(
                f'<li><a href="#{anchor_for(finding["id"])}">{_esc(finding["id"])}</a> '
                f'{_esc(cwe.name_for(finding["cwe"]))} '
                f'<span class="badge {_esc(badge)}">{_esc(badge)}</span></li>'
            )
        add("</ul></details>")
    if not grouped:
        add("<p>No findings met the reporting thresholds.</p>")
    add("</nav>")


def _render_header(
    add, report: dict[str, Any], grouped: dict[str, list[dict[str, Any]]]
) -> None:
    profile = report["profile"]
    overrides = f" (overrides: {profile['overrides']})" if profile.get("overrides") else ""
    add(f'<header id="top"><h1>Security Report — {_esc(report["workspace"]["id"])}</h1>')
    add(
        f'<p class="meta">Scan <code>{_esc(report["scan_id"])}</code> · '
        f'mode {_esc(generate_report.mode_label(report))} · '
        f'profile {_esc(profile["name"])}{_esc(overrides)} · '
        f'repositories {_esc(", ".join(report["workspace"]["members"]))}</p>'
    )
    counts = [
        f'<a class="band-count" href="#band-{band.lower()}">{band}: '
        f"{len(grouped[band])}</a>"
        for band in BANDS
        if grouped.get(band)
    ]
    if counts:
        add(f'<p class="meta">{"".join(counts)}</p>')
    add("</header>")


def _render_finding(add, finding: dict[str, Any]) -> None:
    location = finding["location"]
    where = location["file"] + (f"#{location['symbol']}" if location.get("symbol") else "")
    where += f":{location['line_start']}"
    if location.get("tier") == "file":
        where += " (file-level location; symbol unconfirmed)"
    verification = finding.get("verification") or {}
    badge = verification.get("status", "unverified")

    add(f'<section class="finding" id="{anchor_for(finding["id"])}">')
    add(
        f'<h3>{_esc(finding["id"])} — {_esc(cwe.name_for(finding["cwe"]))} '
        f'<span class="badge {_esc(badge)}">{_esc(badge)}</span></h3>'
    )
    add('<p class="back"><a href="#index">↑ index</a></p>')
    add("<ul>")
    cwe_line = f'<li><strong>CWE</strong>: {_esc(finding["cwe"])}'
    if finding.get("owasp_top10"):
        cwe_line += f' · <strong>OWASP</strong>: {_esc(finding["owasp_top10"])}'
    add(cwe_line + "</li>")
    severity = (
        f'<li><strong>Severity</strong>: {_esc(finding["severity_score"])} '
        f'({_esc(finding["severity_band"])}) · <strong>Confidence</strong>: '
        f'{_esc(finding["confidence"])}'
    )
    if finding.get("detection"):
        severity += f' · <strong>Detection</strong>: {_esc(finding["detection"])}'
        if finding["detection"] == "heuristic":
            severity += " (review required)"
    if finding.get("code_context") == "test":
        severity += " · <strong>Context</strong>: test code"
    add(severity + "</li>")
    file_ref = _file_anchor(location["repo"], location["file"])
    add(
        f'<li><strong>Location</strong>: <code>{_esc(location["repo"])}</code> → '
        f'<a href="#{file_ref}"><code>{_esc(where)}</code></a></li>'
    )
    if finding.get("compliance_refs"):
        add(f'<li><strong>Compliance</strong>: {_esc(", ".join(finding["compliance_refs"]))}</li>')
    if finding.get("flow_category"):
        # Feature 015 (FR-014): the flow narrative rides inside the finding.
        narrative = finding.get("flow_narrative") or {}
        label = (
            "Regulatory breach in business flow"
            if finding["flow_category"] == "regulatory-violation"
            else "Business-flow gap"
        )
        add(
            f'<li><strong>{label}</strong>: <code>{_esc(str(finding.get("flow_ref", "?")))}</code>'
            f' — {_esc(str(narrative.get("name", "")))}</li>'
        )
        steps = narrative.get("steps") or []
        if steps:
            add("<li><strong>Steps</strong>:<ol>")
            for step in steps:
                detail = f" — {_esc(str(step['detail']))}" if step.get("detail") else ""
                add(f'<li><code>{_esc(str(step["node_id"]))}</code>{detail}</li>')
            add("</ol></li>")
        add(
            "<li><strong>Missing/violated check</strong>: "
            f'{_esc(str(narrative.get("missing_check", "")))}</li>'
        )
        add(
            "<li><strong>How security is compromised</strong>: "
            f'{_esc(str(narrative.get("compromise", "")))}</li>'
        )
        if finding.get("regulatory_refs"):
            refs = ", ".join(
                f"{ref['regime']}: {ref['obligation']}"
                + (f" (detected via: {ref['basis']})" if ref.get("basis") else "")
                for ref in finding["regulatory_refs"]
            )
            add(f'<li><strong>Regulations</strong> (potential compliance risk, not legal '
                f'advice): {_esc(refs)}</li>')
    if finding.get("tool_ref"):
        add(f'<li><strong>Reported by</strong>: <code>{_esc(finding["tool_ref"])}</code></li>')
    usage = finding.get("usage") or {}
    if usage.get("state") == "found":
        locations = ", ".join(
            f"<code>{_esc(loc['repo'])}:{_esc(loc['file'])}</code> ({_esc(loc['kind'])})"
            for loc in usage.get("locations") or []
        )
        add(f"<li><strong>Dependency usage</strong>: found "
            f"({_esc(usage.get('role', 'runtime'))}): {locations}</li>")
    elif usage.get("state") == "none-found":
        add("<li><strong>Dependency usage</strong>: no import, config reference, or literal "
            "dynamic use of this package was found — the finding stands, but exposure is "
            "conditional on the package being exercised</li>")
    elif usage.get("state") == "undetermined":
        add(f"<li><strong>Dependency usage</strong>: undetermined — "
            f"{_esc(usage.get('reason', ''))}</li>")
    integration = finding.get("integration") or {}
    if integration.get("state") == "no-integration-found":
        add("<li><strong>Integration</strong>: no integration with the governed technology "
            "was found — if unused, remove the configuration rather than hardening it</li>")
    elif integration.get("state") == "undetermined":
        add(f"<li><strong>Integration</strong>: undetermined — "
            f"{_esc(integration.get('reason', ''))}</li>")
    # Feature 013: triage verdicts and open questions render with the finding
    # (never in place of its proven grading).
    triage_block = finding.get("triage")
    if triage_block:
        previous = triage_block.get("previous_severity")
        change = (
            f" (was {_esc(previous)})"
            if triage_block.get("verdict") == "downgraded" and previous is not None
            else ""
        )
        provenance = (
            " — resolved from a user-declared answer"
            if triage_block.get("user_declaration")
            else ""
        )
        add(
            f'<li><strong>Triage</strong>: {_esc(triage_block["verdict"])}{change}'
            f"{provenance}</li>"
        )
    if finding.get("awaiting_verification"):
        add(
            "<li><strong>Awaiting verification</strong>: "
            f"{_esc(finding['awaiting_verification']['question'])}</li>"
        )
    if finding.get("triage_unresolved"):
        add(
            "<li><strong>Triage incomplete</strong>: "
            f"{_esc(finding['triage_unresolved']['reason'])}</li>"
        )
    add("</ul>")

    add(f'<p>{_esc(finding["description"])}</p>')
    add(f'<p><strong>Attack scenario.</strong> {_esc(finding["attack_scenario"])}</p>')
    add(f'<p><strong>Impact.</strong> {_esc(finding["impact"])}</p>')

    if verification.get("path"):
        add(f'<p><strong>Traced path.</strong> {_esc(" → ".join(verification["path"]))}</p>')
    if verification.get("gap"):
        add(f'<p><strong>Verification gap.</strong> {_esc(verification["gap"])}</p>')

    repro = finding.get("reproduction")
    if repro:
        hypothesis = repro.get("mode") == "hypothesis"
        add("<h4>Reproduction" + (" (hypothesis — not observed)" if hypothesis else "") + "</h4>")
        add("<ol>")
        add(f'<li><strong>Preconditions</strong>: {_esc(repro["preconditions"])}</li>')
        if repro.get("trigger"):
            add(f'<li><strong>Trigger</strong>: {_esc(repro["trigger"])}</li>')
        else:
            add(f'<li><strong>No achievable trigger</strong>: '
                f'{_esc(repro.get("trigger_omitted_reason", ""))}</li>')
        add(f'<li><strong>Expected</strong>: {_esc(repro["expected_behavior"])}</li>')
        if repro.get("observed_behavior"):
            add(f'<li><strong>Observed</strong>: {_esc(repro["observed_behavior"])}</li>')
        else:
            add(f'<li><strong>To check</strong>: {_esc(repro.get("outcome_to_check", ""))}</li>')
        if repro.get("traced_trail"):
            add(f'<li><strong>Traced path</strong>: '
                f'{_esc(" → ".join(repro["traced_trail"]))}</li>')
        add("</ol>")

    add("<p><strong>Evidence.</strong></p><ul>")
    for item in finding["evidence"]:
        symbol = f"#{item['symbol']}" if item.get("symbol") else ""
        ref = _file_anchor(item["repo"], item["file"])
        add(
            f'<li><a href="#{ref}"><code>{_esc(item["repo"])}:{_esc(item["file"])}'
            f"{_esc(symbol)}</code></a> — {_esc(item['reason'])}</li>"
        )
    add("</ul>")
    add(f'<p><strong>Recommendation.</strong> {_esc(finding["recommendation"])}</p>')

    _render_excerpt(add, finding)
    add("</section>")


def _render_excerpt(add, finding: dict[str, Any]) -> None:
    """Redacted code block for the finding (FR-007-FR-010, FR-013)."""
    excerpt = finding.get("code_excerpt")
    if not excerpt:
        return
    label = (
        f"{excerpt['repo']}:{excerpt['file']}:"
        f"L{excerpt['cited_start']}-L{excerpt['cited_end']}"
    )
    if excerpt["status"] != "ok":
        add(f'<p><em>Code excerpt unavailable: {_esc(excerpt.get("reason", ""))} '
            f"({_esc(label)})</em></p>")
        return
    add(f'<p><strong>Code</strong> — <code>{_esc(label)}</code>'
        + (" <em>(truncated)</em>" if excerpt.get("truncated") else "") + "</p>")
    language = excerpt.get("language") or ""
    add(f'<pre class="excerpt" data-language="{_esc(language)}">')
    for line in excerpt["lines"]:
        css = "row cited" if line["cited"] else "row"
        marker = " … [truncated]" if line.get("truncated") else ""
        add(
            f'<span class="{css}"><span class="ln">{line["number"]}</span>'
            f"{_esc(line['text'])}{_esc(marker)}</span>"
        )
    add("</pre>")


def _render_cross_references(add, report: dict[str, Any]) -> None:
    if report.get("cross_system_findings"):
        add('<section id="cross-system"><h2>Cross-System Findings</h2><p>These findings '
            "carry evidence from more than one segment or repository: ")
        links = ", ".join(
            f'<a href="#{anchor_for(i)}"><code>{_esc(i)}</code></a>'
            for i in report["cross_system_findings"]
        )
        add(links + "</p></section>")
    if report.get("attack_paths"):
        add('<section id="attack-paths"><h2>Attack Paths</h2><ul>')
        for path in report["attack_paths"]:
            ids = ", ".join(
                f'<a href="#{anchor_for(i)}"><code>{_esc(i)}</code></a>'
                for i in path.get("finding_ids", [])
            )
            add(f"<li>{_esc(path['description'])} ({ids})</li>")
        add("</ul></section>")


def _render_coverage(add, report: dict[str, Any]) -> None:
    coverage = report["coverage"]
    add('<section id="coverage"><h2>Coverage</h2><ul>')
    add(f'<li>Repositories analyzed: {_esc(", ".join(coverage["repos_analyzed"]))}</li>')
    add(f'<li>Segments analyzed: {_esc(coverage["segments_analyzed"])}</li>')
    if coverage.get("unavailable_members"):
        add(f'<li><strong>Unavailable members</strong> (coverage gap): '
            f'{_esc(", ".join(coverage["unavailable_members"]))}</li>')
    details = sorted(
        coverage.get("gap_details") or [],
        key=lambda d: (not d["security_critical"], d["file"]),
    )
    for index, detail in enumerate(details):
        marker = "<strong>SECURITY-CRITICAL</strong>" if detail["security_critical"] else "Gap"
        ref = _file_anchor(detail["file"].split(":", 1)[0], detail["file"])
        add(
            f'<li id="gap-{index}">{marker}: <a href="#{ref}"><code>{_esc(detail["file"])}'
            f"</code></a> ({_esc(detail['cause'])}, segment {_esc(detail['segment_id'])}) — "
            f"{_esc(detail['impact'])}</li>"
        )
    for gap in coverage.get("gaps", []):
        add(f"<li>Gap: {_esc(gap)}</li>")
    for outcome in coverage.get("audit_outcomes", []):
        line = (
            f"Dependency audit: {_esc(outcome['member'])} ({_esc(outcome['ecosystem'])}) — "
            f"{_esc(outcome['status'])}"
        )
        if outcome.get("reason"):
            line += f": {_esc(outcome['reason'])}"
        add(f"<li>{line}</li>")
    for gap in coverage.get("blocking_gaps", []):
        add(f"<li>Blocking gap: {_esc(gap)}</li>")
    triage_cov = coverage.get("triage")
    if triage_cov is not None:
        if triage_cov.get("enabled"):
            add(
                "<li>Finding triage: ran "
                f"({_esc(triage_cov.get('candidates', 0))} candidates, "
                f"{_esc(triage_cov.get('adjudicated', 0))} adjudicated); "
                f"{_esc(triage_cov.get('mode_note', ''))}".rstrip() + "</li>"
            )
        else:
            add("<li>Finding triage: disabled (profile/config)</li>")
    flow_cov = report.get("flow_coverage")
    if flow_cov:
        # Feature 015 (FR-014): the flow coverage ledger mirrors the Markdown
        # coverage section — same declarations, same numbers.
        applicability = flow_cov.get("applicability") or {}
        add(
            f'<li>Business flows: {_esc(len(flow_cov.get("reconstructed") or []))} '
            f'reconstructed · {_esc(len(flow_cov.get("analyzed") or []))} analyzed · '
            f'{_esc(len(flow_cov.get("partial") or []))} partial · '
            f'{_esc(len(flow_cov.get("unanalyzed") or []))} unanalyzed</li>'
        )
        evaluated = ", ".join(applicability.get("evaluated_regimes") or []) or "none"
        add(
            f'<li>Regime applicability: {_esc(applicability.get("mode", "hybrid"))} mode; '
            f'evaluated: {_esc(evaluated)}</li>'
        )
        if applicability.get("skipped_reason"):
            add(f'<li>Obligation evaluation skipped: {_esc(applicability["skipped_reason"])}</li>')
        for entry in flow_cov.get("partial") or []:
            add(
                f'<li>Partial flow <code>{_esc(entry["flow_id"])}</code>: '
                f'{_esc(", ".join(entry["gap_reasons"]))}</li>'
            )
        for entry in flow_cov.get("unanalyzed") or []:
            add(
                f'<li>Unanalyzed flow <code>{_esc(entry["flow_id"])}</code>: '
                f'{_esc(entry["reason"])}</li>'
            )
        for entry in flow_cov.get("undetermined") or []:
            add(
                f'<li>Undetermined flow <code>{_esc(entry["flow_id"])}</code>: '
                f'{_esc("; ".join(entry["reasons"]))}</li>'
            )
        for entry in flow_cov.get("candidate_regimes") or []:
            add(
                f'<li>Candidate regime (suggested, not evaluated): '
                f'<code>{_esc(entry["regime"])}</code> — detected '
                f'{_esc(", ".join(entry["detected_categories"]))}; declare it in '
                "business_flow.declared_regimes to evaluate</li>"
            )
    for limitation in coverage.get("tool_limitations", []):
        # Feature 008 (FR-009): external tooling the report implicitly lacks,
        # named with its reason — absence never reads as clean.
        line = (
            f"External tool: {_esc(limitation['tool_id'])} — {_esc(limitation['status'])}"
        )
        if limitation.get("reason"):
            line += f": {_esc(limitation['reason'])}"
        if limitation.get("affected_ecosystems"):
            line += f" (coverage: {_esc(', '.join(limitation['affected_ecosystems']))})"
        add(f"<li>{line}</li>")
    if report.get("unavailable_features"):
        add("<li>Unavailable in this execution mode:<ul>")
        for feature in report["unavailable_features"]:
            add(f"<li>{_esc(feature)}</li>")
        add("</ul></li>")
    add("</ul></section>")

    if report.get("suppressions"):
        # Feature 008 (FR-007): cross-check suppressions, auditable in report.
        suppressions = report["suppressions"]
        add(f'<section id="suppressions"><h2>Suppressed external findings '
            f"({len(suppressions)})</h2>")
        add("<p>The cross-check deterministically disproved these tool findings; "
            "each is excluded with its ground and evidence — none is silently dropped.</p><ul>")
        for record in suppressions:
            location = (record["finding"].get("location") or {}).get("file") or "manifest"
            add(
                f"<li>[{_esc(record['disproof_ground'])}] {_esc(record['tool_id'])}: "
                f"{_esc(record['finding']['description'][:160])} ({_esc(location)})<ul>"
            )
            for evidence in record["evidence"]:
                add(f"<li>{_esc(evidence)}</li>")
            add("</ul></li>")
        add("</ul></section>")

    if report.get("awaiting_verification"):
        # Feature 013: findings the triage round could not settle, with the
        # question that would settle each. Entries remain in the finding list.
        awaiting = report["awaiting_verification"]
        add(
            f'<section id="awaiting-verification"><h2>Awaiting verification '
            f"({len(awaiting)})</h2>"
        )
        add(
            "<p>These findings depend on facts outside the repository. Answer a "
            "question in <code>.secscan/triage/declarations.json</code> and re-run "
            "the scan to resolve it.</p><ul>"
        )
        for item in awaiting:
            location = item.get("location") or {}
            add(
                f"<li><strong>{_esc(item['finding_id'])}</strong> "
                f"(<code>{_esc(location.get('repo'))}:{_esc(location.get('file'))}</code>)"
                f"<ul><li>Question: {_esc(item['question'])}</li>"
            )
            if item.get("settling_evidence_hint"):
                add(f"<li>Settling evidence: {_esc(item['settling_evidence_hint'])}</li>")
            add("</ul></li>")
        add("</ul></section>")


def _render_files(
    add, report: dict[str, Any], findings: list[dict[str, Any]]
) -> None:
    """Referenced-files section: the target for every file reference (FR-006)."""
    citing: dict[tuple[str, str], set[str]] = {}
    for finding in findings:
        location = finding["location"]
        citing.setdefault((location["repo"], location["file"]), set()).add(finding["id"])
        for item in finding.get("evidence") or []:
            citing.setdefault((item["repo"], item["file"]), set()).add(finding["id"])
    coverage = report.get("coverage") or {}
    for detail in coverage.get("gap_details") or []:
        citing.setdefault((detail["file"].split(":", 1)[0], detail["file"]), set())

    add('<section id="files"><h2>Referenced Files</h2>')
    if not citing:
        add("<p>No files referenced.</p></section>")
        return
    add("<ul>")
    for (repo, path) in sorted(citing):
        citing_ids = sorted(citing[(repo, path)])
        refs = ", ".join(
            f'<a href="#{anchor_for(i)}"><code>{_esc(i)}</code></a>' for i in citing_ids
        )
        add(
            f'<li id="{_file_anchor(repo, path)}"><code>{_esc(repo)}:{_esc(path)}</code>'
            + (f" — cited by {refs}" if refs else "")
            + "</li>"
        )
    add("</ul></section>")


def _render_usage(add, report: dict[str, Any]) -> None:
    usage = UsageTracker.from_dict(report.get("usage") or {})
    add('<section id="usage"><h2>Usage &amp; Cost</h2><table>')
    rows = [
        ("Analysis invocations", str(usage.invocations)),
        ("Input tokens", f"{usage.total_input_tokens:,}"),
        ("Output tokens", f"{usage.total_output_tokens:,}"),
        ("Batch / interactive", f"{usage.batch_invocations} / {usage.interactive_invocations}"),
        ("Batch fallbacks", str(usage.fallbacks)),
        (
            "Estimated saving vs interactive pricing",
            f"{usage.estimated_saving_percent}% (assumes the {SAVING_ASSUMPTION})",
        ),
        ("Savings vs maximal-context baseline", f"{usage.savings_factor}x"),
    ]
    for metric, value in rows:
        add(f"<tr><th>{metric}</th><td>{value}</td></tr>")
    add("</table></section>")


def _check_links(document: str) -> None:
    """Every internal reference resolves, or the report is not published (FR-006)."""
    emitted = set(re.findall(r'id="([^"]+)"', document))
    dangling = sorted(set(re.findall(r'href="#([^"]+)"', document)) - emitted)
    if dangling:
        raise ValueError(f"unresolved internal references: {', '.join(dangling)}")
