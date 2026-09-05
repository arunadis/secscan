"""T095: the accuracy benchmark gate (FR-043, FR-043a, FR-043b).

Assertions are grouped **per accuracy defect class**, so a regression in one class
fails the run without being masked by another class improving. A single aggregate
score would let the injection fix hide a dependency regression, which is exactly
the kind of blind spot that let the reviewed scan ship.

Each defect class below is checked against a live scan of a fixture that
reproduces the benchmark's shape. The reviewed real target itself is not scanned
here — it is an external repository — so its expected outcomes live in
`cases/reviewed_real.json` as declared baselines, and the mechanisms that would
change its verdict are what get exercised.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import run as run_mod
from pipeline.consistency import check as consistency_check
from tests.benchmark import DEFECT_CLASSES, load_cases
from tests.integration.conftest import write_config

# ------------------------------------------------------------- case integrity


def test_every_defect_class_has_an_expectation() -> None:
    """FR-043b: per-class assertions, so no class can be silently unguarded."""
    cases = load_cases()
    assert cases, "no benchmark case is defined"
    covered: set[str] = set()
    for case in cases:
        covered.update(case.classes_covered)
    missing = set(DEFECT_CLASSES) - covered
    assert not missing, f"defect classes with no expectation: {sorted(missing)}"


def test_every_expectation_records_its_baseline() -> None:
    """An expectation without a baseline cannot show that anything improved."""
    for case in load_cases():
        for expectation in case.expectations:
            assert expectation.assertion
            assert expectation.baseline, (
                f"{case.case_id}/{expectation.defect_class}: no baseline recorded"
            )


def test_reviewed_case_names_its_source_of_truth() -> None:
    """The reviewer, not the fixture, is authoritative (FR-043)."""
    reviewed = [c for c in load_cases() if c.kind == "reviewed-real"]
    assert reviewed
    for case in reviewed:
        assert "review" in case.source_of_truth.lower()
        assert case.target


def test_usage_baseline_is_recorded_with_its_profile_and_target() -> None:
    """SC-013 is only measurable if the comparison is like-for-like."""
    payload = json.loads((Path(__file__).parent / "cases" / "baseline_usage.json").read_text())
    for key in ("savings_vs_maximal_context", "min_acceptable_savings", "profile", "target"):
        assert key in payload
    assert payload["min_acceptable_savings"] < payload["savings_vs_maximal_context"]


def test_defect_class_business_flow(tmp_path) -> None:
    """Feature 015 (SC-002): the seeded business-flow gap is its own release-
    blocking defect class — detection asserted per fixture ground truth, safe
    flows asserted unflagged."""
    from pipeline import run as run_mod
    from tests.fixtures.flow_app import GROUND_TRUTH, build, flow_oracle_answer
    from tests.integration.conftest import oracle_responder

    def responder(request) -> str:
        answer = flow_oracle_answer(request)
        return answer if answer is not None else oracle_responder(request)

    root = build(tmp_path)
    write_config(root, {"business_flow": {"enabled": True}})
    result = run_mod.run_scan(root, responder=responder, full=True)

    gaps = [f for f in result.findings if f.get("flow_category") == "flow-gap"]
    assert len(gaps) == len(GROUND_TRUTH["flow_gaps"])
    assert all(
        GROUND_TRUTH["flow_gaps"][0]["missing_check"] in f["flow_narrative"]["missing_check"]
        for f in gaps
    )
    # Safe flows are never flagged (the false-positive guard).
    for finding in result.findings:
        narrative = finding.get("flow_narrative") or {}
        assert not any(
            route in str(narrative.get("name", "")) for route in GROUND_TRUTH["safe_flows_at"]
        )


def test_defect_class_regulatory_flow(tmp_path) -> None:
    """Feature 015 (SC-006/SC-007): obligation breaches and honest candidates are
    their own release-blocking defect class."""
    from pipeline import run as run_mod
    from pipeline.state import ArtifactStore
    from tests.fixtures.flow_app import GROUND_TRUTH, build, flow_oracle_answer
    from tests.integration.conftest import oracle_responder

    case = GROUND_TRUTH["regulatory_case"]

    def responder(request) -> str:
        answer = flow_oracle_answer(request)
        return answer if answer is not None else oracle_responder(request)

    # Declared: the breach is found once, naming regime and obligation.
    root = build(tmp_path / "declared")
    write_config(
        root,
        {"business_flow": {"enabled": True, "applicability_mode": "declared-only",
                           "declared_regimes": [case["expected_regime"]]}},
    )
    result = run_mod.run_scan(root, responder=responder, full=True)
    violations = [
        f for f in result.findings if f.get("flow_category") == "regulatory-violation"
    ]
    assert len(violations) == 1
    assert (
        violations[0]["regulatory_refs"][0]["regime"],
        violations[0]["regulatory_refs"][0]["obligation"],
    ) == (case["expected_regime"], case["expected_obligation"])

    # Hybrid, nothing declared: candidates declared, but never evaluated.
    root = build(tmp_path / "hybrid")
    write_config(root, {"business_flow": {"enabled": True}})
    result = run_mod.run_scan(root, responder=responder, full=True)
    assert not [
        f for f in result.findings if f.get("flow_category") == "regulatory-violation"
    ]
    candidates = ArtifactStore(root).read("business-flows.json")["coverage"][
        "candidate_regimes"
    ]
    assert case["expected_regime"] in {c["regime"] for c in candidates}


def test_defect_class_triage_correctness(tmp_path) -> None:
    """FR-016: triage correctness is its own release-blocking defect class.

    The corpus (cases/triage_ground_truth.json) mirrors the audited baseline's
    disprovable classes. Each entry declares its expected triage outcome next to
    the fixture; the gate runs the full scan with a scripted reasoning answer and
    compares the outcome recorded in the scan's own triage artifacts.
    """
    import importlib

    entries = json.loads(
        (Path(__file__).parent / "cases" / "triage_ground_truth.json").read_text()
    )["entries"]
    assert entries, "the triage corpus is empty"
    module = importlib.import_module("tests.fixtures.triage_targets")

    for entry in entries:
        root = tmp_path / entry["id"]
        builder = module.build_repo
        member = builder(root)
        write_config(member)
        answer = getattr(module, entry["answer"])  # corpus-driven selection
        result = run_mod.run_scan(member, responder=module.scripted_responder(answer),
                                  full=True)
        store = member / ".secscan"
        suppressions = result.report.get("suppressions") or []
        awaiting = result.report.get("awaiting_verification") or []
        decisions = json.loads(
            (store / "triage" / "decisions.json").read_text()
        )["payload"]["decisions"]

        annotation = entry["annotation"]
        if annotation == "expect-refuted":
            assert any(s["disproof_ground"] == "triage-control-present"
                       for s in suppressions), entry["id"]
            verdicts = {d["verdict_attempted"] for d in decisions}
            assert "refuted" in verdicts, entry["id"]
        elif annotation == "expect-flagged":
            assert awaiting, entry["id"]
            assert not any(s["disproof_ground"] == "triage-control-present"
                           for s in suppressions), entry["id"]
        elif annotation == "must-survive":
            # The credential finding survives every refutation aimed at the code
            # finding, and its grading is intact — zero true-positive loss (SC-002).
            assert any(f["cwe"] == "CWE-798" and f["severity_score"] >= 7.0
                       for f in result.reported_findings), entry["id"]
            cred_decisions = [
                d for d in decisions
                if any(f["id"] == d["finding_id"] and f["cwe"] == "CWE-798"
                       for f in result.findings)
            ]
            assert all(d["verdict_attempted"] != "refuted" or d["outcome"] != "applied"
                       for d in cred_decisions), entry["id"]
        else:  # pragma: no cover - corpus discipline
            raise AssertionError(f"unknown triage annotation: {annotation}")

    # FR-017: triage never changes what detection produced — decisions can only
    # remove from or annotate the deterministic stream, and the pre-triage
    # artifact must still show both seeds.
    root = tmp_path / "recall-check"
    member = module.build_repo(root)
    write_config(member)
    run_mod.run_scan(member, responder=module.scripted_responder(
        module.REFUTING_ANSWER), full=True)
    correlated = json.loads(
        (member / ".secscan" / "findings" / "correlated.json").read_text()
    )["payload"]["findings"]
    assert {f["cwe"] for f in correlated} == {"CWE-862", "CWE-798"}


def test_usage_evidence_gate(tmp_path) -> None:
    """Feature 014 T006 (FR-001–FR-003, SC-002): usage evidence gates advisory narratives.

    Encodes the 20260904 cross-check failure: an advisory narrated exploitation
    for a package nothing imports. The stale member's finding must survive with
    usage none-found, capped confidence, and a conditional narrative; the
    consumer's must say found with its import location; and every dependency
    finding in the fixture carries a usage state (SC-002 invariant).
    """
    from tests.fixtures import dependency_usage
    from tests.integration.conftest import silent_responder

    root = tmp_path / "usage"
    workspace = dependency_usage.build(root)
    write_config(
        workspace,
        {
            "workspace": {
                "members": [
                    {"name": "stale", "path": "stale"},
                    {"name": "consumer", "path": "consumer"},
                ]
            }
        },
    )
    run_mod.run_scan(workspace, responder=silent_responder, full=True)
    correlated = json.loads(
        (workspace / ".secscan" / "findings" / "correlated.json").read_text()
    )["payload"]["findings"]

    truth = dependency_usage.GROUND_TRUTH
    dependency = [f for f in correlated if f.get("dependency")]
    assert dependency, "the fixture produced no dependency findings at all"

    # SC-002: silence on usage is a defect for every dependency finding.
    for finding in dependency:
        usage = finding.get("usage") or {}
        assert usage.get("state") in ("found", "none-found", "undetermined"), (
            f"{finding['id']}: dependency finding is silent on usage"
        )

    for member, package in truth["advisory_packages"].items():
        matched = [
            f
            for f in dependency
            if f["dependency"]["package"] == package
            and f["location"]["repo"] == member
        ]
        assert matched, f"no advisory finding for {package} in {member}"
        usage = matched[0].get("usage") or {}
        expected = truth["expected_usage_state"][member]
        assert usage.get("state") == expected, f"{member}: {usage}"
        if expected == "none-found":
            assert matched[0]["confidence"] <= 0.5, f"{member}: confidence not capped"
            text = (matched[0]["impact"] + matched[0]["attack_scenario"]).lower()
            assert "no usage" in text or "no import" in text
            assert "only if" in text, f"{member}: narrative still asserts the chain"
        else:
            locations = usage.get("locations") or []
            assert locations and all(loc["kind"] for loc in locations)
            assert any("cli.ts" in loc["file"] for loc in locations)


def test_template_sink_escaping_gate(tmp_path) -> None:
    """Feature 014 T016 (FR-005–FR-007): escaped template bindings engage the control.

    Encodes the 20260904 cross-check failure: `[innerHTML]` under Angular's
    sanitizer, no bypass — script execution must NOT be asserted; the variant
    with bypassSecurityTrustHtml keeps the finding at full standing.
    """
    from tests.fixtures import template_escaped

    def xss_responder(request) -> str:
        payload = request.payload
        repo = payload.get("repo", "web")
        findings = []
        for path in sorted(payload.get("source") or {}):
            if not path.endswith(".html"):
                continue
            findings.append(
                {
                    "cwe": "CWE-79",
                    "severity_score": 8.2,
                    "confidence": 0.9,
                    "location": {"repo": repo, "file": path, "line_start": 3},
                    "description": "Unsanitized user content rendered via innerHTML.",
                    "evidence": [{"repo": repo, "file": path, "reason": "[innerHTML] binding"}],
                    "attack_scenario": "Stored script executes in a victim's browser.",
                    "impact": "Script execution.",
                    "recommendation": "Sanitize the bound value.",
                    "segment_id": payload.get("segment_id"),
                }
            )
        return json.dumps({"findings": findings})

    for with_bypass in (False, True):
        root = tmp_path / ("bypass" if with_bypass else "clean")
        template_escaped.build(root, with_bypass=with_bypass)
        write_config(root)
        run_mod.run_scan(root, responder=xss_responder, full=True)
        correlated = json.loads(
            (root / ".secscan" / "findings" / "correlated.json").read_text()
        )["payload"]["findings"]
        xss = [f for f in correlated if f["cwe"] == "CWE-79"]
        assert xss, f"with_bypass={with_bypass}: no CWE-79 finding produced"
        finding = xss[0]
        control = finding.get("framework_control") or {}
        if with_bypass:
            assert control.get("state") == "bypassed", control
            assert "bypass_site" in control
            assert finding["severity_score"] == 8.2, "credit must be withheld"
        else:
            assert control.get("state") == "credited", control
            assert finding["severity_score"] == round(8.2 * 0.5, 1), finding
            assert "not achievable" in finding["impact"], finding["impact"]


def test_currency_merge_gate(tmp_path) -> None:
    """Feature 014 T021 (FR-008/FR-009): one currency finding per (member, product, cycle)."""
    from tests.fixtures.multi_member_workspace import build

    workspace = build(tmp_path)
    write_config(
        workspace,
        {
            "workspace": {
                "members": [
                    {"name": "web", "path": "web"},
                    {"name": "api", "path": "api"},
                ]
            }
        },
    )
    run_mod.run_scan(workspace, responder=silent_responder_module(), full=True)
    correlated = json.loads(
        (workspace / ".secscan" / "findings" / "correlated.json").read_text()
    )["payload"]["findings"]
    currency = [
        f
        for f in correlated
        if (f.get("dependency") or {}).get("signals") == ["past-eol"]
    ]
    web_currency = [f for f in currency if f["location"]["repo"] == "web"]
    angular = [f for f in web_currency if f["dependency"]["product"] == "angular"]
    assert len(angular) == 1, (
        f"angular 9 EOL must appear exactly once for web; got {len(angular)}"
    )
    assert angular[0]["dependency"]["packages"] == [
        "@angular/core",
        "@angular/platform-browser",
    ]
    assert len(angular[0]["evidence"]) == 2


def silent_responder_module():
    from tests.integration.conftest import silent_responder

    return silent_responder


def test_defect_class_missed_detection(tmp_path) -> None:
    """FR-011/D5. Baseline: 5 verified misses across the two reference scans.

    Every must-find corpus entry names a fixture reproducing the miss; the gate
    runs a full scan over each fixture and asserts the rule's finding appears.
    A miss on any entry fails the build alone (FR-043b precedent).
    """
    entries = json.loads(
        (Path(__file__).parent / "cases" / "must_find.json").read_text()
    )["entries"]
    assert len(entries) == 5, "the must-find corpus covers the five evidenced misses"

    from pipeline import run as run_mod
    from tests.fixtures.missed_detection_sites import build_fixture
    from tests.integration.conftest import silent_responder, write_config

    for entry in entries:
        root = tmp_path / entry["fixture"]
        build_fixture(entry["fixture"], root)
        write_config(root)
        run_mod.run_scan(root, responder=silent_responder, full=True)
        correlated = json.loads(
            (root / ".secscan" / "findings" / "correlated.json").read_text()
        )["payload"]
        marker = f":{entry['rule_id']}"
        matched = [
            f
            for f in correlated["findings"]
            if marker in str(f.get("tool_ref", ""))
            or marker in str((f.get("dependency") or {}).get("audit_source", ""))
            # Advisory entries match the outcome regardless of which audit path
            # (bundled baseline or native tool) produced it — the gate asserts
            # the user-visible finding exists; offline behavior is unit-tested.
            or (
                entry.get("expect_package")
                and (f.get("dependency") or {}).get("package") == entry["expect_package"]
            )
        ]
        assert matched, f"must-find entry still missed: {entry['rule_id']} ({entry['reference']})"


# --------------------------------------------------------------- live scan
def ssrf_responder(request) -> str:
    """Reproduces the benchmark's two findings: a request-forgery and an XSS."""
    payload = request.payload
    findings = []
    for path in sorted(payload.get("source") or {}):
        if "client.ts" not in path:
            continue
        findings.append(
            {
                "cwe": "CWE-918",
                "severity_score": 4.3,
                "confidence": 0.65,
                "location": {
                    "repo": "fixed-prefix-sink",
                    "file": path,
                    "symbol": "fetchUser",
                    "line_start": 5,
                    "line_end": 8,
                },
                "description": "The id is interpolated into a request URL without encoding.",
                "evidence": [
                    {
                        "repo": "fixed-prefix-sink",
                        "file": path,
                        "symbol": "fetchUser",
                        "reason": "unencoded template-literal interpolation",
                    }
                ],
                "attack_scenario": "An attacker distributes a crafted link.",
                "impact": "The request is steered to an unintended endpoint.",
                "recommendation": "Encode the value.",
                "segment_id": payload.get("segment_id"),
            }
        )
    return json.dumps({"findings": findings})


@pytest.fixture(scope="module")
def benchmark_scan(tmp_path_factory):
    from tests.fixtures.unparsed_language import build_fixed_prefix

    root = tmp_path_factory.mktemp("benchmark")
    repo = build_fixed_prefix(root)
    write_config(repo)
    result = run_mod.run_scan(repo, responder=ssrf_responder, full=True)
    report = json.loads(Path(result.report_json_path).read_text())["payload"]
    correlated = json.loads(
        (repo / ".secscan" / "findings" / "correlated.json").read_text()
    )["payload"]
    return repo, report, correlated


def _analysis_findings(correlated: dict) -> list[dict]:
    return [f for f in correlated["findings"] if f["source"] == "analysis"]


def test_defect_class_evidence_integrity(benchmark_scan) -> None:
    """Baseline: 2 of 2 locations wrong; 1 of 2 published unresolved; 2 of 2 repros unachievable."""
    _repo, report, correlated = benchmark_scan
    findings = [f for items in report["findings_by_band"].values() for f in items]
    assert findings

    for finding in findings:
        assert finding["location"].get("tier") in ("symbol", "file"), finding["id"]
        gap = (finding.get("verification") or {}).get("gap") or ""
        assert "could not be matched to the code graph" not in gap

        repro = finding["reproduction"]
        verified = finding["verification"]["status"] == "verified"
        assert repro["mode"] == ("observed" if verified else "hypothesis")
        if not verified:
            assert "observed_behavior" not in repro
        # A trail is a path or it is absent.
        for entry in repro.get("traced_trail") or []:
            assert entry in (finding["verification"].get("path") or [])

    assert report["coverage"]["resolution_tiers"]["rejected"] == 0


def test_defect_class_classification(benchmark_scan) -> None:
    """Baseline: 1 of 2 misclassified — CWE-918 on a browser-only target."""
    _repo, _report, correlated = benchmark_scan
    findings = _analysis_findings(correlated)
    assert findings
    assert all(f["cwe"] != "CWE-918" for f in findings)
    remapped = [f for f in findings if f.get("reclassification")]
    assert remapped, "the request-forgery finding was not remapped"
    assert remapped[0]["reclassification"]["original_cwe"] == "CWE-918"
    assert "A10" not in remapped[0].get("owasp_top10", "")


def test_defect_class_calibration(benchmark_scan) -> None:
    """SC-006. Baseline: 2 of 2 overstated; confidence 0.85 with reachability unconfirmed.

    SC-006 as written asks whether "an expert reviewer judges" a severity
    overstated, which no test can answer. What is asserted here is the machine
    -checkable proxy: an unproven finding carries capped confidence and a recorded
    control state. The human judgement itself remains a manual release gate --
    see tests/benchmark/MANUAL_REVIEW.md.
    """
    _repo, _report, correlated = benchmark_scan
    for finding in _analysis_findings(correlated):
        if finding["verification"]["status"] != "verified":
            assert finding["confidence"] <= 0.5, finding["id"]
        assert finding["framework_control"]["state"] in (
            "credited",
            "bypassed",
            "absent",
            "unassessed",
        )


def test_defect_class_coverage(benchmark_scan) -> None:
    """Baseline: 0 of 5 file classes represented; template sinks found manually."""
    repo, report, _correlated = benchmark_scan
    classes = {entry["file_class"] for entry in report["coverage"]["file_classes"]}
    assert {"source", "template", "dependency-manifest"} <= classes
    graph = json.loads((repo / ".secscan" / "code-graph.json").read_text())["payload"]
    manifests = [n for n in graph["nodes"] if n.get("file_class") == "dependency-manifest"]
    assert manifests, "package.json is still absent from the code model"


def test_defect_class_dependency_coverage(benchmark_scan) -> None:
    """SC-008/SC-008a. Baseline: the domain produced nothing; 23 advisories invisible.

    SC-008's ">=90% of runtime advisories reported" needs a reachable advisory
    database, so in an offline test environment the assertable half is FR-033's:
    the domain is either reported or *loudly* unassessed, never silently empty.
    """
    _repo, report, correlated = benchmark_scan
    outcomes = report["coverage"].get("audit_outcomes") or []
    gaps = report["coverage"].get("blocking_gaps") or []
    dependency = [f for f in correlated["findings"] if f["source"] == "dependency-audit"]
    # Either the domain produced findings, or it declared itself unassessed with a
    # runnable command. Silence is the one outcome that is not acceptable.
    assert dependency or gaps or outcomes
    # The benchmark's end-of-support stack must be caught either way.
    assert any("angular" in json.dumps(f).lower() for f in dependency), (
        "Angular 9.0.1 was not reported as past end of support"
    )


def test_defect_class_redaction_precision(benchmark_scan) -> None:
    """Baseline: 4 of 12 coverage notes were identifier false positives."""
    _repo, report, _correlated = benchmark_scan
    from pipeline.redact import identifier_shape

    for gap in report["coverage"].get("gaps") or []:
        if "high-entropy" not in gap:
            continue
        # No gap may be caused by something that decomposes as an identifier.
        for token in gap.replace(":", " ").split():
            assert identifier_shape(token) is None, f"identifier caused a gap: {gap}"


def test_defect_class_report_consistency(benchmark_scan) -> None:
    """Baseline: 'see the High section' in a report with no High section."""
    _repo, report, _correlated = benchmark_scan
    problems = consistency_check(report)
    assert problems == [], "\n".join(str(p) for p in problems)


def test_defect_class_credential_precision() -> None:
    """FR-012/SC-003. Baseline: identifier-name FPs published as verified CWE-798.

    The audited baseline declares, per finding of scan 20260831T081536Z-438706,
    whether it was a true or false positive. The external target is not scanned
    here; what is asserted is (a) the audit's integrity and (b) the mechanism on
    the fixture corpora — the same detector that produced those findings.

    Feature 010 mutation check (2026-09-02, T026): re-adding the blanket
    ``\\$\\{[^}]*\\}`` placeholder to ``_PLACEHOLDER`` turns this test red (the
    ``${ENV_SECRET}`` corpus entry loses its exempt-reference decision, and the
    ``${DB_PASSWORD:-hunter2hunter2}`` must-find is silently exempted again);
    disabling the assigned-secret exemption branch turns it red on the SEC-0080
    line. The guard bites in both directions.
    """
    audit_path = Path(__file__).parent / "cases" / "audited_credential_baseline.json"
    audit = json.loads(audit_path.read_text())
    entries = audit["entries"]

    # Audit integrity: complete, sorted, and decidable.
    assert len(entries) == 23, "the baseline scan's CWE-798 cluster has 23 findings"
    assert [e["source_label"] for e in entries] == sorted(
        e["source_label"] for e in entries
    )
    for entry in entries:
        assert entry["verdict"] in ("true-positive", "false-positive")
        assert entry["rationale"]

    false_positives = [e for e in entries if e["verdict"] == "false-positive"]
    true_positives = [e for e in entries if e["verdict"] == "true-positive"]
    assert false_positives, "audit found no false positives — SC-003 is vacuous"
    assert true_positives, "audit found no true positives — recall is unguarded"

    # Feature 010 follow-up audit (SC-003): the runtime-reference findings from a
    # later scan of the same workspace. Labels collide with the 2026-08-31 scan's,
    # so they live in their own block rather than in `entries`.
    (follow_up,) = audit["follow_up_scans"]
    assert follow_up["feature"] == "010-runtime-credential-refs"
    assert [e["source_label"] for e in follow_up["entries"]] == ["SEC-0080", "SEC-0082", "SEC-0084"]
    for entry in follow_up["entries"]:
        assert entry["verdict"] == "false-positive"
        assert "runtime reference" in entry["rationale"]
        assert entry["file"].endswith(".sh")

    # Mechanism, FP side: the fixture corpus reproducing the audited FP classes
    # produces no hits, hence no findings (SC-001).
    from pipeline.redact import Redactor
    from pipeline.secret_findings import findings_from_hits
    from tests.fixtures.identifier_corpus import IDENTIFIERS

    redactor = Redactor()
    for line, token, why in IDENTIFIERS:
        result = redactor.redact(line, origin="src/app.ts")
        assert not findings_from_hits(result.hits, "repo"), f"FP finding: {token} ({why})"

    # Feature 010 FP side: runtime references (SEC-0080 class) are never findings
    # and every exemption is recorded (FR-012, SC-001, SC-004).
    from tests.fixtures.runtime_reference_corpus import REFERENCES

    for origin, line, why in REFERENCES:
        result = redactor.redact(line, origin=origin)
        assert result.hits == [], f"hit on runtime reference: {line} ({why})"
        assert not findings_from_hits(result.hits, "repo"), f"FP finding ({why})"
        assert any(e.decision == "exempt-reference" for e in result.exempted), why

    # Mechanism, TP side: every seeded credential is still detected (SC-002),
    # and heuristic-labelled findings never publish as verified (FR-008).
    from tests.fixtures.credential_corpus import CREDENTIALS

    for origin, line, why in CREDENTIALS:
        result = redactor.redact(line, origin=origin)
        assert result.redacted >= 1, f"missed credential ({why})"

    # Feature 010 recall GAIN (FR-007, FR-013): the literal default that the old
    # blanket `${…}` placeholder silently exempted is now a finding.
    gained = redactor.redact('password: "${DB_PASSWORD:-hunter2hunter2}"', origin="compose.yml")
    assert gained.redacted == 1 and findings_from_hits(gained.hits, "repo")

    # Feature 010 report integrity (FR-009, SC-005): a long slash-joined path on a
    # line naming a credential symbol survives the reproduction backstop.
    from pipeline.reproduce import build_reproduction

    path = "skillhunt-portal-backend/migration/p0/verify-account.sh"
    block = build_reproduction(
        {"cwe": "CWE-798", "verification": {"status": "verified"},
         "location": {"repo": "skh", "file": path, "symbol": "AWS_SECRET_ACCESS_KEY"}},
        flow=None,
    )
    assert path in block["trigger"] and "[REDACTED" not in block["trigger"]
    heuristic = findings_from_hits(
        [
            h
            for origin, line, _ in CREDENTIALS
            for h in redactor.redact(line, origin=origin).hits
        ],
        "repo",
    )
    for finding in heuristic:
        if finding["detection"] == "heuristic":
            assert finding["confidence"] < 0.95, finding["location"]


def test_defect_class_llm_detection(tmp_path) -> None:
    """Spec 007: modern-exploit detection quality (cases/llm_scan.json).

    The per-variant assertions live in test_llm_detection.py; this entry point
    is what keeps the class covered by the regression-masking gate below.
    """
    from tests.benchmark import test_llm_detection as llm

    llm.test_direct_prompt_injection_is_found(tmp_path / "direct")
    llm.test_structured_separation_produces_no_finding(tmp_path / "safe")
    llm.test_sensitive_data_in_context_is_found(tmp_path / "sensitive")
    llm.test_insecure_output_handling_is_found(tmp_path / "output")
    llm.test_indirect_injection_is_found_with_capability_reach(tmp_path / "indirect")
    llm.test_bounded_ingestion_produces_no_indirect_finding(tmp_path / "bounded")


def test_defect_class_supply_chain_detection(tmp_path) -> None:
    """Spec 007: supply-chain/dependency-confusion quality (cases/supply_chain.json)."""
    from tests.benchmark import test_supply_chain_detection as scd

    scd.test_confusion_and_mutable_exposure_is_found(tmp_path / "vulnerable")
    scd.test_unguarded_scope_records_guard_as_undetermined(tmp_path / "guard")
    scd.test_hardened_manifest_produces_zero_supply_chain_findings(tmp_path / "hardened")


def test_no_defect_class_regression_is_masked(benchmark_scan) -> None:
    """FR-043b, stated as a property: every class is independently asserted."""
    asserted = {
        name.replace("test_defect_class_", "").replace("_", "-")
        for name in globals()
        if name.startswith("test_defect_class_")
    }
    assert asserted == set(DEFECT_CLASSES), (
        f"defect classes without their own test: {set(DEFECT_CLASSES) - asserted}"
    )


def test_remediation_order_puts_dependencies_first(benchmark_scan) -> None:
    """SC-012: the report's ranked order reproduces the reviewer's priority.

    The independent reviewer's reprioritized list put dependency upgrade first,
    ahead of both filed findings. The benchmark scan's own top recommendation was
    the item the reviewer ranked third, and the reviewer's first item was absent
    entirely. This asserts the ordering property: where a dependency or
    end-of-support finding exists, it is not ranked below a code-smell finding of
    lower severity.
    """
    _repo, report, _correlated = benchmark_scan
    recommendations = report.get("recommendations") or []
    if not recommendations:
        pytest.skip("no findings met the profile thresholds")

    findings = [f for items in report["findings_by_band"].values() for f in items]
    dependency_cwes = {"CWE-1035", "CWE-1104"}
    has_dependency = any(f["cwe"] in dependency_cwes for f in findings)
    if not has_dependency:
        pytest.skip("no dependency finding in this scan")

    positions = {
        cwe: index
        for index, line in enumerate(recommendations)
        for cwe in dependency_cwes | {f["cwe"] for f in findings}
        if f"({cwe})" in line
    }
    dependency_at = min(
        (positions[c] for c in dependency_cwes if c in positions), default=len(recommendations)
    )
    others = {c: i for c, i in positions.items() if c not in dependency_cwes}
    for cwe, index in others.items():
        by_cwe = [f for f in findings if f["cwe"] == cwe]
        dependency_findings = [f for f in findings if f["cwe"] in dependency_cwes]
        if max(f["severity_score"] for f in by_cwe) < max(
            f["severity_score"] for f in dependency_findings
        ):
            assert dependency_at < index, (
                f"{cwe} is ranked above the dependency finding despite lower severity"
            )
