# Quickstart validation: Business-Flow (Functional) Vulnerability Analysis

Prerequisites: `uv venv --python 3.11 && uv pip install -e ".[dev]"`
(see AGENTS.md). All runs use the bundled test fixtures; no real project and no
network needed in the default path. Contracts referenced: [business-flow-artifact](contracts/business-flow-artifact.md), [config-skill](contracts/config-skill.md).

## Scenario 1 — Default is off (SC-001, FR-001/FR-004/FR-005)

1. `secscan run --full` on fixture `tests/fixtures/flow-app/` (created by tasks T004)
   with no `business_flow` config.
2. **Expect**: no `business-flows.json`, no `findings/flows.json`; report and all
   artifacts byte-identical to a run by the pre-feature tool (two-run comparison).

## Scenario 2 — Flow-gap detection (SC-002, FR-006/FR-007/FR-008/FR-017)

1. Enable: `secscan run --set analysis_depth.business_flow=true` (or config
   `business_flow.enabled: true`) on the fixture containing the seeded two-step
   privilege-escalation flow (second step omits its role check).
2. **Expect**:
   - `.secscan/business-flows.json` reconstructs the flow with ordered steps and
     per-step annotations (contract §2).
   - Report contains exactly one flow-gap finding for it: `flow_category: flow-gap`,
     narrative naming the flow, steps, missing check (role re-check), compromise
     (user gains staff operation), `verification.status` per the path semantics
     (FR-017).
   - Finding sits in the merged ranked list under the profile's thresholds (FR-014).
   - Deliberately safe flows in the fixture appear in `flow_coverage.analyzed` with
     zero findings.
3. Cost check (SC-005): usage table itemizes `business_flow_analysis` separately; no
   request exceeded budget (asserted in tests against serialized requests).

## Scenario 3 — Undetermined and partial honesty (SC-004, FR-010/FR-016)

1. Run against the multi-repo workspace fixture `tests/fixtures/flow-workspace/`
   (created by tasks T006) where members connect via one declared `sync-api`
   integration and one undeclared hop.
2. **Expect**: the cross-repo flow stitches across the declared integration with
   per-step repo attribution (FR-015); the flow hitting the undeclared hop is
   `partial: true` with `gap_reasons: ["integration-undeclared"]` and is declared in
   the report's flow coverage. No inference, no silence.

## Scenario 4 — Regulatory obligations (SC-006/SC-007, FR-018–FR-023)

1. `declared_only`: config `business_flow: {applicability_mode: declared-only,
   declared_regimes: [gdpr]}` on the fixture whose signup flow stores personal data
   with no consent step.
   **Expect**: one `regulatory-violation` finding naming `gdpr` + the consent
   obligation, failing step(s), and how the flow fails it (FR-019); one finding even
   if multiple regimes are declared (no per-regime duplication).
2. Same fixture, `declared_regimes: []`, mode `hybrid`: **Expect** `candidate_regimes`
   entry (personal-data detected → `gdpr` suggested) declared in coverage; **zero**
   regulatory-violation findings (FR-023, SC-006).
3. Mode `inferred-only`: **Expect** the finding with `regulatory_refs[].basis`
   stating the detection basis (FR-023).
4. `declared_regimes: [bogus]`: **Expect** config error (strict validation).

## Scenario 5 — Interactive ask & remember (FR-002/FR-003, config-skill contract §2)

1. Install the skill in a scratch agent dir; run the skill with no
   `business_flow.enabled` key.
   **Expect**: agent asks; run honors the answer via per-scan override.
2. Answer and accept "remember this choice".
   **Expect**: `business_flow.enabled` written; next run asks nothing.
3. Decline remember ⇒ nothing written ⇒ asked again. (Covered by skill-level and
   integration tests; direct CLI runs never ask.)

## Scenario 6 — Triage & correlation integration (FR-011)

1. Fixture where a missing role check appears both per-endpoint and as a flow gap.
2. **Expect**: both findings published, linked by `relationships: related` both ways;
   flow finding is triage-eligible and its triage verdicts pass citation
   re-verification against flow-step evidence; user declaration flow (`flagged` →
   `declarations.json`) works unchanged.

## Gates

- `pytest -q` and `pytest -q -m slow` green (including the scale scan with flow
  analysis on/off).
- `ruff check src tests` clean.
- Contract tests pass for `business_flow.json`, `flow_answer.json`, and the additive
  finding/report fields.
- Accuracy benchmark: seeded flow-gap and regulatory classes meet the SC-002/SC-006
  bars with zero safe-flow flags; regression in any single class fails the build.
