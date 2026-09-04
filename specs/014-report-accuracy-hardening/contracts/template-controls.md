# Contract: Template-Aware Framework Controls (FR-005 – FR-007)

Owner stage: `src/pipeline/controls.py` `evaluate()` (extended); candidate handoff via existing `triage.collect_candidate_controls`.

## Surface

- **Input**: finding (CWE, location, verification path); code graph including `type:"template"` nodes with binding annotations; `framework_controls.json` (unchanged data).
- **Output**: unchanged finding field `framework_control` (`state` ∈ credited / bypassed / absent / unassessed) — extended to cover template sinks; plus, when `unassessed` for a hedgeable template case and the finding meets triage candidacy, the control ships as a `candidate_controls` entry.

## Decision rules (hybrid, clarification Q2)

For a finding whose location/path touches a template node:

1. Sink admitted: the template node carries a binding annotation matching some entry of the control's `sinks` list. No match ⇒ control not applicable to this sink (`absent` semantics; the sink list is the sole authority).
2. Admitted sink ⇒ deterministic credit requires BOTH:
   - zero `control_bypass`-annotated nodes across the member (member-wide scan, not path-scoped), and
   - every source file in the member is `parsed: true` (a bypass in an unparsed file cannot be ruled out).
   Otherwise ⇒ `unassessed` with reason (bypass present / coverage incomplete), and the finding is eligible for the triage round with the control as candidate.
3. `bypassed` when a `control_bypass` node exists in the member; the bypass node is recorded as `bypass_site` evidence.
4. Non-template findings: existing path-scoped behavior (FR-022 family) unchanged.
5. Existing guards inherited unchanged: no framework recognized ⇒ `unassessed`; `requires_config` + non-default-escaping framework ⇒ `unassessed`.

## Policy invariants

- Crediting is never derived from model output (Principle I); the triage refute/downgrade path remains citation-gated and mechanically re-verified (existing `triage_evidence.verify_citations`).
- Credited controls continue to receive the existing calibration treatment (confidence factor, residual-impact reframing) — no change to `calibrate.py` semantics.
- A bypass unrelated to this sink still withholds *deterministic* credit (conservative), but does NOT auto-confirm the finding — hedged cases go to triage or stay `unassessed`.

## Failure modes

| Condition | Behavior |
|---|---|
| Template node lacks binding annotations (extraction gap) | `unassessed`, reason: template bindings could not be established |
| Control entry without `sinks` list | Treated as not template-applicable (data-validated: bypass list still mandatory) |
| Multiple frameworks with escaping controls in one member | Per-sink selection by sink list; first deterministically creditable control wins; conflicts impossible because sink lists are disjoint per control data (asserted by contract test) |
