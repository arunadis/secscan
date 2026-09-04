# Contract: Misconfig Integration Evidence (FR-004)

Owner stage: `src/pipeline/misconfig.py` (extends the existing misconfig pass; no new stage).

## Surface

- **Input**: misconfig findings; workspace model + code graph; `misconfig_rules.json` entries extended with `integration_markers`.
- **Output**: every misconfig finding carries an `integration` block per data-model.md §3.
- **Shipped data**: `integration_markers` — `{packages?, imports?, config_presence?}` per rule class. Adding a rule class or extending markers is a data change only.

## Deterministic guarantees

1. Marker matching is exact-string against declared manifests, file-node `imports`, and known config presence — no heuristics, no model.
2. States: `integrated` (≥1 marker hit, hits listed as evidence) / `no-integration-found` (rule carries markers, all evaluated, zero hits) / `undetermined` (rule carries no markers, or a referenced manifest could not be read — `reason` required).
3. Evidence list sorted by `(repo, file, reason)`.

## Policy invariants

- `no-integration-found` NEVER suppresses; it declares absence of integration and render-time remediation MUST lead with removal/decommissioning of the unused configuration before hardening advice.
- `undetermined` NEVER inflates severity or confidence and NEVER reads as clean (reported as "integration could not be determined").
- Existing misconfig findings pre-014 render unchanged (absent block tolerated).

## Failure modes

| Condition | Behavior |
|---|---|
| Rule entry lacks `integration_markers` | `undetermined`, reason: rule class carries no markers |
| Marker references a manifest class not extracted in this repo | `undetermined`, reason names the missing evidence class |
| `misconfig_rules.json` invalid shape | Hard scan failure (contract-test validated) |
