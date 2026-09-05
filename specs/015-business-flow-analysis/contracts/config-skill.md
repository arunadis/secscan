# Contract: configuration surface & skill interaction

Feature 015 | Parent: [../research.md](../research.md#decision-3-configuration-surface-and-precedence)

## 1. Configuration keys (all plain, non-secret)

| Key | Type | Default | Notes |
|---|---|---|---|
| `business_flow.enabled` | bool | **absent** (unset) | Absence ≠ `false`: absence triggers the skill ask |
| `business_flow.applicability_mode` | enum | `hybrid` | `hybrid` \| `declared-only` \| `inferred-only` |
| `business_flow.declared_regimes` | string[] | `[]` | Each MUST exist in `regimes.json`; unknown ⇒ config error |
| `profiles.<name>.analysis_depth.business_flow` | bool | `false` in all built-ins | Per-profile depth variance |

**Strict validation** (existing `_check_unknown_keys`): unknown keys/values are
config errors, not warnings. `declared_regimes` with unknown regime ids is an error in
every mode.

**Precedence** for effective enablement: `--set` profile override → active profile's
`analysis_depth.business_flow` → `business_flow.enabled` → `false`.

**Env overrides**: `SECSCAN_BUSINESS_FLOW_ENABLED`,
`SECSCAN_BUSINESS_FLOW_APPLICABILITY_MODE`, `SECSCAN_BUSINESS_FLOW_DECLARED_REGIMES`
(comma-separated). Other `SECSCAN_*` vars remain ignored.

## 2. Skill interactive ask (`SKILL.md` behavior contract)

Preconditions: scan launched through the installed skill **and**
`.secscan/config.yaml` has no `business_flow.enabled` key **and** no profile-selected
enablement.

1. Agent asks the user whether to run business-flow analysis for this run.
2. The answer governs this run (agent passes a per-scan `--set` override).
3. The agent MUST offer "remember this choice"; only on explicit assent does it write
   `business_flow.enabled: <answer>` into the config. Declined ⇒ nothing written ⇒
   asked again next time.
4. A user-edited or removed key restores the ask.
5. Non-interactive `secscan run` never asks, never blocks; unset ⇒ disabled (FR-004).

The scanner never writes the config itself, and never writes into the scanned project —
the remember-write is an agent action on scanner-owned state.

## 3. Hybrid-mode candidate confirmation

Confirming a candidate regime = user adds its id to `business_flow.declared_regimes`.
Next scan: regime moves from `candidate_regimes` to `evaluated_regimes`; the model
stage re-runs (config key in resume hash). The scanner never confirms a candidate on
its own.
