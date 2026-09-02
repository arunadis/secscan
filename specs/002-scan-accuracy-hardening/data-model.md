# Data Model: Scan Result Accuracy Hardening

Extends the model in `001-hierarchical-security-scan/data-model.md`. **All schema changes are
additive** — no existing required field changes type or meaning, so `schema_version` stays `1` and
artifacts written by the previous version remain readable (see `contracts/schema-deltas.md` for the
field-level diff). Entities below are new or newly-extended only.

## Architecture Profile

The deterministically determined execution shape of a workspace member or segment (FR-013–FR-014).
Attached to the repository manifest per member and, when it differs, to the segment.

| Field | Type | Rules |
|-------|------|-------|
| `scope` | `member` \| `segment` | segment scope overrides member scope for findings inside it (Edge Cases), **except** where the segment has an outgoing cross-segment edge into differently-shaped code — narrowing there would suppress a class whose path genuinely reaches it (FR-015a) |
| `shape` | enum | `server-request-issuer` \| `browser-client` \| `cli` \| `library` \| `undetermined` |
| `evidence` | string[] | ≥1 when `shape` ≠ `undetermined`; the manifest/config facts that determined it |
| `undetermined_reason` | string | required when `shape` = `undetermined` |

**Invariants**: `undetermined` is never replaced by an assumed value (FR-013b). A member may carry
several shapes across its segments (FR-014); a hybrid repository is represented as differing segment
scopes, not as a compound shape.

**State**: terminal on write — architecture is derived from source, so it changes only when a rescan
reclassifies (relevant to the Phase 7 invalidation cascade).

## Applicability Conclusion

The result of evaluating the applicability relation over the traced workspace path for one finding
(FR-015a–FR-015c). Recorded on the finding; never inferred at render time.

| Field | Type | Rules |
|-------|------|-------|
| `reachable_shapes` | string[] | every architecture shape reachable from the location, deduped and sorted |
| `applicable` | bool \| `undetermined` | `undetermined` when reachability or architecture could not be settled |
| `enabling_member` | string | the member that makes the class applicable, when one does |
| `reason` | string | required when `applicable` is `false` or `undetermined` |

**Invariant**: only `applicable: false` may trigger a remap. Both `true` and `undetermined` retain the
finding as classified (FR-015c, FR-013a) — the relation may only ever *remove* a claim it can
disprove structurally.

## Reclassification Record

Retained even when the resulting finding falls below the reporting threshold (FR-017).

Fields: `original_cwe`, `new_cwe`, `original_severity`, `new_severity`, `reason`,
`applicability_conclusion` (embedded), `operator_override` (bool — set when FR-019 made the operator's
explicit profile request win over suppression).

## Resolved Location

Replaces the analysis-supplied location on every published finding (FR-001–FR-004, FR-003a).

| Field | Type | Rules |
|-------|------|-------|
| `tier` | `symbol` \| `file` | `symbol` where the language is parsed; `file` otherwise |
| `line_start`, `line_end` | integer | authoritative from the code model at `symbol` tier; verified within file bounds at `file` tier |
| `symbol_confirmed` | bool | `false` at `file` tier even when a symbol name was reported (Edge Cases) |
| `alternatives_existed` | bool | set when the symbol name was ambiguous (FR-004) |
| `chosen_by` | string | the deterministic tie-break applied when `alternatives_existed` |

**Lifecycle**: `reported → resolved(symbol|file) → rejected`. Rejection is terminal and carries a
reason; a rejected finding never reaches the report (FR-003). `file` tier is a **positive** result and
must not be rendered as an unresolved location (FR-003b).

**Ordering constraint**: resolution completes before deduplication, so findings differing only in
guessed line numbers collapse (FR-007). Ranking and deduplication must remain well defined across
mixed tiers within one scan (Edge Cases).

## Framework Control Evaluation

Per finding, the state of the framework default protection relevant to its weakness class
(FR-021–FR-022d).

| Field | Type | Rules |
|-------|------|-------|
| `state` | `credited` \| `bypassed` \| `absent` \| `unassessed` | `absent` is a determined state; `unassessed` is not (Edge Cases) |
| `control` | string | the control's identifier in the shipped catalogue |
| `bypass_site` | Location | required when `state` = `bypassed`; must lie on the traced path to this sink (FR-022) |
| `unassessed_reason` | string | required when `state` = `unassessed`: unrecognized framework, or an unparsed file on the path |

**Invariants**: `credited` requires that every file class on the traced path was parsed (FR-022a).
`unassessed` never inflates severity and always caps confidence (FR-022c). A bypass off the traced
path never changes this finding's state — it becomes its own hygiene finding (FR-022b). A target with
no framework yields `absent`, not `unassessed`, and produces no coverage gap.

## Calibration Record

Why a finding's published severity and confidence differ from what analysis proposed (FR-020).

Fields: `proposed_severity`, `proposed_confidence`, `published_severity`, `published_confidence`,
`caps_applied[]` (each with `rule` and `reason`).

**Invariant**: after calibration, no `plausible` finding with unconfirmed reachability outranks any
`verified` finding (FR-020). The record is always rendered when non-empty, so a reader can see that a
cap was applied and why.

## Reproduction (extended)

`observed_behavior` becomes conditional (FR-008–FR-011). The block gains:

| Field | Type | Rules |
|-------|------|-------|
| `mode` | `observed` \| `hypothesis` | `observed` permitted only when verification is `verified` |
| `outcome_to_check` | string | replaces `observed_behavior` when `mode` = `hypothesis` |
| `trigger_omitted_reason` | string | required when no achievable probe exists (FR-010) |
| `traced_trail` | string[] | traced-path nodes only (FR-005); omitted when no path was traced |

**Invariants**: `trigger` is present only when a probe with an achievable success criterion was
derived, judged against the sink's value-construction shape (FR-009). The previous single
`evidence_trail` field is **deprecated, retained, and no longer populated** — see
`contracts/schema-deltas.md` for why it is kept rather than removed; `traced_trail` replaces it with a
strictly narrower guarantee. Supporting evidence stays in `evidence` and is never rendered with
dataflow notation (FR-006). Existing safety constraints are unchanged (FR-012).

## Dependency Advisory

A known-vulnerable component finding (FR-030–FR-035).

| Field | Type | Rules |
|-------|------|-------|
| `package`, `ecosystem` | string | ecosystem from the shipped stack descriptors |
| `affected_range`, `fixed_version` | string | `fixed_version` may be absent (no fix published) |
| `advisory_ids` | string[] | CVE/GHSA/OSV ids, sorted |
| `exposure` | `runtime` \| `development` | runtime ranks above development (FR-032) |
| `affected_members` | string[] | every member the advisory affects (FR-030b) |
| `attribution` | `per-member` \| `workspace-not-derivable` | FR-030e/FR-030f |
| `version_ambiguous` | bool | set when a manifest has no lockfile (FR-035) |
| `audit_source` | string | the adapter and capability class that produced it |

**Identity**: grouped by (`ecosystem`, `package`, `affected_range`) so one advisory yields one finding
across members (FR-030b). Grouping happens after normalization, so the same advisory arriving from a
native adapter and from an installed external scanner merges rather than double-reporting.

## Audit Outcome

Per member and ecosystem, the tri-state result that keeps FR-033 honest.

Fields: `member`, `ecosystem`, `status` (`advisories` \| `clean` \| `could-not-check`),
`reason` (required for `could-not-check`), `remediation_command` (the exact command an operator should
run), `tool`, `tool_version`.

**Invariant**: a non-zero exit, a missing toolchain, or an unreachable advisory source maps to
`could-not-check` — never to `clean` (FR-033, Edge Cases). Availability is recorded per member so a
partially audited workspace is never presented as fully audited (FR-030c).

## Coverage Statement (extended)

Per file class, what the code model represented (FR-027, FR-029).

Fields: `file_class` (`source`, `template`, `dependency-manifest`, `deploy-config`, `datastore-rules`,
`client-cache-config`), `represented` (int), `unparsed[]` (`{path, format, reason}`),
`not_attempted[]`, `remediation_command?`.

**Invariant**: every enumerated security-relevant file is in exactly one of `represented`, `unparsed`,
or `not_attempted`. Silent exclusion is a contract violation, not a missing field (FR-027).

## Redaction Decision (extended)

The redactor's `SecretHit` gains `decision` (`redacted` \| `blocked` \| `exempt-identifier`) and, for
exemptions, `identifier_shape` (`camelCase` \| `PascalCase` \| `snake_case` \| `kebab-case` \|
`module-path`) plus the decomposed segment count.

**Invariants**: exemption requires both identifier shape and the absence of credential context on the
line (FR-036). Recall is preserved absolutely — no exemption rule may cause a seeded credential to go
undetected (FR-037). Blocked values that become coverage gaps carry file, line, and reason (FR-038).
Fully deterministic and offline (FR-039).

## Code Graph (extended)

- **Node `type`** gains `template` and `config`. Config and unparsed-language nodes exist at **file
  granularity only**, which is what gives FR-003's file tier something to resolve against (FR-003c).
- **Node `annotations`** gain `template_sink`, `framework_control`, `control_bypass`.
- **Node** gains `parsed` (bool) and `format` (string) so the coverage statement is derivable from
  the graph rather than recomputed.
- **Edge `type`** gains `renders` (code → template binding), linking a template sink back to the code
  supplying the bound value (FR-025).

## Accuracy Benchmark Case

The regression fixture entity (FR-043–FR-043b).

Fields: `case_id`, `kind` (`reviewed-real` \| `seeded-workspace`), `target`, `expectations[]` (each
with `defect_class`, `assertion`, `baseline`), `source_of_truth` (the independent review, or the
fixture generator's declared ground truth).

**Invariant**: assertions are per defect class, so a regression in one class fails the check without
being masked by improvements in another (FR-043b).

## Finding (extended)

The Finding entity from feature 001 gains, all optional and additive:
`location.tier`, `location.symbol_confirmed`, `location.alternatives_existed`, `reclassification`,
`applicability`, `framework_control`, `calibration`, `dependency` (the Dependency Advisory payload
when `source` = `dependency-audit`), and `reproduction.mode` / `outcome_to_check` /
`trigger_omitted_reason` / `traced_trail`.

`source` gains the value `dependency-audit` alongside `analysis` and `scanner-ingest`.

**Lifecycle (revised)**: `local → resolved → reclassified? → correlated → verified → calibrated →
reported` (or `rejected` with a reason). The added states are all deterministic transitions; none
involves a model.
