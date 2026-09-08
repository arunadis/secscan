# Phase 0 Research — Outcome-Quality Hardening (feature 017)

All decisions settled; the approved Devin plan file carries the rationale. Resolved items:

## R1 — Presence-verified class catalogue (FR-001)

**Decision.** The class membership list becomes a module-level constant
`PRESENCE_VALID_CWES` in `verify.py`, composed from the existing hard-coded config/
secret set plus the identity pack's `no_refute_cwes()` (the pack already declares
its members as presence-valid — clarify 016 Q2). Reachability-sensitive members
(`CWE-306`, `CWE-290`) demote under the active gap (016 FR-009) via a
`_REACHABILITY_SENSITIVE_PRESENCE` constant.

**Rationale.** Single point of truth; pack extension automatically extends the
grade contract. Alternative (schema listing) rejected: verdict semantics belong to
the stage, not data validation.

## R2 — Version-aware resume keys (FR-002)

**Decision.** `build_code_graph`'s resume key becomes
`{file_hashes, tool: TOOL_VERSION, extractor: EXTRACTOR_VERSION, rules: {redactor,
identity pack, cwe dataset versions}}`. `EXTRACTOR_VERSION` bumps when enrichers' /
graph-builder recognition changes. `partition_repo` auto-follows (graph-hash key).

**Rationale.** Directly closes the observed failure path: "upgraded tool reused a
stale graph". Content-only keys are identical across tool versions — violating the
constitution's framing of identical *tool version* by construction.

## R3 — Provenance visibility of deterministic findings (FR-003)

**Decision.** Fix at the normalizer: deterministic-pack fields (`detection`,
`tool_ref`, `code_context`) MUST traverse `FindingNormalizer.normalize` intact for
`source="analysis"` deterministic records. Dedup/correlate unchanged (distinct
keys by `tool_ref`).

**Rationale.** The schema admits the fields; invisible dropping at normalization
would defeat the pack's auditability guarantee. Diagnosis precedes fix (test-first
reproduction task).

## R4 — Family grouping (FR-004)

**Decision.** Family key = the shared attacker-controlled *channel literal* (the
identity header/cookie name) extracted from member function-documented evidence
texts and guarded by graph annotations (`authentication_required` adjacency) and/or
pack provenance. Anchor = the finding located at the trust-decision symbol (rule:
finding whose location symbol carries `authentication_required` or pack origin);
others link `dependent`. Rendering: anchor full block; dependents one-line
references with distinct evidence retained within each own entry.

**Alternatives.** CWE-level merge (too coarse — `_link_systemic` already does that
and produces duplication rather than presentation), full cluster analysis (not
stable-scope).

## R5 — Coverage dedupe (FR-006) and tool-limitation accuracy (FR-007)

**Decision.** Warning text carries level information only in the per-escalation
progress warnings; the report-facing coverage list dedupes on
`(segment, file-set, cause)` after stripping the level token. Tool-limitation
reasons for npm-audit re-derive against the member's manifest file list so a
budget-dropped lockfile is presented as "present but outside analysis scope".

## R6 — Question batching (FR-008)

**Decision.** Report groups by normalized question text; declarations store
unchanged shape (they bind question+finding already), application fans out.

## Constitution check preview

I (determinism): all changes deterministic or cache-aware. III: no secret-bearing
text anywhere new. IV: provenance never erased. V: unknown never suppressed —
batching changes presentation only, not finding fate. VI: read-only.
