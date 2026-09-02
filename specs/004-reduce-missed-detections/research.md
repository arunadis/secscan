# Phase 0 Research: Reduce Missed Detections

All unknowns resolved against the shipped implementation via three codebase explorations
(controls/extract, audits, system-review/coverage). No NEEDS CLARIFICATION remains.

## R1 — Misconfiguration detection: pattern rules over raw source, before redaction

**Decision**: A new deterministic stage (`misconfig.py`) evaluates a versioned rule pack
(`misconfig_rules.json`) — glob-selected files + anchored regex patterns — over *raw* source
text, emitting findings with file/line/rule and never copying matched values into artifacts.

**Rationale**: The evidenced misses (`csrf().disable()`, `allowedOrigins("*")` in
`WebSecurityConfig.java:38-40`) are structural method calls, not secrets. The exploration
confirmed no extraction exists today: Spring Security DSL is invisible to `enrichers.py`
(`_AUTH_HINTS`/`_AUTHZ_HINTS` cover annotations, not DSL calls; enrichers.py:144-152), and the
controls catalogue only covers CWE-79 output escaping (framework_controls.json). Matching raw
text makes FR-002 (redaction resilience) true by construction — the check never reads the
redacted/blocked value, only the call shape around it. Rule fields: id, stack, cwe, severity,
file globs, pattern, description, recommendation — validated at load like `controls.py:38-51`.

**Alternatives considered**: (a) tree-sitter semantic extraction of the security DSL — rejected:
a grammar pass still needs per-framework semantic tables, and the evidenced patterns are
syntactically stable one-liners; (b) extending `framework_controls.json` — rejected: that
catalogue models *default controls on traced paths*, not *dangerous config states*; a separate
rule pack keeps both honest.

## R2 — Compound findings: a rule engine on whole-repo structures, pre-correlation

**Decision**: A new deterministic stage (`compound.py` + `compound_rules.json`) runs after
segment analysis completes (run.py:250-258) and before dependency audits, appending raw findings
into `raw_findings` so they flow through normalization, location resolution, verification, and
calibration exactly like every other finding.

**Rationale**: The exploration shows all segment work is complete at run.py:258 with `graph`,
`flows`, `workspace`, `segments`, and warnings available; emitting into `raw_findings` (rather
than post-correlation appends) gives compound findings the FR-4/FR-6 guarantees (resolvable
locations, honest verdicts) for free. Each rule is a set of *evidence legs*; each leg has a
`kind` naming a deterministic whole-repo evaluator and parameters. The leg vocabulary is code
(stable, reviewed); rules binding legs to parameters are data (extensibility-as-data). Leg kinds
needed for the two seed rules: `endpoint-unauthenticated` (route match + no auth annotation,
from endpoint nodes and security-config extraction), `graphql-schema-cycle` (R3),
`config-absent` (deterministic search over enumerated files for any of a pattern set — the
searched space is recorded in evidence per FR-005), `seeded-credential-pattern` (R6),
`public-auth-entrypoint` (login mutation/endpoint without auth annotation).

**Alternatives considered**: (a) post-correlation stage appending finished findings — rejected:
bypasses location resolution and verification, reintroducing the report-quality bugs feature 002
removed; (b) an LLM system-review call — rejected: the deterministic baseline must catch these
without a model (Principle I); the existing `final_review.md` prompt stays agent-mediated.

## R3 — GraphQL schema support: enumeration + line-based fact extraction, no new grammar

**Decision**: Add `.graphql`/`.graphqls` to `state.py:_SOURCE_SUFFIXES` and
`discover_repo.py:LANGUAGE_BY_SUFFIX`; extract schema facts with a line/delimiter pass:
type definitions, field→type references, and cycles in the type-reference graph.

**Rationale**: The constitution pins grammar wheels, and no maintained GraphQL wheel is a
current dependency — adding one is a build-environment change for marginal gain: the depth-DoS
leg needs only the type-reference graph (Article→comments→Comment→article→…), which is regular
enough for a delimiter pass. The file is enumerated as an unparsed file node (like `.sql`), so it
is segment-assigned and coverage-visible.

**Alternatives considered**: tree-sitter-graphql — rejected (new pinned dependency for one leg
kind); model-side reasoning over the schema — rejected (Principle I; also the schema never
reached a segment at all — the root cause of the miss).

## R4 — Dependency advisories: bundled per-ecosystem snapshots as the offline baseline

**Decision**: Ship `advisories/<ecosystem>.json` (OSV-derived shape: package → introduced/fixed/
ids/severity/summary — the shape `audits/java.py:53-79` already expects), parsed against
manifests/lockfiles deterministically and offline. Native tools (npm audit, pip-audit,
govulncheck) remain as augmentation when available; the bundled match is the always-on default.
Fix the dedupe collapse: dependency findings carry `location.symbol = <package>` so distinct
packages in one manifest no longer merge (normalize_findings.py:283-311 keys on location).

**Rationale**: The exploration found *no* bundled advisory data exists — even
`maven_advisories.json` (referenced by java.py:35) is absent, so Java always falls to
could-not-check, and npm/PyPI/Go depend on network-bound tools that fail offline. That is why
`marked@1.1.1`'s ReDoS CVEs never became a finding. The snapshot follows the established
eol.json convention: `version`, `dataset_date`, `source`, `staleness_threshold_days`, manual
refresh instructions (scan_cli.py:151-158 precedent). Initial content is curated for the
reference repositories' dependency trees plus fixture needs; FR-008's could-not-check honesty
applies to ecosystems whose snapshot is stale beyond threshold.

**Alternatives considered**: (a) wrapping osv-scanner offline — rejected: new binary dependency,
needs a downloaded DB (violates no-downloads constraint); (b) native-tools-only — rejected:
offline default path is constitutional; (c) full OSV dump — rejected: hundreds of MB; curated
subset + documented refresh is honest about coverage.

## R5 — Coverage gaps: structured, additive `gap_details` with impact ranking

**Decision**: Keep the legacy `coverage.gaps` string array (schema compatibility) and add an
additive `coverage.gap_details` array: `{cause: blocked-value | budget-dropped | unparsed-format,
file, segment_id, security_critical: bool, impact}`. The Markdown report renders critical gaps
first, and also renders `audit_outcomes`/`blocking_gaps` (a rendering gap the exploration found:
they are in JSON but never printed).

**Rationale**: `build_context.py` already knows each gap's cause (warnings at :134-139 for
budget, redaction warnings for blocked); the change is threading structured records through
instead of flat strings. Security-criticality is deterministic: the file carries security
annotations, is a config/datastore-rules file class, or matches security-config path
conventions (the same globs as misconfig rules — one definition, data-driven). Breaking the
`gaps` string array would force a schema_version bump; additive `gap_details` avoids it
(constitution: additive schemas).

**Alternatives considered**: replacing `gaps` with structured objects — rejected (breaking
schema change for zero reader benefit); leaving strings but sorting — rejected: no impact
assessment, which is FR-010's core.

## R6 — Seeded-credential detection: deterministic pattern over migration files

**Decision**: A leg/evaluator scans `.sql` (and seed-fixture) raw text for account-provisioning
patterns — `INSERT INTO <user-table>` plus a password hash/placeholder plus a comment or literal
documenting the shared password — and records the match location without the value; the value is
redacted by the existing redactor on any packet path, and the compound finding carries no
secret (Principle III, same guarantee as `secret_findings.py`).

**Rationale**: `.sql` files are enumerated but unparsed (build_code_graph.py:134-150), so the
content is available on disk but invisible to the graph — a targeted raw-text pass is the
deterministic answer. The "documented password" signal (a comment naming the shared password
beside bcrypt inserts) is a stable textual pattern in seed migrations.

**Alternatives considered**: parsing SQL with a grammar — rejected (no grammar wheel; the
pattern is textual); reporting each seeded account separately — rejected: one finding per
migration file, occurrences counted (secret_findings precedent).
