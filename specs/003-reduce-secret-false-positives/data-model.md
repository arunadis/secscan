# Phase 1 Data Model: Reduce Hard-Coded-Credential False Positives

Entities are additive extensions of existing pipeline artifacts. No existing field changes type
or meaning; per the constitution's additive-schema rule, no `schema_version` bump is required.

## Detection Decision (extends the redactor's decision records)

A single match evaluated by the deterministic detector. Existing records (`redacted`, `blocked`,
`exempted` in `RedactionResult`) persist; the exemption record gains a reason dimension.

| Field | Type | Notes |
|-------|------|-------|
| origin | string (repo-relative path) | existing |
| line | integer ≥ 1 | existing |
| rule | string | NEW — the redactor rule/label that matched (e.g. `high-entropy-secret`, `assigned-secret`), or `entropy-candidate` for exempted entropy matches; required by FR-004 |
| value | string | recorded only in decision logs; never in published artifacts |
| classification | `identifier` \| `message-string` \| `credential-format` \| `ambiguous-literal` | NEW — why the value matched or was exempted |
| decision | `redacted` \| `blocked` \| `exempt-identifier` \| `exempt-message` | extends existing `decision` field (002) with `exempt-message` |
| reason | string | human-readable, cites the matched rule and the structural basis (e.g. "identifier shape camelCase on a declaration line; credential word appeared only inside the identifier") |

**Vocabulary mapping** (spec ↔ this artifact): the spec's finding-level decision terms map to
redactor-level decisions as follows — `reported` ↔ `redacted` (a finding may follow);
`suppressed` ↔ `exempt-identifier` / `exempt-message`; `flagged-for-review` ↔ `blocked`
(published as a coverage warning, not a finding).

**Validation rules**

- A `message-string` or `identifier` exemption is permitted only when the line's credential
  context, computed with the candidate span masked out (research R1), is empty (FR-003).
- A value assigned to a credential-named key is never exempted, regardless of classification
  (FR-006) — the assignment check precedes all exemption logic.
- A rule-pack (format) match is never exempted (FR-007).

## Credential Finding (extends `finding` artifact)

| Field | Type | Notes |
|-------|------|-------|
| detection | `format` \| `heuristic` | NEW — `heuristic` iff the originating redactor label is `high-entropy-secret`; all other built-in labels are `format` |
| code_context | `production` \| `test` | NEW — from deterministic test-path classification (research R5) |
| confidence | number 0–1 | exact emission values: format/production 0.95, heuristic/production 0.6, format/test 0.55, heuristic/test 0.2. These are *emission* values — the calibration stage may cap the published confidence under its own rules; when it does, `calibration.proposed_confidence` holds the emitted value |
| verification.status | `verified` \| `plausible` \| `disproven` | auto-verify shortcut applies only when `detection == "format"` (research R4); heuristic findings take the standard trace path |

**State transition**: none — findings are immutable once emitted; the new fields are set at
emission in `secret_findings.py` and propagated unchanged through normalization and correlation.

**Validation rules**

- `detection == "heuristic"` ⇒ `verification.status != "verified"` (FR-008), enforced by a
  contract test, not by convention.
- `code_context == "test"` ⇒ confidence strictly below the same detection class in production
  code (FR-010), and the description states the test-code context.

## Test-Path Convention (new versioned data)

| Field | Type | Notes |
|-------|------|-------|
| stack | string | e.g. `jvm`, `node`, `python`, `go` |
| patterns | list of glob strings | e.g. `src/test/**`, `**/*.test.*`, `**/*_test.go`, `tests/**` |

Ships alongside the existing stack descriptors; adding a stack's conventions is a data-only
change (constitution: extensibility as data).

## Corpus Entry (extends benchmark fixture data)

| Field | Type | Notes |
|-------|------|-------|
| sample | string (source text) | identifier, message string, or seeded credential |
| expected_findings | integer | 0 for false-positive corpus entries |
| expected_recall | boolean | true for seeded credentials (must be detected) |
| code_context | `production` \| `test` | drives FR-010 assertions |
| rationale | string | e.g. "SEC-0085: camelCase pricing identifier containing 'Token'" |
| source_label | string | for audited baseline entries: the original finding id (SEC-XXXX) and true/false-positive verdict |
