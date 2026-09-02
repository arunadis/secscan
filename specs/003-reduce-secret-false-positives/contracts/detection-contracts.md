# Contract: Credential Detection Precision

Contracts asserted by tests. Each maps to spec requirements; a failure of any is a build failure.

## C1 — Credential context is structural (FR-003)

For any candidate match `m` on line `L`, credential context is evaluated against `L` with the
span of `m` masked out. Substrings inside `m` never create context.

- MUST: `private Double openaiModelInputTokenCostGpt51ChatLatest;` produces no hit.
- MUST: `String apiKey = "<24+ char high-entropy value>";` produces a hit (the key name `apiKey`
  survives masking).
- MUST: evaluation is a pure function of (text, position) — byte-identical across runs.

## C2 — Identifier and message-string exemption (FR-001, FR-002)

A heuristic (entropy-path) candidate is exempted only when **all** hold:

1. its shape classifies as `identifier` (existing shape gate) or `message-string`
   (natural-language literal: spaces + multiple words or sentence punctuation), and
2. the masked line carries no credential context (C1), and
3. it is not assigned to a credential-named key (FR-006 takes precedence), and
4. it did not match a rule-pack format pattern (FR-007 takes precedence).

Every exemption is recorded as a Detection Decision with classification and reason (FR-004).

## C3 — Recall floor (FR-005, FR-006, FR-007)

- Every entry of the seeded credential corpus is detected — 100% recall, asserted per entry.
- `password = "<readable multi-word passphrase>"` is detected (credential-named assignment beats
  readability).
- Every rule-pack label (`aws-access-key`, `github-token`, `private-key-block`, …) fires
  identically before and after this feature, verified by the pre-existing redaction tests
  remaining green unmodified in expectation.

## C4 — Honest confidence and verification (FR-008, FR-009, FR-010)

The gradings below apply **at emission** (the deterministic secret stage). The
calibration stage may cap the *published* confidence afterwards under its own
rules (e.g. unassessed framework control, unconfirmed reachability); C4's
ordering is an emission-level contract, and integration assertions read
`calibration.proposed_confidence` when a cap was applied.

- `detection == "heuristic"` findings: confidence strictly below the `format` class;
  `verification.status` is never `verified`.
- `detection == "format"` findings: confidence and auto-verify behavior unchanged.
- `code_context == "test"` findings: reported (never suppressed), with confidence **and severity** strictly below the same detection class in production code (FR-010), description names the test-code context.
- Heuristic-only descriptions state the heuristic basis ("possible credential — review
  required") rather than asserting exposure.

## C5 — Schema additivity

- `finding` artifacts gain only the optional fields `detection` and `code_context`; no existing
  field changes type or meaning; `schema_version` is unchanged.
- The artifact redaction sweep passes over every artifact containing the new fields — no
  credential value appears anywhere, including in Detection Decision records in published
  artifacts.

## C6 — Benchmark gate (FR-011, FR-012)

- The false-positive corpus produces zero credential findings.
- The benchmark asserts the credential-precision defect class; a regression in that class fails
  the build regardless of other classes.
- The audited baseline (23 labelled CWE-798 findings from scan `20260831T081536Z-438706`) is
  asserted entry by entry: confirmed false positives are no longer reported; confirmed true
  positives still are.
