# Contract: Missed-Detection Reduction

Contracts asserted by tests; any failure fails the build. Rule/data citations refer to
`data-model.md`; research decisions as R1–R6 from `research.md`.

## D1 — Misconfiguration rules (US1; FR-001, FR-002, FR-003)

- Every rule in `misconfig_rules.json` MUST fire on its must-find fixture and MUST NOT fire on
  its must-not-find fixture; both fixtures ship with the rule.
- Evaluation MUST run over raw source text (R1): a redaction-blocked value elsewhere in the
  same file MUST NOT change whether a rule fires (FR-002). Asserted by a fixture whose
  security config also contains an unclassifiable high-entropy value.
- Matched text MUST NOT be copied into findings or artifacts; findings carry file, line, and
  rule id only (the artifact redaction sweep still passes).
- Adding a rule MUST be a data-only change: no pipeline module is edited to add one (FR-003).
- The evidenced cases MUST fire: `csrf().disable()` and `allowedOrigins("*")` in a Spring
  security config produce CWE-352 and CWE-942 findings with exact locations.

## D2 — Compound rules (US2; FR-004, FR-005, FR-006)

- A compound finding publishes only when every leg is `evidenced` or `absent-proven`; each leg's
  evidence carries resolvable locations, and an `absent-proven` leg records the exact search
  space (file set + patterns) in the finding's evidence (FR-005).
- A leg that cannot be evaluated records `undetermined` with the reason; the finding is
  published as `plausible` with the weak leg named — never verified, never suppressed
  (Principle V).
- The `graphql-depth-dos` rule MUST fire on a fixture with a permitAll `/graphql` endpoint, a
  cyclic schema, and no depth-limit config; adding a depth-limit config anywhere in the
  enumerated config space MUST change the leg to evidenced and the finding MUST NOT publish.
- The `seeded-shared-password` rule MUST fire on a fixture migration provisioning loginable
  accounts with a documented shared password plus a public login entrypoint; no password value
  appears in any artifact (Principle III; redaction sweep passes).
- Adding a rule binding existing leg kinds MUST be a data-only change.

## D3 — Dependency advisories (US3; FR-007, FR-008)

- For every ecosystem (npm, maven, pypi, go), a fixture pinning a version inside a bundled
  advisory's range MUST produce a first-class finding naming the advisory ids, affected range,
  pinned version, and manifest location; a version at/above `fixed` MUST NOT.
- The baseline match MUST run fully offline: no native tool is invoked for it; manifests and
  lockfiles are parsed deterministically.
- Distinct vulnerable packages in one manifest MUST produce distinct findings (location.symbol
  carries the package; no dedupe collapse).
- A snapshot older than `staleness_threshold_days` yields could-not-check for that ecosystem
  with the reason named; it MUST NOT read as clean.
- Native-tool audits, when available, augment but never contradict the bundled baseline.

## D4 — Coverage gaps (US4; FR-009, FR-010)

- Every blocked value and budget-dropped file produces a `gap_details` record with cause, file,
  segment, security-criticality, and a concrete impact statement; the legacy `coverage.gaps`
  strings are unchanged.
- Security-critical gaps render before non-critical ones in the Markdown report; audit outcomes
  and blocking gaps render there too.
- A gap in a security-config file states which rule class could not be assessed.
- The report schema change is additive only; existing report consumers are unaffected.

## D5 — Must-find gate (FR-011, FR-012)

- `tests/benchmark/cases/must_find.json` covers every evidenced miss from the reference scans:
  GraphQL depth-DoS, seed-data shared password, CORS wildcard, CSRF disablement, and the
  `marked` ReDoS advisories.
- The benchmark asserts each corpus entry end-to-end on fixtures; a miss fails the build, per
  defect class.
- Feature 003's suites (false-positive corpus, credential recall, credential-precision class)
  MUST pass unchanged — recall expansion never trades against precision (FR-012).
