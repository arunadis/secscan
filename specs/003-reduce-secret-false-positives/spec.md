# Feature Specification: Reduce Hard-Coded-Credential False Positives

**Feature Branch**: `003-reduce-secret-false-positives`

**Created**: 2026-08-31

**Status**: Draft

**Input**: User description: "The scanner identified false positives — e.g. SEC-0085, a CWE-798 'Use of Hard-coded Credentials' finding with confidence 0.95 and status 'verified' at TokenCostBreakdownBuilderUtil.java:22, where the 'secret' is only the camelCase field name `openaiModelInputTokenCostGpt51ChatLatest` (a `@Value`-injected pricing Double). The deterministic detector flags any 24+ char run with entropy > 4.0 on a line containing a credential-context word — and the substring 'Token' inside the identifier itself satisfies that context check. The deterministic secret-findings stage then emits a CWE-798 finding independently of the analysis verdict. Sibling findings (UI message constants like INVALID_PASSWORD, login-page identifiers) are the same artifact. What can be done to reduce these false positives?"

## Clarifications

### Session 2026-08-31

- Q: Should the missed-detection work (false negatives found by comparing against another scanner's report on the same repository — GraphQL depth DoS, seed-data shared password, CORS wildcard / CSRF disable, `marked@1.1.1` ReDoS CVEs) join spec 003, or should spec 003 stay precision-only with missed detections specified separately? → A: Keep 003 precision-only; missed detections become a separate feature. Root causes differ (segment-local reasoning, redaction-blocked segments, missing deterministic config/dependency checks vs. detection-rule precision), as do the constitutional risks (Principles II and III vs. III only).
- Q: How should the scanner treat credential-shaped literals found in test code, such as a fake signing secret in a unit test? → A: Report them at reduced severity and confidence, explicitly noting the test-code context — never suppressed (a committed credential is a real exposure if it is ever a live value, and recall takes precedence), but calibrated so reviewers can distinguish fixture credentials from production ones at a glance.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Identifiers are not reported as credentials (Priority: P1)

A security engineer reviewing the scan report sees a High-severity "hard-coded credential" finding, opens the file, and finds only a declared field name such as `openaiModelInputTokenCostGpt51ChatLatest` — an identifier, not a value. The detector matched it because the identifier is long, has entropy just above threshold, and contains the substring "Token", which the context check treats as credential context. The engineer loses trust in the report: a "verified, 0.95 confidence" finding that is visibly not a credential undermines every genuine finding next to it.

The scanner must distinguish credential *values* from source-code *identifiers that merely mention credential words*. A declared name — a field, variable, constant, function, module, or path segment — is never itself a credential, even when it contains "token", "key", "password", or "secret".

**Why this priority**: This is the defect the user reported, and it is the largest single source of false positives in the CWE-798 cluster (SEC-0085's "17 occurrences" are all identifier names; SEC-0091/0092/0093 are the same artifact). Until identifier noise is gone, reviewers cannot trust any credential finding.

**Independent Test**: Run the scanner over a source file containing only identifier declarations whose names embed credential words (e.g. a pricing-config class with `openaiModel*TokenCost*` fields) and confirm zero credential findings are published, while a seeded real credential in the same file is still detected.

**Acceptance Scenarios**:

1. **Given** a source file declaring `private Double openaiModelInputTokenCostGpt51ChatLatest;` (an injected config value, not a literal), **When** the scan runs, **Then** no hard-coded-credential finding is published for that file.
2. **Given** a source file whose constant names embed credential words (e.g. a UI message constant `INVALID_PASSWORD`), **When** the scan runs, **Then** no credential finding is published for those names.
3. **Given** the same files also contain a genuine credential literal assigned to a variable, **When** the scan runs, **Then** that credential is still detected and reported — recall is unchanged.
4. **Given** a suppression decision was made, **When** the scan artifacts are inspected, **Then** each suppressed match is recorded with file, line, and reason — suppression is auditable, never silent.

---

### User Story 2 - Heuristic detections carry honest confidence (Priority: P2)

A reviewer reads two findings side by side: one matching a known credential format (e.g. an AWS access key pattern), and one produced only by a statistical heuristic (a long high-entropy string near a credential word). Both are labelled 0.95 confidence and "verified". The reviewer cannot calibrate: the heuristic match is an educated guess, yet it is presented with the same certainty as a format-confirmed credential.

Findings derived solely from heuristic signals must be presented as heuristic: lower confidence than format-matched credentials, never "verified", and framed as requiring review rather than as a confirmed exposure. An unproven finding must not outrank a proven one.

**Why this priority**: Even after identifier noise is removed, some entropy-heuristic matches will be genuinely ambiguous (e.g. encoded non-secret data). Honest grading keeps residual uncertainty visible without pretending it is proof — this is a direct application of the project's Honest Uncertainty principle.

**Independent Test**: Scan a fixture containing (a) a format-matched credential and (b) an ambiguous high-entropy literal that is not identifier-shaped, and confirm the published confidence and verification status differ in the expected direction.

**Acceptance Scenarios**:

1. **Given** a finding whose only evidence is a statistical heuristic match, **When** the report is generated, **Then** its confidence is strictly lower than that of a format-matched credential finding and it is not marked verified.
2. **Given** a heuristic-only finding, **When** a reviewer reads it, **Then** the description states that the match is heuristic and requires human review, rather than asserting a confirmed exposure.

---

### User Story 3 - False-positive regression guard (Priority: P3)

A maintainer tunes detection rules and has no way to know whether the change re-introduces old false positives or drops real credentials. Detection quality must be asserted, not eyeballed: a maintained corpus of known false positives (identifiers embedding credential words, UI message constants, import specifiers, module paths) must produce zero credential findings, and a seeded credential corpus must retain full recall — both enforced in the build.

**Why this priority**: This is what makes US1 and US2 durable. The project constitution already requires test-first fixtures with deliberate false positives and treats accuracy regressions as release-blocking; this story extends that guarantee to credential-finding precision.

**Independent Test**: Run the detection test suite against the false-positive corpus and the seeded credential corpus; the build fails if either a known false positive is reported or a seeded credential is missed.

**Acceptance Scenarios**:

1. **Given** the maintained false-positive corpus (including the SEC-0085-style identifier cases), **When** the test suite runs, **Then** zero credential findings are produced from it.
2. **Given** the seeded credential corpus, **When** the test suite runs, **Then** every credential is still detected — 100% recall, asserted in the build.
3. **Given** a future change that would re-introduce an identifier false positive or drop a real credential, **When** the build runs, **Then** it fails.

---

### Edge Cases

- **Readable passphrase as a real credential**: a value assigned to a credential-named key that happens to be human-readable (e.g. `password = "correct horse battery staple style"`) MUST still be reported. Credential context supplied by an *assignment* or *key name* overrides any identifier-shaped readability of the value — recall always wins.
- **Credential-named config key with a literal value** (e.g. `"apiKey": "..."` in structured data): MUST still be reported; the key naming a credential is genuine context, unlike a substring inside a matched identifier.
- **Ambiguous non-identifier literal**: a high-entropy literal that is neither identifier-shaped nor format-matched (e.g. encoded non-secret data) is neither suppressed silently nor published as a confirmed credential — it is recorded as requiring review with honest (reduced) confidence.
- **Grouped occurrences**: repeated matches of the same kind in one file (the "17 occurrences" pattern) remain a single finding; suppression applies per match and is recorded per match.
- **Known credential format inside an identifier-like context**: a format-matched credential (e.g. an AWS key pattern) is reported wherever it appears — format match is definitive and bypasses all precision gates.

## Requirements *(mandatory)*

### Functional Requirements

**Detection precision**

- **FR-001**: The system MUST NOT publish a hard-coded-credential finding when the matched value is a source-code identifier — a declared field, variable, constant, function, module, or path name — regardless of credential-related words embedded in the identifier.
- **FR-002**: The system MUST NOT publish a hard-coded-credential finding when the matched value is a human-readable message string (UI text, error message, label) rather than credential material.
- **FR-003**: Credential-context detection MUST be based on the structural role of the match — a value assigned to, or associated with, a credential-named key — and MUST NOT treat a credential-related substring inside the matched value itself as credential context.
- **FR-004**: Every suppression decision MUST be recorded in the scan artifacts with file, line, matched rule, and reason, so precision improvements are auditable rather than silent.

**Recall preservation (absolute)**

- **FR-005**: Credential-detection recall MUST NOT regress: every credential detectable before this change, and every seeded credential in the test corpus, MUST still be detected and reported.
- **FR-006**: A value assigned to a credential-named key MUST be reported as a credential finding regardless of how readable or identifier-shaped the value is.
- **FR-007**: A match against a known credential format MUST be reported wherever it occurs; precision gates apply only to heuristic matches, never to format matches.

**Honest confidence**

- **FR-008**: Findings whose sole evidence is a heuristic signal MUST carry strictly lower confidence than findings matching a known credential format, and MUST NOT be presented as verified.
- **FR-009**: Heuristic-only findings that cannot be confirmed MUST be presented as requiring human review, with descriptions that state the heuristic basis rather than asserting a confirmed exposure.
- **FR-010**: Credential findings located in test code MUST still be reported — never suppressed — but at reduced severity and confidence, with the test-code context stated explicitly in the finding so reviewers can distinguish fixture credentials from production ones (clarified 2026-08-31).

**Quality gates**

- **FR-011**: A maintained corpus of known false positives — identifiers embedding credential words, UI message constants, import specifiers, module paths — MUST be asserted to produce zero credential findings in the build.
- **FR-012**: The accuracy benchmark MUST measure credential-finding precision as its own defect class; a regression in that class MUST fail the build even if other classes improve.

### Key Entities

- **Detection Decision**: a single match evaluated by the deterministic detector. Attributes: matched rule, location (repo, file, line), classification of the matched text (identifier shape, message string, credential format, ambiguous literal), decision (reported | suppressed | flagged-for-review), and the reason for that decision. Decisions are recorded whether or not they produce a finding.
- **Credential Finding**: an existing report entity; for this feature it gains an honest provenance distinction — format-confirmed vs heuristic-only — reflected in confidence and verification status, plus a code-context distinction (production vs test code) reflected in severity and confidence (clarified 2026-08-31).
- **False-Positive Corpus Entry**: a source sample known not to contain a credential (e.g. the pricing-config identifier case), with the expectation of zero findings and a recorded rationale, versioned alongside the scanner.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Zero hard-coded-credential findings are produced from the maintained false-positive corpus, including the identifier cases behind SEC-0085, SEC-0091, SEC-0092, and SEC-0093.
- **SC-002**: Credential-detection recall remains at 100% on the seeded credential corpus; no credential detectable before this change is lost.
- **SC-003**: On the reference repository scan that produced the reported false positives, confirmed false-positive credential findings are reduced by at least 80% with zero true positives lost.
- **SC-004**: 100% of suppressed heuristic matches are recorded in the scan artifacts with location and reason; suppression is fully auditable.
- **SC-005**: Every published credential finding is traceable to an actual literal value location; no published finding's evidence resolves to a declaration name alone.
- **SC-006**: Reviewer triage burden on credential findings measurably drops: heuristic-only matches are visibly distinguished from format-confirmed credentials in the report, so a reviewer can calibrate trust at a glance.

## Assumptions

- **Out of scope — missed detections (false negatives)**: findings this scanner missed on the same repository (GraphQL depth/complexity DoS, seed-data shared password, CORS wildcard / CSRF disable configuration, and dependency CVEs such as `marked@1.1.1` ReDoS) are NOT addressed by this feature. Their root causes — segment-local reasoning limits, redaction-blocked segments suppressing analysis, and missing deterministic security-config / dependency checks — are specified as a separate feature (clarified 2026-08-31).
- **Recall precedence is absolute** (constitution Principle III): wherever a choice is forced between a false positive and a false negative, over-reporting wins. All precision improvements in this feature must provably keep every known credential detectable.
- **Suppressed matches are recorded, not dropped silently**: consistent with the existing exemption-recording precedent (feature 002, FR-038), suppressed heuristic matches appear in scan artifacts as inspectable decisions rather than as low-confidence findings.
- **Precision must come from the deterministic layer**: because values are redacted before any analysis review, the analysis stage never sees the matched value and therefore cannot veto a deterministic finding. Cross-checking against analysis verdicts is out of scope; discrimination must be deterministic and reproducible.
- **The redaction side benefit is preserved**: redaction must still locate every credential (constitution Principle III makes the detector authoritative precisely because it must find them all). Tightening what becomes a *finding* must not weaken what gets *redacted* — a suppressed finding's value is still removed from context if there is any doubt.
- **Baseline**: the scan outputs referenced in the report (the `skh` workspace scan, scan id `20260831T081536Z-438706`) and its 23 CWE-798 findings serve as the evaluation baseline for SC-003; genuine findings in that set (e.g. default truststore password, hard-coded API-key constant) must survive.
- **Ground-truth audit is part of this feature**: measuring SC-003 requires a one-time manual audit labelling each of the baseline scan's credential findings as true or false positive against the source. That labelled set becomes part of the maintained corpora (must-not-find entries for confirmed false positives; must-find entries for confirmed true positives).
