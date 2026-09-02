# Feature Specification: Finding Verification Pass

**Feature Branch**: `006-finding-verification-pass`

**Created**: 2026-09-01

**Status**: Draft

**Input**: User description: "once the report is generated, i did a final round of cross check agains the codebase vs the report and got the following output. can we do a final round of verification to wipe out the falls possitives. here is the output -> [43 findings manually cross-checked: 10 confirmed, 11 partially confirmed (real but mitigated/dev-only), 22 refuted — including the only Critical finding, which was a runtime-constructed connection string matched by shape, not a committed value; remaining false positives were secret-heuristic matches on runtime-built values, minted tokens, env reads, random-UUID lines, and 14 test fixtures]"

## Clarifications

### Session 2026-09-01

- Q: How should the verification stage itself be proven correct, so it wipes out false positives without hiding real findings? → A: Manual-review replay only — the previously reviewed 43-finding report (with the recorded manual verdicts as ground truth) is the acceptance test; no new curated fixture corpus is created.
- Q: How should the new verification verdicts relate to the pipeline's existing verified/plausible/disproven states? → A: One unified vocabulary — verification verdicts extend the existing verified/plausible/disproven states (adding mitigated and undetermined), exposed as a single per-finding verdict field via an additive change.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Automatically verify every finding against the codebase before delivery (Priority: P1)

After the report is generated and before it is delivered to the user, the scanner runs a final verification round: every finding in the report is cross-checked against the actual source code it cites. A finding whose claimed evidence does not exist at the cited location, or whose "secret" value is provably constructed at runtime (built from variables, read from the environment, minted by a function call, or generated randomly), is not presented as a real issue. The user receives a report they can trust without repeating the manual cross-check that today takes a full review pass per finding.

**Why this priority**: This is the direct ask. A manual cross-check of a 43-finding report just refuted 22 findings — roughly half the report was noise, including its only Critical finding. Until the scanner performs this verification itself, every report requires the user to redo the scanner's job, which destroys the report's credibility and the user's trust (Principle IV: a claim must be traceable to the code that supports it).

**Independent Test**: Replay the previously manually-reviewed 43-finding report through the verification round, using the recorded manual verdicts (10 confirmed, 11 mitigated, 22 refuted) as ground truth. Verify that the replayed report keeps the manually confirmed findings as confirmed, excludes the manually refuted findings from the findings set with stated reasons, and adjusts mitigated findings consistently with the manual review.

**Acceptance Scenarios**:

1. **Given** a scan that produced a draft report with findings, **When** the verification round runs, **Then** each finding is assigned a verification verdict (confirmed, mitigated, or refuted) with a plain-language rationale tied to the code actually observed at the cited location.
2. **Given** a finding claiming a hard-coded secret, **When** the cited location contains an expression that builds the value at runtime rather than a credential literal, **Then** the finding is refuted and does not appear in the report's confirmed findings.
3. **Given** a finding claiming a hard-coded secret, **When** the cited location reads the value exclusively from an environment variable or generates it at runtime (e.g., an identifier-generation call), **Then** the finding is refuted on the grounds that no value is committed to the repository.
4. **Given** a finding located in test or fixture code whose matched value is an obvious dummy (placeholder prefixes, intentionally invalid samples used to assert rejection), **When** verification runs, **Then** the finding is refuted as a test artifact.
5. **Given** a finding whose weakness is real but whose reach or impact is constrained by an observed control (e.g., an admin-only endpoint, a signature-verified inbound channel, a development-gated code path), **When** verification runs, **Then** the finding is retained with a mitigated verdict and its severity is adjusted to what was actually proven — never inflated by assumption.

---

### User Story 2 - See the verification outcome declared in the report (Priority: P2)

A reviewer opening the report sees not only the confirmed findings but an explicit verification summary: how many findings were checked, how many were confirmed, how many were downgraded because existing controls or context reduced the verified impact, and how many were refuted as false positives — with each refuted or downgraded finding listed along with the reason. Nothing the scanner once suspected disappears silently: refutation is declared, not deletion.

**Why this priority**: Principle V (Honest Uncertainty) forbids silent exclusion: a dropped finding without a declared reason reads as either incompetence or concealment. The manual review the user performed produced exactly such a summary table; making the scanner produce it turns an ad-hoc review artifact into a standard, auditable part of every report.

**Independent Test**: In the replayed 43-finding report, verify the verification account's verdict counts exactly match the per-finding verdicts (expected ground truth: 10 confirmed, 11 mitigated, 22 refuted), and that every refuted or downgraded finding is listed with its rationale.

**Acceptance Scenarios**:

1. **Given** a completed verification round, **When** the report is rendered, **Then** it contains a verification summary with verdict counts that exactly match the per-finding verdicts.
2. **Given** a refuted or downgraded finding, **When** the reader looks it up, **Then** they find the finding identifier, its original claim, its verdict, and the reason (e.g., "value constructed at runtime", "test fixture", "admin-only path") — with a location that resolves against the codebase.
3. **Given** two runs over identical input with identical tooling, **When** the verification summaries are compared, **Then** they are identical.

---

### User Story 3 - Focus remediation effort on genuinely confirmed issues (Priority: P3)

A developer acting on the report can order their work by verified severity and confidence: the genuinely confirmed issues — those whose evidence the verification round re-established from the code — sort ahead of mitigated items, and refuted items never consume remediation time. The report's headline severity profile (counts per severity band) reflects only confirmed findings, so a single refuted Critical can no longer dominate the top line.

**Why this priority**: The manual review ended with a prioritized fix list built from the verdicts. Delivering that prioritization by default is where the verification round converts accuracy into action — but it stands on the shoulders of US1 and US2 and is independently shippable after them.

**Independent Test**: Produce a report where the highest-severity draft finding is refuted during verification. Verify the top-line severity summary no longer includes it, confirmed findings are presented first, and mitigated findings are clearly ranked as lower-risk-than-claimed.

**Acceptance Scenarios**:

1. **Given** a draft report whose highest-severity finding is refuted by verification, **When** the final report is generated, **Then** the severity summary counts only verified findings and the refuted top-severity item appears solely in the verification account with its refutation reason.
2. **Given** a mix of confirmed and mitigated findings, **When** the reader reviews the findings list, **Then** confirmed findings are presented ahead of mitigated ones, and mitigated findings carry their adjusted severity.

---

### Edge Cases

- What happens when verification cannot determine whether a value is a committed literal or a runtime construction (e.g., value assembled across files or through unanalyzed code)? The finding MUST NOT be auto-confirmed or silently refuted — it is retained with an explicit undetermined verification state and a stated reason, and it may not outrank a verified finding.
- What happens when a finding's cited location no longer resolves against the code model? The finding is rejected from the report as unverifiable and declared in the verification account, per the existing location-resolution guarantees.
- What happens when a value matches a credential shape and no runtime construction is observed, but context suggests it is a placeholder (documentation examples, committed defaults)? Verification classifies the context (test fixture, example file, development-only configuration) and records it — a match in such context is reported at reduced severity or refuted with the context as the stated reason, and never promoted.
- What happens when verification would reduce detection of a genuinely committed credential? Recall takes absolute precedence: no verification behavior may suppress a real committed credential to reduce false positives; a refutation requires positive evidence of runtime construction or fixture context, not the mere absence of certainty.
- How does verification treat partial matches (real code, real weakness, but observed mitigations)? It keeps the finding, adjusts severity to what was proven, and records the observed control as evidence — presence of a control is proven only when observed.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The scanner MUST run a verification round over every finding after the report payload is assembled and before any report artifact is written.
- **FR-002**: The verification round MUST re-confirm, for each finding, that the claimed evidence exists at the cited file, symbol, and line location as resolved against the code model; a finding whose claimed evidence does not materialize MUST be refuted with "location/evidence mismatch" as the reason.
- **FR-003**: For findings claiming a committed secret or credential, verification MUST determine whether the flagged value is a literal in the source or is constructed at runtime (string interpolation from variables, environment-variable reads, tokens returned by a function or service call, generated identifiers); only a genuine committed literal may be confirmed as a hard-coded-secret finding.
- **FR-004**: Refutation MUST require positive evidence (runtime construction, environment-only sourcing, fixture/dummy value, location mismatch). Mere inability to confirm MUST produce an explicit undetermined state — never a refutation, and never a promotion.
- **FR-005**: Verification MUST classify finding context (production code, test or fixture code, documentation or example files, development-only configuration) and MUST NOT report test-fixture dummy values as real findings.
- **FR-006**: When verification observes an existing control, gate, or context that constrains a finding's impact (authorization gate, signature verification, development-only profile, admin-only access), the finding MUST be retained with severity adjusted to what was proven, and the observed constraint recorded as rationale.
- **FR-007**: Every verified finding MUST carry a single per-finding verdict drawn from one unified vocabulary that extends the pipeline's existing verified/plausible/disproven states additively — mapping confirmed to `verified`, mitigated to a new `mitigated` state, refuted to `disproven`, and undetermined to a new `undetermined` state — plus a plain-language rationale that cites the code evidence the verdict rests on.
- **FR-008**: The report MUST present confirmed and mitigated findings as its main finding set, ordered so that confirmed findings precede mitigated ones; refuted findings MUST NOT appear in the severity summary or findings list.
- **FR-009**: The report MUST contain a verification account listing every refuted, downgraded, unverifiable, and undetermined finding with its original claim, verdict, and rationale, plus verdict counts that reconcile exactly with the per-finding verdicts.
- **FR-010**: The verification round MUST be deterministic: identical input and identical tool version MUST produce byte-identical verdicts, rationales, and summaries.
- **FR-011**: The verification round MUST be read-only and static — no code execution, no network access, no mutation of the scanned project — consistent with the observe-never-attack invariant.
- **FR-012**: No verification behavior may suppress a genuinely committed credential finding; any tuning toward lower false-positive rates MUST be accompanied by fixtures asserting that real-credential detection recall is unchanged.
- **FR-013**: Acceptance of the verification round MUST be demonstrated by replaying the previously manually-reviewed 43-finding report, comparing each produced verdict against the recorded manual verdict for that finding; no new curated fixture repository is created for this purpose.

### Key Entities

- **Finding Verdict**: The outcome of verifying one finding, held in a single per-finding field that extends the pipeline's existing verified/plausible/disproven vocabulary: confirmed (`verified`), mitigated (real but lower verified impact), refuted (`disproven` — false positive, with reason), or undetermined (could not be established, with reason) — attached to the finding with its rationale.
- **Verification Account**: The per-report record of the verification round: total findings checked, counts per verdict, and the list of non-confirmed findings with original claim, verdict, and reason.
- **Verification Context**: The classification of where a finding's evidence lives — production code, test/fixture, documentation/example, or development-only configuration — used to calibrate verdicts and severity.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On a manual cross-check modeled on the user's review, at least 95% of findings presented as confirmed in the final report re-verify as real issues against the source code (versus roughly 50% in the unverified report).
- **SC-002**: 100% of findings whose claimed secret value is constructed at runtime, sourced only from the environment, randomly generated, or located in test fixtures are absent from the confirmed findings and appear in the verification account with a stated reason.
- **SC-003**: The severity summary of the final report contains zero findings later refuted on manual review — a refuted Critical can never headline the report again.
- **SC-004**: Detection of genuinely committed credentials in the accuracy benchmark is unchanged (zero recall regression) after the verification round is introduced.
- **SC-005**: Users can identify the prioritized list of genuinely confirmed issues within one minute of opening the report, without performing any manual cross-check.
- **SC-006**: Two scans over identical input produce byte-identical verification accounts and reports.
- **SC-007**: On the acceptance replay, all 10 manually confirmed findings remain confirmed (zero recall loss), and every one of the 22 manually refuted findings is excluded from the findings set with a stated reason; mitigated findings carry severities no higher than the manual review established.

## Assumptions

- The verification round operates on the scanner's existing code model and evidence artifacts; it does not introduce dynamic analysis or any form of execution, in line with the project's observe-never-attack invariant.
- "Wiping out false positives" means removing refuted findings from the report's finding set and severity summary while declaring them — with reasons — in the verification account; nothing is dropped silently (Principle V).
- Deterministic checks (location re-resolution, literal-vs-runtime-construction detection, fixture-context classification) are the primary verification mechanism; where model reasoning participates, its output is constrained by the shipped schema and bounded evidence, consistent with existing pipeline discipline.
- A unified verdict vocabulary (extending the existing verified/plausible/disproven states with mitigated and undetermined) satisfies the report's audience; no free-form grading and no second, parallel verdict field are required. Schema changes remain additive.
- The user's manual review of the 43-finding report is representative of current noise sources: runtime-constructed connection strings, environment-only tokens, minted tokens, generated identifiers, and test-fixture dummies dominate the false positives.
