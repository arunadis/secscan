# Feature Specification: Finding Triage Reasoning Round

**Feature Branch**: `013-finding-triage`

**Created**: 2026-09-04

**Status**: Draft

**Input**: User description: "Based on a post-reasoning analysis of scan report 20260903T042832Z-c63749 (45 findings: 8 real, 21 false positives, 16 context-dependent), add a finding-triage reasoning round: after findings are correlated, hand them back to the reasoning layer so the agent/model can verify each finding against the codebase — refuting false positives with evidence, downgrading over-graded ones, and flagging context-dependent ones with a concrete question for the user, instead of leaving all of that to a manual reviewer."

## Problem Statement

A recent scan report (scan `20260903T042832Z-c63749`, 45 findings: 1 Critical, 12 High,
32 Medium) was manually audited against the codebase. The audit confirmed 8 real findings
and identified 21 false positives and 16 context-dependent findings. Three observations
matter for this feature:

1. **The recall-first design is working as intended, but the cost lands on the reviewer.**
   The scanner deliberately over-reports (recall takes absolute precedence over precision),
   but every hedge then becomes a human's job. In this report, roughly 80% of findings
   required human dismiss-or-act judgment, and the headline ("1 Critical, 12 High")
   materially overstated the actual risk.
2. **The largest false-positive class is disprovable from code the original reasoning never
   saw.** A controller flagged for missing authorization was protected by a filter
   registered in a security-configuration file; a bundle-integrity finding was contradicted
   by checksum verification in another module; an SSRF finding was refuted by a URL
   validation helper with a host allowlist. These are *search* problems: the mitigating
   evidence exists in the repository, but segment-local reasoning never received it.
3. **A second class is genuinely context-dependent and can only be resolved by the user.**
   Dev-only tokens, throwaway E2E database passwords, and static bearer credentials used
   exclusively against localhost are real patterns whose risk depends on deployment facts
   the scanner cannot see. For these the valuable output is not a verdict but a precise
   question ("is this value ever used outside localhost dev-auth?") the user can answer.

Today the reasoning layer is consulted only to *produce* findings (segment analysis) and to
*add* cross-boundary findings (system review). Nothing asks reasoning to re-examine the
findings it helped produce — detection evidence and mitigating controls never meet. This
feature adds that missing pass: a triage round in which findings are handed back to the
reasoning layer with bounded context, verdicts are constrained to a closed set, and any
verdict that changes a finding must cite evidence the deterministic pipeline re-verifies
against the code model before it takes effect.

## Clarifications

### Session 2026-09-04

- Q: Should credential-value legitimacy (is this literal a real secret or a shaped fake?)
  join the triage round? → A: No. The reasoning layer never sees a matched credential value
  (layered redaction runs before any context packet), so it cannot and must not judge
  values. Value-shape and fixture-precision work stays with the deterministic detector
  improvements specified in feature 003. Triage may reason about *context* (file kind,
  surrounding code, referenced configuration) — never about values.
- Q: In agent-mediated mode, may the triage reasoner consult the raw repository directly,
  beyond the redacted context packet? → A: Hybrid answer keyed to the redactor's own
  per-file verdicts. Reasoning over the redacted context packet is the default in every
  execution mode. In agent-mediated mode the reasoner MAY additionally consult repository
  files directly — but only files the deterministic redactor classified as containing zero
  redaction hits (the redactor already enumerates every file while building the code model,
  so this set is known exactly, offline). A file with any redaction hit is consultable only
  through its redacted excerpt. No constitution amendment is required: secret values still
  never reach a model, and the boundary is enforced deterministically rather than by
  instruction to the agent.
- Q: Does triage reasoning happen at each level of the analysis hierarchy (per segment and
  escalation level), or once on the finalized findings before the report? → A: A single
  round, on the finalized finding set — after normalization, verification, and correlation,
  before report generation. The escalation ladder is unchanged and produces findings only;
  triage never runs inside it. Rationale: only the finalized stage has the deduplicated
  finding set, traced verification paths, candidate cross-segment control locations, and
  calibrated grading that a verdict (and its deterministic re-verification) depends on —
  and it costs one reasoning pass per candidate finding, not one per finding per level.
- Q: How does the user's answer to a flagged finding's question (e.g. "is this token ever
  used outside localhost?") get back into the scan results? → A: As a persisted
  user-declared answer, applied on the next scan — never interactively mid-scan. The user
  records an answer against a flagged finding; the subsequent scan applies it as
  user-declared evidence, resolving the flag according to its content (downgrade or
  refute). The declaration carries explicit user provenance distinct from pipeline-derived
  evidence, is fully auditable, and is reversible: removing it restores the flag. An
  unanswered question keeps the finding flagged. If the flagged finding is no longer
  detected at the same location and weakness, the answer lapses and the finding is
  re-flagged — a stale declaration never suppresses by accident.
- Q: Which finding classes are triage-eligible by default — including known-vulnerable
  dependency advisories, or only code/config/credential findings? → A: Code,
  configuration, misconfiguration, and credential-context findings only. Dependency
  advisories are excluded from the triage round: the deterministic cross-check already
  owns that domain (package absent, resolved version outside the advisory range), and
  reasoning over a machine-checkable fact adds spend without judgment. Credential findings
  remain eligible for context-based downgrade and flagging but never for refutation
  (FR-008).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Refuting disprovable findings (Priority: P1)

A security engineer runs a scan and gets a finding claiming an endpoint group lacks
authorization. In the reviewed report the engineer had to manually discover that a
framework-level filter — registered in a separate security-configuration file — maps every
route in that group to a permission the default role lacks. The finding was a false
positive that cost real triage time.

With the triage round, the reasoning layer re-examines each candidate finding with the
finding's evidence plus deterministically collected candidate-control locations (security
configuration, filter and middleware registrations, route-to-permission mappings, integrity
and validation helpers reachable from the finding's location). When the reasoner finds a
control that refutes the finding, it records the refutation **with citations** — file,
symbol, and lines. The pipeline then re-verifies each citation against the code model:
the file must exist, the cited lines must exist, and the cited structure must be present.
Only a refutation whose citations all verify moves the finding out of the report body into
the auditable suppressions list, which the report continues to display. A refutation whose
citations cannot be verified falls back to flagging — an unverifiable claim is never
suppression grounds.

**Why this priority**: This is the defect the user reported. Six of the eight biggest
false-positive classes in the audited report (missing-authorization, missing-integrity,
SSRF-with-allowlist, and similar control-elsewhere patterns) are refutations of exactly
this shape, and every one of them could have been discharged automatically with cited,
re-verifiable evidence. It is also the highest-risk story constitutionally — it is where
"reasoning suppresses findings" first becomes possible — so its evidence gates define the
safety posture of the whole feature.

**Independent Test**: Given a fixture repository containing (a) an endpoint group whose
authorization is enforced only in a framework security-configuration file and (b) a
genuinely unprotected endpoint group, run the scan and confirm: finding (a) is refuted with
citations that re-verify and lands in the report's suppression list with its ground and
evidence, while finding (b) survives triage unchanged in the report body.

**Acceptance Scenarios**:

1. **Given** a finding whose weakness is provably neutralized by a control declared
   elsewhere in the repository, **When** the triage round runs, **Then** the reasoner
   refutes it citing the control's exact location, the pipeline re-verifies every citation,
   and the finding moves to the suppression list — visible in the report, never silent.
2. **Given** a refutation answer whose cited file, lines, or structure do not exist or do
   not contain the claimed control, **When** the pipeline re-verifies the citations,
   **Then** the refutation is rejected and the finding remains in the report, additionally
   flagged for user attention with the reason the refutation failed.
3. **Given** a genuine finding with no mitigating control, **When** the triage round runs,
   **Then** it is confirmed and reaches the report unchanged — triage can never remove a
   true positive (zero true positives lost, measured on the seeded corpus).
4. **Given** a refuted finding, **When** the scan artifacts are inspected, **Then** the
   suppression record names the triage round as the authority, the refutation ground, and
   every citation that was re-verified — the exclusion is auditable end to end.
5. **Given** identical repository input and previously persisted triage answers, **When**
   the scan is re-run, **Then** refutation outcomes are identical to the first run — triage
   verdicts are replayed from persisted answers keyed to the exact serialized request.

---

### User Story 2 - Calibrating true findings that are over-graded (Priority: P2)

A reviewer sees a High-severity wildcard-CORS finding and must manually determine that
credential forwarding is disabled, making cookie-credential theft impossible — the finding
is real but its headline severity overstates it. The value of the triage round here is not
removal but honest grading: the reasoner identifies the limiting facts (no credentials,
non-externalized surface) and the finding is downgraded with the reasons recorded.

Downgrades use the same evidence discipline as refutations: the facts relied upon must be
cited and re-verified, and the adjusted severity and confidence are recorded with their
rationale using the existing calibration bookkeeping, so "no unproven finding outranks a
proven one" remains the report invariant after triage.

**Why this priority**: Downgrades are strictly safer than refutations — the finding stays
in the report — yet they carry most of the reviewer-trust value for the "context-dependent,
low practical risk" headline findings: the report's top band stops overstating while losing
nothing.

**Independent Test**: Given a fixture repository with a wildcard-origin configuration that
does not forward credentials, run the scan and confirm the finding is reported with
reduced severity, an explicit rationale citing the limiting facts, and no change to its
visibility in the report.

**Acceptance Scenarios**:

1. **Given** a finding whose real-world impact is limited by verified repository facts
   (the reasoner cited them; the pipeline re-verified them), **When** the report is
   generated, **Then** the finding appears with adjusted severity/confidence and the
   downgrade rationale is part of its record.
2. **Given** a downgrade whose cited limiting facts fail re-verification, **When** the
   pipeline applies verdicts, **Then** the downgrade is discarded and the finding keeps its
   original grading — an unverifiable claim never reduces a finding either.

---

### User Story 3 - Flagging context-dependent findings for the user (Priority: P2)

The audited report contained sixteen findings whose verdict depends on facts outside the
repository: a development-authentication token (real risk only if reused outside local
dev-auth), throwaway database passwords for disposable end-to-end containers, a static
bearer credential exercised only against localhost. A scanner cannot answer "is this ever
used beyond localhost?" — but it can *ask it precisely*.

When the reasoner cannot confirm, refute, or justify a downgrade from repository evidence
alone, it flags the finding with a concrete, answerable question for the user. Flagged
findings are rendered in a distinct report section — "awaiting verification" — that names
the finding, the open question, and what evidence would settle it. Flagging never
suppresses: an unresolved finding stays fully visible, graded by what was proven.

**Why this priority**: This is the user's third ask ("or flag them so that the user can
verify") and it converts the least actionable slice of the report into a checklist the user
can actually clear. It shares the reasoning round and the honest-uncertainty discipline
with US1/US2 but changes only report presentation, so it can ship with either.

**Independent Test**: Given a fixture whose seeded credential is used only in code paths
that target a local development server, run the scan and confirm the finding appears in the
awaiting-verification section with a specific question, while remaining present and
normally graded in the finding stream.

**Acceptance Scenarios**:

1. **Given** a finding whose risk depends on deployment facts absent from the repository,
   **When** the triage round runs, **Then** the finding is flagged with a concrete question
   and rendered in the report's awaiting-verification section.
2. **Given** a flagged finding, **When** the reviewer reads it, **Then** the finding's own
   severity and confidence reflect only what the pipeline proved — flagging changes
   neither.
3. **Given** the user has recorded an answer to a flagged finding's question, **When** the
   next scan runs, **Then** the flag resolves according to the answer's content (downgrade
   or refute), the resolution is recorded with explicit user-declared provenance, and
   removing the answer restores the flag on the following scan (clarified 2026-09-04).
4. **Given** a user-declared answer whose flagged finding is no longer detected at the same
   location and weakness, **When** the scan runs, **Then** the stale answer neither
   suppresses nor downgrades anything and the finding is re-flagged with its question.

---

### User Story 4 - Triage quality is asserted, not eyeballed (Priority: P3)

A maintainer tunes the triage pass (prompt, candidate selection, evidence gates) and has no
way to know whether the change now suppresses real findings or leaves obvious false
positives behind. Triage quality must be asserted in the build: a maintained corpus holds
deliberate false positives that MUST be refuted or flagged (with re-verifiable evidence)
and seeded genuine findings that MUST survive triage, and the accuracy benchmark treats
triage regressions as a release-blocking defect class like any other.

**Why this priority**: This is what makes US1–US3 durable, and it mirrors the established
precedent (feature 003, FR-011/FR-012) for detection precision. It is lower priority only
because it gates the build rather than the user-visible report.

**Independent Test**: Run the benchmark against a corpus containing both deliberate false
positives (control-elsewhere patterns) and seeded genuine findings; the build fails if a
genuine finding is refuted/downgraded incorrectly or a deliberate false positive passes
triage unexamined.

**Acceptance Scenarios**:

1. **Given** the maintained triage corpus, **When** the benchmark runs, **Then** every
   deliberate false positive is refuted with re-verified citations or flagged with a user
   question, and every genuine finding survives with its grading intact.
2. **Given** a change that would cause triage to suppress a genuine finding, **When** the
   build runs, **Then** it fails.

---

### Edge Cases

- **Triage reasoner unavailable or unresponsive** (batch window expired, agent never
  answers, endpoint budget exhausted midway): every untriaged finding is reported exactly
  as it would have been without the feature, and the report's coverage section declares
  the partial triage — an unrun or unfinished triage round is a named gap, never an
  assumed outcome.
- **Credential findings**: because the reasoner never sees the matched value, refutation on
  value grounds is impossible by construction. A credential finding may be downgraded from
  context (test code, non-production surface) or flagged with a question — never refuted.
- **Reasoner cites real but irrelevant evidence** (file and lines exist, claimed control is
  not actually present or does not address the weakness): if the claimed structure cannot
  be re-verified, the verdict is rejected; where relevance cannot be judged
  deterministically, the verdict degrades to flagging rather than suppression.
- **Self-contradicting answers** (multiple verdicts, citations pointing at the finding's
  own location as its own refutation, malformed output): the whole answer is rejected for
  that finding, and the finding proceeds as untriaged.
- **Multiple findings over the same code**: each finding is triaged independently; a
  control that refutes one does not automatically refute the others.
- **Re-run after repository change**: persisted triage answers are reused only when the
  serialized triage request is identical; an edited control file changes the request and
  forces fresh reasoning — stale verdicts can never outlive the code they rely on.

## Requirements *(mandatory)*

### Functional Requirements

**Candidate selection**

- **FR-001**: The triage round MUST run exactly once, after findings are finalized
  (normalized, verified, correlated) and before report generation — never inside the
  segment-analysis escalation ladder (clarified 2026-09-04). The system MUST present every
  eligible finding above a profile-determined selection threshold to the triage round.
  Eligible classes are code, configuration, misconfiguration, and credential-context
  findings; known-vulnerable-dependency findings MUST NOT enter the triage round — their
  domain belongs to the deterministic structural cross-check (clarified 2026-09-04). The
  threshold MUST be visible configuration with a per-profile default: deeper scan profiles
  triage more finding classes, shallow profiles may skip triage entirely.
- **FR-002**: Triage MUST be a distinct round with its own requests: it MUST NOT reuse or
  mutate segment-analysis answers, and each triage request MUST be budgeted and measured
  like any other analysis invocation.

**Reasoning round**

- **FR-003**: Each triage request MUST contain the finding itself, its redacted excerpt,
  and candidate mitigating-control locations deterministically collected from the code
  model (security configuration, filter/middleware registration, route mappings, integrity
  and validation structure reachable from the finding). The reasoner MUST NOT be asked to
  locate candidate controls without this seed.
- **FR-004**: The triage verdict vocabulary MUST be closed: `confirmed`, `downgraded`,
  `refuted`, `flagged`. No other outcome may affect a finding.
- **FR-005**: A verdict that would suppress or downgrade a finding MUST carry citations
  (file, line range, and the structure relied upon) for every claim it depends on.
- **FR-006**: In agent-mediated mode the reasoner MAY consult raw repository files beyond
  the packet, restricted to files with zero redaction hits as classified by the
  deterministic redactor (clarified 2026-09-04). Files with any redaction hit MUST be
  consultable only through their redacted excerpts, in every mode. The consultation
  boundary in effect MUST be stated in the report's methodology note.

**Deterministic evidence gates**

- **FR-007**: Before any refutation or downgrade is applied, the deterministic pipeline
  MUST re-verify every citation against the code model: cited file exists, cited lines
  exist, cited structure is present. A verdict that fails re-verification MUST be rejected
  in full — it degrades to `flagged`, never to suppression or downgrade.
- **FR-008**: The triage round MUST NOT receive, and MUST NOT be able to act on, matched
  credential values. Refutation of credential-class findings is impossible by construction;
  context-based downgrade and flagging remain available.
- **FR-009**: A finding whose triage request was never answered (unavailable reasoner,
  expired round, exhausted budget) MUST be reported exactly as if the feature did not
  exist; the report MUST declare the triage coverage gap.

**Report presentation and auditability**

- **FR-010**: Refuted findings MUST move to the auditable suppression list, recorded with a
  triage-specific disproof ground, the full citation set, and the re-verification result —
  exclusion is never silent.
- **FR-011**: Downgraded findings MUST remain in the report with their adjusted grading and
  recorded rationale, and MUST NOT be represented as less visible than confirmed findings.
- **FR-012**: Flagged findings MUST be rendered in a distinct awaiting-verification section
  carrying a concrete user question, while remaining present and normally graded in the
  finding stream.
- **FR-013**: After triage, the report's severity bands MUST reflect the applied verdicts:
  refuted findings MUST NOT inflate headline counts, and confidence/severity invariants
  (no unproven finding outranks a proven one) MUST still hold.
- **FR-014**: Every triage decision — including rejected verdicts — MUST be recorded in the
  scan artifacts with finding, verdict attempted, citations, and outcome, so the round is
  auditable even where it changed nothing.

**Persistence and determinism**

- **FR-015**: Triage answers MUST persist keyed to the exact serialized triage request and
  the reasoning tier that answered, and MUST be reused only when both match — identical
  repository input with cached answers MUST produce byte-identical triage outcomes.

**User-declared answers**

- **FR-018**: The system MUST accept user-recorded answers to flagged findings' questions
  as durable input, bound to the finding's identity (location and weakness), and MUST apply
  them as user-declared evidence on subsequent scans — never interactively mid-scan
  (clarified 2026-09-04).
- **FR-019**: A user declaration resolves its flag according to its content (downgrade or
  refute), MUST be recorded with explicit user-declared provenance distinct from
  pipeline-derived or code-verified evidence, MUST be fully reversible (removing the
  declaration restores the flag on the next scan), and MUST NOT be presented as evidence
  the pipeline itself established.
- **FR-020**: A user declaration lapses when its flagged finding is no longer detected at
  the same location and weakness; a lapsed declaration MUST NOT suppress or downgrade
  anything, and the finding MUST be re-flagged with its question.

**Quality gates**

- **FR-016**: The accuracy benchmark MUST treat triage correctness as its own defect class:
  suppressing or downgrading a seeded genuine finding, or passing a deliberate
  control-elsewhere false positive without refutation or flag, MUST fail the build.
- **FR-017**: Detection recall MUST be unaffected: triage changes the fate of findings
  after detection, and MUST NOT change what the deterministic detector or segment analysis
  detect.

### Key Entities

- **Triage Request**: one finding's invitation to re-examination. Attributes: the finding,
  its redacted excerpt, deterministically collected candidate-control locations, budget,
  and a stable request identity derived from the serialized request. Created after findings
  are finalized; never reuses segment-analysis artifacts.
- **Triage Verdict**: the reasoner's closed answer for one finding — `confirmed`,
  `downgraded`, `refuted`, or `flagged` — with rationale, the citations the verdict depends
  on, and (for `flagged`) the concrete user question. Persists as the existing answer
  entity: request identity, answer key, content — nothing policy-dependent.
- **Evidence Citation**: a pointer the pipeline can check: repository member, file, line
  range, and the structure relied upon. Citations are the only channel through which
  reasoning can change a finding's fate.
- **Triage Suppression**: an entry in the established suppression list extended with a
  triage-specific ground, the citations, and the re-verification result; rendered in the
  report like any other suppression.
- **Awaiting-Verification Item**: a flagged finding plus its open question and the evidence
  that would settle it; a report-section entity, not a suppression.
- **User Declaration**: a durable, user-recorded answer to an awaiting-verification item's
  question. Attributes: the flagged finding's identity (location, weakness), the question,
  the answer, and its resolution effect (downgrade or refute). Carries user-declared
  provenance, is reversible, and lapses when its finding is no longer detected at the same
  location and weakness.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On the audited baseline scan (`20260903T042832Z-c63749`, the ground-truth
  labelling from the manual audit: 8 real, 21 false positives, 16 context-dependent), at
  least 80% of the context-disprovable false positives (the control-elsewhere classes:
  missing-authorization, missing-integrity, allowlisted-SSRF, credential-reference
  patterns) are refuted with re-verified citations or flagged with a precise question —
  automatically, without human audit.
- **SC-002**: Zero true positives are suppressed or incorrectly downgraded: all 8
  confirmed-real findings of the baseline audit reach the report with their severity
  ordering intact.
- **SC-003**: 100% of refuted and downgraded findings carry citations that re-verified
  deterministically; 0% of applied verdicts rest on unverified reasoning output.
- **SC-004**: 100% of context-dependent findings that reasoning could not settle appear in
  the awaiting-verification section with a concrete question; none is silently dropped or
  silently left to implication.
- **SC-005**: A re-run over identical input with persisted triage answers produces
  byte-identical triage outcomes and report verdicts; a single edited candidate-control
  file invalidates exactly the decisions that relied on it.
- **SC-006**: Reviewer triage burden measurably drops: the baseline report's top severity
  bands no longer include any finding the audit confirmed as a context-disprovable false
  positive.

## Assumptions

- **Baseline and ground truth**: the manual audit of scan `20260903T042832Z-c63749`
  (45 findings; labelled 8 real / 21 false positive / 16 context-dependent) is the
  evaluation baseline. The labelled set becomes part of the maintained corpora —
  refute/flag entries for confirmed false positives, must-survive entries for confirmed
  real findings (precedent: feature 003's corpus discipline).
- **Value-legitimacy precision stays out of scope**: credential-detector false-positive
  reduction at the *value* level (placeholder shapes, identifier-vs-value confusion,
  test-fixture shaped fakes) belongs to feature 003's deterministic work and to external
  scanner allowlisting; this feature neither duplicates nor gates on it.
- **Severity grading of the same class across sources remains separate work**: e.g.
  external-scanner findings lacking the native detector's test-context severity step-down
  is a deterministic calibration gap, not a triage responsibility.
- **Triage runs in every execution mode** the scan supports (agent-mediated via the
  handoff/resume contract, provider endpoint, and provider batch), with the evidence gates
  identical in all modes; an unavailable reasoning channel degrades to an untriaged report
  with a declared gap (FR-009), it is not a scan failure.
- **Determinism accounting**: triage outcomes are content-addressed by the serialized
  request, so the determinism invariant is evaluated the way existing LLM round-trips are —
  byte-identical *with cached answers*; fresh answers over changed code are new outcomes,
  not nondeterminism.
- **The suppression machinery is extended, not replaced**: triage reuses the existing
  auditable suppression list and report suppressions section with a new triage ground
  rather than inventing a parallel exclusion channel.
- **Dependency advisories stay with the deterministic cross-check** (clarified
  2026-09-04): known-vulnerable-dependency findings are suppressed only by structural
  disproof against resolved pins, which already exists; triage neither duplicates nor
  overrides that channel.
