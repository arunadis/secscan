# Feature Specification: Business-Flow (Functional) Vulnerability Analysis

**Feature Branch**: `015-business-flow-analysis`

**Created**: 2026-09-05

**Status**: Draft

**Input**: User description: "i want the tool to be able to identify the functional vulnerabilities as well. those may not necessaraly be introduced due to bad coding practices, but the gaps in the business functionalityies. due to these gaps, the users may gain elivated access and do the operations tjhat the users are not allows to do. so the hierachical analysis should consider businesss flows and identify the glitches in the flows. the repost should incluse the respective flow and how the secrity can be compromized in the flow. when executing the skill, it shuls ask from the user whether they need to do functional flow analysis or not, or this should be configured in the profile. by default it is disabled as it may requre more tokens"

## Problem Statement

Today the scanner reasons over code structure: per-segment analysis finds defects in
individual units (injection, missing output encoding, hard-coded secrets), and the system
review adds cross-boundary issues. What neither pass can see is a class of vulnerability
that lives **above the code level**: the business flow itself is wrong. Each individual
step can be perfectly written — parameterized queries, correct encoding, no secrets —
while the sequence of steps lets a user reach an operation they were never meant to reach:

- a multi-step checkout where step 3 ("confirm order") never re-checks that step 2
  ("apply discount") was performed by an authorized role, so any shopper grants
  themselves staff pricing;
- an account-recovery flow whose "verify identity" step can be skipped by calling the
  "reset password" endpoint directly, because the flow's state is implicit;
- an admin-approval workflow where the "approve" action checks the *viewer's* role but
  the underlying operation mutates resources owned by another tenant.

These are **functional vulnerabilities**: gaps in the business logic, not bad coding
practices. They are only visible when you trace a user journey — actor, role, ordered
steps, trust transitions — and ask "at every step, who is allowed to be here, and is that
enforced?" This feature adds an opt-in business-flow analysis round to the hierarchical
analysis: flows are reconstructed from the repository model, reasoned over as wholes,
and gaps are reported with the flow, the missing or violated check, and a concrete
explanation of how security is compromised in that flow. Because this reasoning is
additional and token-hungry, it is **disabled by default**, enabled per scan via profile
configuration or an explicit user choice at scan time.

## Clarifications

### Session 2026-09-05

- Q: When a business flow crosses a repository boundary inside a scanned workspace, how
  should the analysis treat that boundary? → A: Stitch declared, typed cross-repo
  integration points into one flow (steps across repositories form a single flow).
  Undeclared or undetermined connections make the flow explicitly *partial* and are
  declared as coverage gaps with reasons. No inference of undeclared integrations —
  that remains roadmap work.
- Q: In the report, should functional (business-flow) findings live in a separate
  flow-centric section, or be merged into the same ranked finding list as code-level
  findings? → A: Merged. A flow-gap finding is a normal finding in the one ranked
  finding list, marked with a flow category, carrying its flow narrative and compromise
  path inline; profile severity thresholds and ranking apply exactly as for code-level
  findings.
- Q: For a flow-gap finding, whose defect is an *absent* check rather than a dangerous
  data path, what should the static verification verdicts (verified / plausible /
  disproven) mean? → A: Path-based semantics. *Verified* = a concrete traversable path
  through the flow's steps reaches the privileged operation without passing the
  missing/violated check, with locations that resolve. *Plausible* = such a path exists
  in the model but some reachability or control state along it is undetermined.
  *Disproven* = every modeled path through the flow passes the check — handled like any
  disproven finding.
- Q: Should detecting potential regulation-violating flows (e.g., personal-data collection
  without a consent step, no data-deletion path) be in scope for this feature? → A: Yes,
  in scope. Flow analysis additionally evaluates reconstructed flows against regulatory
  obligations and reports breaches as flow findings carrying regulation references. The
  bounded reasoning layer may identify and triage candidate violations; which regimes
  apply to a project is determined deterministically (never from model output).
- Q: How should the scanner determine which regulatory regimes apply to a scanned project
  — from what the user declares, from what the code reveals, or both? → A: Hybrid, with
  the applicability mode configurable. Default (*hybrid*): user-declared regimes are
  always evaluated, and deterministically detected regulated-data categories additionally
  raise candidate regimes that are recorded as suggested-but-not-evaluated until the user
  confirms them. The user can instead select *declared-only* (declared regimes evaluated,
  nothing inferred) or *inferred-only* (regimes selected from detected regulated-data
  categories, all candidates evaluated). Inference is always deterministic — data
  categories from the code model mapped through versioned data — never model output.
- Q: When the installed skill asks whether to run business-flow analysis and the user
  answers, should that answer be saved so future runs don't ask again? → A: Persist only
  on opt-in. The answer governs the current run; the question offers "remember this
  choice", and only an explicit assent writes the setting (a plain, non-secret key) into
  the project configuration. A declined answer is asked again on the next unconfigured
  run, and a user can change or remove a remembered setting anytime.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Scan reports business-flow gaps with the compromised flow (Priority: P1)

A security engineer runs a scan with business-flow analysis enabled on an application
with multi-step user journeys (registration with approval, checkout, role changes). The
scan reconstructs the business flows from the repository model, analyzes each flow for
authorization and state-integrity gaps across its steps, and the report contains
flow-gap findings. Each such finding names the flow it belongs to, shows the relevant
sequence of steps, identifies the missing or violated check, and explains how a user
elevates access or performs a disallowed operation as a result.

**Why this priority**: This is the entire value of the feature — findings a code-level
scan structurally cannot produce. Without it there is nothing to toggle.

**Independent Test**: Scan a fixture application containing a seeded privilege-escalation
flow (e.g., a two-step flow whose second step omits a role check) with the feature
enabled, and confirm the report contains a finding that names the flow, the missing
check, and the compromise path — while a code-level scan of the same fixture reports
nothing for it.

**Acceptance Scenarios**:

1. **Given** an application whose checkout flow lets a non-staff user reach the
   staff-discount step without a role check, **When** a scan runs with business-flow
   analysis enabled, **Then** the report contains a finding that names the checkout flow,
   shows the relevant steps, states which check is missing, and explains that a regular
   user obtains staff pricing.
2. **Given** an application whose flows are all correctly enforced, **When** a scan runs
   with business-flow analysis enabled, **Then** the report contains no flow-gap finding
   for those flows (deliberately safe flows are not flagged).
3. **Given** a flow whose authorization posture cannot be determined from the repository,
   **When** the scan runs with business-flow analysis enabled, **Then** the undetermined
   state is recorded and declared as a coverage gap — it neither suppresses other
   findings nor reads as clean.

---

### User Story 2 - User controls whether flow analysis runs (Priority: P2)

The feature costs additional reasoning tokens, so the user decides per scan. The choice
is available in two places: as a persistent scan-profile / configuration setting, and as
an explicit question when a scan is launched through the installed skill without an
existing preference. When neither is set, business-flow analysis is **off**. A scan run
with the feature disabled behaves exactly as before the feature existed.

**Why this priority**: The toggle is meaningless without the detection from US1, but it
is a hard requirement from the user and protects every existing user from a silent cost
increase. Second-highest.

**Independent Test**: Run three scans of the same fixture — (a) default settings, (b)
profile with flow analysis enabled, (c) interactive skill execution where the user
answers "yes" to the flow-analysis question — and confirm (a) is byte-identical to a
pre-feature scan while (b) and (c) both include the flow-analysis round.

**Acceptance Scenarios**:

1. **Given** no profile setting and no prior preference, **When** a scan is launched
   through the installed skill interactively, **Then** the user is asked whether to run
   business-flow analysis, and the answer governs that run.
2. **Given** the user answers the question and accepts "remember this choice", **When**
   subsequent scans are launched, **Then** no question is asked and the remembered
   preference governs until the user changes or removes the setting; **Given** the user
   declines to remember, **When** the next unconfigured scan is launched, **Then** the
   question is asked again.
3. **Given** a profile that enables business-flow analysis, **When** a scan runs with
   that profile, **Then** flow analysis runs without any interactive question.
4. **Given** a profile that disables business-flow analysis (or no preference at all) in
   a non-interactive execution, **When** the scan runs, **Then** flow analysis is skipped
   and the scan never blocks waiting for an answer.
5. **Given** business-flow analysis disabled, **When** a scan completes, **Then** every
   artifact is byte-identical to the equivalent scan from before this feature (determinism
   and backward compatibility are preserved).

---

### User Story 3 - Scan flags flows breaching declared regulatory obligations (Priority: P3)

A compliance-minded user runs a scan with business-flow analysis enabled on a project
subject to declared regulations (e.g., a privacy regime such as GDPR/CCPA, or a healthcare
standard). Beyond authorization gaps, the scan evaluates each reconstructed flow against
the obligations of the declared regimes — for example a personal-data collection flow with
no consent step, an account flow with no data-subject deletion path, or a flow moving
health data to a third party without a safeguard step — and reports breaches as flow
findings that name the regulation, the specific obligation breached, the flow, and how it
fails the obligation.

**Why this priority**: This is the second detection class the feature was asked to cover,
and it depends on the flow machinery and opt-in controls from US1/US2 — valuable, but
layered on top of them.

**Independent Test**: Scan a fixture containing a consent-less personal-data collection
flow with a privacy regime declared, and confirm a flow finding names the regime, the
breached obligation, and the flow — and confirm a scan of the same fixture with no regimes
declared produces no such finding.

**Acceptance Scenarios**:

1. **Given** a fixture whose signup flow stores personal data with no consent step and a
   privacy regime declared for the project, **When** a scan runs with business-flow
   analysis enabled, **Then** the report contains a flow finding naming the regime, the
   breached obligation, the signup flow, and how it fails the obligation.
2. **Given** a fixture whose account flow offers no data-subject deletion path and a
   privacy regime declared, **When** the scan runs, **Then** the missing deletion path is
   reported against the flow with the regulation reference.
3. **Given** flow analysis enabled but no regime applicable under the configured
   applicability mode (none declared, and none inferred or confirmable under that mode),
   **When** the scan runs, **Then** obligation evaluation is skipped and the undeclared
   state is declared explicitly — regulatory obligations are never guessed.
4. **Given** a regulatory-violation finding, **When** it reaches the report, **Then** it
   sits in the merged ranked list like any flow-gap finding and passes the same
   verification (path-based verdicts) and triage (citation re-verification) gates.

---

### User Story 4 - Flow-analysis cost is visible and bounded (Priority: P4)

A user who enabled flow analysis wants to know what it cost and that it cannot overrun
their budget. The scan's usage summary shows the incremental reasoning cost of the
flow-analysis round, and the round obeys the same serialized-request token budgets as
every other reasoning round — escalation starts small and grows only on stated
insufficiency.

**Why this priority**: Cost transparency is what makes an opt-in expensive feature safe
to offer, but the feature delivers value before the accounting is perfect.

**Independent Test**: Run the same fixture with flow analysis off and on, and confirm the
usage summary for the enabled run itemizes the flow-analysis round separately and no
individual request exceeded its budget.

**Acceptance Scenarios**:

1. **Given** a scan with flow analysis enabled, **When** it completes, **Then** the usage
   summary attributes token consumption of the flow-analysis round separately from
   segment analysis.
2. **Given** a fixture large enough that one flow cannot be reasoned over within the
   request budget, **When** the scan runs, **Then** the flow is subdivided along its
   security boundaries or declared as a coverage gap — never silently truncated.

---

### Edge Cases

- What happens when the repository contains no recognizable multi-step business flow
  (e.g., a pure library)? The round records zero flows analyzed, costs nothing, and the
  report simply contains no flow-gap findings — no finding, no gap, no noise.
- What happens when a flow gap and an existing code-level finding describe the same
  location (e.g., a missing role check found per-endpoint *and* as a flow gap)? The two
  are related so the reader sees one issue from both angles, never double-counted.
- What happens when roles/permissions are not declared anywhere in the code (implicit
  authorization model)? The flow's authorization posture is recorded as undetermined and
  declared, per the honest-uncertainty principle — never assumed permissive or strict.
- What happens when the user answers "no" to the interactive question? Identical to
  having it disabled in the profile: the round does not run and no artifact references it.
- What happens when a flow-analysis answer never arrives in agent-mediated mode? The
  handoff mechanism governs it exactly like any other reasoning round: exit code 3,
  resume on answer; a run may complete with flows pending only if the user abandons them,
  in which case those flows are declared unanalyzed.
- What happens when business logic spans repositories but the integration between two
  members is not declared, or its type cannot be determined? The affected flow is
  recorded as explicitly partial, the undeclared or undetermined boundary is declared as
  a coverage gap with a reason, and no stitching is attempted across it.
- What happens when verification cannot settle a flow gap either way because reachability
  of the privileged operation is undetermined? The verdict is *plausible* with the
  undetermined state declared — the finding is published, never silently dropped, and its
  confidence reflects what was not proven.
- What happens when flow analysis is enabled but no regulatory regime is declared and
  (under the configured applicability mode) none is determinable? Obligation evaluation
  is skipped, the undeclared state is recorded and declared, and no regulatory content is
  guessed — absence of a declaration never reads as "no obligations apply".
- What happens in the default hybrid mode when the code model reveals regulated-data
  categories (e.g., health data) but the user declared no matching regime? The candidate
  regime is recorded and declared as suggested-but-not-evaluated; no finding is produced
  for it until the user confirms the regime.
- What happens when a declared regime's obligations cannot be mapped onto anything
  observable in the flows (e.g., records-retention rules with no retention logic in the
  code)? The regime's coverage is declared as unassessable for those obligations rather
  than reported clean.
- What happens when one flow violates obligations of more than one declared regime? A
  single finding is published for the breach, carrying all applicable regulation
  references — never one finding per regime.

- What happens when the user declines "remember this choice" after answering? The answer
  applies to the current run only, nothing is written, and the question is asked again on
  the next run that has no configured preference.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Business-flow analysis MUST be disabled by default in every profile and
  every execution mode.
- **FR-002**: Users MUST be able to enable or disable business-flow analysis through
  scan-profile / configuration settings, with the profile value taking effect without
  any interactive question.
- **FR-003**: When a scan is launched through the installed skill and no preference is
  configured, the skill MUST ask the user whether to run business-flow analysis for that
  run, and MUST honor the answer. The question MUST offer to remember the choice; only on
  explicit assent is the preference persisted into the project configuration as a plain,
  non-secret setting, so future runs skip the question until the user changes or removes
  the setting.
- **FR-004**: In non-interactive execution with no configured preference, the scan MUST
  proceed with flow analysis disabled and MUST NOT pause or fail waiting for an answer.
- **FR-005**: A scan run with flow analysis disabled MUST produce results byte-identical
  to the equivalent scan from before this feature existed.
- **FR-006**: When enabled, the analysis MUST reconstruct business flows — an actor or
  role traversing an ordered sequence of operations with trust transitions — from the
  repository model, at the hierarchical layers above individual segments.
- **FR-007**: When enabled, the analysis MUST examine each reconstructed flow for
  functional gaps, including at minimum: steps reachable without the authorization the
  preceding steps establish (missing enforcement between steps), step-order or
  state-integrity violations that allow skipping an enforced step, and cross-role or
  cross-tenant transitions that grant elevated access.
- **FR-008**: Every flow-gap finding MUST name the flow it belongs to, present the
  relevant sequence of steps, state the missing or violated check, and explain how
  security is compromised in that flow (who gains what they are not allowed to do).
- **FR-009**: Flow-gap findings MUST conform to the same finding contract as all other
  findings: weakness identifier, severity, confidence, and evidence-backed locations that
  resolve against the code model. Anything rendered as a data-flow trace MUST contain
  only traced edges; a flow's step sequence (FR-008) is presented as ordered steps with
  evidence, never rendered as a source-to-sink trace.
- **FR-010**: When a flow's authorization posture or reachability cannot be determined
  from the repository, the scan MUST record an explicit undetermined state and declare
  the coverage gap; an unknown MUST NOT suppress a finding, read as clean, or raise
  severity.
- **FR-011**: Flow-gap findings MUST flow through the same normalization, verification,
  triage, and correlation passes as all other findings; flow gaps and code-level findings
  describing the same weakness MUST be related rather than double-counted.
- **FR-012**: The flow-analysis round MUST obey the same token-budget discipline as every
  other reasoning round: budgets enforced against the serialized request, context starts
  at the smallest useful slice and escalates only on stated insufficiency, and oversized
  units are subdivided along security boundaries or declared as coverage gaps — source is
  never silently truncated.
- **FR-013**: The scan usage summary MUST attribute the flow-analysis round's token
  consumption separately, so a user can see what the opt-in cost.
- **FR-014**: Flow-gap findings MUST be rendered in all report formats the scanner
  supports, merged into the single ranked finding list alongside code-level findings —
  marked with a flow category so they are identifiable, carrying the flow narrative and
  compromise explanation inline, and subject to the same profile severity thresholds and
  ranking as every other finding.
- **FR-015**: When the scanned workspace spans multiple repositories, flow analysis MUST
  stitch steps across repository boundaries into a single business flow wherever a
  declared, typed integration point (synchronous API, asynchronous messaging, shared
  datastore, identity propagation) connects them; each step in such a flow MUST remain
  attributable to the repository it lives in.
- **FR-016**: When a cross-repository connection is undeclared or its type cannot be
  determined, the affected flow MUST be recorded as explicitly partial and declared as a
  coverage gap with a reason; the analysis MUST NOT infer undeclared integrations.
- **FR-017**: Static verification of a flow-gap finding MUST use path-based verdict
  semantics: *verified* when a concrete traversable path through the flow's steps reaches
  the privileged operation without passing the missing/violated check and every location
  resolves; *plausible* when such a path exists in the model but reachability or control
  state along it is undetermined (never a reason to suppress); *disproven* when every
  modeled path through the flow passes the check, handled exactly as a disproven
  code-level finding is. Verification remains fully static — no flow is ever executed —
  and a flow's step sequence is presented as a step sequence with evidence, never dressed
  as a source-to-sink data-flow trace.
- **FR-018**: When flow analysis is enabled and regulatory regimes apply to the project,
  the analysis MUST evaluate each reconstructed flow against the obligations of the
  applicable regimes — covering at minimum consent-before-collection for personal data,
  data-subject rights (access and deletion paths), and regime-specific handling of
  regulated data categories (e.g., health data). Candidate breaches may be identified by
  the bounded reasoning layer over prepared evidence, subject to the same budgets as
  US1's gap detection.
- **FR-019**: A regulatory-violation finding MUST be a flow finding in the merged ranked
  list (FR-014): it names the regulation and the specific obligation breached, shows the
  flow and the failing step(s), explains how the flow fails the obligation, and conforms
  to the same finding contract (FR-009), path-based verification (FR-017), and triage
  with citation re-verification (FR-011) as every other finding. A breach spanning
  multiple regimes MUST be one finding carrying all applicable regulation references.
- **FR-020**: Regulatory regimes and their obligations MUST ship as versioned data, so
  adding a regime or obligation changes data, never pipeline stages.
- **FR-021**: Regulatory-violation content MUST be framed as potential compliance risk
  with evidence, never as a legal determination; wording follows the same
  not-audit-ready stance as the existing weakness-to-control annotations.
- **FR-022**: Regime applicability MUST be governed by a configurable applicability mode
  with three settings — *declared-only*, *inferred-only*, and *hybrid* (the default) —
  settable in the profile/configuration. In every mode, applicability decisions are
  deterministic: declared regimes come from configuration; inferred regimes come from
  regulated-data categories detected in the code model through versioned mapping data;
  nothing about applicability comes from model output.
- **FR-023**: In *hybrid* mode, detected regulated-data categories MUST raise candidate
  regimes that are recorded and declared as suggested-but-not-evaluated until the user
  confirms them (by declaring the regime); a candidate regime MUST NOT be evaluated or
  produce findings before confirmation. In *declared-only* mode, no inference occurs; in
  *inferred-only* mode, detected candidates are evaluated without requiring declaration,
  and each finding states the detection basis.

### Key Entities *(include if feature involves data)*

- **Business Flow**: A named user journey reconstructed from the repository model —
  actor/role, ordered steps (operations, endpoints, state transitions), and the trust
  transitions between steps. In a multi-repository workspace, steps may span repositories
  when declared, typed integration points join them; a flow with an undeclared or
  undetermined cross-boundary connection is recorded as *partial*. Derived
  deterministically; the same workspace yields the same flows.
- **Flow Gap (finding)**: A finding bound to a Business Flow: which check is missing or
  violated at which step(s), the roles involved, the resulting elevation or disallowed
  operation, and evidence locations. It is a first-class finding in the unified ranked
  list, distinguishable by its flow category marker, and carries severity and confidence
  like any finding.
- **Flow Coverage**: The declaration of which flows were reconstructed, which were
  analyzed, which could not be (with reasons), and the undetermined states recorded —
  the honest-uncertainty ledger for this round.
- **Regulatory Regime**: A named body of obligations (e.g., a privacy regime, a
  healthcare data standard) whose obligations ship as versioned data. Applicability is
  governed by the configured mode: *declared* (from configuration), *inferred* (from
  regulated-data categories detected in the code model), or *candidate* (raised by
  detection in hybrid mode, suggested-but-not-evaluated until confirmed). A finding may
  be bound to a regime + obligation; a regime with unassessable obligations is declared,
  never reported clean.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A scan with flow analysis disabled produces output byte-identical to a
  pre-feature scan on the same repository and tool version (zero behavioral change by
  default).
- **SC-002**: On the evaluation fixtures, the flow-analysis round detects at least 80%
  of seeded functional/business-logic vulnerabilities, while flagging 0 deliberately
  safe flows — matching the accuracy-bar the project applies to every other defect class.
- **SC-003**: 100% of published flow-gap findings name their flow, show the relevant
  steps, and state the compromise path — a report never publishes a flow finding a
  reader cannot trace back to a flow.
- **SC-004**: 100% of undetermined flow-analysis states appear as declared coverage gaps
  in the report; none are silent.
- **SC-005**: A user can determine the token cost of enabling flow analysis from the
  usage summary of a single enabled scan, and no single request exceeds its budget.
- **SC-006**: On evaluation fixtures, at least 80% of seeded regulatory-violation flow
  cases are detected with the correct regime and obligation named for every regime that
  is applicable under the configured applicability mode; 0 regulatory-violation findings
  are produced for regimes not applicable under that mode (including hybrid-mode
  candidates the user has not confirmed).
- **SC-007**: 100% of regulatory-violation findings name the regime and the specific
  breached obligation; 100% of declared-but-unassessable regimes appear as declared
  coverage gaps rather than reading as clean.

## Assumptions

- "When executing the skill, ask the user" applies to interactive, agent-mediated
  execution (the installed skill). The non-interactive command-line path is governed by
  profile / configuration alone, per FR-004, because a blocking question would break
  automation and CI use.
- Flow-gap findings reuse the existing weakness taxonomy (e.g., missing/incorrect
  authorization weakness classes) rather than introducing a separate taxonomy; any new
  weakness or flow classes ship as versioned data, consistent with the project's
  extensibility-as-data principle — no pipeline stage is special-cased per flow type.
- Business flows are reconstructed deterministically from the existing repository model
  (routes, handlers, role/permission checks, data-store access, trust annotations) —
  the model already enumerates the ingredients; identification of flows is a new
  derivation over it, not a new repository crawl.
- "May require more tokens" is treated as the reason for the default-off posture; the
  round still obeys the same budget and escalation discipline as existing rounds, so
  enabling it raises cost by a bounded, visible amount rather than unpredictably.
- Flow-gap findings participate in the existing finding-triage round (feature 013)
  like any other finding; triage of a flow finding may refute or downgrade it with
  evidence, subject to the same citation re-verification gates.
- Cross-repository flow joining relies on the declared, typed integration points of the
  existing workspace model; inferring undeclared integrations is out of scope (a
  known-open roadmap item), per the clarification recorded above.
- The existing CWE-derived compliance annotations on findings continue unchanged and are
  distinct from the regulatory obligation evaluation introduced here; the latter binds a
  flow to a named regime obligation with evidence, the former remains a weakness-level
  annotation.
- Regulatory-violation identification and triage use the same bounded reasoning layer as
  the rest of the scan (per the clarification recorded above); which regimes apply to a
  project is a deterministic decision over declared configuration and code structure
  under the configured applicability mode (*hybrid* by default), never model output.
- Confirmation of a hybrid-mode candidate regime means the user declares it in the
  profile/configuration; the scanner never confirms a candidate on its own.
- All new settings introduced by this feature (the flow-analysis toggle, the applicability
  mode, declared regimes, and any remembered interactive preference) live in the existing
  layered configuration surface — profiles in project configuration, per-scan overrides,
  and environment overrides — as plain non-secret keys, at workspace scope for
  multi-repository scans. No new storage mechanism or file format is introduced, and the
  scanner still never writes into the scanned project.
- When enabled under a depth-capped profile (e.g., `quick`), the flow-analysis round
  obeys the active profile's escalation ceiling like every other reasoning round; flows
  needing more depth than the ceiling allows are declared as coverage gaps, never
  silently under-analyzed.
