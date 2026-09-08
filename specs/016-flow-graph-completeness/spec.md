# Feature Specification: Flow & Graph Completeness

**Feature Branch**: `016-flow-graph-completeness`

**Created**: 2026-09-07

**Status**: Draft

**Input**: User description: "Elaborate the requirements for improving secscan so that issues hidden in the flows/graph are identified — not limited to the missed spoofable-identity-header case, but the class of issues that hide when the graph/flow substrate is incomplete."

## Background & Problem Statement

A real scan of an Express-style application (header-asserted identity enforced by
middleware) produced a report that missed a Critical authentication bypass. The
post-mortem showed the miss was not a reasoning error but a substrate failure: the
graph contained no edges for middleware wiring, request headers were not recognised
as attacker-controlled sources, the database driver's call conventions were not
recognised as data access, flow tracing produced zero flows for the entire project
(and the report did not say so), and the segment carrying the decisive code was
framed as having no entry points. Every downstream stage — analysis packets,
verification verdicts, the executive summary — faithfully consumed an untruthful
input. This feature hardens the deterministic substrate and its honesty contracts so
that trust-boundary weaknesses hidden in flows/graph are either detected or openly
declared as uncovered, never silently missed.

## Clarifications

### Session 2026-09-07

- Q: When a finding accuses a guard of being fake/weak, may that same guard be cited — by the triage reasoner or the deterministic verify gate — as the "control" that refutes the finding? → A: No — implicated-guard exclusion at both stages: the verify gate (already landed in `verify.py`; a control the finding implicates can never disprove it) **plus** a triage rule rejecting `refuted`/`downgraded` verdicts whose citations resolve to locations the finding implicates. Only an *independent* control elsewhere on the path can refute.
- Q: Should the new deterministic client-asserted-identity findings (FR-014) go through the reasoning triage round regardless of severity band, like generic heuristic findings do today? → A: No — archetype rules produce `format` detections (like hard-coded-secret rules): they enter triage only above the minimum severity band, and `refuted` verdicts are invalid for them by construction; the reasoning stage may still downgrade from context or flag with a user question.
- Q: How should the presence-vs-traced distinction (FR-008/FR-009) be represented in artifacts so triage, calibration, and resume behavior stay consistent? → A: Additive `basis` field (`"traced"` | `"presence"`) on the verification record; statuses stay `verified`/`plausible`/`disproven`, so triage admission, calibration caps, and answer/resume keys are unchanged. While an FR-007 reachability gap is active, reachability-sensitive presence-based findings are demoted to `plausible` with a named gap; the report summary reads `basis` to separate the two counts.
- Q: For route modules that lack the guard their siblings all attach (FR-016), should the inconsistency surface only as packet/system-review evidence, or also as its own reportable finding? → A: Evidence only — surfaced in the per-file role digest and the system-level review; no standalone finding, because deterministic absence of a guard is not per se a weakness (the archetype rules and reasoning stages catch the real ones), and each heuristic finding would cost a triage round.
- Q: Should feature 016 add a per-scan recall check that re-examines segments that produced zero findings, or should recall assurance stay off the per-scan path? → A: Off the per-scan path. Recall assurance ships through the accuracy benchmark's ground truth (FR-018), the declared coverage gaps (FR-007/FR-009), and deterministic archetype rules that bypass segment reasoning entirely (FR-014). A sweep premised on "the packet might be hiding something" would be guessing over unknowns, which a production scan must never do; it is meaningful only where ground truth exists — the benchmark.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Middleware-borne controls are real in the graph (Priority: P1)

An engineer scans a project whose access control lives in framework middleware
(attached via route/module wiring calls rather than call-site invocations) and whose
identity or tenant selector is read from request headers or cookies. The scan must
"see" that wiring: every protected route traces through its guard, header/cookie
reads count as attacker-controlled sources, and the middleware's trust decision is
analysable as the security-critical point it is.

**Why this priority**: This is the direct root cause of the observed Critical miss.
Without correct edges and source recognition, nothing downstream — flows,
validations, verification, prompts — can ever reason about the issue class.

**Independent Test**: Scan a reference project built on middleware-attached guards
with header-asserted identity (the timesheet-app pattern). The scan must produce a
finding anchored at the middleware trust decision itself (not merely at neighbouring
route/client code), and the persisted graph must contain traversable edges from
protected routes to the guard symbol.

**Acceptance Scenarios**:

1. **Given** a project where routes attach a guard via module/router wiring calls,
   **When** the repository is scanned, **Then** the code graph contains a traversable
   edge between each protected route and the guard function.
2. **Given** code that reads identity, tenant, role, or metadata values from request
   headers or cookies, **When** the graph is built, **Then** those read sites are
   recorded as attacker-controlled sources and can originate traced flows.
3. **Given** data-access calls written in a supported driver's non-generic calling
   convention (e.g. convenience query methods rather than a generic execute call),
   **When** the graph is built, **Then** those calls are recorded as data-access
   facts and flow tracing can terminate at them.
4. **Given** the reference header-identity project, **When** scanned end to end,
   **Then** the report contains a finding whose location is the middleware trust
   function and whose weakness is spoofable/unverified identity.

---

### User Story 2 - Incomplete substrate is declared, never silent (Priority: P1)

An engineer scans any project. If the graph cannot connect externally reachable entry
points to security-relevant operations — even though both were found — the report
must say so as a named, actionable coverage gap, and depth-of-verification claims
must distinguish what was truly traced from what was confirmed by presence only. The
operator can immediately tell "scanned, nothing found" from "analysis could not
establish reachability here".

**Why this priority**: This is the general safety net. Extraction can never know
every framework's wiring idiom, so the honest-degradation contract is what turns an
unknowable future blind spot from a silent miss into an auditable gap — the
constitution's Honest Uncertainty principle applied to graph completeness.

**Independent Test**: Remove or disable middleware/driver recognition and scan a
project containing both endpoints and data access: the report must contain a named
reachability coverage gap, and its summary must not claim complete traced paths for
presence-confirmed findings.

**Acceptance Scenarios**:

1. **Given** a repository where entry points and data-access facts both exist but
   flow tracing connects none of them, **When** the scan completes,
   **Then** the report's coverage section declares a named "reachability unconfirmed"
   gap and the finding is never presented as a clean result.
2. **Given** findings confirmed by presence without a complete traced path, **When**
   the summary is rendered, **Then** traced-verified and presence-verified counts are
   stated separately and no sentence claims a complete path for presence-verified
   findings.
3. **Given** the zero-flow condition of scenario 1, **When** a finding of a
   reachability-sensitive weakness class has no traced path, **Then** its published
   status is reduced certainty with an explicit reason, not the strongest verdict.
4. **Given** an exported symbol whose name is security-meaningful (authentication,
   authorization, session, permission) with no inbound references from production
   code, **When** the graph is built, **Then** this "unattached security guard"
   condition is recorded as a graph fact available to later stages.

---

### User Story 3 - Subdivided segments keep reachability context (Priority: P2)

An engineer scans a module too large for one context slice, so it is subdivided.
Regardless of which subdivision a security-critical file lands in, the analyst
reasoning over that part still knows which external routes the module exposes and
what structural role each file plays (who references it, what wiring attaches it).
Alphabetical accident (e.g. test directories sorting first) must not decide which
part receives the entry-point context.

**Why this priority**: Reachability framing is what the model uses to judge severity
and whether an issue is in scope; losing it during routine subdivision silently
downgrades real issues — as happened in the observed miss.

**Independent Test**: Scan a repository that forces subdivision with test files
sorted first. Every subdivision part must carry the module's route enumeration and a
per-file role digest, and endpoints defined only in test files must be attributable
as test-scoped.

**Acceptance Scenarios**:

1. **Given** a module subdivided into multiple parts, **When** context packets are
   built, **Then** every part includes the module's compact route enumeration, not
   only the first part.
2. **Given** a module whose alphabetically-first files are tests, **When** parts are
   formed, **Then** production files take ordering precedence over test files for
   context-framing purposes.
3. **Given** any file in a segment, **When** packets are built, **Then** a compact,
   deterministically derived role digest (inbound references, wiring references,
   outbound calls) accompanies it.
4. **Given** endpoints detected only inside test files, **When** the graph or packets
   enumerate entry points, **Then** those endpoints are marked test-scoped so they
   cannot masquerade as production reachability.

---

### User Story 4 - Client-asserted identity is a first-class detectable weakness (Priority: P2)

An engineer scans any supported-stack project in which identity, role, or tenant is
asserted by a client-supplied request value (header, cookie, body field) and consumed
without verifying any credential, signature, or token. The weakness is detected
deterministically where the shape is recognisable, and the reasoning stages know the
archetype by name so they report it even under degraded framing. Where multiple route
groups attach the same guard and one group attaches none, that inconsistency is
surfaced as evidence.

**Why this priority**: Deterministic pattern detection survives bad framing that the
model cannot; the archetype (CWE-290 / CWE-565 family) is a recurring real-world
shape, not a one-off bug.

**Independent Test**: Scan fixture projects implementing the archetype in covered
stacks: the deterministic ruleset flags the trust decision; and a fixture where the
shape is unrecognisable still yields the finding via the reasoning stage when framing
is intact.

**Acceptance Scenarios**:

1. **Given** code reading an identity value from a client-controlled channel and
   invoking the downstream handler without any credential/signature verification,
   **When** scanned, **Then** a finding of the spoofed-identity / missing-authentication
   weakness class is produced at the trust decision.
2. **Given** several route modules in one project that attach the same guard and one
   that attaches none, **When** analysed, **Then** the unguarded module is surfaced as
   evidence or a finding rather than treated as ordinary.
3. **Given** the domain guidance presented to analysis, **When** the archetype is
   present, **Then** the guidance explicitly covers client-asserted identity without a
   credential so the weakness is in scope even under degraded reachability framing.

---

### User Story 5 - Regression net against this failure class (Priority: P3)

A maintainer changes extraction, partitioning, or reporting months later. The
accuracy benchmark contains a fixture embodying this failure class (middleware guard,
header identity, non-generic data-access calls) with declared ground truth, so any
re-introduction of the blind spot fails the build.

**Why this priority**: Prevents silent backslide; each extraction heuristic is
inherently fragile without asserted ground truth. Lower priority only because it
delivers value *through* stories 1–4 rather than alone.

**Independent Test**: Run the benchmark with and without the new substrate rules; the
fixture's expected findings must be detected, and its deliberate safe patterns must
remain unreported.

**Acceptance Scenarios**:

1. **Given** the new fixture repository, **When** the accuracy benchmark runs,
   **Then** every ground-truth finding in the fixture's defect class is asserted
   present, at the trust-decision location.
2. **Given** deliberate look-alike safe patterns in the fixture, **When** the
   benchmark runs, **Then** none is reported.
3. **Given** any change removing a substrate recognition introduced by this feature,
   **When** the benchmark runs, **Then** the build fails on the affected defect class.

---

### Edge Cases

- Middleware registered conditionally or composed dynamically (wrappers, factory
  functions, arrays spread into registrations): when the attachment cannot be
  resolved, the guard relationship is recorded as *undetermined* rather than assumed
  present or absent.
- Header/cookie reads that are demonstrably not identity-bearing (e.g. cache or
  tracing headers): source recognition must not flood findings; recognition targets
  the channel as attacker-controlled while weakness classification stays with the
  usage.
- A project legitimately architecture-free of data access (pure static site): the
  zero-connectivity gap must not fire spuriously; the gap requires positive evidence
  of both entry points and security-relevant operations.
- Presence-verified findings in a fully-traced project: the presence/path distinction
  must not downgrade findings whose weakness class is presence-valid by nature
  (e.g. hard-coded secrets).
- Custom/roll-your-own wiring idioms no pattern knows: the honest-degradation path
  (Story 2) is the specified behaviour; no guessing at attachment.

## Requirements *(mandatory)*

### Functional Requirements

**Graph extraction & wiring recognition**

- **FR-001**: The graph MUST contain traversable edges from route/endpoint nodes to
  every guard or handler function attached via framework wiring idioms (router-level
  or application-level attachment calls, and function arguments in route
  registrations), for each supported stack.
- **FR-002**: Cross-file route mounting (a wiring call attaching an imported routing
  module under a path prefix) MUST link the mount point to the imported module's
  routing nodes so guards and routes connect across files.
- **FR-003**: Reads from request headers and cookies MUST be recorded as
  attacker-controlled sources, for each supported stack's request idioms.
- **FR-004**: Data-access recognition MUST cover the calling conventions of supported
  drivers and ORMs beyond a single generic execute call; the convention catalogue
  MUST be shipped as versioned data and version-stamped in artifacts.
- **FR-005**: Security-signal recognition (authentication/authorization context
  markers) MUST match identifier-prefix conventions (e.g. `authenticateX(`,
  `verifyYToken(`), not only exact literal names, via versioned pattern data.
- **FR-006**: Exported symbols with security-meaningful names and zero inbound
  production references MUST be recorded as "unattached security guard" graph facts.

**Honest degradation & verification truthfulness**

- **FR-007**: When entry points and security-relevant operations both exist in a
  project but flow tracing connects none of them (exact zero; any relaxed threshold
  is configuration per Assumptions), the scan
  MUST declare a named "reachability unconfirmed" coverage gap in the report; the
  absence of flows MUST NEVER read as a clean or complete result.
- **FR-008**: Verification outcomes MUST distinguish presence-confirmed from
  path-traced confirmation via an additive `basis` field on the verification
  record (`traced` | `presence`); the status vocabulary MUST NOT change
  (`verified`/`plausible`/`disproven`), so triage admission, calibration caps,
  and answer/resume keys are unaffected. The report summary MUST state the two
  counts separately and MUST NOT claim a complete source-to-sink path for
  presence-confirmed findings.
- **FR-009**: While the FR-007 gap is active, reachability-sensitive findings of
  weakness classes whose verdict rests on reachability (notably missing
  authentication) MUST be demoted one level — presence-confirmed becomes
  `plausible` with the named gap as its documented reason — never the strong
  verdict. Weakness classes whose finding IS presence-in-source by nature
  (hard-coded secrets, insecure configuration states) keep their verdict.
- **FR-010**: Unresolved guard attachment (Edge Case: conditional/dynamic wiring)
  MUST be recorded as a distinct undetermined state with a reason; it MUST NOT
  suppress a finding and MUST NOT inflate severity.
- **FR-020**: A control that a finding implicates MUST NOT refute or downgrade that
  finding. The accusation perimeter comprises the finding's location, every piece
  of its evidence, and its related symbols. At the deterministic verification gate,
  a mitigating annotation on the traced path counts only when it does not resolve
  to an implicated location. At the reasoning triage stage, a `refuted` or
  `downgraded` verdict whose citations resolve to implicated locations MUST be
  rejected wholesale (the finding proceeds as untriaged). Only an independent
  control elsewhere on the path may refute.

**Context partitioning & packet framing**

- **FR-011**: Every subdivided part of a module MUST receive the module's compact
  externally-reachable-route enumeration; subdivision MUST NOT concentrate
  reachability context into one part.
- **FR-012**: Production files MUST take precedence over test/example files in
  subdivision ordering, and endpoints defined only within test-files MUST be
  attributed as test-scoped wherever entry points are enumerated.
- **FR-013**: Every segment context packet MUST include a per-file role digest
  derived deterministically from the graph (inbound references, wiring references,
  outbound calls), so a file's structural role is visible even where full edges are
  absent.

**Detection archetypes**

- **FR-014**: Versioned detection rules MUST cover the client-asserted-identity
  archetype: identity/role/tenant read from a client-controlled channel, consumed
  with no credential, signature, or token verification, followed by dispatch into
  the handler; per supported stack; shipped as data, never requiring pipeline-stage
  changes to extend. Archetype rule matches are **format detections**: demonstrated
  code shape is presence-valid, so they enter the triage round only at or above the
  configured minimum severity band, and reasoning `refuted` verdicts are invalid
  for them — the reasoning stage may only confirm, downgrade from cited context, or
  flag with a concrete user question.
- **FR-015**: Authentication domain guidance presented to reasoning stages —
  segment analysis, finding triage, and system review alike — MUST
  explicitly include the client-asserted-identity-without-credential archetype
  (CWE-290/CWE-565/CWE-306 family).
- **FR-016**: When multiple route modules in one unit attach a shared guard and some
  attach none, the inconsistency MUST be surfaced as packet evidence (per-file role
  digest) and in the system-level review — never normalised away — but MUST NOT be
  emitted as a standalone finding: deterministic absence of a guard is not per se a
  weakness, and each evidence-only item would otherwise consume a triage round.

**Governance & regression**

- **FR-017**: All new recognitions (conventions, source channels, patterns, rules)
  MUST ship as versioned data with a data-version stamp recorded in affected
  artifacts; schema changes MUST be additive.
- **FR-018**: The accuracy benchmark MUST include a fixture embodying this failure
  class with declared ground truth (including deliberate look-alike safe patterns
  that MUST NOT be reported); a regression in the new defect class MUST fail the
  build.
- **FR-019**: Determinism and safety invariants MUST be preserved: identical input
  plus identical data/tool versions yield byte-identical artifacts; all recognition
  is offline and read-only against the scanned project.
- **FR-021**: Recall assurance MUST be exercised off the per-scan path. It is
  provided by the accuracy benchmark's per-defect-class ground-truth assertions
  (FR-018), the declared coverage gaps (FR-007) with their certainty demotions
  (FR-009), and deterministic detection rules independent of reasoning (FR-014).
  A production scan MUST NOT re-examine zero-finding segments speculatively, and a
  segment with no findings and no applicable declared gap reads as "analyzed, no
  findings" — the gaps, never the absence, carry the residual-risk signal.

### Key Entities *(include if feature involves data)*

- **Wiring Edge**: A traversable graph relationship expressing "route/entry point is
  guarded or handled by symbol X" — including attachment kind (route-level,
  module-level, application-level) and a determination state (attached / unattached /
  undetermined).
- **Request Source**: A recorded site where attacker-controlled input enters —
  attributes: channel (parameter, body, header, cookie), stack idiom, containing
  symbol.
- **Guard Attachment Matrix**: Per-unit mapping of route modules to their attached
  guards, including explicit absence; consumed by packets, verification, and the
  system-level review.
- **Coverage Gap (reachability)**: A named, reasoned declaration that flow tracing
  could not connect entry points to security-relevant operations; attributes: cause,
  affected scope, operator action.
- **Verification Grade**: Resolved finding confirmation strength —
  path-traced / presence-confirmed / reduced-certainty-with-reason — recorded per
  finding and aggregated honestly in the summary.
- **Recognition Catalogue**: Versioned data defining naming patterns, calling
  conventions, source-channel idioms, and archetype rules per supported stack.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Re-scanning a reference project with middleware-attached, header-asserted
  identity produces a Critical/High finding located at the trust-decision function —
  100% of runs on the reference fixture.
- **SC-002**: In 100% of benchmark scans where entry points and security-relevant
  operations both exist but cannot be flow-connected, the report contains a named
  reachability coverage gap; zero silent zero-flow reports.
- **SC-003**: Zero occurrences across the benchmark corpus of a summary claiming a
  complete traced path for a presence-confirmed finding.
- **SC-004**: The new defect class ("guard-hidden trust boundary") is asserted per
  class in the accuracy benchmark; overall benchmark remains green with zero new
  reports against deliberate look-alike safe patterns.
- **SC-005**: Every finding previously detected in the benchmark corpus is still
  detected (no recall regression in any existing class).
- **SC-006**: Repeated scans of the same unchanged input remain byte-identical,
  including during the FR-007 degraded-coverage condition.

## Assumptions

- Recognition breadth follows the stacks the tool already supports; per-stack
  recognitions ship incrementally as versioned data, and an unrecognised idiom within
  a supported stack degrades via Story 2's declared gap rather than failing the scan.
- The reference failure pattern is defined by the observed miss (JavaScript/Express
  style middleware with header-asserted identity); Story 1's acceptance uses that
  fixture, but all mechanisms are specified stack-neutrally.
- "Negligibly small fraction" in FR-007 defaults to zero connected flows; the exact
  threshold, if any is later justified, is configuration, not a spec change.
- Test-scope attribution reuses existing file-classification conventions; no separate
  test-detection subsystem is introduced.
- Executable probing of suspected runtime wiring remains out of scope (constitution:
  observe, never attack); all recognition is static.

## Out of Scope

- Per-scan recall sweeps that re-examine zero-finding segments (see FR-021; recall
  is assured by the benchmark and declared gaps, not by speculative re-analysis).
- Supporting frameworks/stacks the tool does not already claim to support.
- Any runtime or dynamic analysis of the scanned project.
- Changes to finding schema semantics beyond additive fields for the new states.
