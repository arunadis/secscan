# Feature Specification: Reduce Missed Detections (False Negatives)

**Feature Branch**: `004-reduce-missed-detections`

**Created**: 2026-08-31

**Status**: Draft

**Input**: User description: "A comparison of this scanner's report against another scanner's report on the same repository (uc-framework-upgrade-monolith-to-microservices) found verified-real issues this scanner missed: (1) no GraphQL depth/complexity limit enabling unauthenticated DoS — /graphql is permitAll, the schema has an Article↔Comment cycle, and no depth/complexity config exists anywhere — requiring cross-file reasoning (schema shape + absence of config); (2) seed data provisioning loginable accounts with a shared, documented password (V2__seed_data.sql seeds users with bcrypt('password123'), plaintext in a comment) — requiring cross-file reasoning (migration + public login mutation); (3) CORS allowedOrigins('*') and csrf().disable() in WebSecurityConfig.java:38-40, missed by both scanners — this scanner's coverage section shows redaction blocked a value in that very file; (4) marked@^1.1.1 carrying known ReDoS CVEs, mentioned only inside the XSS finding, never reported as a dependency issue. The scanner's own coverage section also admits blocked values in 5 segments and 1 file dropped for token budget. What can be done to fix these misses?"

## Clarifications

### Session 2026-08-31

- Q: Should v1 ship only the two evidenced compound weakness patterns as fixed checks, or a data-driven compound-rule framework with those two as its first rules? → A: A data-driven compound-rule framework, with GraphQL depth-DoS and seed-data shared password as its first shipped rules — consistent with the constitution's extensibility-as-data principle; new compound patterns must not require pipeline-stage changes.
- Q: How broad should the initial deterministic misconfiguration rule set be? → A: The four named checks (CSRF disabled, wildcard CORS, sensitive endpoints anonymous, dev consoles exposed) plus the top OWASP misconfiguration patterns for every supported stack — each rule still requires must-find and must-not-find fixtures.
- Q: Which dependency ecosystems must the offline advisory data cover in v1? → A: All supported ecosystems (JVM, Node, Python, Go) — every ecosystem ships with asserted benchmark fixtures so no advisory data ships untested.
- Q: Must compound findings assemble evidence legs across repository boundaries in multi-repository workspaces? → A: No — single-repository compound detection only for v1; cross-repository evidence legs are out of scope. Both evidenced misses are single-repository, and per-repo legs keep absence-of-control search spaces verifiable.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Dangerous security configuration is always detected (Priority: P1)

A security engineer scans a repository whose security configuration disables CSRF protection and allows wildcard CORS origins. The scanner analyses the file — it even publishes two other findings from it — yet says nothing about these textbook misconfigurations, because no deterministic check exists for them and the model's attention was elsewhere (the file also had a redaction-blocked value, and the analysis even referenced the blocked marker as if it were a filename).

Security-relevant configuration states are structural facts, not matters of model judgment. Dangerous configurations — CSRF protection disabled, wildcard CORS origins, sensitive endpoints permitting anonymous access, development consoles exposed — MUST be detected deterministically and reported every time, regardless of what else happens in the file.

**Why this priority**: This is the cheapest class to fix and the most embarrassing to miss: these are pattern-detectable facts that a reviewer spots in seconds, and their absence destroys the report's credibility ("it found the subtle JWT issue but not `csrf().disable()`?").

**Independent Test**: Scan a fixture project containing `csrf().disable()` and `allowedOrigins("*")` in its security configuration and confirm findings are published — including a variant where an unrelated high-entropy value elsewhere in the same file is redacted or blocked.

**Acceptance Scenarios**:

1. **Given** a project whose security configuration disables CSRF protection and allows wildcard CORS origins, **When** the scan runs, **Then** both are reported as findings with exact locations.
2. **Given** the same configuration file also contains a value that redaction blocks, **When** the scan runs, **Then** the configuration findings are still reported — redaction of an unrelated value MUST NOT degrade extraction of structural security facts.
3. **Given** a new dangerous-configuration pattern needs to be covered, **When** it is added, **Then** it ships as versioned data without changes to any pipeline stage.

---

### User Story 2 - Compound findings are assembled across files (Priority: P1)

The most damaging misses require combining evidence that no single segment contains: a public endpoint *plus* a cyclic query schema *plus* the *absence* of any depth/complexity limit is an unauthenticated DoS; a seed-data migration with a shared documented password *plus* a public login mutation is a credential-stuffing gift. Segment-local analysis cannot see these, and "the model didn't notice" is not an acceptable reason.

The scanner MUST assemble compound findings at the whole-repository level from deterministic evidence. Crucially, a claim that a control is *absent* ("no depth limit configured anywhere") MUST be backed by a deterministic search of the repository's configuration space — never by the model not having seen one. Where the configuration space cannot be fully enumerated, the control state is `undetermined` and the finding says so.

**Why this priority**: The two verified misses the comparison surfaced are both this class, and this class is where segment-local architecture systematically blinds the scanner — it cannot be fixed by tuning prompts.

**Independent Test**: Scan a fixture repository containing a public query endpoint with a cyclic schema and no depth-limiting configuration, and confirm a compound finding is published citing each leg of evidence (endpoint authz, schema cycle, searched configuration space); then add a depth-limit configuration in an arbitrary location and confirm the finding changes accordingly.

**Acceptance Scenarios**:

1. **Given** a repository with a publicly accessible GraphQL endpoint, a cyclic schema, and no depth/complexity configuration anywhere, **When** the scan runs, **Then** a compound DoS finding is published citing all three legs of evidence, including the configuration space that was searched to prove absence.
2. **Given** a repository whose seed migration provisions loginable accounts with a shared, documented password reachable through a public authentication mutation, **When** the scan runs, **Then** a finding is published citing both the migration and the mutation — without exposing the password value in any artifact.
3. **Given** a repository where the presence of a control cannot be determined (e.g. configuration may live in a format the scanner does not parse), **When** the scan runs, **Then** the finding is presented as plausible with the undetermined leg named — never as verified absence, and never silently suppressed.

---

### User Story 3 - Known-vulnerable dependencies are first-class findings (Priority: P2)

A reviewer reads that `marked@^1.1.1` "carries known ReDoS CVEs" — but only as a remark inside an XSS finding. There is no dependency finding to ticket, assign, or track to resolution. Known-vulnerable components MUST be reported as findings in their own right: the advisory identity, the affected version range, the project's pinned version, and where the dependency is declared.

**Why this priority**: Dependency vulnerabilities are the most actionable findings a scanner can produce (upgrade a version, done) and the easiest to verify — yet they are currently invisible as trackable items.

**Independent Test**: Scan a fixture project pinning a dependency version with a known published advisory and confirm a first-class finding is produced naming the advisory and the pinned version.

**Acceptance Scenarios**:

1. **Given** a project pinning a dependency version within a known advisory's affected range, **When** the scan runs, **Then** a finding is published naming the advisory, the affected range, the pinned version, and the manifest location.
2. **Given** advisory data is unavailable or stale for an ecosystem, **When** the scan runs, **Then** that outcome is recorded as could-not-check with the reason — never reported as clean.
3. **Given** the default scan path, **When** dependency auditing runs, **Then** it uses versioned advisory data shipped with the scanner — no network access.

---

### User Story 4 - Coverage gaps can never hide a finding silently (Priority: P3)

The scanner's own coverage section admitted blocked values in five segments and a file dropped for token budget — but nothing in the pipeline treats those gaps as potential missed findings. A dropped or partially-masked security-critical file is a recall risk, not a footnote. Every coverage gap MUST be evaluated for security impact, and gaps touching security-critical files (security configuration, authentication, authorization, migrations) MUST be flagged prominently with what class of issue could be hiding there.

**Why this priority**: This is the honest-uncertainty backstop for everything above — and it is what turns the coverage section from an apology into an actionable work list. Lower priority because US1–US3 remove the most common consequences.

**Independent Test**: Scan a fixture project engineered to force a coverage gap inside a security-critical file (e.g. a blocked value in the security configuration) and confirm the report's coverage section names the file, the cause, and the security- impact assessment — and that deterministic config extraction (US1) still succeeded despite the gap.

**Acceptance Scenarios**:

1. **Given** a scan where a value is blocked or a file is dropped within a security-critical file, **When** the report is generated, **Then** the coverage section names the file, the cause, and what could not be assessed.
2. **Given** a coverage gap in a non-security-critical file, **When** the report is generated, **Then** the gap is still recorded but ranked below security-critical gaps.

---

### Edge Cases

- **Control present in an unrecognized location or format**: absence-of-control claims MUST degrade to `undetermined` with the unsearched space named — an unproven negative is never asserted (constitution Principle V).
- **Seed data clearly intended for development only**: still reported. Real-world breaches come from exactly this pattern reaching deployed environments; severity and description reflect the deployment-context uncertainty rather than suppressing the finding.
- **Compound finding with one leg undetermined**: the finding is published as plausible with the weak leg named — an unknown never buys silence.
- **Dependency pinned via lockfile vs manifest**: the finding cites both where available; a lockfile-only pin is still reported.
- **Fixture repositories that are sample/demo apps**: the reference repository is itself a workshop sample; findings are reported identically — it is the deployer's choice to act, not the scanner's to forgive.
- **Redaction of seed-data secrets**: values are withheld from analysis context as always; the *finding* (seeded credential pattern) is emitted deterministically without the value, exactly as hard-coded-secret findings already are.

## Requirements *(mandatory)*

### Functional Requirements

**Deterministic misconfiguration detection**

- **FR-001**: The system MUST deterministically detect dangerous security-configuration states — at minimum: CSRF protection disabled, wildcard CORS origins, sensitive endpoints permitting anonymous access, and development consoles exposed — and report them as findings with exact locations. Beyond these four, the initial rule set MUST also cover the top OWASP misconfiguration patterns for every supported stack (clarified 2026-08-31); every rule ships with both a must-find fixture and a must-not-find fixture.
- **FR-002**: Security-fact extraction MUST be resilient to redaction: a redacted or blocked value elsewhere in a file MUST NOT prevent extraction of unrelated structural security facts from that file.
- **FR-003**: New misconfiguration checks MUST be addable as versioned data (patterns, applicable stacks, severity, weakness identifier) without modifying any pipeline stage.

**Compound cross-file detection**

- **FR-004**: The system MUST assemble findings whose evidence spans multiple files or segments — each leg established by deterministic whole-repository evidence — at the whole-repository review level. Compound weakness patterns MUST be defined as data-driven rules shipping as versioned data (extensibility as data); adding a new compound pattern MUST NOT require modifying any pipeline stage. The initial rule set includes at minimum the GraphQL depth-DoS pattern and the seed-data shared-password pattern. Evidence legs are scoped to a single repository (clarified 2026-08-31); cross-repository legs are out of scope for this feature.
- **FR-005**: Every absence-of-control claim MUST be backed by a deterministic search of the repository's configuration space, and the finding MUST cite the space that was searched. If the space cannot be fully enumerated, the control state MUST be recorded as `undetermined` and the finding MUST present the claim as plausible with the unsearched space named.
- **FR-006**: Compound findings MUST carry resolvable locations for every leg of their evidence; a finding whose legs cannot all be evidenced MUST NOT be published as verified.

**Dependency vulnerability findings**

- **FR-007**: The system MUST report components with known vulnerabilities as first-class findings, each naming the advisory identity, affected version range, the project's pinned version, and the declaration location. Advisory coverage MUST span every ecosystem the scanner supports — JVM, Node, Python, and Go (clarified 2026-08-31) — with benchmark fixtures per ecosystem so no advisory data ships untested.
- **FR-008**: Dependency auditing MUST run offline against versioned advisory data shipped with the scanner; when advisory data is unavailable or stale for an ecosystem, the outcome MUST be recorded as could-not-check with the reason, and MUST NOT read as clean.

**Coverage and recall governance**

- **FR-009**: Security-relevant data files — including database migrations and seed data — MUST be within analysis scope, and seeded-credential patterns (shared or documented passwords provisioning loginable accounts) MUST be detected deterministically without exposing values.
- **FR-010**: Every coverage gap MUST record its cause, the affected file, and a security-impact assessment; gaps in security-critical files MUST be ranked prominently in the report's coverage section.
- **FR-011**: A curated must-find corpus for reference repositories MUST gate the build: every expected finding on the corpus MUST be detected, and any miss fails the build — per defect class, so a recall regression in one class cannot be masked by improvements elsewhere.
- **FR-012**: Recall expansion MUST NOT regress precision: the false-positive corpus and the guarantees of feature 003 MUST continue to pass unchanged.

### Key Entities

- **Control Check**: a data-driven rule describing a dangerous configuration state — pattern, applicable stacks and file classes, severity, weakness identifier, and the rationale. Ships as versioned data. Initial set: the four evidenced checks plus the top OWASP misconfiguration patterns per supported stack (clarified 2026-08-31).
- **Compound Finding Rule**: a named weakness pattern defined as a set of evidence legs, each leg a deterministic whole-repository requirement (presence of X, absence of Y over a declared search space); a finding is published only when every leg is evidenced, with per-leg states supporting `undetermined`. Ships as versioned data (clarified 2026-08-31): the initial rule set is GraphQL depth-DoS and seed-data shared password.
- **Dependency Advisory**: a known-vulnerability record — advisory identity, ecosystem, affected version ranges, fix guidance — shipped versioned with the scanner. Related to **Component Instance**: a pinned dependency at a specific version with its declaration location.
- **Must-Find Corpus Entry**: a reference-repository, expected-finding pair with weakness class and rationale, versioned alongside the scanner; the build gate defined by FR-011 evaluates it.
- **Coverage Gap** (extended): cause (blocked value | budget-dropped file | unparsed format), affected file, security-impact assessment, and disposition.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On the reference repository from the comparison, 100% of the previously missed issue classes are now detected: the GraphQL depth/complexity DoS, the seed-data shared password, the CORS wildcard, the CSRF disablement, and the `marked` ReDoS advisories as a first-class dependency finding.
- **SC-002**: 100% of the must-find corpus is detected on every build; a single miss fails the build.
- **SC-003**: Every absence-of-control finding cites the configuration space searched to establish absence — 100% of "no X configured" claims are independently verifiable from the report.
- **SC-004**: 100% of known-vulnerable pinned components in the benchmark corpus — spanning every supported ecosystem — produce first-class dependency findings.
- **SC-005**: Zero recall regressions: every finding class detected before this feature is still detected; zero new false positives on the false-positive corpus maintained under feature 003.
- **SC-006**: No finding is silently lost to a coverage gap: 100% of blocked values and budget-dropped files carry a cause and security-impact assessment in the report, with security-critical gaps ranked first.

## Assumptions

- **Reference baselines**: the `codev-workshops/uc-framework-upgrade-monolith-to-microservices` comparison scan (report `20260831T071644Z-c3b48b`, 8-finding external CSV) and the `skh` workspace scan seed the must-find corpus; both are real, reviewable ground truth.
- **Bounded context is preserved**: compound findings are assembled from deterministic whole-repository evidence and summaries — the whole-repository stage never receives raw segment source in bulk (constitution Principle II).
- **Redaction precedence is unchanged**: values never reach a model; deterministic detectors emit findings about secrets without values, as hard-coded-secret findings already do (constitution Principle III).
- **Offline default**: dependency advisory data ships versioned inside the scanner payload; no network access is added to the default path (constitution Principle I).
- **Deterministic-first division of labor**: everything pattern-detectable (config states, dependency versions, seeded-credential shapes) is detected deterministically; model reasoning is reserved for judgment over prepared evidence, never for discovery (constitution Principle I).
- **Interaction with feature 003**: the false-positive reduction work proceeds in parallel; this feature's recall expansion is gated by 003's precision corpus (FR-012) so the two cannot trade against each other silently.
- **Out of scope — cross-repository compound evidence**: compound finding legs are assembled within a single repository only (clarified 2026-08-31). Multi-repository workspaces still benefit from per-repo compound detection; cross-repo legs are a future extension.
