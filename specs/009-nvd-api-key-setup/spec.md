# Feature Specification: NVD API Key Setup During Initialization

**Feature Branch**: `009-nvd-api-key-setup`

**Created**: 2026-09-02

**Status**: Draft

**Input**: User description: "I need to enhance the tool to configure the NVD_API_KEY at the time of initialization. if the key is not provided indicate the implications to the user and give the option to skip the installation/configuration"

## Clarifications

### Session 2026-09-02

- Q: When a user chooses "provide a key" in the middle of an interactive initialization run, how should initialization bring that key into effect? → A: Install-and-wire by name — the tool is installed/configured referencing `NVD_API_KEY` by name, the user is told how to set it in their shell, and the report shows "awaiting key" until the variable is present; the key takes effect at scan time once set, and re-running init upgrades the status to fully configured. The secret value is never prompted for, passed through init, or persisted.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Provide an NVD API key during initialization (Priority: P1)

A user runs the tool's initialization for the first time. During the external-tooling
step, initialization detects that an NVD-backed dependency-audit tool (a tool that
downloads data from the National Vulnerability Database) is part of the install plan.
Initialization asks the user whether they have an NVD API key, guides them to where
the key can be requested, and records how the key will be supplied at scan time
(by environment-variable *name* only — the key's value is never written into any
file, echoed back, or persisted in configuration). The tool installation and
configuration then proceed with the key in place, so the tool's NVD data sync runs
at full speed.

**Why this priority**: This is the happy path the feature exists to enable. Without
a key, the NVD-backed audit is severely degraded; getting the key configured at
init time — before the first scan — prevents a poor first-run experience and hours
of unexplained slowness inside the first scan.

**Independent Test**: Can be fully tested by running initialization with the key
already present in the environment (or supplying it when prompted) and confirming
that (a) initialization reports the key as available for the NVD-backed tool,
(b) the tool's installation/configuration proceeds with the key wired in, and
(c) the key value never appears in any generated file, log, or output.

**Acceptance Scenarios**:

1. **Given** the NVD API key is already set in the environment, **When** the user
   runs initialization, **Then** initialization detects it, reports the key as
   available for the NVD-backed tool (by variable name, never value), and proceeds
   with installation/configuration without prompting for the key.
2. **Given** no key is set and initialization is interactive, **When** the user
   chooses to provide a key, **Then** initialization tells the user where to obtain
   a key and exactly how to make it available in their shell environment
   (`NVD_API_KEY`), proceeds to install and configure the tool wired to the
   environment-variable reference by name only, and reports the tool as
   "awaiting key" until the variable is present — the key value is never prompted
   for, written to disk, or passed through initialization.
3. **Given** the tool was installed in "awaiting key" status and the user later
   sets `NVD_API_KEY`, **When** initialization is re-run (or a scan runs),
   **Then** the key takes effect at scan time and a re-run of initialization
   upgrades the reported status from "awaiting key" to fully configured.

---

### User Story 2 - Initialize without an NVD API key (informed choice) (Priority: P2)

A user runs initialization without an NVD API key (and does not have one handy).
Initialization clearly explains the implications of proceeding keyless — the
NVD-backed tool's first data download is heavily rate-limited without a key and can
take many times longer; repeated rate-limiting can also cause the tool's data sync
to fail intermittently — and then offers an explicit choice: skip the
installation/configuration of the affected NVD-backed tool(s), or proceed anyway in
degraded mode. Skipping does not block initialization of everything else; the
remaining checks and tools initialize normally, and initialization still reports
"ready" — with the skipped tool declared as *deliberately skipped*, not missing by
accident.

**Why this priority**: This is the explicit behavior the user asked for (indicate
implications, offer to skip). It is P2 rather than P1 only because it depends on the
same prompt/detection machinery as P1; as a user-facing outcome it carries equal
weight — a user pushed through a multi-hour rate-limited download without warning
is the failure mode this feature prevents.

**Independent Test**: Can be fully tested by running initialization interactively
with no key set and choosing "skip": the NVD-backed tool is excluded from the
install plan, initialization completes successfully, and the report names the tool
as skipped with a one-line note on how to add it later.

**Acceptance Scenarios**:

1. **Given** no NVD API key is set and initialization is interactive, **When** the
   NVD-backed tool step is reached, **Then** the user sees a plain-language warning
   of the implications (rate-limited, much slower first sync, possible intermittent
   sync failures) before any installation of that tool begins.
2. **Given** the warning has been shown, **When** the user chooses to skip, **Then**
   the NVD-backed tool is removed from the install plan, no part of its
   installation or configuration runs, and the init report lists the tool as
   "skipped — re-run init to add it later".
3. **Given** the warning has been shown, **When** the user explicitly chooses to
   proceed without a key, **Then** the tool is installed/configured and the report
   marks it as degraded (no NVD key) so the later slow sync is not a surprise.
4. **Given** the tool was skipped earlier, **When** the user re-runs initialization
   after acquiring a key, **Then** the tool can be installed/configured normally.

---

### User Story 3 - Non-interactive initialization behaves deterministically (Priority: P3)

A user (or automation) runs initialization in a non-interactive/headless context
(CI, scripts). Initialization never hangs waiting for an NVD-key answer: with no
key present and no explicit instruction, the NVD-backed tool is skipped by default
and the skip is declared in the report with its reason. The user can still opt into
installing the tool keyless via an explicit non-interactive instruction.

**Why this priority**: Matters for automation but is a narrowly applicable path;
the interactive flows (P1/P2) cover the primary audience.

**Independent Test**: Can be fully tested by running initialization in
non-interactive mode with no key set and verifying it completes without any prompt,
skips the NVD-backed tool, and reports the skip.

**Acceptance Scenarios**:

1. **Given** non-interactive initialization with no key and no explicit opt-in,
   **When** initialization runs, **Then** it never prompts, skips the NVD-backed
   tool, declares the skip and reason in the report, and completes successfully.
2. **Given** non-interactive initialization with the key set in the environment,
   **When** initialization runs, **Then** the NVD-backed tool is installed and
   configured with the key available, without any prompt.

---

### Edge Cases

- **Key variable set but empty**: An empty value is treated as *not provided* — the
  same warning and skip/proceed choice as a missing key.
- **Pre-existing NVD-backed tool installation**: If the tool is already installed
  on the system, initialization still performs the key check and reports the tool's
  key status (available/degraded); it does not skip the check just because no
  installation is required.
- **User consents to "install all tools" but has no key**: A blanket "install all"
  consent does NOT silently include the NVD-backed tool in degraded mode; the
  keyless warning and skip/proceed decision is still surfaced for that tool
  (interactive) or it is skipped with a declared reason (non-interactive), unless
  the user has explicitly pre-authorized keyless installation.
- **Key present but invalid/expired**: Initialization does not validate the key
  against the NVD service (no network call just to check a credential). An invalid
  key surfaces as a tool data-sync failure at scan time; initialization states that
  it checks presence, not validity.
- **Key set between init runs**: A tool left in *awaiting key* status upgrades to
  *configured with key* on the next initialization run without re-installing, and
  the key works at scan time the moment it is present in the environment.
- **Init re-run after skipping**: Skipping is not sticky state that blocks the
  tool forever; a later init run with a key (or an explicit opt-in) installs and
  configures the tool normally.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: During initialization, the system MUST identify which tools in the
  install plan depend on National Vulnerability Database access (the NVD-backed
  set), and MUST perform an NVD API key presence check whenever any such tool is
  to be installed or configured — including when the tool is already installed on
  the system.
- **FR-002**: The key presence check MUST look for the key exclusively by
  environment-variable presence (`NVD_API_KEY`), consistent with the project rule
  that credentials are supplied only by environment-variable name and never stored
  in configuration. An unset or empty variable counts as *not provided*.
- **FR-003**: Initialization MUST NOT validate the key against the NVD service
  (no network access solely for credential validation); it checks and reports
  presence only, and states this limitation when reporting "available".
- **FR-004**: When no key is provided and initialization is interactive, the
  system MUST present the implications of proceeding without a key before any
  installation or configuration of the NVD-backed tool(s) begins: the tool's NVD
  data download is heavily rate-limited without a key, the first sync can take
  many times longer, and rate-limiting can cause intermittent sync failures.
- **FR-005**: Following that warning, the system MUST offer the user an explicit
  choice: (a) skip installation/configuration of the NVD-backed tool(s), (b)
  proceed without a key in degraded mode, or (c) provide a key. Choosing "provide
  a key" MUST guide the user to obtain one and make it available in their shell
  environment (`NVD_API_KEY`); initialization then proceeds to install and
  configure the tool(s) wired to the environment-variable reference by name only
  and reports them as *awaiting key*. The system MUST NEVER prompt for the key
  value directly, echo it, write it to any file, or attempt to read a value the
  user sets in another shell (a key set after init started is not visible to the
  running process — the presence check re-runs on the next init run or at scan
  time).
- **FR-006**: When the user chooses to skip, the system MUST exclude the
  NVD-backed tool(s) from the install plan, run no part of their installation or
  configuration, and MUST NOT count the skip as a failure — initialization still
  reports "ready" if all remaining required checks pass.
- **FR-007**: The initialization report MUST declare the NVD key/tool status in a
  distinct state for each outcome: *configured with key*, *awaiting key —
  installed, key not yet present* (the install-and-wire path of FR-005c), *degraded
  — no key (explicit user choice)*, or *skipped — no key*; a skipped tool is never
  presented as though it were merely absent, and a degraded or awaiting-key tool
  is never presented as fully configured. Re-running initialization once the key
  is present MUST upgrade an *awaiting key* tool to *configured with key*.
- **FR-008**: The report MUST tell the user how to add a skipped tool later
  (re-run initialization after setting the key or explicit opt-in), and
  re-running initialization after a skip MUST allow the tool to be installed and
  configured normally.
- **FR-009**: In non-interactive mode (no prompting), initialization MUST NEVER
  wait for an NVD-key answer: with no key present, the NVD-backed tool(s) are
  skipped by default and the report declares the skip and its reason; an explicit
  documented opt-in permits keyless installation; with the key present, the tools
  install normally.
- **FR-010**: A blanket consent to install all tools MUST NOT silently include an
  NVD-backed tool in degraded mode: interactively, the keyless warning/choice from
  FR-004/FR-005 still applies; non-interactively, the tool is skipped unless
  keyless installation was explicitly pre-authorized.
- **FR-011**: The key's value MUST NOT appear in any initialization output, log,
  generated configuration, or state file — status is reported by variable name
  and presence only.

### Key Entities *(include if feature involves data)*

- **Credential Reference**: The association between an external tool and the
  environment-variable *name* that supplies its credential. Carries presence state
  (available / not provided) — never the credential value.
- **Tool Install Decision**: The per-tool outcome of initialization: installed,
  already present, skipped (with reason), or degraded (installed but credential
  missing, with user consent). Recorded in the initialization report and tooling
  availability state.
- **NVD-backed Tool Set**: The subset of the external tooling registry whose
  operation depends on National Vulnerability Database access; membership is
  declared per tool so the key check applies automatically to current and future
  NVD-backed tools.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of initialization runs in which an NVD-backed tool is in scope
  report the NVD key status in exactly one of the four declared states
  (configured / awaiting key / degraded / skipped) — no silent absence of key
  information.
- **SC-002**: A user without a key completes interactive initialization (including
  reading the warning and choosing skip or proceed) in under 2 minutes of added
  time compared with a keyless run before this feature.
- **SC-003**: Non-interactive initialization never blocks waiting for input:
  100% of headless runs terminate and report the NVD-backed tool's outcome without
  any prompt.
- **SC-004**: 0 occurrences of the key value appearing in any initialization
  output, log, or file (verified by a redaction-style sweep over generated
  artifacts when the key is supplied).
- **SC-005**: A user who skipped the tool can re-run initialization after
  obtaining a key and reach a fully configured state in a single additional run.
- **SC-006**: 100% of users shown the keyless warning state that they understood
  the implication (slow, rate-limited first sync) before choosing — measurable in
  usability testing; at minimum the warning text states the implication in plain
  language understandable to a first-time user.

## Assumptions

- The NVD API key is supplied only via the `NVD_API_KEY` environment variable,
  by-name, consistent with the project's existing credential rule (credentials are
  referenced by environment-variable name, never stored in configuration). The
  feature therefore "configures the key" by detecting it, guiding its setup, and
  wiring the variable reference into the tool's invocation — not by persisting any
  secret.
- The primary NVD-backed tool today is the OWASP Dependency-Check
  installation/configuration introduced in feature 008; the prompt/skip logic is
  defined generically (`NVD-backed tool set`) so any future tool that syncs NVD
  data inherits the same behavior without spec changes.
- "Initialization" means the existing `init` command flow (configuration
  generation plus environment/tooling checks and the consented install plan), not
  a separate wizard.
- The rate-limit implications described to the user reflect NVD's public guidance
  (keyless requests are heavily throttled; the first full data sync without a key
  is dramatically slower and more failure-prone).
- Skipping is a per-run decision with a "how to add later" note, not persisted
  state that permanently disables the tool; persisted suppression of the prompt is
  out of scope for this feature.
- Live validation of the key against the NVD service is out of scope; presence
  checking only.
