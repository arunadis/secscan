<!--
SYNC IMPACT REPORT
==================
Version change: 1.1.0 → 1.2.0 (2026-09-04)

MINOR: materially expanded guidance under Development Workflow & Quality Gates.
The "Honest documentation" gate previously required only that README status
claims match the repository; it now normatively enumerates the README surfaces
that MUST be reconciled with every implementation change (Status header,
Roadmap, feature lists, command/exit-code references, artifact layout) and
requires that "specified, not yet built" claims be re-verified against the code
whenever a change could have closed them. Trigger: a 2026-09-04 review found the
README Roadmap describing shipped features (specs 005, 008–014) as missing and
omitting exit code 4 — staleness discovered by manual inspection, not by a gate.

Modified principles: none (no Core Principle touched; the expanded rule is a
quality gate, not a principle).
Added sections: none.
Removed sections: none.
Placeholders resolved: none.
Deferred TODOs: none.

--- 1.0.1 → 1.1.0 ---

Version change: 1.0.1 → 1.1.0 (2026-09-02)

MINOR: materially expanded guidance under Development Workflow & Quality Gates.
The "Honest documentation" gate previously covered README status claims only; it
now normatively requires documentation updates to accompany every behavioral,
contract, or structural change in the same change set, across the full docs
surface (README, docs/, CONTRIBUTING, spec records).

Modified principles: none (no Core Principle touched; the expanded rule is a
quality gate, not a principle).
Added sections: none.
Removed sections: none.
Placeholders resolved: none.
Deferred TODOs: none.

--- 1.0.0 → 1.0.1 ---
Version change: 1.0.0 → 1.0.1 (2026-08-31)

PATCH: factual update to the Known Non-Compliance register only. No principle was
added, removed, or redefined, and no normative statement changed — so this is a
clarification rather than a MINOR bump.

  - All three gaps recorded at ratification (Principles II, IV, V) are closed by
    feature 002-scan-accuracy-hardening, and the register now says so with the
    specific mechanism that closed each one.
  - The register retains the resolved entries rather than deleting them: a
    constitution that shows what was wrong and how it was fixed is more useful
    than one that shows only the current state.

--- original ratification report ---

Version change: (unversioned template) → 1.0.0

Rationale: first ratification. The file previously contained only unfilled placeholder
tokens, so every principle is newly defined. Initial adoption of a governance document is
recorded as 1.0.0 rather than a MAJOR bump from 0.x, because no prior ratified version
existed to break compatibility with.

Modified principles: none (no prior principles existed).

Added sections:
  - Core Principles I–VI (six principles; template provided five slots, one added)
  - Safety Invariants (was [SECTION_2_NAME])
  - Development Workflow & Quality Gates (was [SECTION_3_NAME])
  - Governance, including a Known Non-Compliance register

Removed sections: none.

Placeholders resolved:
  PROJECT_NAME → secscan
  PRINCIPLE_1..5_NAME/DESCRIPTION → Principles I–V (VI added)
  SECTION_2_NAME/CONTENT → Safety Invariants
  SECTION_3_NAME/CONTENT → Development Workflow & Quality Gates
  GOVERNANCE_RULES → Governance
  CONSTITUTION_VERSION → 1.0.0
  RATIFICATION_DATE → 2026-08-30
  LAST_AMENDED_DATE → 2026-08-30

Deferred TODOs: none.

Note: Principle V is not yet satisfied by the implementation. This is recorded openly in
the Known Non-Compliance register rather than by weakening the principle.
-->

# secscan Constitution

## Core Principles

### I. Determinism Before Intelligence

Deterministic tooling MUST perform all discovery, splitting, and evidence collection. The
language model is a reasoning engine over prepared evidence, never the repository analyzer.

- Identical input plus identical tool version MUST produce byte-identical artifacts. All
  serialized collections are sorted; identifiers are stable (`<repo>:<path>#<symbol>`).
- Classification, applicability, architecture, and control decisions MUST be derived from
  shipped data and code structure, never from model output.
- Third-party tool output MUST be normalized into a stable projection before it reaches an
  artifact. Output fields known to vary between runs MUST be discarded, not recorded.
- No network access in the default path. Standards data ships versioned inside the payload.

**Rationale**: reproducibility is what makes a security report auditable. A finding that
cannot be regenerated cannot be defended, and a model asked to decide a structural question
will answer confidently and inconsistently.

### II. Context Is a Managed Resource

The repository does not fit in a context window, and pretending otherwise is the failure
mode this project exists to avoid.

- Every analysis invocation MUST be bounded by a token budget enforced against the *actual
  serialized request*, never an estimate.
- Context MUST start at the smallest useful slice and expand only when the evidence is
  genuinely insufficient. Escalation is a response to stated insufficiency, not a default.
- Oversized units MUST be subdivided along security boundaries. Files are dropped whole and
  reported as coverage gaps — source is NEVER silently truncated.
- Partitioning MUST follow security and business boundaries, never line counts.

**Rationale**: bounded context is both the cost lever and the correctness lever. Truncated
source produces confident answers about code the model never saw.

### III. Secrets Never Reach a Model

A deterministic, layered redactor MUST run before any context packet is constructed.

- Redaction is offline and rule-based. No model participates in deciding what to redact.
- Content the redactor cannot confidently classify MUST be blocked, not passed through.
- Recall takes absolute precedence over precision. No change may reduce detection of a
  known credential in order to reduce false positives.
- Because the redactor must locate every credential anyway, it is also the authoritative
  hard-coded-secret detector: secrets are reported while their values appear nowhere.

**Rationale**: this is the one invariant whose violation is unrecoverable. A leaked
credential cannot be un-sent.

### IV. Evidence Over Assertion

A finding is a claim about code, and every claim MUST be traceable to the code that
supports it.

- Findings MUST conform to the shipped schema. Free-form model prose is rejected outright.
- Every finding MUST carry a weakness identifier, severity, confidence, file/symbol/line
  location, and evidence. Locations MUST resolve against the code model, which is the sole
  authority for line ranges.
- A trail rendered as a data flow MUST contain only traced edges. Supporting evidence is
  presented as evidence and MUST NOT be dressed as a path.
- The report MUST NOT assert an observation the pipeline did not make, and MUST NOT contain
  internal references that do not resolve.

**Rationale**: "the model said so" is not evidence. The distinction between what was traced
and what was inferred is the entire value of the output.

### V. Honest Uncertainty (NON-NEGOTIABLE)

Never guess in either direction. Declare the unknown.

- When architecture, reachability, control state, ownership, or advisory status cannot be
  determined, the pipeline MUST record a distinct third state — never substitute an assumed
  value and never pick the convenient answer.
- An unknown MUST NEVER buy silence. Undetermined reachability may not suppress a finding;
  an unaudited dependency domain may not be reported as clean; unverified host ownership may
  not exempt a host.
- An unknown MUST NEVER inflate either. Absence of an established control is not evidence
  that no control exists, and MUST NOT raise severity.
- Coverage gaps MUST be declared, named, and actionable. Silent exclusion is a defect.
- Confidence and severity MUST reflect what was proven. An unproven finding may not outrank
  a proven one.

**Rationale**: the project's credibility rests on the reader being able to calibrate. A scan
that overstates is as useless as one that misses, and a scan that hides its gaps is worse
than both. This principle exists because it was learned the hard way — see the Known
Non-Compliance register.

### VI. Observe, Never Attack

The scanner analyzes; it does not exploit.

- Verification is static. A traced source-to-sink path decides `verified` / `plausible` /
  `disproven`. No attack is ever executed.
- Reproduction steps MUST use non-destructive canary values, MUST contain no real
  credentials, and MUST target a local or test deployment only.
- A reproduction step MUST NOT be emitted unless its success criterion is actually
  achievable against the code as written.
- Tooling invoked against a scanned project MUST be read-only: no install, no upgrade, no
  modification of any manifest, lockfile, or source file.
- The scanner MUST exclude its own payload and tooling directories from analysis.

**Rationale**: a security tool that mutates or attacks the thing it is measuring cannot be
run where it is most needed — on production code, by someone who does not yet trust it.

## Safety Invariants

These are enforced by tests, not intent. A change that weakens one is a constitution
violation regardless of the benefit claimed.

| Invariant | Enforcement |
|---|---|
| Secrets never reach a model | Redaction sweep over every artifact using the redactor's own rules |
| No attack executed | Verification is trace-only; reproduction blocks are asserted benign |
| Budgets never exceeded | Asserted against the serialized request in scale-scan tests |
| Byte-identical for identical input | Two-run comparison across all artifacts |
| Scanner ignores itself | Payload and tool directories excluded from enumeration |
| Read-only against scanned projects | Manifest and lockfile hashes compared before and after |

Technology constraints: Python 3.11+; deterministic offline parsing via pinned tree-sitter
grammar wheels; no runtime dependency that requires a build environment or downloads
artifacts on demand; credentials supplied only by environment-variable *name*, never stored
in configuration.

## Development Workflow & Quality Gates

- **Spec-first.** Features are specified, clarified, planned, and task-listed before
  implementation. Requirements carry stable identifiers and every task cites the requirement
  it discharges.
- **Test-first.** Tests are written before implementation and MUST fail first. Fixtures
  declare ground truth so detection quality is asserted rather than eyeballed — including
  deliberate false positives that MUST NOT be reported.
- **Gates before merge.** `pytest` green, `ruff check src tests` clean, contract tests
  passing for every schema, and no reduction in credential-detection recall.
- **Additive schemas.** Artifact schema changes are additive by default. A breaking change
  requires a `schema_version` bump and a documented upgrade path.
- **Extensibility as data.** Taxonomies, applicability rules, framework controls, stack
  descriptors, and support-window data ship as versioned data. Adding a stack, rule, or
  control MUST NOT require changing a pipeline stage.
- **Accuracy regressions are release-blocking.** The accuracy benchmark asserts per defect
  class; a regression in any single class fails the build even if other classes improve.
- **Honest documentation.** Status claims in `README.md` MUST match the repository. Planned
  work is labelled as planned. A change that alters what is shipped MUST reconcile every
  README surface that describes it in the same change set: the Status header, the Roadmap
  feature lists, command and exit-code references, and the artifact layout. A feature is
  incomplete while the README describes shipped capability as planned or unbuilt, or omits
  a shipped feature. Claims of "specified, not yet built" MUST be re-verified against the
  code on every change that could have closed them: later features routinely deliver earlier
  roadmap phases, so a stale "not built" claim is silent until checked, and MUST be treated
  as a blocking documentation defect on par with an overstated one.
- **Documentation currency.** Every behavioral, contract, or structural change MUST update
  the affected documentation in the same change set — `README.md`, the relevant pages in
  `docs/`, `CONTRIBUTING.md`, `AGENTS.md` where agent guidance is affected, and the spec
  record where requirements moved. A change that leaves documentation stale is incomplete;
  reviewers MUST treat stale docs as a blocking defect on par with a failing test. New
  user-visible surfaces (commands, flags, config keys, artifacts, schemas) MUST NOT land
  without corresponding documentation.

## Governance

This constitution supersedes conflicting practice. Where a plan, spec, or task list
contradicts a principle here, the artifact is amended — not the principle.

**Amendment procedure.** Amendments are proposed as an explicit constitution change,
separate from any feature work, stating the principle affected, the rationale, and the
migration required for artifacts already in flight. A principle may not be diluted or
reinterpreted to accommodate an implementation difficulty; either the implementation changes
or the principle is amended openly.

**Versioning policy.** Semantic versioning applies to this document. MAJOR for backward-
incompatible removal or redefinition of a principle; MINOR for a new principle or materially
expanded guidance; PATCH for clarification and wording.

**Compliance review.** `/speckit-plan` MUST evaluate every feature against these principles
and record the result in its Constitution Check, before Phase 0 and again after Phase 1.
`/speckit-analyze` treats a conflict with any principle as CRITICAL. Complexity that appears
to require an exception MUST be justified in writing in the plan's Complexity Tracking table.

**Known Non-Compliance.** Recorded openly, because a constitution that misdescribes the
codebase is worse than none.

**None outstanding.** All six principles are believed satisfied and are covered by the
Safety Invariants table.

*Resolved 2026-08-31* — the three gaps recorded at ratification were closed by feature
`002-scan-accuracy-hardening` (104/104 tasks, 495 tests):

| Principle | Gap at ratification | Closed by |
|---|---|---|
| II. Context Is a Managed Resource | Markup templates, dependency manifests and platform configuration were absent from the code model, so segments were bounded over an incomplete repository view | Template and configuration extraction; every security-relevant file class is now represented and segment-assigned, and per-file-class coverage is reported |
| IV. Evidence Over Assertion | Locations were taken from model output; reports could contain references that do not resolve | Tiered location resolution against the code model, with unresolvable locations rejected rather than published; a pre-write consistency gate withholds a self-contradicting report |
| V. Honest Uncertainty | No third state existed for an undetermined architecture, reachability or control, so unknowns resolved to a guess | `undetermined` architecture, `undetermined` applicability, `unassessed` control state, `could-not-check` audit outcome — each recorded with a reason, none able to suppress a finding or read as clean |

The gaps above were found by external review rather than by a gate. That is the reason this
document exists, and the reason the compliance review above is mandatory rather than advisory:
the next such defect should be caught by a plan's Constitution Check, not by a reviewer.

**Version**: 1.2.0 | **Ratified**: 2026-08-30 | **Last Amended**: 2026-09-04
