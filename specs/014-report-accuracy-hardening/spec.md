# Feature Specification: Report Accuracy Hardening

**Feature Branch**: `014-report-accuracy-hardening`

**Created**: 2026-09-04

**Status**: Draft

**Input**: User description: "Manual cross-check of a generated report (20260904T085653Z-7ab7bd.md) found false positives and quality defects that the pipeline should have caught: (A) a dependency advisory described an exploitation scenario for a package that has no import site in the source (node-fetch declared but never imported; the code uses unfetch); (B) an XSS-through-[innerHTML] finding claimed script execution despite the scanned stack's framework escaping HTML by default with no bypass present (Angular DomSanitizer), and two EOL/unmaintained findings for the same package set were reported as separate findings instead of one; (C) the report's narrative sections referenced a finding identifier that does not exist in the findings list. Improve report accuracy so these classes of defect are prevented, qualified, or caught before publication."

## Clarifications

### Session 2026-09-04

- Q: When a dependency advisory finding has no usage locations found in the source, how should its severity be treated — confidence and narrative are already handled by FR-003, but should the severity score itself also change? → A: Severity follows the CWE dataset default (or any explicitly reported severity); only confidence is capped and only the narrative is reframed. Severity is never adjusted by usage evidence.
- Q: For XSS-class findings whose sink is an escaped template binding, where should the mitigation decision be made — deterministically during the scan, or by the model in the triage reasoning round? → A: Hybrid — deterministic credit when the member has zero bypass calls from the control's bypass list AND the sink is in the control's shipped sink list; a bypass present or incomplete coverage routes the control to the reasoning round as a candidate subject to the existing citation gates; a sink not in the control's sink list is not applicable (`absent`) and is never a candidate.
- Q: FR-004 gates service-configuration findings on evidence that the governed service is actually integrated — which config classes should be in scope for this feature? → A: All misconfiguration findings — every misconfig rule class carries integration markers for the technology it configures; classes whose integration cannot be determined record an undetermined integration state, which neither suppresses nor inflates the finding.
- Q: For the usage evidence in FR-001, what should count as "usage" of a declared dependency — which kinds of references must the scan look for before it may report none-found? → A: Static import/require statements, references in config files that load code by package name (bundler aliases, plugin lists), and dynamic-import forms matched by deterministic rules from shipped data; dynamic forms that cannot be attributed deterministically yield undetermined, never none-found.
- Q: When the report contains a dangling finding-identifier reference, what should the scan do at publication time? → A: Quarantine + publish — write the report without the offending narrative section, record the defect visibly in the report, and signal it via exit status; valid findings still reach the reader and the corruption is contained and declared.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Dependency findings state their usage evidence (Priority: P1)

A developer runs a scan and reads a known-vulnerable-dependency finding. Before the finding describes an exploitation scenario, the report states whether the dependency is actually used in the scanned source: import sites, call sites of the affected API, or an explicit "no usage location found in the member's source" statement. When no usage is found, the finding is NOT suppressed (per Honest Uncertainty — an uncalled vulnerable function stays reported), but its narrative impact is reframed to the residual exposure, its confidence reflects the lack of usage evidence, and the absence of usage is presented as evidence rather than folded into a confident exploitation chain.

**Why this priority**: This was the most consequential false-positive class in the cross-check — a CVE scenario was narrated for a package that likely never ships. Dependency findings are currently excluded from the reasoning round and the structural cross-check deliberately never judges reachability, so nothing qualifies their impact narratives. This also generalizes to service-configuration findings (e.g., permissive rules for a backend service whose client SDK is absent from the repo): absence of integration evidence must be declared, and the finding reframed to "no evidence the protected resource is in use" rather than reported as a live attack surface.

**Independent Test**: Scan a fixture containing a manifest that declares a vulnerable package with zero import statements for it. The report must contain the finding (not suppressed), must state that no usage location was found, and must not present an end-to-end exploitation narrative as established fact. Independent of stories 2–4.

**Acceptance Scenarios**:

1. **Given** a member whose manifest pins a package covered by an advisory, and no import or reference to that package exists in the member's source, **When** the scan completes, **Then** the finding is reported with an explicit "no usage location found" evidence entry, confidence no higher than the unproven-reachability ceiling, and an impact narrative framed as potential-if-used exposure.
2. **Given** the same advisory and at least one import site in the member's source, **When** the scan completes, **Then** the usage locations are listed as evidence on the finding.
3. **Given** a permissive service-configuration file (e.g., database access rules) for a service whose client SDK is absent from the member's manifests and source, **When** the scan completes, **Then** the finding states that no client integration was found and frames the finding as stale/unused configuration (with removal as the primary remediation), not as a live attack surface.
4. **Given** usage cannot be determined (unsupported language, unparseable manifest), **When** the scan completes, **Then** the usage state is recorded as undetermined with a reason; the finding is neither suppressed nor inflated.

---

### User Story 2 - Framework escaping mitigations engage on template sinks (Priority: P2)

A developer scans a stack whose framework escapes output by default (e.g., HTML inserted through a templating binding). A finding that claims script execution through that binding is evaluated against the shipped framework-control knowledge: if the binding is a known escaped sink and no sanitization bypass exists anywhere in the member's source, the finding is downgraded or refuted with mechanically re-verified citations pointing at the framework usage and the absence of bypasses — or, where deterministic crediting is impossible, the control is offered to the reasoning round as a candidate that must be cited to count. Reported residual impact honors the control's documented residual exposure rather than the generic CWE impact.

**Why this priority**: The cross-check showed a control the tool already knows about (framework-level sanitization, with sink list and bypass list shipped as data) failing to engage because the sink lives in a markup template rather than in a traced code path. This is the second-largest false-positive class observed.

**Independent Test**: Scan a fixture using escaped template bindings and no bypass calls. Any XSS-class finding for those bindings must arrive with the control engaged (credited, or refuted/downgraded by the reasoning round with verified citations), and must not claim script execution. Same fixture with a bypass call present must keep the finding at full standing. Independent of stories 1, 3, 4.

**Acceptance Scenarios**:

1. **Given** a member whose stack ships an escapes-by-default control and whose templates contain a sink binding listed in that control's sink list, **When** a finding claims script execution through that binding, **Then** the control is credited against the finding (severity reduced by the credited-control factor, impact reframed to the documented residual exposure) OR the finding enters the reasoning round with the control as a candidate and is refuted/downgraded only with citations that pass mechanical re-verification.
2. **Given** the same templates plus at least one bypass call (from the control's bypass list) in the member's source, **When** the scan completes, **Then** the control is not credited and the finding retains its standing.
3. **Given** a template sink for which no shipped control applies, **When** the scan completes, **Then** no control is credited and the finding stands on its own evidence (no silent assumption either way).

---

### User Story 3 - Currency findings for the same product cycle merge into one (Priority: P3)

A developer whose project carries several end-of-life or unmaintained packages reads the supply-chain section of the report. Each distinct `(member, product, cycle)` combination produces at most one currency finding; multiple currency signals and packages for the same product cycle (end-of-life framework family, unmaintained dependency, abandoned linter, etc.) are consolidated into that one finding with all applicable packages listed as evidence, instead of appearing as near-duplicate findings with different weakness identifiers.

**Why this priority**: Cosmetic compared to P1/P2 but directly observed: two findings describing the same root condition erode trust in the report's numbering and inflate the finding count. Lower risk, fully deterministic, no schema impact.

**Independent Test**: Scan a fixture whose manifest pins multiple packages of the same product-cycle (e.g. two Angular family packages at one version). The report contains one merged finding per product-cycle; benchmark ground truth asserts the count. Independent of stories 1, 2, 4.

**Acceptance Scenarios**:

1. **Given** a package attracting two distinct currency signals (e.g., EOL and unmaintained), **When** findings are normalized and correlated, **Then** a single finding exists for that package, its evidence lists both signals, and it carries the more severe of the contributing severities.
2. **Given** packages in different workspace members attracting the same signal, **When** findings are produced, **Then** per-member findings remain distinct (merging never crosses member boundaries).

---

### User Story 4 - Reports cannot reference findings that do not exist (Priority: P3)

Any narrative text in the report (system-level review, cross-system analysis, attack paths, recommendations) that names a finding identifier is validated against the findings actually admitted to the report before the report is written. A reference to an identifier that does not resolve — whether from filtering, suppression, or an authoring mistake — blocks publication with an explicit error rather than shipping a corrupt report.

**Why this priority**: The cross-check found a dangling identifier (referenced in the narrative, absent from the findings list). Harmless here, but it violates Evidence Over Assertion ("must not contain internal references that do not resolve") and erodes trust. Cheapest fix of the four.

**Independent Test**: Construct report input whose narrative references a non-existent identifier; report write must fail with the dangling reference named. A well-formed report writes unchanged. Independent of stories 1–3.

**Acceptance Scenarios**:

1. **Given** a report whose system-level narrative names an identifier not admitted to the report, **When** the report is finalized, **Then** the report is published without that narrative section, the omission and dangling identifier are declared in the report, and the exit status signals the defect.
2. **Given** finding identifiers filtered out of a per-member or per-band view, **When** that view is rendered, **Then** narrative references to filtered identifiers are elided or flagged consistently across all view types.

---

### Edge Cases

- Usage evidence for a dependency that is used only in test or build tooling: usage locations are reported with their role (runtime vs. dev/build) so the reader can calibrate; dev-only usage does not raise confidence to the runtime level.
- Aliased or re-exported imports (package imported through an internal wrapper module): the wrapper's import of the package counts as usage; absence of any direct or wrapped import counts as none-found.
- A package whose currency signals change between advisory-data versions: merge is computed fresh per scan; historical pins do not affect the merge.
- A finding identifier appearing in narrative prose that is not meant as a reference (e.g., an illustrative example): by design, any token matching the identifier syntax in a scanned narrative section IS treated as a reference and must resolve — narrative authors (pipeline or agent) must not write identifier-shaped tokens except as real references. This strictness is deliberate: it keeps validation fully deterministic and removes any judgment call about intent.
- Templates using multiple frameworks' escaping controls in one member: the correct control is selected per sink via the control's sink list; conflicting crediting is impossible by construction.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: For every known-vulnerable-dependency or currency finding, the pipeline MUST attach usage evidence: a sorted list of source locations that import or reference the package (`state: "found"`), an explicit `none-found` marker, or an `undetermined` marker with a reason. Usage detection MUST cover: (a) static import/require statements in source; (b) references in configuration files known to load code by package name (bundler aliases, plugin lists) — which classes count is shipped as versioned data; and (c) dynamic-import forms matched by deterministic rules from shipped data. A reference form that cannot be attributed deterministically MUST yield undetermined, never none-found; none-found may only be reported when every applicable detection form completed.
- **FR-002**: `none-found` MUST NEVER suppress a finding, and `undetermined` usage MUST NOT be treated as none-found. Undetermined is a distinct recorded state.
- **FR-003**: A dependency finding whose usage state is `none-found` MUST carry confidence no higher than the existing unproven-reachability ceiling, and its impact narrative MUST be framed as potential exposure conditional on the package being exercised. Severity MUST NOT be adjusted by usage evidence in either direction — it keeps the explicitly reported severity or the weakness dataset default.
- **FR-004**: Every misconfiguration finding MUST be paired with integration evidence for the technology it configures (SDK or dependency declared, client imported, or integration point in the workspace model), with markers per rule class shipped as versioned data. Three states are recorded: integrated (evidence listed), no-integration-found (declared on the finding; primary remediation shifts toward removal of unused configuration), and undetermined (with a reason). No-integration-found and undetermined MUST NOT suppress the finding, and undetermined MUST NOT inflate it.
- **FR-005**: The control-crediting mechanism MUST consider sinks located in markup templates, not only in traced code paths, using the shipped control sink lists. Template-sink crediting is hybrid: a control is credited deterministically only when the sink appears in the control's shipped sink list AND no bypass from its bypass list exists anywhere in the member's source; in all other cases the control is routed to the reasoning round as a candidate (FR-007).
- **FR-006**: A control MUST NOT be credited when any bypass from that control's bypass list is present in the member's source; the bypass locations MUST be cited as evidence for withholding the credit.
- **FR-007**: Where deterministic crediting cannot decide (a bypass is present in the member but unrelated to this sink, or member source coverage is incomplete), the control MUST be offered to the reasoning round as a candidate control for templated sinks, subject to the existing citation and re-verification gates. A sink that matches no entry in the control's sink list is NOT hedged: the control is simply not applicable to it (`absent`), and no candidate is created.
- **FR-008**: Currency findings (end-of-life, unmaintained, equivalent signals) within the same workspace member MUST roll up per `(member, product, cycle)` — packages of one product-cycle pair (e.g. `@angular/core` and `@angular/platform-browser` at 9.0.1) become a single finding listing every package's signal as evidence, carrying the highest contributing severity. Same-package multi-signal merging is subsumed by this key.
- **FR-009**: Merging MUST NOT cross workspace-member boundaries and MUST NOT merge currency findings with advisory (CVE) findings for the same package.
- **FR-010**: Before any report artifact is written, every finding identifier referenced in narrative sections (system review, cross-system findings, attack paths, recommendations) MUST resolve to a finding admitted to the report. An unresolvable reference MUST trigger quarantine: the report is published WITHOUT the offending narrative section, the omitted section and the dangling reference are declared visibly in the report itself, and the scan's exit status signals the defect. Publication as-is MUST NOT occur for a report containing an unresolvable reference.
- **FR-011**: All new markers, evidence entries, and merge behavior MUST be additive schema extensions and MUST produce byte-identical artifacts for identical input and tool version.
- **FR-012**: Each new behavior MUST be represented in the accuracy benchmark as ground truth, including deliberate-false-positive fixtures that MUST NOT regress (escaped-sink-without-bypass MUST NOT report executable XSS; unused-package advisory MUST NOT narrate exploitation as established fact).

### Key Entities

- **Usage evidence**: record attached to a dependency finding — state (found / none-found / undetermined with reason), and when found, a sorted list of usage locations with their role (runtime / development).
- **Template sink**: a sink binding located in markup template extraction nodes, linked to the member whose framework control applies.
- **Control credit decision**: extension of the existing credited / unassessed / not-applicable states to template sinks, with bypass evidence when credit is withheld.
- **Merged currency finding**: one finding per `(member, product, cycle)` aggregating all currency signals and packages; signals retained as evidence entries.
- **Report reference**: a finding identifier appearing in any narrative section, resolved against admitted findings before publication.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Re-scanning the repository that produced the cross-checked report eliminates the observed defects: the unused-package advisory no longer narrates exploitation as fact, the escaped-template XSS claim is downgraded or refuted with verified citations, the duplicated EOL pair appears as one finding, and no dangling identifiers survive publication.
- **SC-002**: 100% of dependency findings in benchmark fixtures carry a usage-evidence state (found / none-found / undetermined) — none are silent on usage.
- **SC-003**: Zero regressions across all existing benchmark defect classes and the credential-detection recall gate; new ground-truth cases for stories 1–4 pass and are release-blocking.
- **SC-004**: Identical input produces byte-identical artifacts across two runs, including the new evidence fields and merged findings (Safety Invariant preserved).
- **SC-005**: Reports published after the change contain zero unresolvable internal finding references (enforced by gate, not sampling).

## Assumptions

- The existing no-suppression policy for dependency findings (reachability never disproves) stands unchanged; this feature adds honest framing and confidence adjustment, not new suppression grounds.
- Import/reference detection supports at least the package-manifest ecosystems the scanner already audits (npm, pypi, go, maven); ecosystems whose import syntax is not extracted today record undetermined usage rather than none-found.
- Template extraction already produces markup/template nodes in the code model (closed by feature 002); this feature consumes those nodes and does not re-specify extraction.
- Merging currency findings changes finding counts and identifiers; downstream benchmark ground truth is updated in the same change set.
- Identifier validation applies to scanner-produced narratives and agent-produced narratives alike; the existing pre-write consistency gate is the enforcement point.
