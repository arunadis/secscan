# Feature Specification: External Scanner Tooling Integration

**Feature Branch**: `008-external-scanner-integration`

**Created**: 2026-09-02

**Status**: Draft

**Input**: User description: "during the init process, i need to install the applicable available scanning tools such as gradle/maven dependency check, npm audit, owasp tools etc and run them also as part of analysis so that it would be a comprehensive analysis. also cross check those reports with the codebase for false positives and remove them"

## Clarifications

### Session 2026-09-02

- Q: What must happen before any tool installation begins? → A: Init must present the exact list of tools it intends to install and obtain user confirmation for that list before installing anything; nothing installs without confirmation of the enumerated list
- Q: What if the project already provides a tool itself? → A: Init must first discover whether the project already provides an applicable tool through its own toolchain (project-local package dependencies, declared build plugins, wrapper toolchains) and use that instance directly instead of installing a duplicate
- Q: Should the cross-check be able to suppress findings from code-scanning tools (secrets, SAST, IaC findings), or must suppression be limited to dependency findings only? → A: All tool kinds may be suppressed, but only on deterministic structural disproof — target file or package absent, location unresolvable, or finding references a component the project does not contain; reachability-based grounds (vulnerable function never called, sink unreachable, "unused code") MUST NEVER suppress a finding
- Q: When init presents the list of tools it intends to install, can the user approve only some of them, or is it all-or-nothing? → A: Selective — the user confirms the presented list and may deselect individual tools before installation proceeds; only the confirmed subset is installed, and deselected tools are reported as skipped with that reason

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Provisioning applicable scanning tools during init (Priority: P1)

A developer runs `secscan init` on a project. The scanner determines which ecosystems the project actually uses (JavaScript/Node, JVM with Maven or Gradle, Python, Go, and so on) from the project's own manifests and build files, and identifies the external security tools that apply to each detected ecosystem — package-manager audit commands (such as the Node audit command), ecosystem vulnerability scanners, and OWASP dependency-check tooling. For each applicable tool, init first discovers whether the project itself already provides it — as a project-local package dependency, a declared build plugin, or through the project's own toolchain wrappers — and plans to use that instance directly. Only genuinely missing tools become installation candidates, and before anything is installed init presents the exact list it intends to install and waits for the user to confirm that list. A project with three ecosystems is offered three relevant tools rather than the full catalogue; an ecosystem the project does not use is never offered a tool; a tool the project already provides is never reinstalled. When the user declines installation or installation fails, init reports the gap honestly and the scanner remains ready to run in its built-in, zero-dependency mode.

**Why this priority**: Every later story depends on the right tools being present. Today init only reports four fixed tools and installs nothing, so a comprehensive analysis is impossible from a fresh machine. Applicability-driven provisioning is the enabler, and it delivers standalone value even without the run-and-merge stories: the user leaves init knowing exactly what external coverage they have and what they are missing.

**Independent Test**: Run init on a fixture multi-ecosystem project (Node manifest plus a Gradle build) and on a single-ecosystem project (Python only), covering three availability states per tool: missing, system-installed, and project-provided. Verify that init detects ecosystems correctly, uses project-provided instances directly without offering duplicates, presents the exact install list and installs nothing before confirmation, leaves the project untouched, and reports an honest readiness summary either way.

**Acceptance Scenarios**:

1. **Given** a project containing a Node manifest and a Maven build file, **When** init runs, **Then** the applicable tools for both ecosystems are identified, their availability status is reported, and no tool for an absent ecosystem is offered.
2. **Given** an applicable tool that the project already provides through its own toolchain (a project-local dependency or a declared build plugin), **When** init runs, **Then** the tool is reported as provided by the project and marked for direct use — it does not appear on the installation list.
3. **Given** applicable tools that are genuinely missing, **When** init runs, **Then** the exact list of tools to be installed is presented and no installation begins until the user confirms that list; the user may deselect individual tools and only the confirmed subset is installed, with deselected tools reported as skipped.
4. **Given** three missing tools where the user deselects one, **When** init completes, **Then** the two confirmed tools are installed, the deselected one is reported as skipped with that reason, and its missing coverage is declared as a limitation.
5. **Given** an applicable tool that is missing and the user declines installation (or init runs unattended without an install flag), **When** init completes, **Then** the gap is reported as a declared limitation and the scanner remains ready in its built-in mode.
6. **Given** any init run, **When** discovery or installation executes, **Then** no manifest, lockfile, or source file in the scanned project is created or modified — discovering project-provided tools is read-only, and confirmed installations land outside the scanned project.

---

### User Story 2 - Running installed tools as part of the analysis (Priority: P2)

A security engineer runs a scan on a project where applicable tools are available. The analysis invokes each applicable, installed tool in read-only mode against the project, collects its report, normalizes the results into the scanner's stable internal projection, deduplicates them against the scanner's own findings, and merges the survivors into the final report with clear provenance showing which tool produced each finding. A dependency vulnerability surfaced only by an external advisory feed (and therefore missed by the scanner's offline checks) now appears in the report, making the analysis genuinely comprehensive. Each tool's contribution — ran, skipped with reason, or failed with reason — is declared in the report so the reader can calibrate coverage.

**Why this priority**: This is the core "comprehensive analysis" value the user asked for. It builds on Story 1's availability state but is independently valuable: tools installed before init (or by other means) already produce a richer report. Each tool's results must be trustworthy enough to merge without polluting the deduplicated finding set, which is why normalization and provenance are in scope here.

**Independent Test**: Scan a fixture repository containing a dependency with a known vulnerability that the scanner's offline data does not cover, with the applicable external tool available. Verify the vulnerability appears in the merged report exactly once, with tool provenance, and that the report declares each tool's run status. Repeat with the tool absent and verify the scan still completes, declaring the missing contribution.

**Acceptance Scenarios**:

1. **Given** an applicable and available tool, **When** a scan runs, **Then** the tool executes in read-only mode against the scanned project and its findings appear in the merged report, normalized, deduplicated, and attributed to the tool.
2. **Given** a tool whose invocation requires network access for advisory data, **When** the scan runs, **Then** that network dependency is declared in the scan output rather than occurring silently, and failure to reach it is recorded as a tool failure — never as a clean result.
3. **Given** a tool that crashes, times out, or emits an unparseable report, **When** the scan completes, **Then** the scan succeeds overall, the failure is declared with its reason, and no partial results from that tool are merged.
4. **Given** an ecosystem for which no applicable tool is available, **When** the scan completes, **Then** the missing coverage is declared as a limitation and the scanner's built-in analysis for that ecosystem is unaffected.
5. **Given** any tool run, **When** it executes, **Then** it modifies nothing in the scanned project — manifests, lockfiles, and sources are byte-identical before and after.

---

### User Story 3 - Cross-checking tool findings against the codebase (Priority: P3)

External tools report raw claims; they do not know what the build actually resolved or what the project actually contains. The scanner cross-checks every tool-produced finding — dependency, code (secrets, SAST), and infrastructure alike — against its own code model and dependency graph before publishing it. A finding is removed only when the cross-check deterministically and structurally disproves it: the reported package is not present in the project's resolved dependencies, the vulnerable version range does not match the resolved version, the finding's location does not resolve against the code model, or the finding references a component the project does not contain. Reachability or usage judgments — a vulnerable function never called, a sink apparently unreachable, code that "looks unused" — are never grounds for suppression: they stay in the report with their verification state saying what was and was not proven. Every removal is recorded in an auditable suppression list naming the finding, the tool that produced it, and the deterministic reason it was disproven — suppression is never silent. Where the cross-check cannot resolve the question (resolution data unavailable, version undetermined), the finding is kept and its verification state says so, consistent with the honest-uncertainty rule: an unknown never buys silence.

**Why this priority**: False-positive removal is the second half of the user's request and what makes merged output trustworthy; without it teams drown in tool noise. It sequences third because it operates on the merged findings from Story 2 and reuses the existing evidence and verification model.

**Independent Test**: Prepare a fixture project plus recorded external-tool reports containing a mix of seeded true findings and seeded false positives across tool kinds — a vulnerable package the project does not depend on, a version range that does not match the resolved version, a code finding whose location does not resolve, and a code finding that is reachable-looking but real. Run the scan. Verify every true finding survives in the report, every structurally disproven finding appears only in the auditable suppression list with its reason, and no finding is suppressed on reachability or usage grounds.

**Acceptance Scenarios**:

1. **Given** a tool finding about a package absent from the project's resolved dependencies, **When** the report is assembled, **Then** the finding is excluded from the findings and recorded in the suppression list with the reason.
2. **Given** a tool finding whose vulnerable version range does not cover the version the project resolved, **When** the report is assembled, **Then** the finding is suppressed with the resolved-version evidence cited.
3. **Given** a tool finding the cross-check can neither confirm nor disprove, **When** the report is assembled, **Then** the finding is retained with an explicit undetermined verification state and reason — it is neither silenced nor inflated.
4. **Given** any suppressed finding, **When** the report is reviewed, **Then** the suppression count and per-item reasons are visible to the reviewer; removing them from the suppression view requires no re-scan.

---

### Edge Cases

- A project with no recognized ecosystem manifests offers no tools and declares that no external-tool coverage applies — never an unexamined assumption that none is needed.
- A project that already provides a tool at a version whose compatibility cannot be confirmed: the instance is used directly but its compatibility is declared as undetermined, never assumed compatible — and never silently replaced with a system copy.
- A tool present both project-locally and system-wide: the project-provided instance is used directly; the duplicate is noted in the availability record, and no installation is offered.
- Init running unattended (CI) must never prompt; installation requires an explicit opt-in flag, and interactive consent is the default otherwise.
- Tool installation or tool execution without network access (air-gapped environment): the dependency on network is detected and declared; built-in offline analysis continues unaffected.
- A tool that is installed but for a wildly different version than the registry entry expects (report format drift): the report is rejected as unparseable and declared as a tool failure, not merged partially.
- Duplicate findings from the scanner's own detectors and from external tools collapse into a single finding that records every contributor, so provenance is preserved without duplicate noise.
- Findings about dev/test-only or transitive dependencies must not be suppressed merely for being indirect; suppression requires the stricter absence/version-mismatch evidence above.
- Code or infrastructure findings whose only doubt is reachability or usage (the vulnerable function appears uncalled, the sink appears unreachable) are retained with an undetermined verification state — structural disproof grounds are the only grounds, per the honest-uncertainty principle.
- Tool caches, databases, or installation directories created by this feature live outside the scanned project and are excluded from the scanner's own enumeration, consistent with the scanner-ignores-itself invariant.
- Lockfiles touched by a tool that resolves them lazily: a tool run must be confined to modes that do not write into the scanned project; if a tool cannot run read-only, it is declared inapplicable for live execution rather than run destructively.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: During init, the system MUST deterministically detect the ecosystems a scanned project uses from its manifests and build files, and MUST map each ecosystem to the applicable external scanning tools (including package-manager audit commands, ecosystem vulnerability scanners, and OWASP dependency-check tooling) via shipped, versioned registry data. Adding or updating a tool MUST be a data change, not a pipeline change, consistent with extensibility-as-data.
- **FR-002**: Init MUST report, per applicable tool: availability status and its source (project-provided, system-installed, or missing), version when determinable, the coverage it contributes, and any network requirement its execution implies. Discovery of project-provided instances MUST be read-only against the scanned project.
- **FR-003**: Init MUST enumerate the exact list of genuinely missing tools it intends to install and MUST obtain confirmation of that list before any installation begins — interactively by default, or via an explicit opt-in flag in unattended mode. Confirmation is selective: the user MAY deselect individual tools from the presented list, and only the confirmed subset is installed; deselected tools MUST be reported as skipped with that reason. Confirmed installations MUST land in the selected package manager's user-level prefix (or the scanner's own user-level tooling directory for download channels) — never inside the scanned project; scanner-managed caches, databases, and downloads MUST live under the scanner's canonical tooling directory. Installation MUST be skippable without penalty, and installation failures MUST be reported honestly without blocking scanning.
- **FR-003a**: Before offering any installation, init MUST discover whether the project already provides an applicable tool through its own toolchain (project-local package dependencies, declared build plugins, or wrapper-provided tooling) via the registry entry's discovery data. Project-provided instances MUST be used directly, MUST take precedence over installing a duplicate, and MUST be reported with their source and version; where both a project-provided and a system-installed instance exist, the project-provided one is used. Where compatibility of a project-provided instance cannot be determined, this MUST be declared rather than assumed.
- **FR-004**: Neither init nor analysis MUST modify the scanned project in any way: manifests, lockfiles, and source files MUST be byte-identical before and after, per the read-only invariant. A tool that cannot execute read-only against the scanned project MUST be excluded from live execution and the exclusion declared.
- **FR-005**: During analysis, the system MUST invoke every applicable and available tool in its read-only mode, under a bounded timeout, and MUST normalize each tool's report into the scanner's stable internal projection — discarding fields that vary between runs — before merging, consistent with the determinism principle.
- **FR-006**: Merged findings MUST carry tool provenance, and findings equivalent to the scanner's own detections MUST be deduplicated into a single finding recording every contributing source.
- **FR-007**: Every externally produced finding — dependency, code, or infrastructure — MUST be cross-checked against the code model and dependency graph before publication. A finding MUST be suppressed only on deterministic structural disproof: the package is absent from resolved dependencies, the resolved version is outside the vulnerable range, the finding's location does not resolve against the code model, or the finding references a component the project does not contain. Reachability- or usage-based judgments (vulnerable function never called, sink unreachable, apparently unused code) MUST NOT be used as suppression grounds. Every suppression MUST be recorded in an auditable suppression list with the finding's identity, producing tool, and disproof reason.
- **FR-008**: Where the cross-check can neither confirm nor disprove a finding — including any finding whose only doubt is reachability or usage — the finding MUST be retained with an explicit doubt carried in its evidence; verification is then assigned by the existing verification stage as `plausible` with a named gap (the findings schema's explicit third state for unproven reachability) or `verified` when a complete trace exists. An unknown MUST NOT suppress a finding and MUST NOT inflate it.
- **FR-009**: Every tool not run — not installed, not applicable, installation declined, crashed, timed out, or unparseable — MUST appear in the report as a declared coverage limitation with its reason. Absence of external-tool results MUST NOT be presented as a clean state or zero findings.
- **FR-010**: The scanner MUST remain fully functional with zero external tools installed: the existing zero-config, fully offline analysis path MUST be preserved unchanged, and external tooling MUST be strictly additive.
- **FR-011**: Tool reports that transit through any artifact or model-facing context MUST pass through the existing redaction layer; credential values found in tool output are reportable as findings while the values never appear.
- **FR-012**: Tool caches, downloaded advisory databases, and installation directories MUST live outside the scanned project and MUST be excluded from the scanner's own enumeration and findings.
- **FR-013**: All behavior in this feature MUST be exercised by fixtures with declared ground truth — including seeded true findings and deliberate false positives that MUST be suppressed, and undetermined cases that MUST be retained — under the accuracy benchmark's release-blocking regression rule.
- **FR-014**: Init and scan output MUST make tool status reviewable after the fact: which tools were detected as applicable, which ran, and what each contributed or why it did not.

### Key Entities

- **Tool Registry Entry**: a versioned-data record describing an external scanning tool — the ecosystems it applies to, how its presence and version are detected, how it is discovered within a project's own toolchain (project-local dependencies, declared build plugins, wrapper tooling), how it is provisioned, how it is invoked read-only, its network requirements, and how its report is normalized.
- **Ecosystem Detection**: the deterministic result of inspecting a project's manifests and build files, listing the ecosystems present with their evidence locations.
- **Tool Availability Record**: per-tool status captured during init and analysis — applicable/not-applicable; source (project-provided / system-installed / missing); version when determinable; ran/skipped/failed with reason; network dependency declared.
- **Normalized External Finding**: a tool-produced claim projected into the internal finding shape, carrying provenance (tool, tool version, advisory identifiers) and a location that resolves against the code model.
- **Finding Disposition**: the cross-check verdict on an external finding — retained (verified / plausible / undetermined, with reason) or suppressed (with the deterministic disproof reason and evidence).
- **Suppression Record**: an auditable entry in the report listing each suppressed finding, its producing tool, and the disproof reason; never a silent drop.
- **Coverage Limitation Declaration**: a report section naming each tool not run and the reason, so external-tool absence is never read as clean.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On benchmark fixture projects, init identifies 100% of the applicable tools for each detected ecosystem and offers zero tools for ecosystems the project does not use.
- **SC-002**: On fixture projects with consented installation, every missing applicable tool is installed successfully or its failure is reported with a reason; the scanned project's manifests, lockfiles, and sources are byte-identical afterward in 100% of runs.
- **SC-003**: On fixture projects containing seeded dependency vulnerabilities that built-in offline data does not cover, applicable available tools surface 100% of them into the merged report, each appearing exactly once with tool provenance.
- **SC-004**: On the cross-check fixture corpus, 100% of deterministically disprovable seeded false positives are suppressed with recorded reasons, and 0% of seeded true findings are suppressed.
- **SC-005**: With no external tools installed, a scan produces the same findings it does today, completes successfully, and declares each missing tool contribution as a coverage limitation.
- **SC-006**: A single failing or crashing tool never fails the scan: 100% of injected tool-failure fixtures complete with a full report and a declared limitation.
- **SC-007**: On fixtures where the project itself provides an applicable tool, 100% of runs use the project-provided instance directly and offer zero duplicate installations; no installation occurs on 100% of runs until the presented install list is confirmed.

## Assumptions

- Installation actions and advisory-data downloads implicate network and machine changes; they therefore occur only on explicit user consent, and the zero-config default path remains fully offline per the determinism principle. The plan's Constitution Check will record how this opt-in tooling path relates to the no-network default.
- "Install during init" means provisioning via the tool's package manager into the manager's user-level prefix (brew/pipx/go user locations) or, for download channels, the scanner's own user-level tooling directory — never installing into or modifying the scanned project, per the read-only invariant. Scanner-managed caches and databases always live under the scanner's canonical tooling directory; discovery re-probes availability at scan time, so records stay deterministic regardless of where an install landed (Principle I).
- When a tool is available both project-provided and system-installed, the project-provided instance takes precedence because it is pinned to the project and more reproducible; compatibility of a project-provided instance that cannot be confirmed is declared honestly rather than assumed.
- Applicable tools are identified per ecosystem from shipped registry data rather than a fixed hard-coded list; the four tools init reports today become registry entries alongside the newly added ecosystem audit and OWASP tools.
- Suppression is conservative by design: only deterministic disproof removes a finding, every removal is auditable, and undetermined cases are retained — per the honest-uncertainty principle, an unknown never buys silence.
- Interactive environments prompt for install-list confirmation with selective deselection; unattended/CI environments require an explicit opt-in flag, which may name a subset to install (unspecified means all genuinely missing applicable tools), and otherwise skip installation with a declared note.
- Tool execution is bounded (timeouts) so a hung tool cannot hold a scan hostage; bounds are configurable with sane defaults.
- Advisory data versions used by external tools are captured in tool provenance so runs remain attributable even though third-party advisory content evolves.
