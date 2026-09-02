# Feature Specification: Hierarchical LLM-Efficient Security Scanning for Large Codebases

**Feature Branch**: `001-hierarchical-security-scan`

**Created**: 2026-08-30

**Status**: In progress (52/81 tasks; see tasks.md)

**Input**: User description: "LLM-Efficient Security Scanning for Large Codebases — a hierarchical security-analysis pipeline where deterministic tooling performs discovery, splitting, and evidence collection; LLMs reason over small, semantically meaningful segments with bounded context; findings are normalized, correlated across segments, and aggregated into a final security report. See requirements/LLM-Efficient Security Scanning for Large Codebases.md"

## Overview

Security scanning a large codebase with an LLM fails because the repository cannot fit into a single context window. This feature delivers a hierarchical security-scanning capability that treats context as a managed resource: deterministic analysis builds a repository model, the repository is partitioned along security/business boundaries, each segment is analyzed with a small bounded context packet, findings are emitted as structured evidence-bearing records, and cross-segment correlation plus a system-level review produce a final deduplicated security report. The scan target is a *system*: a workspace of one or more repositories (subsystems), so vulnerabilities that arise at integration points between subsystems are analyzed, not just vulnerabilities inside one repository. Every pipeline stage produces a durable artifact so scans are reproducible, resumable, and incrementally re-runnable.

## Clarifications

### Session 2026-08-30

- Q: When the scanner sends code context to the LLM for analysis, what data-protection posture must the pipeline enforce for the scanned repository's source code? → A: Configurable endpoints (cloud LLMs allowed) with mandatory deterministic redaction of secrets/credentials from context packets before anything is sent.
- Q: What severity and confidence scales should every security finding use? → A: Industry-standard CVSS-style numeric severity (0.0–10.0 with derived Critical/High/Medium/Low/None bands) plus numeric confidence (0.0–1.0).
- Q: If a scan is interrupted partway through (crash, kill, or budget exhaustion), what recovery behavior must the system provide? → A: Automatic resume — completed pipeline stages are reused from persisted artifacts and only unfinished work is re-run.
- Q: What wall-clock expectation should a full first-time scan of a large repository meet, given that segments are analyzed in parallel? → A: Approximately 1 hour per 1 million lines of code, with independent segment analyses executed in parallel.
- Q: Which categories of traditional scanner findings must the pipeline be able to ingest in the first version? → A: All four categories — SAST, secrets, dependencies, and infrastructure-as-code — with one reference ingestion adapter shipped per category.
- Q: Should cost-optimized LLM utilization (batch API usage, off-peak scheduling, model tiering) be a configurable execution policy, and at what granularity? → A: Per-scan configurable execution policy — the operator selects an interactive or batch/off-peak profile per scan, with cost-optimized defaults.
- Q: When the batch/off-peak profile is selected, what should happen to the full-scan latency target of roughly 1 hour per 1 million lines? → A: Separate targets per profile — interactive keeps ~1h per 1M lines; batch/off-peak must complete within the configured off-peak window.
- Q: Should the pipeline use different classes of models for different analysis levels, and should that mapping be operator-configurable? → A: Configurable model tiers per analysis level — a cheaper model class for local analysis by default, escalating to stronger model classes for segment/system review and evidence escalation.
- Q: If a batch/off-peak request fails or doesn't return within the configured window, what should the pipeline do? → A: Automatic interactive fallback — failed or expired batch items are re-executed interactively, and every fallback is recorded and reported.
- Q: Should the final security report include a cost and usage summary so cost-effectiveness is visible and measurable? → A: Yes — every scan report includes tokens consumed per stage and model tier, batch vs. interactive share, fallbacks, and estimated savings versus a maximal-context baseline.
- Q: How should a user install the security-scanning capability into their environment? → A: An installer command that scaffolds the skill into the chosen coding agent's skills directory, following the Spec Kit init pattern (e.g., selecting the target agent via a flag).
- Q: Which coding agents must the installed skill work with in the first version? → A: An agent-agnostic core plus thin per-agent adapters; v1 ships adapters for a defined set of major agents, and new agents are supported by adding adapters.
- Q: When the skill is used to scan a repository, where should its configuration and scan artifacts live relative to the repository being scanned? → A: A dedicated dot-directory inside the scanned repository (e.g., `.security-scan/`), gitignored by default with an opt-in to commit.
- Q: Once installed, how should a user trigger a security scan from within their coding agent? → A: The installer registers a named, invocable scan command/skill in the agent; the agent executes it by following the orchestrator instructions and calling the bundled deterministic scripts.
- Q: Should the skill be installed separately into each project that wants scanning, or installed once globally and usable against any repository on the machine? → A: Per-project installation — the installer runs inside each project, pinning that project's scanner version and configuration.
- Q: Should the first version support scanning a system that spans multiple repositories/subsystems, or should v1 stay single-repository with the design explicitly allowing multi-repo later? → A: Multi-repo in v1 — the pipeline natively scans a workspace of repositories and reasons across subsystem integrations from day one.
- Q: How should the user define which repositories and subsystems make up a multi-repo workspace scan? → A: An optional declarative workspace manifest listing member repositories and known integration points; if no manifest exists, the system falls back to auto-discovery from the scan root (multiple checked-out repos, inferred membership and integrations).
- Q: Which kinds of integration points between subsystems must the scanner understand when tracing flows across repositories? → A: Four typed classes — synchronous APIs (HTTP/RPC), asynchronous messaging (queues/events), shared data stores, and identity/trust propagation (tokens, service accounts, SSO).
- Q: For a multi-repo workspace scan, how should findings be reported — one unified system report, or separate per-repository reports? → A: One unified workspace report with every finding attributed to its repository/subsystem; cross-system findings cite evidence from all involved repositories, and per-repository views are derived from the unified report.
- Q: In a multi-repo workspace, when one subsystem's repository changes, what must an incremental rescan re-analyze? → A: The changed repository plus any segments in other repositories that participate in integration points with it; cross-system conclusions are re-derived whenever either side of an integration changes, while unaffected repos and segments reuse prior results.
- Q: After installation, how should the scanner's settings (execution policy, model tiers and endpoints, token budgets, redaction, scanner adapters) be configured? → A: A single human-editable configuration file in the project's scan dot-directory with a documented schema and sensible defaults, with environment-variable overrides for machine-specific values.
- Q: Should there be an explicit initialization step after install that generates the default configuration and verifies the environment before the first scan? → A: Yes — a named init command generates the default config file and runs environment checks (model endpoint connectivity, credentials present, optional scanner tools detected), reporting what is ready and what is missing; a scan attempted without configuration suggests running init.
- Q: How should the scanner's own credentials (for example, the API key for the configured model endpoint) be supplied? → A: Environment variables only — the config file may name which variable to read but MUST never store the secret value, keeping the config safe to commit.
- Q: How should a project upgrade to a newer version of the scanner after it's been installed and configured? → A: In-place upgrade — re-running the installer replaces skill files (scripts, prompts, schemas) with the new version while preserving the project's configuration and scan artifacts, flagging any configuration schema changes.
- Q: What should happen when the configuration file contains invalid values or settings that conflict with each other? → A: Strict upfront validation — the scan refuses to start until the configuration is valid, reporting all problems at once with the setting name and expected values; conflicting settings are rejected with an explanation.
- Q: When no model API key is configured, should the scanner perform its analysis through the coding agent's own model access instead of requiring an external endpoint? → A: Agent-mediated by default — the coding agent executing the skill performs the reasoning steps with its own model while deterministic scripts handle everything else; an external endpoint remains an optional configuration for scale and cost features.
- Q: In agent-mediated mode, how should the cost-optimization features that assume an external endpoint (provider batch APIs, off-peak scheduling, per-level model tiers) behave? → A: Mode-aware degradation — endpoint-only features report as unavailable in agent-mediated mode; evidence escalation and token-budget discipline remain the cost levers in both modes, applied against the agent's context window.
- Q: In agent-mediated mode, how should scans of large workspaces proceed when the work exceeds what a single agent session or context window can carry? → A: Resumable across sessions — pipeline checkpoints let an agent-mediated scan span multiple agent invocations via auto-resume (re-invoking the scan command continues the work), and the report recommends external-endpoint mode for very large workspaces.
- Q: Which success criteria should apply in each execution mode — should the latency targets bind agent-mediated scans the same way they bind external-endpoint scans? → A: Mode-scoped criteria — latency targets bind the external-endpoint modes; agent-mediated mode is validated against the correctness and completeness criteria (evidence quality, deduplication, cross-system detection, budget discipline) with no wall-clock target.
- Q: Should the scanner support named scan profiles (preset configurations such as "quick", "full", or "audit") that bundle settings, and should users be able to define their own? → A: Built-in named profiles plus user-defined custom profiles in the project config; a scan selects a profile and individual settings can still be overridden per scan.
- Q: Which industry standards should the scanner use to categorize and label its findings? → A: CWE as the primary weakness identifier for every finding, with an OWASP Top 10 mapping as a secondary label.
- Q: Should the first version map findings to compliance frameworks (PCI-DSS, SOC 2, ISO 27001, NIST SSDF) in its reports, or defer compliance mapping? → A: Defer full compliance packs — v1 anchors on CWE + OWASP Top 10 and the schema allows compliance mappings to layer on later; where a finding's CWE has a well-established, unambiguous framework mapping, that mapping is included opportunistically without per-framework interpretation work.
- Q: What should the built-in profiles' default settings be for which findings appear in reports? → A: Profile-defined thresholds — `quick` reports High/Critical only, `full` reports Medium+ with a confidence floor (default 0.5), `audit` reports everything; all thresholds are overridable per scan.
- Q: Should a profile's thresholds only filter the report, or should lighter profiles also reduce analysis depth to make the scan cheaper and faster? → A: Both — thresholds filter the report AND lighter profiles reduce analysis depth (fewer vulnerability domains per segment, shallower evidence-escalation ceiling), so `quick` is genuinely cheaper and `audit` is genuinely exhaustive.
- Q: How far should the scanner go in verifying that a finding is actually exploitable before reporting it? → A: Static verification with generated reproduction artifacts — the pipeline confirms exploitability by tracing concrete source-to-sink evidence and emits executable-shaped reproduction steps (exact request/payload, endpoint, preconditions) derived from that evidence; the scanner never executes attacks itself.
- Q: How should reproduction information appear in the final report — inline with each finding, or collected separately? → A: Inline per finding — a structured Reproduction subsection within every reportable finding, in both the human-readable and machine-readable report renderings.
- Q: What safety constraints should apply to the payloads and steps in generated reproduction blocks? → A: Benign-proof standard — reproduction triggers use non-destructive canary values that prove the flaw without causing damage, real credentials/secrets are always redacted even in reproduction blocks, and steps explicitly target a local/test deployment of the scanned code.
- Q: How should verification status interact with report ranking and the profile thresholds? → A: Verification-aware ranking — within each severity band, `verified` findings rank above `plausible` ones and always pass confidence floors (a complete traced path outweighs the heuristic score); `disproven` findings never appear in the report.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Scan a Large Repository End-to-End (Priority: P1)

A security engineer points the scanner at a workspace — one repository, or several repositories forming an enterprise system — far larger than any single LLM context window. The system discovers the workspace structure (including integration points between subsystems), partitions it into logical security-relevant segments (e.g., authentication, payment processing, file upload), analyzes each segment with only the relevant context, and produces a final security report where every finding carries evidence, severity, and confidence — including vulnerabilities that only exist at the integration points between subsystems.

**Why this priority**: This is the core value proposition — without an end-to-end bounded-context scan producing an evidence-backed report, no other capability matters.

**Independent Test**: Run the scanner against a representative multi-module repository and verify that (a) no single analysis step loads the entire repository, (b) a final report is produced, and (c) every finding in the report includes file/symbol/line evidence plus severity and confidence.

**Acceptance Scenarios**:

1. **Given** a repository whose source exceeds a single analysis context window, **When** the user initiates a full scan, **Then** the system completes the scan by analyzing logically partitioned segments and produces a final security report without ever loading the entire repository into one analysis context.
2. **Given** a completed scan, **When** the user opens any finding in the report, **Then** the finding contains a category, severity, confidence score, precise location (file, symbol, line range), supporting evidence references, an attack scenario, impact, and a recommendation.
3. **Given** a repository with distinct functional areas (e.g., auth, payments, uploads), **When** partitioning completes, **Then** each segment corresponds to a meaningful security or business boundary with its entry points, dependencies, and data stores identified — not an arbitrary chunk of lines.

---

### User Story 2 - Install the Scanner into a Coding Agent (Priority: P2)

A security engineer who uses a coding agent installs the scanning capability by running a single installer command inside their project, selecting their agent. The installer scaffolds the skill into the agent's skills directory and registers a named scan command. From then on, the engineer triggers scans through that command, and the agent orchestrates the pipeline using the bundled deterministic scripts.

**Why this priority**: Without a one-command, agent-portable installation, the capability can't reach users regardless of how good the scanning pipeline is; it is P2 only because the core pipeline (P1) defines what gets installed.

**Independent Test**: Run the installer in a fresh project for each supported agent, verify the skill files and scan command are registered, trigger the command, and confirm the pipeline starts and writes artifacts into the project's scan dot-directory.

**Acceptance Scenarios**:

1. **Given** a project without the scanner installed, **When** the user runs the installer selecting their coding agent, **Then** the skill is scaffolded into that agent's skills directory and a named scan command becomes invocable in the agent.
2. **Given** two projects on the same machine, **When** the installer is run in each, **Then** each project has its own pinned scanner version and configuration, independent of the other.
3. **Given** an installed project, **When** the user triggers the scan command, **Then** scan artifacts are created in the project's dedicated dot-directory, which is excluded from version control by default.
4. **Given** a freshly installed project, **When** the user runs the init command, **Then** a default configuration file is generated in the scan dot-directory and an environment check reports model endpoint connectivity, credential presence, and detected scanner tools.
5. **Given** an installed project whose configuration contains an invalid or conflicting setting, **When** the user triggers a scan, **Then** the scan refuses to start and reports every configuration problem with the setting name and expected values.

---

### User Story 3 - Triage Traditional Scanner Findings (Priority: P2)

A security engineer already runs traditional static analysis tools (SAST, secret scanners, dependency scanners, IaC scanners) that generate large volumes of findings, many of which are false positives. The system ingests these findings and uses LLM reasoning, with bounded surrounding context, to determine whether each is actually exploitable in this application.

**Why this priority**: It converts noisy existing tooling output into actionable results and demonstrates the core principle — LLMs reason over evidence rather than hunt through raw code — while remaining independently valuable.

**Independent Test**: Provide the system with scanner output containing known true-positive and false-positive findings and verify the triage verdicts reference concrete code context and correctly assess exploitability for the seeded cases.

**Acceptance Scenarios**:

1. **Given** findings produced by external static analysis tools, **When** the scan runs, **Then** each ingested finding is assessed for exploitability in the application's actual context, and the verdict is recorded with supporting evidence.
2. **Given** an ingested finding whose surrounding code already mitigates the issue (e.g., parameterized query upstream of a flagged database call), **When** the triage step evaluates it, **Then** the finding is marked as not exploitable or downgraded, with the mitigating code cited as evidence.

---

### User Story 4 - Correlate and Deduplicate Cross-Segment Findings (Priority: P2)

Multiple segments frequently surface the same underlying weakness (e.g., a missing authorization check appearing in three segments). The system correlates findings across segments, classifies their relationships (same, related, dependent, duplicate, independent), and reports systemic issues once with consolidated evidence.

**Why this priority**: Without correlation, the final report is noisy and misleading, and cross-boundary vulnerabilities (the ones single-file scanners miss entirely) are never detected.

**Independent Test**: Scan a fixture repository containing a known systemic weakness spanning multiple segments and verify the final report describes the issue once, references evidence from all affected segments, and surfaces the cross-boundary vulnerability.

**Acceptance Scenarios**:

1. **Given** segment-level findings that share a root cause, **When** correlation runs, **Then** the final report presents the issue once and references the evidence from every contributing segment.
2. **Given** a vulnerability that only exists because of how two segments interact (e.g., an identity produced by the auth segment is trusted under different authorization assumptions by another segment), **When** the system-level review runs, **Then** the report identifies the cross-boundary vulnerability even though no individual segment analysis flagged it.

---

### User Story 5 - Incrementally Rescan After a Code Change (Priority: P3)

After an initial full scan, a developer changes one file. Instead of rescanning the entire repository, the system uses its persisted pipeline artifacts to determine which segments, findings, and system-level conclusions are affected, and re-analyzes only those.

**Why this priority**: Incremental scanning makes the pipeline practical in continuous workflows, but it depends on the artifact pipeline from Story 1 and is not required for the initial value delivery.

**Independent Test**: Perform a full scan on a fixture repository, modify a single file, re-run, and verify that only the affected segments and dependent conclusions are re-analyzed and the updated report reflects the change.

**Acceptance Scenarios**:

1. **Given** a completed scan with persisted artifacts, **When** a single file changes and a rescan is triggered, **Then** only the segments containing that file (and their dependent findings/conclusions) are re-analyzed, while unaffected segment results are reused.
2. **Given** a completed scan, **When** the user re-runs the analysis for one specific segment, **Then** that segment can be re-analyzed in isolation without rerunning the entire scan.

---

### Edge Cases

- **Unsupported or mixed languages**: Repositories containing languages or frameworks the deterministic analysis cannot fully parse must still be scanned; unparseable areas are partitioned by directory/module heuristics and flagged with reduced analysis confidence rather than silently skipped.
- **Segment exceeds context budget**: If a logical segment cannot fit within the configured context budget even after compaction, the system must subdivide it further (falling back to finer-grained units) rather than truncating or dropping code.
- **Malformed analysis output**: If an analysis step returns output that does not conform to the structured finding schema, the system must retry or escalate rather than admit free-form text into the findings pipeline.
- **No findings**: A clean repository must produce a valid report stating that no issues were found, listing what was analyzed, so users can distinguish "scanned and clean" from "scan failed silently".
- **Conflicting findings across segments**: When segments disagree about the same code (e.g., one flags it, another deems it safe), the correlation step must reconcile the conflict explicitly and record the reasoning.
- **Very large individual files**: Single files larger than the analysis context budget must be analyzable through function/class-level decomposition with evidence escalation.
- **Redaction uncertainty**: If the secret-redaction step detects content it cannot confidently sanitize, the system must block that content from being sent to the model endpoint and surface a warning, rather than risk leaking a credential.
- **Batch expiry or failure**: If a batch/off-peak request fails or does not return within the configured window, the affected analysis items are re-executed interactively (see FR-016b); the scan must still complete without silent coverage gaps.
- **Missing or unparseable subsystem**: If a workspace manifest references a repository that is unavailable or a member repo cannot be parsed, the system must continue scanning the remaining members, mark cross-system flows through the missing subsystem as unverifiable, and clearly state the coverage gap in the report.
- **Undeclared integration discovered mid-scan**: If analysis discovers an integration point between subsystems that was neither declared nor inferred during discovery, the system must incorporate it into the workspace model and re-evaluate affected cross-system conclusions rather than ignoring it.
- **Missing credentials at scan time**: If no external endpoint credential is configured, the scan proceeds in agent-mediated mode (the host agent's own model performs analysis) and the report states this; if an external endpoint IS configured but its credential variable is unset, the system must stop with a clear message naming the expected variable — never prompting interactively mid-scan.
- **Config schema drift after upgrade**: If an in-place upgrade introduces configuration schema changes, the next scan must surface the required configuration updates through the strict validation path (FR-026) rather than silently applying new defaults.
- **Switching to a deeper profile**: If a project previously scanned with a lighter profile (e.g., `quick`) and then scans with a deeper one (e.g., `audit`), the system must re-analyze at the new depth — reusing prior artifacts where they remain valid — and must not present the earlier shallow analysis as if it were exhaustive.

## Requirements *(mandatory)*

### Functional Requirements

**Distribution & Installation**

- **FR-020**: The system MUST provide an installer command that scaffolds the scanning skill into a chosen coding agent's skills directory, allowing the operator to select the target agent at install time. Installation is per-project: the installer runs inside each project and pins that project's scanner version and configuration. Re-running the installer in an installed project MUST perform an in-place upgrade — replacing skill files (scripts, prompts, schemas) while preserving the project's configuration file and scan artifacts, and clearly flagging any configuration schema changes introduced by the new version.
- **FR-021**: The scanning capability MUST be structured as an agent-agnostic core skill plus thin per-agent adapters; v1 MUST ship adapters for a defined set of major coding agents, and supporting a new agent MUST require only adding an adapter.
- **FR-022**: The installer MUST register a named, invocable scan command/skill in the target agent; triggering that command MUST start the scan pipeline, with the agent following the orchestrator instructions and invoking the bundled deterministic scripts.
- **FR-023**: Project settings (execution policy, model tiers and endpoints, token budgets, redaction rules, scanner adapters) MUST live in a single human-editable configuration file in the project's scan dot-directory, with a documented schema and sensible defaults; machine-specific values MUST be overridable via environment variables without editing the file.
- **FR-028**: The system MUST ship built-in named scan profiles (at minimum: `quick`, `full`, `audit`) that bundle settings for common scanning intents, MUST allow users to define custom profiles in the project configuration, and MUST allow any individual setting to be overridden per scan on top of the selected profile. The active profile and all overrides MUST be recorded in the scan artifacts and final report. Default report-inclusion thresholds: `quick` reports High/Critical findings only, `full` reports Medium and above with confidence ≥ 0.5, `audit` reports all findings regardless of severity or confidence. Profiles MUST control both reporting and analysis depth: lighter profiles reduce analysis scope (fewer vulnerability domains per segment, shallower evidence-escalation ceiling) so `quick` is genuinely cheaper and faster, while `audit` performs maximal-depth analysis.
- **FR-024**: The system MUST provide a named init command that generates the default configuration file and runs environment checks — model endpoint connectivity, credential presence, and detection of optional external scanner tools — reporting what is ready and what is missing. Triggering a scan in a project without configuration MUST produce a clear message directing the user to run init rather than failing with a low-level error.
- **FR-025**: The scanner's own credentials (e.g., model endpoint API keys) MUST be supplied via environment variables; the configuration file may reference which variable to read but MUST NOT store secret values, and the init environment check MUST verify credential presence without printing or persisting the secret. Credentials are OPTIONAL: when no external endpoint is configured, the system MUST run in agent-mediated mode (FR-027).
- **FR-027**: By default, analysis reasoning MUST be performed by the coding agent executing the skill, using the agent's own model access — no external endpoint or API key is required for a scan to run. Configuring an external endpoint MUST switch analysis to that endpoint (explicit configuration takes precedence over agent-mediated mode), and every scan report MUST state which execution mode was used. Agent-mediated scans MUST be resumable across agent sessions through the artifact pipeline's checkpoints (FR-016a): re-invoking the scan command continues unfinished work, so large workspaces can be scanned over multiple sessions without a hard size ceiling; when a workspace is very large, the system SHOULD recommend external-endpoint mode in its output.
- **FR-026**: Before any scan work begins, the system MUST validate the full configuration against its documented schema, refusing to start an invalid scan and reporting all problems at once — naming each setting and its expected values; mutually conflicting settings (e.g., a batch policy with no off-peak window defined) MUST be rejected with an explanation.

**Workspace & Discovery**

- **FR-001**: The system MUST generate a compact repository manifest capturing languages, frameworks, modules, entry points, data stores, and external service integrations, small enough to be understood without consuming significant context budget.
- **FR-001a**: The scan target MUST be a workspace of one or more repositories (subsystems); the system MUST model the workspace as a first-class entity listing its member repositories and the integration points between them, and single-repository scans MUST behave as a workspace with one member.
- **FR-001c**: Workspace membership SHOULD be definable via a declarative manifest listing member repositories (by local path) and known integration points; the manifest MUST be optional — when absent, the system MUST auto-discover member repositories from the scan root and infer integration points, flagging inferred entries with lower confidence than declared ones.
- **FR-001b**: The system MUST extend its code graph and data-flow tracing across repository boundaries, so a flow that starts in one subsystem and crosses an integration point into another subsystem is analyzable end to end, and the system-level review MUST reason over cross-subsystem trust boundaries. Integration points MUST be typed into four classes: synchronous APIs (e.g., HTTP/RPC), asynchronous messaging (queues/events), shared data stores, and identity/trust propagation (tokens, service accounts, SSO).
- **FR-002**: The system MUST build a dependency/call graph of the repository (components and their call/dependency relationships) using deterministic analysis, sufficient to trace flows from entry points through services to data stores.
- **FR-003**: The system MUST identify security-relevant boundaries in the repository (trust boundaries, externally controlled inputs, sensitive data stores, external systems) and annotate the repository model with them.

**Partitioning & Context**

- **FR-004**: The system MUST partition the repository into segments that correspond to meaningful security or business boundaries; partitioning MUST NOT be based on raw size or line count alone.
- **FR-005**: The system MUST construct, for each segment, a bounded context packet containing the segment's purpose, entry points, relevant files, dependencies, call-graph and data-flow summaries, and security-relevant symbols — so analysis receives relevant context, not the repository.
- **FR-006**: The system MUST support evidence escalation: analysis begins with the smallest relevant context (e.g., a single function) and expands (calling/called code → full segment plus data flow → cross-segment context) only when evidence is insufficient for a confident verdict.
- **FR-006a**: The system MUST deterministically redact secrets and credentials (e.g., API keys, tokens, private keys, passwords) from every context packet and artifact before any content is sent to an analysis model — whether the host agent's own model (agent-mediated mode, FR-027) or an operator-configured external endpoint; redaction MUST apply regardless of which model performs the analysis.
- **FR-007**: The system MUST enforce an explicit token budget per analysis invocation, configurable with maximum context size, maximum output size, and an escalation threshold, and MUST record budget consumption per invocation.
- **FR-007a**: The system MUST expose a per-scan configurable execution policy controlling cost optimization — including whether analysis requests use provider batch APIs, whether work is scheduled into operator-defined off-peak windows, and which model class serves each analysis level — with cost-optimized values as the default. Batch APIs, off-peak scheduling, and provider model tiers require an external endpoint; in agent-mediated mode (FR-027) the system MUST report these features as unavailable rather than silently ignoring them, while evidence escalation (FR-006) and token budgets (FR-007) remain enforced against the agent's context window in both modes.

**Analysis**

- **FR-008**: The system MUST perform multi-level analysis: local (individual functions/classes), segment (combinations of components within a boundary), and system (cross-segment reasoning over findings, architecture, and data flows).
- **FR-008a**: The system MUST support configurable model tiers per analysis level: by default, local analysis uses a cheaper model class, while segment review, system review, and evidence-escalation steps use a stronger model class; the operator MUST be able to override the model class assigned to each level.
- **FR-009**: The system MUST ingest findings from traditional deterministic scanners across all four categories — SAST, secrets, dependencies, and infrastructure-as-code — and assess each finding's actual exploitability within the application's context. Ingestion MUST be format-agnostic via adapters, with at least one reference adapter shipped per category; additional tools are integrated by adding adapters, not by changing the pipeline.
- **FR-010**: The system MUST trace security-relevant data flows from externally controllable sources to sensitive sinks and evaluate whether the security boundary between source and sink is adequately enforced.
- **FR-011**: The system MUST apply analysis guidance specialized per vulnerability domain (e.g., authentication, injection, data protection, API security, infrastructure), loading only the guidance relevant to each segment rather than all rules for every analysis.

**Findings & Correlation**

- **FR-012**: Every finding MUST conform to a structured schema including a unique identifier, category, severity, confidence score, precise location (file, symbol, line range), description, evidence references, attack scenario, impact, recommendation, and related symbols. Severity MUST be expressed as an industry-standard CVSS-style numeric score (0.0–10.0) with a derived severity band (Critical/High/Medium/Low/None); confidence MUST be a numeric value from 0.0 to 1.0. Every finding MUST be categorized with a CWE identifier as its primary weakness classification and SHOULD carry an OWASP Top 10 mapping as a secondary label when applicable; ingested scanner findings MUST retain their original rule/tool identifiers alongside the normalized CWE mapping.
- **FR-013**: The system MUST NOT admit free-form or schema-nonconforming analysis output into the findings pipeline.
- **FR-014**: The system MUST correlate findings across segments, classifying relationships as same, related, dependent, duplicate, or independent, and MUST NOT report the same underlying issue as multiple independent vulnerabilities.
- **FR-029**: Every reported finding MUST undergo static verification: the system MUST trace a concrete source-to-sink path from the finding's evidence and record a verification status (`verified` — complete source-to-sink path traced with entry point and preconditions identified; `plausible` — partial path with the gap documented; `disproven` — refuted by the trace, kept out of the report). The scanner MUST NOT execute attacks against a running application. Reports MUST rank verification-aware: within each severity band, `verified` findings appear above `plausible` ones, and `verified` findings always pass profile confidence floors regardless of their raw confidence value.
- **FR-030**: Every finding with status `verified` or `plausible` MUST carry a structured reproduction block derived from its evidence: preconditions (required role/permissions/state), the concrete trigger (endpoint, method, parameters/payload or input sequence), the observed-vs-expected security behavior, and the evidence trail reference. Reproduction triggers MUST use non-destructive canary values that prove the flaw without causing damage, MUST NOT contain real credentials or secrets (redaction rules apply to reproduction blocks), and MUST explicitly target a local/test deployment of the scanned code.
- **FR-015**: Cross-segment claims in the final report MUST reference findings from multiple segments as evidence.

**Artifacts & Pipeline**

- **FR-016**: Every pipeline stage MUST produce a durable, structured artifact (repository manifest, architecture model, code graph, segments, context packets, local findings, segment findings, correlated findings, system review, final report) so that any stage can be re-run in isolation.
- **FR-016a**: If a scan is interrupted partway through (crash, termination, or budget exhaustion), the system MUST automatically resume from the last completed stage using persisted artifacts on the next invocation, re-running only unfinished work; a full restart MUST NOT be required.
- **FR-016b**: Under the batch/off-peak execution policy, analysis items whose batch requests fail or exceed the configured window MUST be automatically re-executed interactively; the system MUST NOT silently skip or stall analysis units, and every fallback MUST be recorded and surfaced in the final report.
- **FR-017**: The system MUST support incremental scanning: given a file-level change, it MUST identify affected segments, findings, and system-level conclusions and re-analyze only those. In a multi-repository workspace, a change in one member repository MUST additionally trigger re-analysis of segments in other member repositories that participate in integration points with the changed repository, and cross-system conclusions MUST be re-derived whenever either side of an integration changes.
- **FR-018**: The system MUST produce a final security report containing an executive summary, findings grouped by severity, attack paths, and recommendations. For multi-repository workspace scans, the report MUST be a single unified workspace report: every finding is attributed to its repository/subsystem, cross-system findings MUST cite evidence from all involved repositories, and per-repository filtered views MUST be derivable from the unified report. Every reportable finding MUST include a structured Reproduction subsection (preconditions, trigger, expected vs. observed behavior, evidence trail) inline in both the human-readable and machine-readable report renderings.
- **FR-019**: Every scan MUST emit a usage and cost summary — tokens consumed per pipeline stage and model tier, the share of analysis performed via batch vs. interactive requests, any batch fallbacks, and estimated savings versus a maximal-context baseline — included in the final report.

### Key Entities *(include if feature involves data)*

- **Workspace**: The scan target — a set of one or more repositories (subsystems) plus the typed integration points between them (synchronous APIs, asynchronous messaging, shared data stores, identity/trust propagation). A single-repository scan is a workspace with one member.
- **Repository Manifest**: Compact description of one member repository — languages, frameworks, modules, entry points, data stores, external services. Input to all downstream reasoning.
- **Code Graph**: Nodes (classes, functions, endpoints, data stores, external systems) and edges (calls, depends-on, data-flows-to) derived deterministically; annotated with security properties such as trust boundaries and sensitive data.
- **Segment**: A logical partition of the repository along a security/business boundary, with its files, entry points, dependencies, and purpose.
- **Context Packet**: The bounded bundle of source and structural summaries handed to a single analysis invocation for one segment.
- **Finding**: A structured, evidence-bearing record of a potential vulnerability (identity, category, severity, confidence, location, evidence, attack scenario, impact, recommendation) with a verification status (`verified`/`plausible`/`disproven`) and, for reportable findings, a structured reproduction block (preconditions, trigger, expected vs. observed behavior).
- **Scan Artifact**: A durable, versioned output of a pipeline stage enabling reproducibility, resumability, and incremental re-analysis.
- **Security Report**: The final aggregated assessment — executive summary, severity-grouped deduplicated findings, attack paths, recommendations.

## Success Criteria *(mandatory)*

### Measurable Outcomes

*Correctness and completeness criteria (SC-001–SC-005, SC-007–SC-010) apply in both execution modes. Latency targets (SC-006) apply to external-endpoint modes only; agent-mediated mode (FR-027) has no wall-clock target.*

- **SC-001**: The system completes a full scan of a repository at least 10x larger than a single analysis context window, with no individual analysis invocation exceeding its configured context budget in 100% of invocations.
- **SC-002**: 100% of findings in the final report include precise location references (file, symbol, line range), supporting evidence, severity, and confidence.
- **SC-003**: For seeded ground-truth fixture repositories, the final report contains no duplicate root-cause vulnerabilities — each systemic issue appears exactly once with consolidated evidence from all affected segments.
- **SC-004**: Total analysis token consumption for a full scan is at least 5x lower than a naive approach that sends maximal context to every analysis call (evidence escalation keeps the large majority of invocations at the smallest context tier).
- **SC-005**: An incremental rescan triggered by a single-file change completes in under 20% of the time and analysis cost of a full scan of the same repository.
- **SC-006**: A full first-time scan of a repository of approximately 1 million lines of code completes within approximately 1 hour under the interactive execution policy when independent segment analyses are executed in parallel; independent segment analyses MUST NOT be forced to run serially. Under the batch/off-peak policy, the same scan MUST complete within the operator-configured off-peak window instead.
- **SC-007**: Any single pipeline stage (e.g., one segment's analysis) can be re-run from persisted artifacts without re-executing any other stage.
- **SC-008**: A scan interrupted at an arbitrary point (crash, termination, or budget exhaustion) resumes automatically on next invocation and completes without re-executing any already-completed stage, verified by interrupting a scan at a random stage during testing.
- **SC-009**: On seeded fixture repositories with known vulnerabilities (including at least one cross-boundary vulnerability invisible to single-file analysis), the final report identifies at least the known true positives at the segment and system levels.
- **SC-010**: On a seeded multi-repository fixture workspace containing a known vulnerability that exists only at an integration point between two subsystems (e.g., identity trusted across a service boundary under mismatched authorization assumptions), the unified workspace report identifies the vulnerability and cites evidence from both repositories.
- **SC-011**: On seeded fixture repositories, 100% of findings reported as Critical or High carry either `verified` status or a `plausible` status with the untraced gap explicitly documented, and every reported finding includes a reproduction block that a developer can follow to demonstrate the issue against a local/test deployment in under 15 minutes.

## Assumptions

- **Deployment form**: The capability is delivered as an orchestrated scanning skill (orchestrator instructions plus deterministic scripts, prompt templates, structured schemas, and an artifact directory), invocable against a local workspace of one or more repositories.
- **Installation**: Users install the capability by running an installer command that scaffolds the skill into their chosen coding agent's skills directory (Spec Kit init-style; see Clarifications, Session 2026-08-30). Manual file copying is not required.
- **Agent portability**: The skill is agent-agnostic at its core, with thin per-agent adapters handling each agent's skill format and directory conventions. v1 ships adapters for the major coding agents (the same class of agents Spec Kit supports); additional agents are integrated by adding adapters, not by changing the core skill.
- **Execution policy**: Each scan runs under an operator-selected execution policy (interactive or batch/off-peak) with cost-optimized defaults; the policy controls batch API usage, off-peak scheduling windows, and model-tier assignment per analysis level (see Clarifications, Session 2026-08-30).
- **LLM access**: Analysis reasoning runs in one of two modes: agent-mediated (default) — the coding agent executing the skill reasons with its own model, requiring no keys or endpoint setup; or external-endpoint mode — an operator-configured cloud or self-hosted endpoint performs analysis. All outbound context passes through mandatory secret/credential redaction first in both modes (see Clarifications, Session 2026-08-30).
- **Language coverage**: Deterministic analysis targets common mainstream languages first; repositories using unsupported languages are still scanned with directory/module-heuristic partitioning and flagged with reduced confidence (see Edge Cases).
- **External scanner integration**: Traditional scanner findings are ingested from their standard machine-readable outputs via adapters; v1 ships one reference adapter per category (SAST, secrets, dependencies, IaC). Running or licensing those tools is a prerequisite, not part of this feature, though the pipeline may invoke them when available.
- **Artifact storage**: Artifacts and scan configuration are persisted in a dedicated dot-directory inside the scanned repository (e.g., `.security-scan/`), added to version-control ignore rules by default with an opt-in to commit; no remote storage or database is required for v1.
- **Out of scope for v1**: A persistent cross-repository security knowledge graph, interactive remediation workflows, CI/CD platform integrations, continuous monitoring, and full compliance-framework reporting packs (PCI-DSS, SOC 2, ISO 27001, NIST SSDF) are future enhancements; the pipeline design must not preclude them. Well-established CWE-to-framework control mappings MAY be attached to findings opportunistically, without per-framework interpretation or audit-ready wording.
- **Compliance extensibility**: The finding schema treats compliance framework mappings as data overlays on the CWE classification, so full compliance packs can be added later without schema or pipeline changes.
- **Report format**: The final report is produced as a structured machine-readable document plus a human-readable rendering; no specific viewer or dashboard is assumed.
