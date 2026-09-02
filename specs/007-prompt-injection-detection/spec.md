# Feature Specification: Prompt Injection Detection

**Feature Branch**: `007-prompt-injection-detection`

**Created**: 2026-09-01

**Status**: Draft

**Input**: User description: "i need to improve the framework to scan the modern exploites such as prompt injections"

## Clarifications

### Session 2026-09-01

- Q: How broad should the "modern exploits" coverage be in this feature — LLM/agent risk category only, or also supply-chain and dependency-confusion exploits? → A: Both — the feature covers the LLM/agent category (prompt injection, excessive agency, sensitive data in context, insecure output handling) AND supply-chain / dependency-confusion detection in the same feature
- Q: Should the scanner also flag unsafe AI tooling configuration shipped in the repository (agent rule files, MCP server/tool configurations, system prompt files, tool-permission declarations), in addition to scanning application code for prompt-injection surfaces? → A: Yes — both code-level injection surfaces AND shipped agent/tool configuration artifacts are scanned; over-privileged grants and sensitive data in prompt artifacts produce standalone findings
- Q: Which model integration styles must the scanner deterministically recognize at v1? → A: SDK clients + raw HTTP calls to model API endpoints + local/self-hosted model endpoints; message-queue/streaming/indirect invocation patterns (agent frameworks, queue-triggered inference) are beyond v1 and fall back to the undetermined-posture declaration

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Detect direct prompt injection attack surfaces in LLM-integrated code (Priority: P1)

A developer maintains an application that integrates a large language model. They run the scanner over the repository and receive findings wherever user-controlled or otherwise untrusted input is incorporated into model prompts (system, developer, or user messages) without a demonstrated isolation or validation control. Each finding cites the exact code locations involved — where the untrusted input originates, where the prompt is assembled, and where it is sent to the model — so the developer can see the full exposure path. Where the scanner cannot determine whether a mitigating control exists, the finding says so explicitly rather than assuming one way or the other.

**Why this priority**: Prompt injection is the headline modern exploit the user named, and it is the top-ranked risk for LLM-integrated applications (LLM01 in the OWASP Top 10 for LLM Applications). A finding here is high-impact (attackers can override application intent, exfiltrate data, or hijack downstream tool calls) and this story alone delivers a viable MVP.

**Independent Test**: Scan a fixture repository containing known prompt injection surfaces (user input concatenated into prompts, system instructions built from request data) and known safe usages (fixed prompts, strict separation of instruction and data). Verify the vulnerable surfaces are reported with correct locations and evidence, and the safe usages produce no findings.

**Acceptance Scenarios**:

1. **Given** a repository where user-supplied input is incorporated into a prompt sent to a model, **When** a scan runs, **Then** a finding is produced identifying the untrusted source, the prompt assembly point, and the model call, with severity and confidence reflecting what was demonstrated.
2. **Given** a repository where prompts are statically defined and user input is passed only as separately structured data with no path into instruction text, **When** a scan runs, **Then** no prompt-injection finding is produced for that usage.
3. **Given** a prompt assembly where the scanner cannot determine whether an isolation or validation control exists, **When** the scan completes, **Then** the finding records that the control state is undetermined and states why — it is not suppressed and not inflated.

---

### User Story 2 - Detect indirect prompt injection exposure via external content (Priority: P2)

An application feeds third-party content into model context — emails, documents, web pages, tickets, code files, tool results, database records. A security reviewer wants the scanner to identify these ingestion points as indirect prompt injection exposure: attacker-controlled text inside otherwise legitimate data can embed instructions the model may act on. Findings describe which external content sources reach model context, whether any content boundary labeling or filtering was demonstrated, and what downstream capabilities the model has (tools, actions, data access) that an injected instruction could abuse.

**Why this priority**: Indirect prompt injection is the more dangerous real-world variant — the attacker never touches the application directly, only data it later consumes. It requires reasoning about data provenance and model capabilities, which builds on the P1 detection pipeline, so it is second in sequencing, not in importance of risk.

**Independent Test**: Scan a fixture repository where external content (e.g., fetched documents, inbound messages) is placed into model context, with and without demonstrated boundaries. Verify exposure findings cite the ingestion point and reachable model capabilities, and bounded/sanitized ingestion produces lower-confidence or no findings.

**Acceptance Scenarios**:

1. **Given** a repository that retrieves third-party content and includes it in model context, **When** a scan runs, **Then** a finding identifies the untrusted content source and the model capabilities reachable from that context.
2. **Given** a repository where third-party content is demonstrably isolated from instruction-bearing context (e.g., labeled as quoted data with no tool reach), **When** a scan runs, **Then** no indirect prompt injection finding is produced, or the finding records the demonstrated boundary with corresponding confidence.
3. **Given** a repository with no external content ingestion into model context, **When** a scan runs, **Then** no indirect prompt injection findings appear.

---

### User Story 3 - Flag over-privileged agent and tool configurations found in the repository (Priority: P3)

Repositories increasingly ship AI agent and tooling configuration alongside code — agent rule files, tool/function definitions, system prompt files, model tool-permission declarations. The scanner reviews these artifacts and flags over-privileged or unsafe configurations: agents granted unrestricted tool access (shell execution, network egress, filesystem writes) with no demonstrated human-approval gate, system prompts that embed sensitive data, and tool definitions whose parameters accept arbitrary commands. These are reported as configuration findings citing the artifact and the specific privilege granted.

**Why this priority**: Over-privileged agents ("excessive agency") turn a successful prompt injection into real-world damage; flagging weak defaults raises the value of P1/P2 findings. It is third because it analyzes the shipped configuration artifacts that also feed the capability reasoning in Story 2.

**Independent Test**: Scan a fixture repository containing agent/tool configuration artifacts with over-privileged grants and equivalent tightly-scoped configurations. Verify the over-privileged grants are flagged with artifact citations and the scoped ones are not.

**Acceptance Scenarios**:

1. **Given** a repository containing an agent/tool configuration granting unrestricted execution or write capabilities without a demonstrated approval gate, **When** a scan runs, **Then** a finding cites the artifact and the specific excessive privilege.
2. **Given** a repository containing a system prompt or prompt template file embedding a credential or other sensitive value, **When** a scan runs, **Then** the sensitive value is redacted per existing redaction rules and a finding is reported without exposing the value.
3. **Given** a repository whose tool definitions are tightly scoped (no shell, bounded parameters, explicit grants), **When** a scan runs, **Then** no excessive-agency findings are produced for those definitions.

---

### User Story 4 - Detect supply-chain and dependency-confusion exposure (Priority: P4)

A maintainer's project declares dependencies; an attacker publishes a malicious package under the same name to a public registry (dependency confusion) or a near-identical name (typosquatting), and the build silently resolves the attacker's version. The scanner reviews the project's dependency declarations for supply-chain exposure: internal-namespace package names that also resolve on public registries without safeguards, unpinned or mutable dependency references, and known typosquatting or suspicious-package signals from the shipped data. Findings cite the manifest location and the specific exposure, and where it cannot be determined whether an upstream registry or lockfile guard exists, the finding declares that state explicitly.

**Why this priority**: The user explicitly chose to include supply-chain and dependency-confusion detection alongside the LLM category. It relies on the existing dependency-manifest analysis, so it sequences after the LLM stories, but it addresses a distinct, actively exploited class of modern attack.

**Independent Test**: Scan a fixture repository whose dependency manifests contain a known dependency-confusion exposure (internal-name pattern resolvable publicly, unpinned or mutable references) and an equivalent hardened manifest (pinned, registry-scoped/internal-source enforced). Verify the exposure is flagged with manifest citations and the hardened manifest produces no findings.

**Acceptance Scenarios**:

1. **Given** a project whose dependency declarations include an internal-namespace package that could resolve from a public registry without a demonstrated guard (lockfile enforcement, private-registry pinning, or claimed public name), **When** a scan runs, **Then** a dependency-confusion finding cites the manifest location and the unguarded package.
2. **Given** a project whose dependency references are unpinned or mutable where pinning is enforceable, **When** a scan runs, **Then** a finding identifies the mutable references and the substitution risk.
3. **Given** a project whose dependencies are pinned and registry-scoped with a demonstrated guard against public substitution, **When** a scan runs, **Then** no supply-chain findings are produced for those declarations.
4. **Given** a manifest where the scanner cannot determine whether a resolution guard exists (e.g., resolution behavior depends on configuration not present in the repo), **When** the scan completes, **Then** the finding records the guard state as undetermined rather than assuming either way.

---

### Edge Cases

- Repositories with no LLM or AI-tooling integration at all must produce zero findings from this category — no noise on traditional projects.
- Prompts assembled dynamically through multiple build steps (template rendering, string interpolation across functions) must still be traced end-to-end; if the chain cannot be fully resolved, the finding declares the unresolved portion rather than guessing.
- Obfuscation or encoding indirection (base64, chunked strings) between the untrusted source and the prompt: the scanner reports what it could trace and explicitly marks trace gaps.
- Non-English or adversarial-looking content located inside the scanned repository: the scanner only observes configuration and code structure; it never executes or "tests" injected text, consistent with the observe-never-attack invariant.
- Model frameworks and SDKs vary widely; integration styles outside the recognized v1 set (especially indirect invocation via agent frameworks, brokers, or queues) are reported with an undetermined integration posture for that call site rather than being skipped silently or assumed unsafe.
- Large monorepos mixing LLM and non-LLM services: analysis is partitioned along existing security boundaries and LLM-relevant segments receive this category's analysis while unrelated segments do not incur noise or extra cost.
- Resolution guards that live in external infrastructure (registry firewall rules, build-pipeline settings not present in the repository) are recorded as undetermined, never assumed present or absent.
- Namespaced/scoped package names that are legitimately public still pass through the same guard evaluation; public status alone does not exempt a declaration from confusion analysis, and internal-looking names are not automatically flagged without an exposure path.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST deterministically discover and classify LLM integration points in a scanned repository — covering at minimum official SDK client calls, raw HTTP calls to model API endpoints, and local/self-hosted model endpoints — including model invocations, prompt construction sites, message assembly, tool/function calling declarations, and agent configuration artifacts. Integration styles outside this recognized set (message-queue/streaming/indirect invocation such as agent-framework brokers or queue-triggered inference) MUST be recorded with an undetermined posture for the call site rather than silently skipped or assumed safe. Classification MUST be derived from code structure and shipped versioned data, never from model output.
- **FR-002**: The system MUST trace untrusted input (request data, runtime input, environment-derived values) into prompt/message assembly, and produce a prompt-injection finding wherever such input reaches instruction-bearing model context without a demonstrated isolation or validation control. Findings MUST cite the untrusted source, the assembly point, and the model call, with evidence resolving against the code model.
- **FR-003**: The system MUST trace external/third-party content (fetched documents, inbound messages, tool results, data records) into model context and report indirect prompt injection exposure, naming the content source and the model capabilities (tools, actions, data access) reachable from that context.
- **FR-004**: Where the presence or absence of a mitigation (isolation boundary, validation, human approval) cannot be determined, the finding MUST record an explicit undetermined state with the reason. An unknown MUST NOT suppress a finding and MUST NOT inflate its severity.
- **FR-005**: The system MUST review shipped AI configuration artifacts (agent rule files, MCP server/tool configurations, system prompt files, tool/function definitions, tool-permission declarations) and flag unsafe configurations as standalone findings, including over-privileged tool grants without demonstrated approval gates (unbounded shell execution, network egress, or filesystem writes) and sensitive values embedded in prompt artifacts. These artifacts MUST also feed the capability-reach reasoning used by indirect prompt injection findings.
- **FR-006**: All findings in this category MUST carry a weakness identifier from the shipped weakness taxonomy; the taxonomy MUST be versioned data extended (not hard-coded) so adding classes does not require pipeline changes, consistent with extensibility-as-data.
- **FR-007**: The system MUST integrate this category into the existing severity, confidence, and verification model: findings receive severity bands, confidence reflecting what was demonstrated, and verification status (verified / plausible / disproven) from static trace evidence only — never from executing or simulating an attack.
- **FR-008**: The system MUST detect supply-chain and dependency-confusion exposure in dependency declarations: internal-namespace package names resolvable on public registries without a demonstrated guard (lockfile enforcement, private-registry pinning, or claimed public names), unpinned or mutable dependency references where pinning is enforceable, and known typosquatting or suspicious-package signals from shipped versioned data. Where resolution guards cannot be determined from the repository, the finding MUST declare the guard state as undetermined.
- **FR-008a**: The system MUST also cover the remaining LLM/agent category classes named in scope: sensitive-information disclosure through model context (secrets or sensitive data demonstrated to enter model context) and insecure model output handling (model output flowing into execution, rendering, or query construction without demonstrated validation).
- **FR-009**: Prompt artifacts and configuration files MUST pass through the same redaction layer as source code before any analysis or artifact writing; credential values embedded in them MUST be reportable as findings while their values never appear in any artifact.
- **FR-010**: The category MUST produce zero findings on repositories with no LLM integration, no AI configuration artifacts, and no dependency-declaration supply-chain exposure; absence of integration MUST be established deterministically, not inferred.
- **FR-011**: Segments, coverage gaps, and report integration MUST follow existing pipeline rules: LLM-relevant file classes join the analysis partition, unanalyzed LLM-relevant content is declared as a coverage gap, and findings appear in all report formats with stable identifiers.
- **FR-012**: All new detectors MUST be exercised by benchmark fixtures with declared ground truth, including deliberate false-positive fixtures that MUST NOT be reported, per the accuracy benchmark's release-blocking regression rule.

### Key Entities

- **LLM Integration Point**: a location where application code constructs or sends model context — prompt assembly, message lists, invocation calls, streaming handlers. Attributes: kind (system/developer/user/tool context), content source, downstream model or tool reach.
- **Prompt Injection Surface**: a claim that untrusted input or third-party content reaches instruction-bearing model context. Attributes: source location, assembly location, reach (tools/actions/data accessible from context), mitigation state (demonstrated / undetermined), category (direct / indirect).
- **AI Configuration Artifact**: a shipped file governing agent behavior — rule files, system prompts, tool definitions, permission declarations. Attributes: artifact kind, granted capabilities, approval-gate posture, embedded-sensitive-value status.
- **Supply-Chain Exposure**: a claim about dependency declarations — an internal-namespace name publicly resolvable without a demonstrated guard, a mutable/unpinned reference where pinning is enforceable, or a match against known suspicious-package data. Attributes: manifest location, package identity, exposure kind, guard state (demonstrated / undetermined).
- **Modern Exploit Class**: a weakness-taxonomy entry covering an LLM-era or modern defect class (prompt injection, excessive agency, sensitive data in context, insecure output handling, supply-chain/dependency-confusion), shipped as versioned data with default severity, domain, and reporting guidance.
- **Mitigation Evidence**: demonstrated isolation boundaries, validation steps, or human-approval gates traceable in code or configuration; the honest third state "undetermined" when none can be proven either way.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On the benchmark corpus of LLM-integrated fixture repositories with declared prompt-injection ground truth, the category detects at least 90% of seeding-confirmed vulnerable surfaces with locations resolving to the seeded files and lines.
- **SC-002**: Zero prompt-injection or agent-configuration findings are produced on the benchmark's non-LLM repositories and on deliberate false-positive fixtures.
- **SC-003**: 100% of findings in this category cite a weakness identifier present in the shipped taxonomy and a location that resolves against the code model; hallucinated identifiers or unresolved locations fail the report gate.
- **SC-004**: 100% of findings where mitigation could not be determined carry an explicit undetermined state with a stated reason; none are silently suppressed or severity-inflated for lack of proof.
- **SC-005**: Two runs over identical input with identical tool version produce byte-identical artifacts including the new category's findings and coverage-gap declarations.
- **SC-006**: 0 credential values embedded in prompt artifacts appear in any output artifact (redaction sweep enforced), while the embedded-secret findings themselves are reported 100% of the time on seeded fixtures.
- **SC-007**: Adding a new modern exploit class to coverage requires only a versioned-data change (no pipeline modification), demonstrated by at least one worked addition in the feature's verification.
- **SC-008**: On seeded dependency-confusion fixtures, 100% of declared supply-chain exposures are reported with manifest citations, and hardened manifests (pinned, registry-scoped) produce zero supply-chain findings.

## Assumptions

- The category targets vulnerabilities discoverable by static analysis of code and configuration: prompt construction, data provenance into model context, and shipped agent/tool configuration. Runtime behavior of a deployed model (jailbreak success, output quality) is out of scope, consistent with the observe-never-attack principle.
- Prompt injection coverage spans both direct (user input into prompts) and indirect (third-party content into context) exposure; both are industry-recognized as the same headline risk class.
- (Confirmed in Clarifications, Session 2026-09-01) "Modern exploits" covers both the LLM/agent category (prompt injection direct and indirect, excessive agency, sensitive data in prompts/context, insecure output handling) and supply-chain/dependency-confusion detection. Classes beyond these two groups (e.g., build-signing integrity, provenance attestation) remain out of scope for this feature.
- Supply-chain detection relies only on evidence obtainable offline from the repository and shipped versioned data (manifests, lockfiles, configuration, known suspicious-package signals); live registry queries are out of scope per the offline constraint. Where a guard exists only in external infrastructure configuration, the guard state is recorded as undetermined.
- (Confirmed in Clarifications, Session 2026-09-01) v1 recognition covers official SDK clients, raw HTTP calls to model endpoints, and local/self-hosted endpoints. Indirect invocation patterns (agent frameworks, brokers, queue-triggered inference) are beyond v1 and receive an "undetermined" posture for that call site per the honest-uncertainty principle, not silent exclusion.
- Detection quality targets are benchmark-driven, matching the existing per-defect-class release-blocking accuracy rule; new classes join that assertion model.
- All analysis remains offline and deterministic; taxonomy and recognition data ship versioned in the payload.
