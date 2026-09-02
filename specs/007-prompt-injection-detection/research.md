# Research: Prompt Injection Detection

**Feature**: `007-prompt-injection-detection` | **Date**: 2026-09-01

All Technical Context unknowns resolved. Decisions below are ordered by dependency; each cites the requirement(s) it discharges.

## R1: Detection strategy — deterministic recognition + model reasoning over traced evidence

**Decision**: Split detection into three layers, each reusing an existing pipeline pattern.

1. **Deterministic recognition** (`extract/llm_integration.py`): regex/AST-anchored patterns from a versioned dataset (`llm_integrations.json`) mark model invocations, prompt assembly, tool declarations, and external-content ingestion as graph annotations. No model participation (Principle I).
2. **Deterministic rule evaluation** (`supply_chain.py`, `agent_config.py`): misconfig.py precedent — versioned rule packs over manifests and AI config artifacts, value-free findings, load-time validation that fails the build rather than the scan.
3. **Model-guided analysis**: a `llm-security` domain assigned to segments with LLM evidence; the segment prompt carries only that domain's guidance (prompts.py filtering precedent); findings must cite traced flows (Principle IV).

**Rationale**: the constitution makes deterministic tooling the sole repository analyzer; the misconfig (feature 004) and enricher (features 001/002) precedents give proven shapes for exactly these two deterministic forms.

**Alternatives considered**: pure rule-based prompt-injection matching — rejected, injection surfaces are semantic (whether input is untrusted and context is instruction-bearing needs flow reasoning); model-only detection — constitution-violating.

## R2: Prompt injection modeled as dataflow sinks; external content as sources

**Decision**: Introduce two annotations in `dataflow.py`'s existing tracer:

- `llm_prompt_sink` — prompt assembly and model invocation nodes; `Dataflow.is_sink` gains recognition so the verify pass (feature 006) adjudicates `verified` (full traced path) / `plausible` (partial) / `disproven` for prompt-injection findings with no new verdict machinery.
- `external_content_source` — nodes where third-party/attacker-influenceable content enters the program (fetch results, inbound message parsers, tool results, record loaders); joins `Dataflow.sources` alongside `user_controlled_input`. This is what makes *indirect* injection traceable rather than a naming heuristic (FR-003).

Validation annotations already flow through `Flow.transforms/validations`; mitigations on an LLM path (boundary labeling, validation, approval gates) are recorded the same way and surface in the verdict reason.

**Rationale**: prompt injection is precisely "untrusted value reaching an instruction interpreter"; the existing tracer is built for exactly that claim shape, and reusing verify.py means severity/confidence calibration (feature 006) applies unchanged (FR-007).

**Alternatives considered**: a bespoke prompt-graph structure — rejected, duplicates the tracer and escapes the established verification/calibration path; treating model calls as `security_sink` — rejected, a distinct sink kind keeps injection findings (which imply concrete interpreter semantics) separate from LLM findings and lets both coexist on one node.

## R3: Integration recognition dataset scope (v1)

**Decision**: `skill_core/data/llm_integrations.json` v1 (versioned, load-time validated) carries three recognition classes per the clarified scope:

1. **SDK clients** — import/module names and client-call shapes for the mainstream hosted SDKs across the grammar-backed languages (e.g., `openai`, `anthropic`, `google.generativeai`/`genai`, `langchain` chat-model wrappers; equivalent npm packages).
2. **Raw HTTP model endpoints** — literal/compound URL construction targeting known model API hosts (pattern data lists host suffixes, e.g., `api.openai.com`, `generativelanguage.googleapis.com`).
3. **Local/self-hosted endpoints** — known local servers (Ollama `11434`, llama.cpp server, vLLM, LM Studio ports) and explicit localhost/loopback model paths.

Anything heuristic-only (call sites suggesting inference without a recognized pattern — brokered, queued, framework-mediated invocation) is annotated as an **undetermined-posture candidate** and declared in the report, never silently dropped and never claimed safe (FR-001, Principle V).

**Rationale**: matches clarified Q3 answer; covers the large majority of current codebases while keeping the dataset small and auditable.

**Alternatives considered**: recognizing indirect invocation (agent frameworks, queue-triggered inference) at v1 — rejected (deferred by clarification; the undetermined-posture declaration keeps those repos honest rather than clean-looking).

## R4: AI configuration artifact file classes

**Decision**: `stacks.json` `file_classes` gains three classes (data-only change, FR-025b precedent):

- `ai-agent-config` — agent rule/instruction files shipped in repos (e.g., `.cursorrules`, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.windsurfrules`, `.github/copilot-instructions.md`).
- `ai-mcp-config` — tool/function-call permission and server configuration (e.g., `mcp.json`, `.mcp.json`, `claude_desktop_config.json`, `.vscode/mcp.json`).
- `prompt-artifact` — shipped prompt/system-instruction files, matched by exact filename per the classifier's existing convention (e.g., `system.prompt`, `agent.prompt`); no glob matching at v1 — a glob-capable classifier would be a separate capability change.

`extract/config_files.py` classifies them as today; `build_code_graph.add_config` gives them graph nodes so they belong to segments and appear in the per-file-class coverage statement (FR-011); `ConfigFile.annotations` gains `ai_config` for these classes, and `partition_repo.DOMAIN_BY_FILE_CLASS` maps them to `llm-security`.

**Rationale**: filename-driven classification is the existing, deterministic mechanism; new classes inherit segment membership, coverage, and redaction for free.

**Alternatives considered**: content sniffing to find prompts in arbitrary files — rejected, non-deterministic recall boundary and high false-positive risk; filename classes are the auditable line.

## R5: LLM-security domain in analysis prompts

**Decision**: `skill_core/prompts/segment_scan.md` gains one `- **llm-security**` guidance bullet inside the DOMAIN-GUIDANCE markers, teaching the analysis pass to: use traced flows as the evidence of injection surfaces; distinguish direct (user input) vs indirect (external content) categories; read tool/capability reach from graph annotations; and state mitigation evidence as demonstrated/undetermined. `partition_repo` maps gain `llm-security` for `llm_prompt_sink`/`llm_invocation`/`tool_declaration` annotations and the new file classes.

**Rationale**: prompt filtering keeps token cost zero for non-LLM segments (Principle II, FR-010); one domain bullet keeps guidance discoverable and per-domain accuracy assertable in the benchmark.

## R6: Weakness taxonomy additions (cwe_map.json v2, additive)

**Decision**: bump `cwe_map.json` to version `2`, adding (ids verified against cwe.mitre.org):

| CWE | Class | domain | default_severity | llm_top10 / owasp |
|---|---|---|---|---|
| CWE-1427 | Improper Neutralization of Input Used for LLM Prompting | `llm-security` | 9.1 | LLM01 |
| CWE-250 | Execution with Unnecessary Privileges (excessive agency) | `llm-security` | 7.8 | LLM06 |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere (dependency confusion / typosquatting) | `dependencies` | 9.8 | A08 |
| CWE-494 | Download of Code Without Integrity Check (mutable/unpinned references) | `dependencies` | 8.1 | A08 |

Existing entries cover the remaining clarified classes: CWE-200 (sensitive info in context → LLM02) and CWE-116/CWE-20 (insecure output handling → LLM05). Add one additive top-level `llm_top10_2025` mapping block mirroring `owasp_top10_2021`, with the note discipline preserved (well-established relationships only). `validate_cwe` and contract tests enforce that no finding references ids outside the dataset (FR-006).

**Rationale**: taxonomy ships as versioned data; additive bump keeps prior findings comparable (additive-schema rule).

**Alternatives considered**: inventing internal "MEC" ids — rejected; findings must carry a standard weakness identifier and CWE has canonical entries for the new classes.

## R7: Supply-chain / dependency-confusion detection mechanics

**Decision**: `supply_chain.py` parses manifests structurally (JSON/TOML/package-text per ecosystem) rather than by raw regex, over `dependency-manifest` files already in the graph. `supply_chain_rules.json` v1 carries rule kinds:

- `internal-namespace-unprotected` — package name matching an org-internal naming pattern (data-configured per ecosystem, e.g., unscoped private names in `.npmrc`-less npm projects, non-public index names in pip projects) with **no demonstrated guard** in the repo: guard evidence = committed lockfile with pinned/resolved versions, registry config pinning a private index (`.npmrc` / `pip.conf` / `pyproject.toml` index settings), or scoped-registry mapping. Guard state is tri-state: `demonstrated`, `undetermined` (evidence lives outside the repo), — never inferred.
- `mutable-reference` — version specifiers that permit substitution where a lockable/pinnable form exists (`latest`, `*`, unpinned ranges without lockfile).
- `suspicious-package` — exact-match against a versioned offline dataset of known typosquat/confusion-prone names.

Findings are value-free rule matches with file/line/rule id, sourced via `misconfig`-style normalization into `findings/supply_chain.json`.

**Rationale**: all evidence is obtainable offline from the repo plus shipped data (spec assumption); structural parsing of manifests avoids the false positives raw regex produces in arrays/scoped names.

**Alternatives considered**: live registry queries (does this internal name exist publicly?) — rejected; violates the offline default path; absence of live resolution is exactly why guard state must be tri-state.

## R8: Agent/tool configuration review mechanics

**Decision**: `agent_config.py` evaluates AI config artifacts with `agent_config_rules.json` v1, two evaluation forms (chosen per artifact format in the rule):

- **structural** — JSON artifacts (MCP configs): rule asserts properties of parsed tool/server entries (e.g., command = shell interpreter, `args` accept arbitrary command strings, no human-approval/confirmation field, credentials in env blocks — the latter handed to the redactor path, not matched literally).
- **anchored-pattern** — markdown agent rule files: misconfig-style anchored regex for explicit privilege grants (full filesystem write, unrestricted network, auto-approve/all-tools-enabled stanzas) absent an adjacent approval-gate statement; matches over **redacted** text so secrets never influence or leak through findings.

Findings cite artifact, rule id, and the granted capability; sensitive values embedded in prompt artifacts are **also** reported through the existing redactor/secret_findings path (value never appears), satisfying both the config-finding and secrets-reporting requirements (FR-005, FR-009).

**Rationale**: misconfig precedent proves anchored-pattern determinism; structural evaluation where JSON is available keeps precision high.

## R9: Benchmark integration

**Decision**: `tests/benchmark` gains two defect classes — `llm-detection` and `supply-chain-detection` — plus new seeded fixtures with declared ground truth (vulnerable prompt assembly with known files/lines; safe structured separation; indirect ingestion bounded vs unbounded; confusion-vulnerable vs hardened manifests; over-privileged vs scoped agent configs) and deliberate false positives that MUST NOT be reported (FR-012). Per-class assertions join the release-blocking accuracy gate; the existing per-file-class coverage tests gain the three new file classes.

**Rationale**: detection quality is asserted via ground truth (constitution quality gates), and SC-001/SC-002/SC-008 map directly onto these assertions.

## R10: CLI and report surface

**Decision**: no new flags — the category runs unconditionally on every scan (misconfig precedent), findings flow through the existing normalize → ingest → verify → report stages and appear in JSON/Markdown/HTML via additive fields only. The redaction sweep's artifact list gains the two new finding artifacts.

**Rationale**: unconditional execution is what makes FR-010's "zero findings on non-LLM repos" a testable guarantee rather than a configuration.
