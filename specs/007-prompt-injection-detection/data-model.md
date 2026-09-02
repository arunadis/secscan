# Data Model: Prompt Injection Detection

**Feature**: `007-prompt-injection-detection` | **Date**: 2026-09-01

Entities introduced or extended by this feature. Code-model entities follow the code graph's stable-id convention (`<repo>:<path>#<symbol>`); finding entities follow `skill_core/schemas/finding.json` and the `findings/misconfig.json` envelope precedent. All additions to existing schemas are additive.

## Code-Graph Entities (additive)

### LLM Integration Point (new node annotations, no new node type)

Model-context construction/invocation recorded as annotations on existing graph nodes (symbols) or new config nodes.

| Field | Type | Notes |
|---|---|---|
| `id` | stable node id | `<repo>:<path>#<symbol>` (or file-level) |
| `annotations` | additive enum values | `llm_invocation`, `llm_prompt_sink`, `tool_declaration`, `external_content_source` — all additive extensions to `code_graph.json`'s annotation enum |
| `integration_style` | enum (context of extraction, not serialized separately) | `sdk-client` / `http-endpoint` / `local-endpoint` / `undetermined` — the last is the honest third state for heuristic-only candidates (R3) |
| `line_start` / `line_end` | int | code model is the sole authority for line ranges |

**Validation**: every `llm_prompt_sink` node must carry at least one of `sdk-client | http-endpoint | local-endpoint` recognition evidence from `llm_integrations.json`, or the `undetermined` posture with a recorded reason; a node may never be annotated from model output.

### Tool Declaration (`tool_declaration` annotated node)

A function/tool exposed to a model: name, parameter schema presence, capability hints drawn from the owning segment's annotations (shell, network, filesystem). Feeds capability-reach reasoning (FR-003) and agent-config review (FR-005).

### AI Configuration Artifact (extension of `ConfigFile`)

`extract/config_files.py` `ConfigFile` extended by three new `file_class` values (additive enum): `ai-agent-config`, `ai-mcp-config`, `prompt-artifact`.

| Field | Type | Notes |
|---|---|---|
| `path` / `file_class` / `format` | existing | unchanged |
| `annotations` | additive | `ai_config` for all three classes; joins `code_graph.json` node annotations |
| redaction | — | artifact text passes the redactor before analysis/artifact writes (FR-009) |

**Lifecycle**: classified → graphed (segment membership + coverage statement) → evaluated by `agent_config.py` (and redactor) → findings normalized → verified → reported. File classes appear in the per-file-class coverage statement so absence is distinguishable from silence (FR-011, Principle V).

## Finding Entities

### Prompt Injection Surface (finding.json, no new required fields)

| Field | Value |
|---|---|
| `cwe` | `CWE-1427` (direct and indirect; category recorded in evidence) |
| `severity` / `confidence` | from taxonomy defaults + calibration (feature 006); confidence reflects mitigation state |
| `verification.status` | `verified` only with a fully traced `user_controlled_input`/`external_content_source` → `llm_prompt_sink` path; otherwise `plausible`; `disproven` rejects the finding |
| `evidence` | traced source node, assembly node, invocation node; capability reach (tools/actions/data) for indirect category |
| `mitigation` *(additive optional field)* | `{ "control": "isolation-boundary|validation|human-approval", "state": "demonstrated|undetermined", "reason": string }` — `undetermined` must carry a reason; never absent-but-assumed (FR-004) |

**State transitions**: produced (segment analysis) → normalized → verified (`verified`/`plausible`/`disproven`→rejected) → reported. Undetermined mitigation never suppresses and never inflates.

### Supply-Chain Exposure (findings/supply_chain.json → normalized finding)

| Field | Value |
|---|---|
| `cwe` | `CWE-829` (confusion/typosquat/suspicious), `CWE-494` (mutable reference) |
| `rule` | id from `supply_chain_rules.json`; value-free (file/line/rule only) |
| guard state | `demonstrated` / `undetermined` recorded in evidence; `undetermined` when resolution config is external to the repo (R7) |

### Agent-Configuration Finding (findings/agent_config.json → normalized finding)

| Field | Value |
|---|---|
| `cwe` | `CWE-250` (excessive agency) |
| `rule` | id from `agent_config_rules.json` (structural or anchored-pattern form) |
| `evidence` | artifact path, granted capability; embedded secrets route through redactor/secret_findings — values never serialized |

### Modern Exploit Class (taxonomy data — `cwe_map.json` v2)

Additive entries (CWE-1427, CWE-829, CWE-494, CWE-250) plus a top-level `llm_top10_2025` mapping block (LLM01, LLM02, LLM05, LLM06 as used), version bumped 1 → 2. `validate_cwe` rejects ids not in the dataset; contract tests cover round-trip.

## Recognition & Rule Data (versioned, load-time validated)

| File | Contents | Validation at load |
|---|---|---|
| `skill_core/data/llm_integrations.json` v1 | `sdk_modules[]` (module/import names, client call shapes, language), `http_endpoints[]` (host suffixes), `local_endpoints[]` (hosts/ports), `candidate_hints[]` (undetermined-posture heuristics) | unique ids, compiled patterns, language within shipped set — invalid data fails the build (R3) |
| `skill_core/data/supply_chain_rules.json` v1 | rules with `id`, `kind` (`internal-namespace-unprotected` / `mutable-reference` / `suspicious-package`), `ecosystems[]`, `cwe`, title/description/recommendation | misconfig-style required-field + pattern-compile + `validate_cwe` checks (R7) |
| `skill_core/data/agent_config_rules.json` v1 | rules with `id`, `form` (`structural` / `anchored-pattern`), `file_classes[]`, `grant` capability, approval-gate test, `cwe` | same load-time validation discipline (R8) |
| `skill_core/data/stacks.json` | `file_classes` gains `ai-agent-config`, `ai-mcp-config`, `prompt-artifact` name lists (version bump) | data change only (FR-025b precedent) |

## Relationships

- LLM Integration Point —(prompt assembly)→ `llm_prompt_sink`; —(capability)→ Tool Declaration; traces connect `user_controlled_input` / `external_content_source` sources to prompt sinks through call edges.
- AI Configuration Artifact —(grants)→ capabilities consumed as evidence by indirect-injection findings (FR-005: artifacts feed capability reach).
- Findings of all three kinds —(verify)→ `verification.status`; —(mitigation/guard tri-state)→ honest uncertainty; —(render)→ all three report formats (FR-011).
