# Implementation Plan: Prompt Injection Detection

**Branch**: `007-prompt-injection-detection` | **Date**: 2026-09-01 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/007-prompt-injection-detection/spec.md`

## Summary

Extend the scanner with a "modern exploits" category covering the LLM/agent risk group (direct and indirect prompt injection, excessive agency, sensitive data in model context, insecure output handling) and supply-chain/dependency-confusion exposure. The design stays inside the pipeline's existing architecture: (1) **deterministic recognition** via new versioned data — an LLM-integration recognition dataset (SDK clients, raw HTTP model endpoints, local endpoints), new AI-artifact file classes in `stacks.json`, and two misconfig-style rule packs (`supply_chain_rules.json`, `agent_config_rules.json`); (2) **dataflow integration** — prompt assembly and model invocation nodes become trace sinks (`llm_prompt_sink`), and third-party content ingestion becomes a trace source (`external_content_source`), so the existing verify pass adjudicates verified/plausible/disproven over traced paths; (3) **model-guided analysis** via a new `llm-security` domain assignment and guidance bullet in the segment prompt; (4) **taxonomy extension** — `cwe_map.json` v2 adds CWE-1427 (prompt injection), CWE-829 and CWE-494 (supply chain), CWE-250 (excessive agency), plus an OWASP LLM Top 10 mapping block. Benchmark gains two new release-blocking defect classes with seeded ground truth and deliberate false positives.

## Technical Context

**Language/Version**: Python 3.11+ (constitution constraint)

**Primary Dependencies**: none added — stdlib only (json, re, fnmatch precedent). Existing: click, jsonschema, tree-sitter grammars, pyyaml

**Storage**: filesystem artifact store (`<scan_root>/.security-scan/`); new deterministic finding artifacts `findings/supply_chain.json` and `findings/agent_config.json` follow the existing `findings/misconfig.json` envelope precedent

**Testing**: pytest (+ `ruff check src tests` gate); contract tests for every schema; accuracy benchmark gains two defect classes (`llm-detection`, `supply-chain-detection`) with seeded fixtures

**Target Platform**: CLI tool, any OS; offline (no network in default path)

**Project Type**: cli / skill payload

**Performance Goals**: new deterministic stages run over already-enumerated files (bounded by file count, not repo tokens); LLM-token impact bounded — `llm-security` guidance ships only to segments whose domains call for it (prompt-filtering precedent); token budgets unchanged and enforced against serialized requests

**Constraints**: offline and deterministic (byte-identical artifacts for identical input); all recognition data ships versioned in the payload; redaction runs over prompt artifacts before any artifact write; schema changes additive only; no attack execution or injected-content emulation; scanner payload and tool directories excluded from analysis

**Scale/Scope**: workspaces of multiple repos; v1 recognition data covers python + javascript SDK modules at minimum (extensible to go/java via data) plus raw HTTP patterns; AI config artifacts recognized by exact filename (classifier convention); supply-chain evaluation over package.json/lockfiles and requirements.txt/pyproject.toml ecosystems initially (ecosystem extensibility via data)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Evaluation | Result |
|---|---|---|
| I. Determinism Before Intelligence | Discovery of LLM integrations, AI config artifacts, and supply-chain exposure is fully deterministic and data-driven (versioned JSON packs); the model only reasons over prepared evidence in the `llm-security` domain analysis; new artifacts sorted, stable IDs, no wall-clock values | PASS |
| II. Context Is a Managed Resource | `llm-security` domain is assigned only to segments with LLM evidence; prompt guidance is filtered per segment; deterministic stages add no tokens; unrecognized call sites recorded as undetermined posture, not escalated into context | PASS |
| III. Secrets Never Reach a Model | Prompt artifacts and AI config files pass the existing redactor before analysis and before any artifact write (new file classes join the redaction sweep); embedded-secret findings report location, never value (secret_findings precedent); deterministic findings are value-free (misconfig precedent) | PASS |
| IV. Evidence Over Assertion | New findings conform to finding.json; deterministic findings carry rule id + location; model findings require traced flows — `llm_prompt_sink` integrates with verify.py so unverified claims downgrade to plausible; taxonomy ids come from the shipped dataset (`validate_cwe`) | PASS |
| V. Honest Uncertainty | Mitigation/guard states are tri-state (demonstrated / undetermined); unrecognized integration styles record undetermined posture rather than silence or assumed safety; supply-chain guard state undetermined when resolution config is external to the repo; new file classes join the per-file-class coverage statement | PASS |
| VI. Observe, Never Attack | All detection is static trace/config review; adversarial text in scanned repos is data, never executed; new stages are read-only against scanned projects; two new benchmark defect classes join the release-blocking accuracy gate | PASS |

No violations; Complexity Tracking table not required.

**Post-design re-check (after Phase 1)**: the design introduces no new principle exposure. Recognition is regex/AST-pattern matching over already-redacted text with anchors on code shape, never values; new data files follow the misconfig/compound_rules load-time validation precedent (invalid data fails the build, not the scan); the only schema changes are additive enum extensions (`file_class`, `annotations`) and one additive optional finding field; the coverage statement gains the new file classes so absence of AI artifacts is distinguishable from non-attempt. All six principles remain PASS after design.

## Project Structure

### Documentation (this feature)

```text
specs/007-prompt-injection-detection/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/
│   └── data-contracts.md # Phase 1 output
└── tasks.md             # Phase 2 output (/speckit-tasks - NOT created here)
```

### Source Code (repository root)

```text
src/
├── pipeline/
│   ├── extract/
│   │   ├── llm_integration.py    # NEW: deterministic recognition of SDK clients,
│   │   │                         #   raw HTTP model endpoints, local endpoints ->
│   │   │                         #   graph annotations (llm_invocation,
│   │   │                         #   llm_prompt_sink, external_content_source,
│   │   │                         #   tool_declaration, undetermined candidates)
│   │   └── config_files.py       # + new AI file classes annotate artifacts
│   ├── build_code_graph.py       # + consume llm_integration extractor; register
│   │                             #   prompt-sink nodes; link tool declarations
│   ├── partition_repo.py         # + llm-security domain in DOMAIN_BY_* maps
│   ├── dataflow.py               # + llm_prompt_sink recognized as trace sink;
│   │                             #   external_content_source as trace source
│   ├── llm_findings.py           # NEW: traced flows -> finding dicts for all
│   │                             #   LLM classes (direct/indirect injection,
│   │                             #   sensitive data in context, insecure output
│   │                             #   handling); mitigations tri-stated
│   ├── verify.py                 # + sink-kind awareness for LLM flows (minimal)
│   ├── supply_chain.py           # NEW: deterministic dependency-confusion /
│   │                             #   mutable-reference / suspicious-package eval
│   ├── agent_config.py           # NEW: deterministic excessive-agency review of
│   │                             #   AI config artifacts (grants vs approval gate)
│   ├── run.py                    # + wire new deterministic stages; normalize ->
│   │                             #   findings/supply_chain.json, agent_config.json
│   └── prompts.py                # unchanged (domain filtering already generic)
├── skill_core/
│   ├── data/
│   │   ├── llm_integrations.json     # NEW: versioned recognition dataset
│   │   ├── supply_chain_rules.json   # NEW: versioned supply-chain rule pack
│   │   ├── agent_config_rules.json   # NEW: versioned excessive-agency rule pack
│   │   └── stacks.json               # + file classes: ai-agent-config,
│   │                                 #   ai-mcp-config, prompt-artifact
│   ├── cwe_map.json                  # v2 (additive): CWE-1427/829/494/250 +
│   │                                 #   llm_top10 mapping block
│   ├── prompts/segment_scan.md       # + **llm-security** domain guidance bullet
│   └── schemas/
│       ├── code_graph.json           # + additive enum: new file_class +
│       │                             #   annotation values
│       └── finding.json              # + optional additive "mitigation" evidence
│                                     #   field (tri-state control evidence)

tests/
├── unit/
│   ├── test_llm_integration_extract.py   # NEW: recognition patterns, candidates
│   ├── test_supply_chain.py              # NEW: rule eval, guard tri-state
│   ├── test_agent_config.py              # NEW: grant/approval rules, redaction
│   └── test_dataflow_llm.py              # NEW: prompt-sink tracing, sources
├── contract/
│   ├── test_data_files.py                # NEW: load-time validation of the
│   │                                     #   three versioned data files
│   └── test_schemas.py                   # + additive enum/field round-trips
├── fixtures/
│   └── llm_workspace/                    # NEW: seeded vulnerable + FP fixtures
└── benchmark/
    ├── __init__.py                       # + llm-detection, supply-chain-detection
    │                                     #   defect classes
    └── cases/llm_scan.json               # NEW: ground-truth benchmark case(s)
```

**Structure Decision**: single-project layout (existing convention). Three new deterministic pipeline modules mirror the misconfig.py precedent (data-driven rule packs, value-free findings, load-time validation); one new extractor mirrors the enrichers.py annotation precedent. No new top-level packages, no new runtime dependencies.

## Complexity Tracking

> No constitution violations — table intentionally empty.
