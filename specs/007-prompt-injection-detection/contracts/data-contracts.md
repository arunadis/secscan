# Contracts: Prompt Injection Detection

**Feature**: `007-prompt-injection-detection` | **Date**: 2026-09-01

Interface surfaces this feature exposes. The project is a CLI/skill: contracts are (a) the CLI (unchanged), (b) the versioned payload data files (new/changed), and (c) the artifact schemas (additive). All data-file contracts are validated at load time — invalid data fails the build, never a scan (misconfig precedent).

## 1. CLI Contract — unchanged

`secscan` gains **no** commands and **no** flags. The new category runs unconditionally on every scan (misconfig precedent); no opt-in/opt-out is offered, which is what makes "zero findings on non-LLM repositories" (SC-002) a guarantee rather than a configuration.

## 2. Payload Data Contracts

### 2.1 `skill_core/data/llm_integrations.json` (NEW, version 1)

```json
{
  "version": "1",
  "dataset_date": "YYYY-MM-DD",
  "sources": ["..."],
  "sdk_modules": [
    { "id": "str", "language": "python|javascript|go|java",
      "patterns": ["regex, anchored on import/identifier shape"] }
  ],
  "http_endpoints": [
    { "id": "str", "host_suffixes": ["api.openai.com"] }
  ],
  "local_endpoints": [
    { "id": "str", "hosts": ["localhost"], "ports": [11434] }
  ],
  "candidate_hints": [
    { "id": "str", "patterns": ["regex"], "note": "undetermined-posture heuristic" }
  ]
}
```

**Rules**: unique ids; every `patterns[]` entry must compile; `language` within the shipped grammar set; determinism — no network fields are ever dereferenced. Consumed only by `extract/llm_integration.py`.

### 2.2 `skill_core/data/supply_chain_rules.json` (NEW, version 1)

```json
{
  "version": "1",
  "rules": [
    { "id": "str", "kind": "internal-namespace-unprotected|mutable-reference|suspicious-package",
      "ecosystems": ["npm", "pypi"],
      "cwe": "CWE-829", "title": "str", "description": "str", "recommendation": "str",
      "pattern": "regex (name/namespace shapes) — required for name-matching kinds" }
  ]
}
```

**Rules**: required fields, unique ids, patterns compile, `cwe` passes `validate_cwe`. `suspicious-package` names are matched as data (exact, case-normalized) — matched package names are never copied into findings (value-free findings).

### 2.3 `skill_core/data/agent_config_rules.json` (NEW, version 1)

```json
{
  "version": "1",
  "rules": [
    { "id": "str", "form": "structural|anchored-pattern",
      "file_classes": ["ai-agent-config", "ai-mcp-config"],
      "grant": "shell-exec|network-egress|fs-write|tool-auto-approve",
      "pattern": "regex — required for anchored-pattern form",
      "cwe": "CWE-250", "title": "str", "description": "str", "recommendation": "str" }
  ]
}
```

**Rules**: `structural` form requires `file_classes` containing `ai-mcp-config` (JSON artifacts); `anchored-pattern` form requires `pattern`; approval-gate tests are declared per rule as sibling-pattern ids in the data, never hard-coded in the module.

### 2.4 `skill_core/data/stacks.json` (additive, version bump)

`file_classes` gains exactly three keys: `ai-agent-config`, `ai-mcp-config`, `prompt-artifact`, each an **exact filename** list — the classifier (`stacks.py file_class_for`) matches bare filenames only, so no glob patterns are supported at v1. If glob-based classing is later required, it is a separate capability change with its own spec. Removing a name is a data change with a version bump and changelog note, same as existing classes.

### 2.5 `skill_core/cwe_map.json` (additive, version 1 → 2)

Additive only: four new `cwes` entries (CWE-1427, CWE-250, CWE-829, CWE-494 — severities and mappings per [../research.md](../research.md) R6) and one new top-level block `llm_top10_2025` mirroring `owasp_top10_2021`. The established note discipline applies: mappings only where the CWE→label relationship is well-established. No existing entry is modified or removed.

## 3. Artifact Schema Contracts (additive)

| Schema | Change | Type |
|---|---|---|
| `code_graph.json` | `file_class` enum gains `ai-agent-config`, `ai-mcp-config`, `prompt-artifact`; node `annotations` enum gains `llm_invocation`, `llm_prompt_sink`, `tool_declaration`, `external_content_source`, `ai_config` | additive enum extension |
| `finding.json` | optional `mitigation` object: `{ "control": "isolation-boundary\|validation\|human-approval", "state": "demonstrated\|undetermined", "reason": "string (required when undetermined)" }` | additive optional property |
| envelope (`envelope.json`) | two new artifacts `findings/supply_chain.json`, `findings/agent_config.json` written with the existing envelope/meta shape (misconfig precedent) | new files, existing schema |
| `report.json` | new findings appear under existing severity-band grouping; per-file-class coverage statement lists the three new classes; no field renames | additive content only |

**Invariants asserted by contract tests**: findings in the new categories validate against `finding.json`; every referenced CWE id passes `validate_cwe`; a `mitigation.state == "undetermined"` carries a non-empty `reason`; every internal reference in reports resolves (consistency gate precedent); two-run byte-identity across all artifacts.

## 4. Internal Module Contracts

| Module | Contract |
|---|---|
| `extract/llm_integration.py` | `classify_file(repo, path, text, graph) -> list[annotation facts]`; input text is the **redacted** view; emits only annotations + evidence offsets; never mutates files |
| `llm_findings.py` | `findings_for_flows(flows, graph) -> list[dict]`; consumes traced direct/indirect/source-category flows and emits finding.json-conformant dicts for all LLM classes (`CWE-1427` direct/indirect, `CWE-200` sensitive data in context, `CWE-116`/`CWE-20` insecure output handling); every finding carries `mitigation` with `state` demonstrated/undetermined (+`reason` when undetermined); emits nothing on no-flow input |
| `supply_chain.py` | `run(roots: dict[str, Path]) -> list[dict]` mirroring `misconfig.run`; findings carry `cwe`, location, rule id, guard state; value-free |
| `agent_config.py` | `run(roots) -> list[dict]`; anchored-pattern evaluation reads redacted text; structural evaluation parses JSON with exact-value provenance discarded from findings |
| `partition_repo.py` | `_domains_for` maps new annotations and file classes to `llm-security`; name-hint table unchanged policy |
| `dataflow.py` | `is_sink` recognizes `llm_prompt_sink`; `sources` include `external_content_source` nodes |
| `verify.py` | unchanged verdicts enum (`verified|plausible|disproven`); LLM flows adjudicated with the same calibration |
