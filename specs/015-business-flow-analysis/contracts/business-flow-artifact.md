# Contract: `business-flows.json` artifact & reasoning round exchange

Feature 015 | Parent: [../data-model.md](../data-model.md)

## 1. New stages

| Stage | Kind | Artifact(s) | Resume key |
|---|---|---|---|
| `business_flow_model` | deterministic | `business-flows.json` | code-graph hash + workspace hash + `business_flow` config + `regimes.json` version |
| `business_flow_analysis` | bounded LLM | `findings/flows.json` | flows artifact hash + fine-grained per-flow answer cache |

Both register in `state.STAGES` (model after `build_code_graph`; analysis after the
deterministic finding passes, before `correlate_findings.finalize`) and in
`run._ANALYSIS_STAGES` so `--full` / depth changes invalidate them.

## 2. `business-flows.json` schema (new `skill_core/schemas/business_flow.json`)

Envelope: standard `{schema_version, produced_by, scan_id, payload}` (version `"1"`).

```json
{
  "payload": {
    "flows": [
      {
        "id": "flow:<workspace>:<sha12>",
        "name": "string",
        "actor": {"kind": "anonymous|authenticated|role", "role": "string?",
                  "determination": "declared|inferred|undetermined"},
        "steps": [
          {"node_id": "<repo>:<path>#<symbol>",
           "operation": "entry|transition|mutation|external-call|terminal",
           "annotations": ["..."],
           "data_categories": ["personal-data|health-data|financial-data"],
           "integration_leg": {"type": "sync-api|async-messaging|shared-datastore|identity-propagation",
                               "target_repo": "string"}}
        ],
        "related_data_flows": ["..."],
        "partial": true,
        "gap_reasons": ["integration-undeclared"]
      }
    ],
    "coverage": {
      "reconstructed": ["..."], "analyzed": ["..."],
      "partial": [{"flow_id": "...", "gap_reasons": ["..."]}],
      "unanalyzed": [{"flow_id": "...", "reason": "..."}],
      "undetermined": [{"flow_id": "...", "reasons": ["..."]}],
      "candidate_regimes": [{"regime": "hipaa", "detected_categories": ["health-data"],
                             "step_refs": ["..."]}],
      "applicability": {"mode": "hybrid", "evaluated_regimes": ["gdpr"],
                        "skipped_reason": "string?"}
    }
  }
}
```

Invariants: sorted canonical JSON with trailing newline; every `node_id` resolves
against `code-graph.json`; a partial flow MUST have non-empty `gap_reasons`; candidate
regimes appear here and (mirrored) in the report — never silently evaluated.

## 3. Reasoning request/answer (per flow, `level="system"`)

**Request** — handoff file `.secscan/handoff/requests/<request-id>.json` in agent
mode (same document shape as today) or provider call in endpoint modes. Payload
(`context_packet`): the flow, its steps' redacted excerpts, obligations of evaluated
regimes, and (agent mode) `consultable_files`. Prompt file:
`skill_core/prompts/business_flow.md` — instructs step-by-step walk ("at every step,
who is allowed to be here, and is that enforced?") and obligation evaluation, and
demands explicit undetermined declarations.

**Answer** — validated against new `skill_core/schemas/flow_answer.json`:

```json
{
  "flow_id": "flow:...",
  "assessment": "clean|gap|violation|undetermined",
  "undetermined_reasons": ["..."],
  "findings": [ { "...": "raw finding fields; flow_category set by pipeline" } ]
}
```

- `findings[]` entries pass through `FindingNormalizer.normalize` with
  `source="analysis"`; malformed entries rejected with reason (existing behavior).
- Pipeline assigns `flow_category`, `flow_ref=flow_id`, and requires
  `regulatory_refs` when the category is `regulatory-violation`.
- `assessment: undetermined` MUST carry reasons, which merge into coverage (FR-010).

**Caching/resume**: `.secscan/analysis/answers/` holds exactly
`{request_id, answer_key, content}` — a cached answer is never counted in run usage.
Pending answers ⇒ `AgentHandoff` ⇒ exit 3 (unchanged semantics).

## 4. Report fields (additive, `report.json` version unchanged)

- Findings: `flow_category`, `flow_ref`, `flow_narrative`, `regulatory_refs` (see
  [data-model](../data-model.md#extensions-to-finding-findingjson-additive-version-unchanged)).
- Report-level: `flow_coverage` mirror; rendered in Markdown/JSON/HTML.
- Flow narratives referencing finding ids pass through
  `resolve_narrative_references` — dangling refs quarantine (exit 4, unchanged).

## 5. Determinism guarantees (contract test surface)

- Disabled ⇒ all artifacts byte-identical to pre-feature scan (SC-001).
- Enabled, identical inputs ⇒ `business-flows.json`, requests, findings, reports
  byte-identical across runs.
- `regimes.json` version bump invalidates `business_flow_model`/`business_flow_analysis`
  only.
