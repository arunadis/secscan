# Contract: Pipeline Artifact Schemas

Every stage produces a durable, schema-versioned artifact (FR-016) under `.security-scan/`. Schemas ship in `skill_core/schemas/` and are enforced by contract tests. All artifacts share an envelope:

```json
{
  "schema_version": "1",
  "produced_by": { "stage": "partition_repo", "tool_version": "x.y.z" },
  "scan_id": "2026-08-30T07:00:00Z-ab12cd",
  "payload": { "...stage-specific..." }
}
```

## Artifact layout

```text
.security-scan/
├── config.yaml                     # project config (contracts/config-schema.md)
├── workspace.json                  # FR-001a/c: members + typed integrations (+ declared/discovered)
├── repository/<repo>.manifest.json # FR-001: per-repo manifest
├── code-graph.json                 # FR-002/003: nodes/edges, stable IDs, security annotations
├── segments/<id>.json              # FR-004: logical security-boundary segments
├── context-packets/<id>-l<level>.json  # FR-005/006a: post-redaction packets + budgets,
│                                   #   one per escalation level actually used (FR-006)
├── handoff/                        # FR-027: agent-mediated reasoning exchange
│   ├── requests/<request-id>.json  #   prompt + bounded packet, written by the pipeline
│   └── responses/<request-id>.json #   findings JSON, written by the host agent
├── scanner-findings.json           # FR-009: normalized ingested findings (tool_ref preserved)
├── findings/local/<seg>.json       # level-1 findings (finding-schema, status=local)
├── findings/segment/<seg>.json     # level-2 findings (status=segment-confirmed)
├── findings/correlated.json        # FR-014/015: relationships, canonical groups
├── system-review.md                # level-3 cross-segment/cross-repo reasoning
├── reports/<scan-id>.md|.json      # FR-018/019: unified report + usage/cost summary
├── state.json                      # checkpoints: stage status, hashes, batch handles (FR-016a/017)
└── usage.json                      # tokens per stage/model tier, batch share, fallbacks (FR-019)
```

## Agent handoff protocol (FR-027)

In agent-mediated mode the pipeline never calls a model itself. When reasoning is
required it writes one request per pending analysis unit and stops with exit code
3; the host agent answers by writing response files and re-runs the scan.

| Direction | Path | Contents |
|-----------|------|----------|
| pipeline → agent | `handoff/requests/<request-id>.json` | `request_id`, `stage`, `escalation_level`, `estimated_tokens`, `budget`, `instructions`, `prompt` (domain-filtered per FR-011), `context_packet` |
| agent → pipeline | `handoff/responses/<request-id>.json` | findings JSON per `prompts/segment_scan.md` (`{"findings": [...]}`, optional `needs_escalation`) |

Request ids are `<segment-id>-l<escalation-level>`, so a response is unambiguously
tied to the exact bounded context it answered. Partial answers are supported: any
unanswered request is re-requested on the next run, which is what lets one scan
span several agent sessions without losing completed work.

## Stage I/O contract

| Stage | Reads | Writes | Resume key |
|-------|-------|--------|-----------|
| `discover_repo` | workspace manifest / scan root | `workspace.json`, `repository/*.manifest.json` | file tree hash |
| `build_code_graph` | manifests, source files | `code-graph.json` | per-file content hash |
| `partition_repo` | code graph | `segments/*.json` | graph hash |
| `build_context` | segments, graph, source | `context-packets/*.json` (redacted) | segment hash + redaction rules version |
| `ingest_findings` | scanner outputs (if present) | `scanner-findings.json` | tool output hash |
| segment analysis (agent/endpoint) | context packets | `findings/local|segment/*.json` | packet hash |
| `normalize_findings` | raw findings | validated findings (schema-enforced) | finding id |
| `correlate_findings` | all findings | `findings/correlated.json` | findings set hash |
| system review (agent/endpoint) | correlated findings, graph, manifests | `system-review.md` | correlated hash |
| `generate_report` | all artifacts | `reports/*`, `usage.json` | — |

## Invariants

1. **Determinism**: identical inputs + tool version ⇒ byte-identical artifacts (sorted keys/arrays, stable IDs — research.md R2 checklist).
2. **Resume**: any stage with a matching resume key is skipped on re-run (FR-016a, SC-007).
3. **Incremental**: per-file content hashes drive affected-segment recomputation; cross-repo changes invalidate integration-dependent segments (FR-017).
4. **Redaction**: `context-packets/*` and anything downstream of them contain no unredacted secrets (FR-006a); enforced by a contract test scanning artifacts with the redactor's own rules.
5. **Versioning**: `schema_version` gates in-place upgrades — a newer tool reads older artifacts and either upgrades them or flags required re-runs (FR-020 upgrade path).
