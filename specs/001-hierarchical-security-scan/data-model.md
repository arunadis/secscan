# Data Model: Hierarchical LLM-Efficient Security Scanning

All pipeline artifacts are JSON documents validated against JSON Schemas shipped in `skill_core/schemas/` (see `contracts/artifact-schemas.md`). Every artifact carries `schema_version` and `produced_by` (stage + tool version) for reproducibility and upgrade handling (FR-016, FR-020).

## Workspace

The scan target: one or more repositories plus typed integration points (FR-001a/b/c).

| Field | Type | Rules |
|-------|------|-------|
| `id` | string | stable slug; derived from scan root |
| `members` | RepositoryRef[] | ≥1; `path` (local), `name`, `role` (optional) |
| `integrations` | Integration[] | typed; `declared: true/false` (declared in manifest vs inferred) |
| `source` | enum: `manifest` / `auto-discovered` | auto-discovered entries flagged lower confidence |

**Integration**: `{ from_repo, to_repo, type: sync-api | async-messaging | shared-datastore | identity-propagation, endpoints_or_channels[], trust_boundary: bool, confidence: 0.0–1.0 }`.

## Repository Manifest

Compact per-repository description (FR-001). Target: < 5 KB per repo regardless of repo size.

Fields: `repository`, `languages[]`, `frameworks[]`, `modules[] {name, path, file_count}`, `entrypoints[] {symbol, kind: http|cli|consumer|rpc}`, `databases[]`, `external_services[]`.

## Code Graph

Nodes/edges JSON (FR-002/FR-003), not a graph database.

- **Node**: `{ id, repo, type: file|class|function|endpoint|datastore|external-service, path, symbol?, annotations[] }` where `annotations` ⊆ `{trust_boundary, authentication_required, authorization_required, sensitive_data, external_system, user_controlled_input, security_sink}`.
- **Edge**: `{ from, to, type: calls|imports|reads|writes|publishes|consumes|authenticates-as, cross_repo: bool }`.

Identity: node `id` = `<repo>:<path>#<symbol>`; stable across runs (required for incremental scans, FR-017).

## Segment

Logical partition along a security/business boundary (FR-004); never sized by raw line count alone, and subdivided if it exceeds the context budget (Edge Cases).

Fields: `id`, `name`, `repo(s)`, `purpose`, `entrypoints[]`, `files[]`, `dependencies[]`, `data_stores[]`, `estimated_tokens`, `subdivided_from?`.

## Context Packet

Bounded input to one analysis invocation (FR-005/FR-006/FR-006a).

Fields: `segment_id`, `escalation_level: 1|2|3|4`, `purpose`, `entrypoints[]`, `call_graph_summary`, `data_flows[] {source, transforms[], validations[], sink}`, `security_relevant_symbols[]`, `source {file: excerpt}` — **post-redaction**, `token_budget {max_context_tokens, max_output_tokens, escalation_threshold}`.

Invariant: every context packet passed to a model has passed the redactor; packets record `redaction {applied: true, blocked_items: n}`.

## Finding

Structured, evidence-bearing record (FR-012/FR-013). Full schema in `contracts/finding-schema.md`.

Core fields: `id` (SEC-NNNN, unique per scan), `cwe` (primary, required), `owasp_top10?` (secondary), `severity_score` (CVSS-style 0.0–10.0), `severity_band` (Critical/High/Medium/Low/None, derived), `confidence` (0.0–1.0), `location {repo, file, symbol, line_start, line_end}`, `description`, `evidence[] {repo, file, symbol, reason}`, `attack_scenario`, `impact`, `recommendation`, `related_symbols[]`, `source: analysis | scanner-ingest`, `tool_ref?` (original scanner rule id), `compliance_refs[]?` (opportunistic well-established CWE→framework mappings only).

**Lifecycle**: `local → segment-confirmed → correlated → reported` (or `rejected` with reason recorded). Correlation attaches `relationships[] {target_id, type: same|related|dependent|duplicate|independent}` (FR-014); cross-segment claims must reference findings from multiple segments (FR-015).

**Verification & reproduction** (FR-029/FR-030): every reported finding carries `verification {status: verified|plausible|disproven, gap?}` from static source-to-sink tracing (scanner never executes attacks), and reportable findings carry `reproduction {preconditions, trigger, expected_behavior, observed_behavior, evidence_trail, target_scope: local/test}` with benign canary payloads only. Disproven findings never reach reports; verified outranks plausible within each severity band.

## Scan Profile

Named settings bundle (FR-028): `name`, `description`, `analysis_depth {domains[], max_escalation_level}`, `report_thresholds {min_severity_band, min_confidence}`, `execution_policy` overrides. Built-ins: `quick` (High/Critical; depth reduced), `full` (Medium+, confidence ≥ 0.5), `audit` (everything; max depth). Custom profiles live in project config; per-scan overrides allowed and recorded.

## Configuration

Single project config file (FR-023; schema in `contracts/config-schema.md`): execution policy (`interactive` | `batch-offpeak` + window), external endpoint (optional; credentials via env-var reference only, FR-025), model tiers per level (FR-008a), token budgets (FR-007), redaction rules, scanner adapters, profiles. Strictly validated pre-scan (FR-026).

## Analysis Request / Response

The unit of exchange with the reasoning model. In agent-mediated mode (FR-027)
both sides are files under `handoff/`, which is what lets a scan span several
agent sessions; with an external endpoint the same pair is an in-flight API call.

**Request** (`handoff/requests/<request-id>.json`): `request_id`
(`<segment-id>-l<escalation-level>`, so an answer is unambiguously bound to the
exact context it addressed), `stage`, `escalation_level`, `estimated_tokens`,
`budget`, `instructions`, `prompt` (filtered to the segment's domains, FR-011),
and the `context_packet`.

**Response** (`handoff/responses/<request-id>.json`): `{"findings": [...]}` plus
an optional `needs_escalation` flag with `escalation_reason` — the model's way of
saying the bounded context was insufficient rather than guessing (FR-006).

**Lifecycle**: `queued → answered → normalized`. Unanswered requests are simply
re-requested on the next run; already-answered ones are consumed from disk, so
partial progress is never lost.

## Scan State / Checkpoint

Durable pipeline state enabling resume (FR-016a) and incremental scans (FR-017): per-stage `status: pending|running|done|failed`, artifact hashes, per-file content hashes for change detection, batch job handles + fallback log (FR-016b), token/cost usage counters per stage and model tier (FR-019).

## Security Report

Unified workspace report (FR-018): executive summary, findings grouped by severity band (attributed per repo; cross-system findings cite evidence from all involved repos), attack paths, recommendations, coverage statement (what was analyzed; gaps, e.g., missing subsystems), execution mode, active profile + overrides, and usage/cost summary (FR-019). Per-repo views are filtered projections of the same data.
