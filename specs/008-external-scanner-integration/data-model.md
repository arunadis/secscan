# Data Model: External Scanner Tooling Integration

Phase 1 output for feature 008. Field types are logical; all artifacts serialize as JSON. Additive-only per the constitution's schema rule — all new artifacts are new files; `findings/external/*.json` gains optional fields only.

## Entities

### ToolRegistryEntry (shipped data, `src/skill_core/data/tools.json`)

One record per external tool.

| Field | Type | Notes |
|---|---|---|
| `id` | string | Stable slug, e.g. `semgrep`, `npm-audit`, `owasp-dependency-check` |
| `display_name` | string | Human name for init/report output |
| `kind` | enum: `sast`, `secrets`, `iac`, `dependency-audit` | Drives report grouping and covered-domain logic |
| `ecosystems` | string[] | Ecosystem ids it applies to (`npm`, `pypi`, `maven`, `go`, `any`) |
| `covers_ecosystems` | string[] | Subset it can fully cover for native-audit displacement (dependency tools only; replaces hard-coded `DEPENDENCY_SCANNERS`) |
| `project_local` | object[] | Declarative discovery rules: `{mechanism: manifest-dep\|manifest-plugin\|bin-path\|wrapper, match...}` (research R3) |
| `system_executable` | string | Probe name for `shutil.which` |
| `version_probe` | string[] | argv for version detection; empty = version undetermined (declared, not guessed) |
| `provision_channels` | object[] | Ordered `{manager, argv[]}` install templates (research R4) |
| `invoke` | object | `{argv[] template, cwd, requires_lockfile, requires_network, report_out}` — the pinned read-only invocation (research R2) |
| `timeout_s` | int | Default 120, matching `audits/base.py` |
| `report_format` | enum: `json`, `sarif` | Selects the adapter parser |
| `network` | enum: `none`, `on-first-use`, `per-run` | Declared on the availability record (FR-002) |

Validation: ids unique; every `kind: dependency-audit` entry has nonempty `covers_ecosystems`; `invoke.requires_lockfile` implies an ecosystem with a known lockfile marker.

### EcosystemDetection (derived at init/scan time, not persisted separately)

| Field | Type | Notes |
|---|---|---|
| `ecosystem` | string | `npm` / `pypi` / `maven` / `go` |
| `evidence` | string[] | Project-relative manifest/build-file paths that establish it |
| `member` | string | Workspace member name (monorepo partitioning) |

Computed from manifest enumeration (`offline._iter_manifests` family) plus Gradle build-file detection; never from model output (Constitution I).

### ToolAvailabilityRecord (`.security-scan/tooling/availability.json`)

Per tool, per scan; re-probed at run time (research R8).

| Field | Type | Notes |
|---|---|---|
| `tool_id` | string | Registry id |
| `applicable` | bool | Derived from detected ecosystems |
| `source` | enum: `project-provided`, `system-installed`, `missing` | Tri-state from clarification; non-applicable tools are represented by `applicable: false` with `source` omitted, not a fourth enum value |
| `version` | string \| null | null renders as "undetermined", never guessed |
| `invocation` | string \| null | Resolved argv preview (wrapper vs standalone) |
| `network` | enum | Copied from registry for visibility |
| `decision` | enum: `use`, `skipped-by-user`, `skipped-no-consent`, `not-applicable`, `missing-declared` | Auditable reason trail |

### ToolRunRecord (`.security-scan/tooling/runs.json`, append-only per scan)

| Field | Type | Notes |
|---|---|---|
| `tool_id`, `tool_version` | string | Provenance (FR-006, research R7). No `scan_id` field: scan correlation comes from store state, so records stay byte-identical across two scans of identical input (SC-013) |
| `db_version` | string \| null | Advisory DB / ruleset version when the tool reports one |

| `status` | enum: `ran`, `skipped`, `failed` | Mirrors `could-not-check` discipline: `failed` always carries `reason` |
| `reason` | string | Empty on `ran`; stable classification string otherwise (no stderr embedding — base.py precedent) |
| `invocation` | string | Actual argv (no secrets; env-var *names* only) |
| `read_only_guard` | enum: `passed`, `tripped`, `waived-not-applicable` | Fingerprint check result; `tripped` discards output |
| `finding_count` | int | Post-normalization count |

### NormalizedExternalFinding (extends `findings/external/*.json` entries)

Existing shape from feature 001 seam, with additive fields:

| Field | Type | Notes |
|---|---|---|
| `source` | string | `external-tool` (existing convention: `dependency-audit`, `llm-analysis`, …) |
| `tool_ref` | string | Existing field; now `<tool_id>` from registry |
| `sources` | string[] | NEW additive: all contributors after dedupe (tool ids and/or `dependency-audit`) |
| `dependency` | object \| null | Existing key set reused for displacement/dedupe (`ecosystem`, `package`, `affected_range`, `advisory_ids`) |
| `location` | object | Must resolve via tiered location resolution; `tier: file` for manifest findings (002 convention) |
| `verification` | enum: `verified`, `plausible`, `undetermined` | Existing tri-state |
| `raw_provenance` | object | `{tool_version, db_version}` — determinism anchor (research R7) |

### FindingDisposition (computed by `crosscheck.py`, embedded in report assembly)

| Field | Type | Notes |
|---|---|---|
| `finding_id` | string | Stable reference |
| `verdict` | enum: `retained`, `suppressed` | |
| `verification` | enum \| null | For `retained`: verified/plausible/undetermined + `reason` |
| `disproof_ground` | enum \| null | For `suppressed`: one of `package-absent`, `version-outside-range`, `location-unresolvable`, `component-absent` — the only permitted grounds (clarification Q1) |
| `evidence` | string[] | Cited evidence (resolved pin, location-resolution failure detail) |

State transitions: `ingested → cross-checked → retained|suppressed`. Reachability/usage input *cannot* move a finding to suppressed; it only informs `undetermined` verification on retention.

### SuppressionRecord (`.security-scan/tooling/suppressions.json` + report section)

| Field | Type | Notes |
|---|---|---|
| `finding` | object | Identity snapshot (tool_ref, description, location) |
| `tool_id` | string | Producing tool |
| `disproof_ground` | enum | Same vocabulary as FindingDisposition |
| `evidence` | string[] | Deterministic evidence |

Never deleted between scans; reviewers see count + reasons without re-running (FR-007, story 3 scenario 4).

### CoverageLimitationDeclaration (report section, data appended to existing summary artifact)

`{tool_id, status: missing|skipped|failed, reason, affected_ecosystems[]}` — one entry per tool not run; FR-009 forbids presenting their absence as clean.

## Relationships

- EcosystemDetection 1—n ToolRegistryEntry (applicability join on `ecosystems`)
- ToolRegistryEntry 1—1 ToolAvailabilityRecord per scan; 1—1 ToolRunRecord per scan
- ToolRunRecord 1—n NormalizedExternalFinding; dedupe merges findings 1—n `sources`
- NormalizedExternalFinding 1—1 FindingDisposition; suppressed verdict 1—1 SuppressionRecord

## Validation rules (from FRs)

- FR-004: any ToolRunRecord with `read_only_guard: tripped` forces `status: failed` and zero merged findings from that tool.
- FR-007: `disproof_ground` must be one of the four structural grounds; a suppression record without evidence fails the report gate.
- FR-008: `verification: undetermined` requires a nonempty `reason`.
- FR-009: every applicable tool lacking `status: ran` has a CoverageLimitationDeclaration.
