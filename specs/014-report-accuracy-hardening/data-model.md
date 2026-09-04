# Data Model: Report Accuracy Hardening (014)

All additions are optional, additive fields — no `schema_version` bump
(constitution gate: additive schemas). All serialized collections are sorted and
written via `store.canonical_json` (Principle I).

## 1. Code graph — file node (additive)

Existing `type:"file"` node (`code_graph.json`) gains:

| Field | Type | Notes |
|---|---|---|
| `imports` | array of string, optional | Sorted, deduplicated raw import texts from `FileFacts.imports` (≤200 chars each, newlines collapsed — existing extractor normalization). Absent (not empty) for nodes whose language has no import grammar or was not parsed. |

Template nodes (`type:"template"`) gain:

| Field | Type | Notes |
|---|---|---|
| `annotations` (existing list) | extended values | Template extraction adds binding annotations derived from shipped control `sinks` lists, so sink matching can run over annotations deterministically. |

Validation: `imports` entries are non-empty strings; the array is sorted
ascending (byte order) — asserted in contract tests.

## 2. Dependency finding — `usage` block (additive)

Attached to every finding carrying a `dependency` block (advisory) and to
currency findings (which gain a `dependency` block — see §4):

```json
"usage": {
  "state": "found | none-found | undetermined",
  "reason": "present only when state=undetermined",
  "locations": [
    {"repo": "member", "file": "src/app/foo.ts", "line_start": 3, "kind": "import | config | dynamic", "role": "runtime | development"}
  ]
}
```

Rules:
- `locations` present iff `state == "found"`; sorted by `(repo, file, line_start)`.
- `none-found` MAY only be recorded when every applicable detection form
  (imports, config rules, dynamic rules) completed for the member (FR-001).
- `undetermined` requires a non-empty `reason`.
- States never suppress (FR-002). `none-found` applies the confidence ceiling and
  narrative reframing at calibration (FR-003); severity is never adjusted (Q1).

## 3. Misconfiguration finding — `integration` block (additive)

```json
"integration": {
  "state": "integrated | no-integration-found | undetermined",
  "reason": "present only when state=undetermined",
  "evidence": [
    {"repo": "member", "file": "package.json", "reason": "declares firebase"}
  ]
}
```

Rules mirror §2: `integrated` requires at least one evidence entry;
`no-integration-found` and `undetermined` never suppress; `undetermined` never
inflates (FR-004). `no-integration-found` findings get removal-oriented
remediation at render time.

## 4. Currency finding — reworked identity (additive)

Currency findings gain a `dependency` block (previously absent —
`audits/__init__.py`):

```json
"dependency": {
  "ecosystem": "npm | pypi | ...",
  "package": "@angular/core",
  "product": "angular",
  "cycle": "9",
  "signals": ["past-eol"],
  "usage": { ... as §2 ... }
}
```

- `signals` is the sorted list of currency signals merged for this group
  (FR-008). **Rollup key: `(repo, product, cycle)`** — all packages of one
  product-cycle pair in a member share one finding; every package appears in
  `packages` and contributes an evidence entry. Merge happens before ID
  assignment; the merged finding keeps the highest contributing severity.
- Currency findings never carry `advisory_ids` and never merge with CVE findings
  (FR-009).

## 5. Report — `quarantined_sections` (additive)

```json
"quarantined_sections": [
  {"section": "system_review | cross_system_findings | attack_paths | recommendations",
   "dangling_id": "SEC-0006",
   "reason": "identifier not admitted to the report"}
]
```

Present (non-empty) only when quarantine fired; the rendered Markdown/HTML
declare the omission inline in place of the section. Absent entirely otherwise
(no churn in clean reports — byte-identical output preserved for well-formed
input).

## 6. Shipped data (versioned)

| File | Change |
|---|---|
| `skill_core/data/usage_patterns.json` (NEW) | `{version, ecosystems: {npm: {module_map: [...], config_files: [{file_class, package_extract: rule}], dynamic_forms: [...], dev_markers: [...]}, ...}}`. Module↔package mapping rules, config-file extraction rules, dynamic-import literal forms, and per-ecosystem dev/build file markers (path patterns identifying test/build-only sources) that drive the `role` classification in §2. Unmapped names ⇒ `undetermined`. |
| `skill_core/data/misconfig_rules.json` | Each rule entry gains `integration_markers: {packages?: [...], imports?: [...], config_presence?: [...]}`. Rule entries without markers evaluate as `undetermined`. |
| `skill_core/data/framework_controls.json` | Unchanged — sink/bypass lists already present; consumption only. |

## State transitions

- **Usage / integration state**: computed once per scan, deterministic; no
  lifecycle (not user-editable; declarations via `triage/declarations.json` are
  out of scope for these blocks).
- **Currency merge**: `per-signal records → merged finding` — one direction,
  complete before ID assignment; no un-merge.
- **Quarantine**: `dangling reference detected → section removed + recorded →
  residual strict gate → publish with exit 4`. No path back to publication of the
  section in the same run.

## Invariants asserted by tests

1. Identical input ⇒ byte-identical `imports` arrays, `usage` blocks, merged
   findings, and reports (two-run comparison).
2. `none-found` never reduces the admitted finding set.
3. `undetermined` never appears with an empty `reason` and never raises
   confidence/severity.
4. Merged currency finding count per `(repo, product, cycle)` ≤ 1; total evidence count
   is preserved (no signal lost).
5. A report with non-empty `quarantined_sections` passes the residual strict
   consistency gate and yields exit code 4.
