# Contract: Schema Deltas

Field-level diff against the schemas shipped in `skill_core/schemas/`. **Every change is additive**:
no existing required field is added, removed, retyped, or given a new meaning. `schema_version`
therefore stays `"1"`, and artifacts written by the previous tool version stay readable, so the
in-place upgrade path of `001:FR-020` is not triggered.

**Reference convention.** Bare `FR-###`/`SC-###` identifiers in this feature's artifacts refer to
`002-scan-accuracy-hardening/spec.md`. References to feature 001's requirements are prefixed `001:`.
The two features share a numbering range and `FR-020` means different things in each — the installer's
in-place upgrade in 001, the verification-aware severity cap in 002.

Contract tests must assert both directions: new artifacts validate, and a fixture artifact captured
before this feature still validates.

## `finding.json`

`additionalProperties: false` is set on this schema, so every new field must be declared explicitly.

### `location` — tiered resolution (FR-001–FR-004, FR-003a)

```json
"tier":                 { "enum": ["symbol", "file"] },
"symbol_confirmed":     { "type": "boolean" },
"alternatives_existed": { "type": "boolean" },
"chosen_by":            { "type": "string" }
```

`tier` is required on any finding whose `status` is `reported`. `line_start`/`line_end` keep their
existing types and bounds; what changes is provenance, not shape.

### `reclassification` (FR-016–FR-017)

```json
"reclassification": {
  "type": "object", "additionalProperties": false,
  "required": ["original_cwe", "new_cwe", "reason"],
  "properties": {
    "original_cwe":      { "type": "string", "pattern": "^CWE-[0-9]+$" },
    "new_cwe":           { "type": "string", "pattern": "^CWE-[0-9]+$" },
    "original_severity": { "type": "number", "minimum": 0.0, "maximum": 10.0 },
    "new_severity":      { "type": "number", "minimum": 0.0, "maximum": 10.0 },
    "reason":            { "type": "string", "minLength": 1 },
    "operator_override": { "type": "boolean" }
  }
}
```

### `applicability` (FR-015a–FR-015c)

```json
"applicability": {
  "type": "object", "additionalProperties": false,
  "required": ["applicable"],
  "properties": {
    "applicable":      { "enum": [true, false, "undetermined"] },
    "reachable_shapes":{ "type": "array", "items": { "enum": [
                            "server-request-issuer","browser-client","cli","library","undetermined"] } },
    "enabling_member": { "type": "string" },
    "reason":          { "type": "string" }
  }
}
```

### `framework_control` (FR-021–FR-022d)

```json
"framework_control": {
  "type": "object", "additionalProperties": false,
  "required": ["state"],
  "properties": {
    "state":             { "enum": ["credited", "bypassed", "absent", "unassessed"] },
    "control":           { "type": "string" },
    "bypass_site":       { "$ref": "#/properties/location" },
    "unassessed_reason": { "type": "string" }
  }
}
```

### `calibration` (FR-020)

```json
"calibration": {
  "type": "object", "additionalProperties": false,
  "properties": {
    "proposed_severity":   { "type": "number", "minimum": 0.0, "maximum": 10.0 },
    "proposed_confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
    "caps_applied": {
      "type": "array",
      "items": { "type": "object", "additionalProperties": false,
                 "required": ["rule", "reason"],
                 "properties": { "rule": {"type":"string"}, "reason": {"type":"string"} } }
    }
  }
}
```

### `dependency` (FR-030–FR-035)

```json
"dependency": {
  "type": "object", "additionalProperties": false,
  "required": ["package", "ecosystem", "exposure", "attribution"],
  "properties": {
    "package":          { "type": "string" },
    "ecosystem":        { "type": "string" },
    "affected_range":   { "type": "string" },
    "fixed_version":    { "type": "string" },
    "advisory_ids":     { "type": "array", "items": { "type": "string" } },
    "exposure":         { "enum": ["runtime", "development"] },
    "affected_members": { "type": "array", "items": { "type": "string" } },
    "attribution":      { "enum": ["per-member", "workspace-not-derivable"] },
    "version_ambiguous":{ "type": "boolean" },
    "audit_source":     { "type": "string" }
  }
}
```

### `reproduction` — hypothesis mode (FR-008–FR-011)

```json
"mode":                    { "enum": ["observed", "hypothesis"] },
"outcome_to_check":        { "type": "string" },
"trigger_omitted_reason":  { "type": "string" },
"traced_trail":            { "type": "array", "items": { "type": "string" } }
```

`trigger` and `observed_behavior` move from the `required` list to conditionally required. This is the
**only** relaxation in this delta, and it is a relaxation rather than a break: every previously valid
reproduction block stays valid.

**Disposition of `evidence_trail`** — the field is **deprecated, retained, and no longer populated**.
It conflated the traced path with unrelated supporting evidence while being rendered with dataflow
notation, which is the defect FR-005/FR-006 remove. It stays declared in the schema (marked
`deprecated: true` with a description saying so) purely so pre-002 artifacts continue to validate;
nothing writes it and the report renderer ignores it. Removal is deferred to a release that bumps
`schema_version`. `traced_trail` replaces it with a strictly narrower guarantee.

The alternative — removing it now — was rejected: it would make this a breaking change, force
`schema_version` to `"2"`, and destroy the "a pre-feature artifact still validates" property that
T010 asserts.

**Conditional-requirement mechanism.** `trigger` and `observed_behavior` cannot simply be dropped
from the static `required` list, so the conditions are expressed with JSON Schema `if`/`then` under
`allOf`. Each condition is additionally guarded on `mode` being *present*, which is what keeps
pre-002 blocks (which carry no `mode`) valid:

```json
"required": ["preconditions", "expected_behavior"],
"allOf": [
  { "if": { "required": ["mode"], "properties": { "mode": { "const": "observed" } } },
    "then": { "required": ["observed_behavior"] } },
  { "if": { "required": ["mode"], "properties": { "mode": { "const": "hypothesis" } } },
    "then": { "required": ["outcome_to_check"] } },
  { "if": { "required": ["mode"], "not": { "required": ["trigger"] } },
    "then": { "required": ["trigger_omitted_reason"] } }
]
```

`additionalProperties: false` is unaffected: every property is declared at the same level as the
`allOf`, which only adds `required` constraints.

### `source`

```json
"source": { "enum": ["analysis", "scanner-ingest", "dependency-audit"] }
```

## `code_graph.json`

```json
"type":        { "enum": ["file","class","function","endpoint","datastore",
                          "external-service","template","config"] },
"annotations": { "items": { "enum": [ ...existing seven...,
                            "template_sink","framework_control","control_bypass" ] } },
"parsed":      { "type": "boolean" },
"format":      { "type": "string" }
```

Edge `type` gains `renders`.

`parsed: false` nodes exist at file granularity only and carry no `symbol`, `line_start`, or
`line_end` — that is exactly the shape FR-003's file tier resolves against.

## `report.json`

```json
"coverage": {
  "properties": {
    "file_classes": {
      "type": "array",
      "items": { "type": "object", "additionalProperties": false,
        "required": ["file_class", "represented"],
        "properties": {
          "file_class":  { "enum": ["source","template","dependency-manifest",
                                    "deploy-config","datastore-rules","client-cache-config"] },
          "represented": { "type": "integer", "minimum": 0 },
          "unparsed":    { "type": "array", "items": { "type": "object",
                             "properties": { "path": {"type":"string"},
                                             "format": {"type":"string"},
                                             "reason": {"type":"string"} } } },
          "not_attempted":       { "type": "array", "items": { "type": "string" } },
          "remediation_command": { "type": "string" }
        } }
    },
    "audit_outcomes": {
      "type": "array",
      "items": { "type": "object", "additionalProperties": false,
        "required": ["member", "ecosystem", "status"],
        "properties": {
          "member": {"type":"string"}, "ecosystem": {"type":"string"},
          "status": { "enum": ["advisories","clean","could-not-check"] },
          "reason": {"type":"string"}, "remediation_command": {"type":"string"},
          "tool": {"type":"string"}, "tool_version": {"type":"string"} } }
    },
    "resolution_tiers": {
      "type": "object", "additionalProperties": false,
      "properties": { "symbol": {"type":"integer"}, "file": {"type":"integer"},
                      "rejected": {"type":"integer"} }
    },
    "blocking_gaps": { "type": "array", "items": { "type": "string" },
                       "description": "rendered at the top of the report (FR-033)" }
  }
}
```

## New schema: `architecture_profile.json`

```json
{
  "type": "object", "additionalProperties": false,
  "required": ["scope", "shape"],
  "properties": {
    "scope":               { "enum": ["member", "segment"] },
    "shape":               { "enum": ["server-request-issuer","browser-client",
                                      "cli","library","undetermined"] },
    "evidence":            { "type": "array", "items": { "type": "string" } },
    "undetermined_reason": { "type": "string" }
  }
}
```

Embedded in `repository/<repo>.manifest.json` and, when it differs, in `segments/<id>.json`.

## Validation rules added

Numbering continues from `001/contracts/finding-schema.md` rules 1–8.

9. `severity_band` MUST be derived from the **published** `severity_score` after calibration and any
   reclassification — not from the analysis-proposed score, and never from the weakness class's
   default severity (FR-040).
10. A `reported` finding MUST carry `location.tier`. A finding with no resolvable file MUST be
    `rejected` and MUST NOT appear in any report (FR-003).
11. `reproduction.mode = "observed"` is permitted **only** when `verification.status = "verified"`.
    Otherwise `mode` MUST be `hypothesis` and `outcome_to_check` MUST be present (FR-008).
12. `reproduction.trigger` present ⇒ an achievable success criterion was derived (FR-009). Absent ⇒
    `trigger_omitted_reason` MUST be present (FR-010).
13. Every entry in `reproduction.traced_trail` MUST appear in `verification.path`. A finding with no
    `verification.path` MUST NOT carry `traced_trail` (FR-005).
14. `reclassification` present ⇒ `cwe` equals `reclassification.new_cwe`, and the record persists even
    when the finding is filtered out by profile thresholds (FR-017).
15. `applicability.applicable` of `true` or `"undetermined"` MUST NOT accompany a `reclassification`
    produced by the applicability relation (FR-015c, FR-013a).
16. `framework_control.state = "credited"` ⇒ every file on `verification.path` has `parsed: true` in
    the code graph (FR-022a). `state = "bypassed"` ⇒ `bypass_site` lies on `verification.path`
    (FR-022).
17. `dependency.attribution = "per-member"` ⇒ `affected_members` is non-empty. `"workspace-not-derivable"`
    ⇒ the report states that per-member attribution was not derivable (FR-030f).
18. An `audit_outcomes` entry with `status` other than `clean` MUST carry `remediation_command`; a
    `could-not-check` entry MUST NOT be summarized anywhere as a clean result (FR-033).
19. Every internal report cross-reference MUST name a section present in that report (FR-040), and no
    finding narrative may contradict its own `verification` or `reproduction` (FR-042). Enforced
    before the report is written.
20. Determinism: all new collections are sorted before serialization, and adapter output is
    normalized onto stable fields — verbatim third-party tool output is never embedded, because some
    of it is not stable across runs (research.md A2).
