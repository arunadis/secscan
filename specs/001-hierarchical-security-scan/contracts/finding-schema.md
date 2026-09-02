# Contract: Finding Schema

Canonical JSON schema for findings (FR-012/FR-013). Shipped as `skill_core/schemas/finding.json` (JSON Schema draft 2020-12); `normalize_findings` rejects non-conforming output — free-form text never enters the pipeline.

```json
{
  "$id": "finding.schema.json",
  "type": "object",
  "required": ["id", "cwe", "severity_score", "severity_band", "confidence",
               "location", "description", "evidence", "attack_scenario",
               "impact", "recommendation", "source", "status"],
  "properties": {
    "id":               { "type": "string", "pattern": "^SEC-\\d{4,}$" },
    "cwe":              { "type": "string", "pattern": "^CWE-\\d+$" },
    "owasp_top10":      { "type": "string" },
    "severity_score":   { "type": "number", "minimum": 0.0, "maximum": 10.0 },
    "severity_band":    { "enum": ["Critical", "High", "Medium", "Low", "None"] },
    "confidence":       { "type": "number", "minimum": 0.0, "maximum": 1.0 },
    "location": {
      "type": "object",
      "required": ["repo", "file", "line_start", "line_end"],
      "properties": {
        "repo":       { "type": "string" },
        "file":       { "type": "string" },
        "symbol":     { "type": "string" },
        "line_start": { "type": "integer", "minimum": 1 },
        "line_end":   { "type": "integer", "minimum": 1 }
      }
    },
    "description":      { "type": "string", "minLength": 1 },
    "evidence": {
      "type": "array", "minItems": 1,
      "items": {
        "type": "object",
        "required": ["repo", "file", "reason"],
        "properties": {
          "repo": { "type": "string" }, "file": { "type": "string" },
          "symbol": { "type": "string" }, "reason": { "type": "string" }
        }
      }
    },
    "attack_scenario":  { "type": "string" },
    "impact":           { "type": "string" },
    "recommendation":   { "type": "string" },
    "related_symbols":  { "type": "array", "items": { "type": "string" } },
    "source":           { "enum": ["analysis", "scanner-ingest"] },
    "tool_ref":         { "type": "string", "description": "original scanner tool:rule id" },
    "compliance_refs":  { "type": "array", "items": { "type": "string" },
                          "description": "well-established CWE->framework mappings only (spec Q3)" },
    "status":           { "enum": ["local", "segment-confirmed", "correlated", "reported", "rejected"] },
    "rejection_reason": { "type": "string" },
    "verification": {
      "type": "object",
      "required": ["status"],
      "properties": {
        "status":  { "enum": ["verified", "plausible", "disproven"] },
        "gap":     { "type": "string", "description": "required when status=plausible: the untraced portion of the path" }
      }
    },
    "reproduction": {
      "type": "object",
      "required": ["preconditions", "trigger", "expected_behavior", "observed_behavior"],
      "properties": {
        "preconditions":     { "type": "string", "description": "required role/permissions/state" },
        "trigger":           { "type": "string", "description": "endpoint/method/payload or input sequence; benign canary values only (FR-030)" },
        "expected_behavior": { "type": "string" },
        "observed_behavior": { "type": "string" },
        "evidence_trail":    { "type": "array", "items": { "type": "string" } },
        "target_scope":      { "const": "local/test" }
      }
    },
    "relationships": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["target_id", "type"],
        "properties": {
          "target_id": { "type": "string", "pattern": "^SEC-\\d{4,}$" },
          "type": { "enum": ["same", "related", "dependent", "duplicate", "independent"] }
        }
      }
    }
  }
}
```

## Validation rules (beyond schema)

1. `severity_band` MUST be the band derived from `severity_score` (Critical ≥ 9.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9, None 0.0).
2. `cwe` MUST exist in the shipped CWE dataset (research.md R6) — no hallucinated IDs.
3. Every `location`/`evidence` path MUST resolve to a file in the scanned workspace.
4. Cross-segment/cross-repo claims: a finding whose `evidence` spans ≥2 segments/repos MUST be `correlated` and referenced by the report's cross-system section (FR-015).
5. `duplicate`-related findings MUST NOT both appear as independent report entries (FR-014); the report cites the canonical finding and all contributing evidence.
6. `scanner-ingest` findings MUST carry `tool_ref`; triage verdict (exploitable / not-exploitable / uncertain) is recorded in `description` + reflected in `confidence`.
7. `verification.status=disproven` findings MUST NOT appear in any report (FR-029). Reportable findings MUST include `reproduction`; `plausible` findings MUST document the untraced gap in `verification.gap`.
8. `reproduction.trigger` MUST use benign canary values only and contain no real credentials (redaction rules apply); `target_scope` is fixed to `local/test` (FR-030).
