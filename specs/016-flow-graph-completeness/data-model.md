# Data Model — Flow & Graph Completeness (feature 016)

Conventions carried from earlier features: identifiers are stable
(`<repo>:<path>#<symbol>`), every serialized collection is sorted, and additions to
schemas are strictly additive (no `schema_version` bump anywhere in this feature).

## Wiring Edge (graph edge, existing schema)

- **from**: endpoint node id (route-scoped attachment) or wiring file node id
  (attachment visibility), **to**: resolved guard symbol node id.
- **type**: `handler` (endpoint → guard) or `calls` (file → guard). Both existing
  enum values; no schema change.
- **resolution**: `name-based` (existing enum). Attachment effects are documented on
  review through the rule pack that produced the underlying fact, never invented
  post-hoc.
- **Determination state**: implicit — edges exist (attached) or not; unresolved
  wiring is recorded per occurrence in the graph document's additive
  `unresolved_wiring` array (`{file, line, name, reason}`, sorted; present even
  when empty) — FR-010's distinct undetermined state. Undetermined wiring can never
  become an edge and never suppresses a finding.

Extraction-side fact (internal, additive to `FileFacts.to_dict`):

```json
{"target": "authenticateUser", "route": "GET /me" | null, "line": 9}
```

## Request Source (annotation channel extension)

- Existing `user_controlled_input` annotation, extended recognition scope: channels
  `header` and `cookie` alongside body/query/param (see research R2 for the idiom
  list per stack).
- No new annotation value; channel attribution rides the existing single category.

## Unattached Security Guard (node annotation)

- `code_graph.json` `annotations` enum gains `"unattached_security_guard"`
  (additive).
- Applied to `function` nodes whose name matches the shipped guard-name catalogue
  and which have no inbound edge from production code (containment edges and
  test-path referrers excluded per research R8).
- Feeds: segment domain derivation (`authentication`, `authorization`), triage's
  candidate-control seeding, role-digest lines.

## Coverage Gap — reachability (report coverage entry)

Existing coverage-gap channel (`build_report.coverage.gaps`, progress warnings).
Fixed message template:

```text
reachability unconfirmed: <E> entry point(s) and <D> security-relevant operation(s) were
found, but flow tracing connected none of them — authentication/authorization wiring,
source channels, or driver calls may use conventions not yet recognized; presence-confirmed
verdicts in this report are reachability-unproven
```

- **Trigger condition** (computed once per run): `endpoint_count > 0 AND
  security_relevant_operations > 0 AND traced_flow_count == 0`, where operations
  are counted by *annotation* (annotated files/symbols or datastore nodes), not by
  datastore nodes alone — otherwise a sink-recognition failure (an unrecognized
  driver produces no datastore nodes at all) would convert itself into silence,
  which is precisely the failure this gap exists to declare.
- Present in the same message the run's `reachability_unconfirmed` flag, consumed by
  verification (FR-009 demotion).

## Verification grade (finding schema, additive)

```json
"verification": {
  "status": "verified" | "plausible" | "disproven",
  "basis": "traced" | "presence",   // additive; required when status = verified
  "gap": "…", "path": ["…"]          // unchanged
}
```

- `basis: "presence"` only for the catalogue of presence-valid classes
  (CWE-798/259/256/522/532 secrets; CWE-352/942/489/1188/295/1004 configuration
  states; CWE-306 absent-mechanism findings).
- While `reachability_unconfirmed`: only CWE-306 demotes (presence → plausible,
  gap = the FR-007 message); secret/config classes keep `basis: presence`.
- `finding.json`: add `basis` to `verification.properties` (enum), keep
  `additionalProperties: false`, mark required-when-verified via description +
  pipeline writer contract (old artifacts without it remain valid: field not added
  to `required`).

## Recognition Catalogue (new versioned data file)

`skill_core/data/identity_archetype_rules.json`:

```json
{
  "version": "1",
  "dataset_date": "2026-09-07",
  "rules": [
    {
      "id": "express-header-identity-no-credential",
      "stacks": ["node"],
      "file_globs": ["**/*.js", "**/*.ts"],
      "scope": "function",
      "identity_read": "req\\.(?:headers|cookies)[\\[.][\\w'\".-]+",
      "requires_absent": ["jwt\\.verify", "passport\\.authenticate",
                           "bcrypt\\.(?:compare|checkpw)", "verify\\w*Token\\s*\\(",
                           "compare(?:Password)?\\s*\\("],
      "dispatch": "next\\s*\\(",
      "cwe": "CWE-290",
      "severity_score": 9.1,
      "title": "Identity asserted from client-controlled header without any credential",
      "description": "…",
      "recommendation": "…"
    }
  ],
  "guard_names": ["authenticat\\w+", "authoriz\\w+", "require_?auth\\w+", "verify_?(?:token|session|auth\\w*)", "guard\\w+", "is_?authenticated", "current_?user", "check_?(?:session|permission\\w*|auth\\w*)", "require_?role\\w*"]
}
```

- `guard_names` doubles as the FR-006 catalogue (single data source, R8).
- Schema (shipped under `skill_core/schemas/` per contract test convention): rules
  validated at load like `misconfig_rules.json` (duplicate ids /
  missing fields → build failure). New fields vs feature-004 rules: `scope`,
  `identity_read`, `requires_absent`, `dispatch`.
- Findings: `detection: "format"`, `confidence: 0.9` (deterministic-match
  precedent), location at function symbol; verdict `verification.status:
  "verified", basis: "presence"`.

## Relationships

- Wiring Edge *connects* Request Source channels (header reads inside the guard) to
  traced flows — the source set for `Flow` tracing is unchanged (annotation-driven).
- Coverage Gap (reachability) *gates* the Verification demotion and *informs* every
  triage packet implicitly through candidate-control seeding.
- Recognition Catalogue *drives*: archetype findings (FR-014), guard attachment
  semantics (FR-001/002 via Wiring facts), unattached-guard annotation (FR-006).
