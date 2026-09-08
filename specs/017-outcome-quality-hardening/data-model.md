# Data Model — Outcome-Quality Hardening (feature 017)

Conventions: additive only; canonical sorted output; no `schema_version` bump.

## Verification class membership (artifact-free, code-governed)

`PRESENCE_VALID_CWES` (frozenset in verify.py): existing presence classes ∪
identity pack members (from `identity_rules.no_refute_cwes()`).
`_REACHABILITY_SENSITIVE_PRESENCE = {"CWE-306", "CWE-290"}` — demoted to
`plausible` under an active FR-016/007 reachability gap, with the gap named.

## Stage resume key (state.json internal identity — not an artifact schema)

`build_code_graph` key payload:
```json
{
  "files": {"<member>:<path>": "<sha>", ...},
  "tool": "<TOOL_VERSION>",
  "recognizers": {"extractor": "<EXTRACTOR_VERSION>", "identity_rules": "<pack version>", "redactor": "<rules_version>", "cwe": "<cwe_map version>"}
}
```

## Finding family link (additive to existing `relationships[]`)

`{"target_id": "<anchor>", "type": "dependent", "reason": "same client-asserted identity channel (<token>)"}` on dependents; anchor carries the symmetrical `related` reference from feature 002 conventions.

Family key: channel token (e.g. `x-user-email`) — evidence-derived; recognized as
identity-bearing when the token's read sits on `authentication_required`-annotated
or pack-originated paths.

## Report blocks (additive)

- `findings_by_band` unchanged — anchors and dependents both present.
- Family presentation lives in rendering: dependents render as compact lines under
  the anchor's `Related findings` block. No JSON shape change.
- `awaiting_verification[]` gains `finding_ids: [..]` (additive) alongside the
  existing per-finding entries; renderer collapses by question text.

## Coverage gap records

Unchanged in shape; dedupe key becomes `(segment, cause, files)` with the
escalation-level token dropped from the report-visible copy.
