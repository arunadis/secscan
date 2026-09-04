# Contract: Report Surface, Suppressions, Decisions, and User Declarations

**Feature**: `013-finding-triage` | **Status**: binding for implementation and
contract tests

## 1. Suppressions record extension

As implemented, triage suppression records persist inside `findings/triaged.json`
(the stage-owned envelope), not by appending to `tooling/suppressions.json`:
appending to the shared file would double-append on resume, since that artifact
is loaded at dependency-audit time and triage runs later. The report merges both
channels (`suppressions = crosscheck + triage`), so the record shape, rendering,
and auditability are identical regardless of the storage file.

Additive to the existing record (no schema-version bump — additive per the schema
policy):

```json
{
  "finding": {"tool_ref": "triage", "description": "...", "location": {...}},
  "tool_id": "triage",
  "disproof_ground": "triage-control-present",
  "evidence": [
    "citation verified: prism-bi/.../SecurityConfig.java:58-64 contains 'PermissionAuthorizationFilter'",
    "..."
  ]
}
```

- A triage suppression is written **only** after every citation re-verifies.
- The report's existing suppressions section renders these alongside
  cross-check suppressions unchanged.
- Refuted findings leave the findings stream and the headline bands; they remain
  fully visible in the suppressions section (FR-010, FR-013).

## 2. Report: awaiting-verification section

New, optional top-level report key `awaiting_verification` (absent when empty —
additive schema rule):

```json
{
  "awaiting_verification": [
    {
      "finding_id": "SEC-0029",
      "location": {"repo": "...", "file": "..."},
      "question": "Is local-dev-token ever used outside localhost:8080 dev-auth?",
      "settling_evidence_hint": "Deployment config or gateway rules routing this header",
      "provenance": "triage"
    }
  ]
}
```

Rules:

1. Entries are sorted by finding id; identical input → identical section.
2. The flagged finding also remains in the findings stream with its proven
   grading (flagging changes nothing about grading — FR-012).
3. A `triage_unresolved` coverage line appears in the report coverage section
   whenever any eligible finding went unanswered (FR-009): triage ran but N of M
   candidates were not adjudicated.
4. A methodology note states the triage mode in effect and the consultation
   boundary (packet-only, or hybrid with the zero-redaction-hit consultable set)
   whenever triage ran or was profile-disabled (FR-006).

Markdown rendering mirrors the JSON: a distinct section listing each finding id,
location, and question, placed after findings and before the suppressions list.

## 3. Decision log (`triage/decisions.json`)

```json
{
  "decisions": [
    {
      "finding_id": "SEC-0011",
      "verdict_attempted": "refuted",
      "outcome": "applied",
      "applied_effect": "suppression-added",
      "citations": [{"file": "...", "line_start": 58, "line_end": 64, "verified": true}],
      "reason": null
    }
  ]
}
```

- One entry per candidate, including `unanswered` and rejected attempts (FR-014).
- Entries sorted by finding id; canonical JSON.

## 4. User declarations (`.secscan/triage/declarations.json`)

User-written, consumed at triage start. Not a scanner artifact — it is input.

```json
{
  "schema_version": 1,
  "declarations": [
    {
      "finding_ref": {
        "repo": "prism-bi",
        "file": "scripts/start-edge-agent.sh",
        "cwe": "CWE-798",
        "symbol": null
      },
      "question": "Is local-dev-token ever used outside localhost:8080 dev-auth?",
      "answer": "No — dev-compose only; gateway rejects it externally.",
      "resolution": "downgrade"
    }
  ]
}
```

Rules (contract tests assert each):

1. Matching binds on `finding_ref` (repo + file + cwe; symbol only when present —
   an absent symbol matches any symbol, i.e. wildcard), line-agnostic,
   **and** question equality; both must match a live flag.
2. Applied declarations record provenance `user-declared` on the finding
   (`triage.user_declaration` block) or on the suppression record — never
   presented as pipeline-derived evidence (FR-019).
3. `resolution: refute` on a credential-class finding invalidates that
   declaration (recorded as `rejected-credential-refute`; the flag stays).
4. Unmatched or lapsed declarations neither suppress nor downgrade; the finding
   is re-flagged and the lapse recorded (FR-020).
5. `answer` is capped at 2000 chars and redaction-swept; swept/blocked content
   invalidates the declaration.
6. Removing a declaration restores the flag on the next scan (reversibility) —
   nothing caches a resolved flag past its declaration's presence.

## 5. Config surface

New `triage` section (all overridable via `SECSCAN_TRIAGE_*`):

| Key | Values | Default |
|---|---|---|
| `enabled` | auto \| on \| off | auto (follows profile) |
| `min_severity_band` | Low \| Medium \| High \| Critical | profile: full=Medium, audit=Low |
| `include_unverified` | bool | true |

Strict validation per the existing loader rules: unknown keys rejected.
