# Contract: Client-asserted-identity archetype rules (feature 016)

Consumers: deterministic archetype detector, finding normalizer, triage gate,
accuracy benchmark. Authority: `src/skill_core/data/identity_archetype_rules.json`.

## 1. Rule pack shape

Extends the feature-004 misconfig rule-pack discipline (load-time validated;
duplicate id / missing field → build failure, never scan failure):

```json
{
  "id": "<stack>-<slug>",
  "stacks": ["node", "python-web", "jvm", "go", …],
  "file_globs": ["**/*.js", …],
  "scope": "function",
  "identity_read": "<regex>",
  "requires_absent": ["<regex>", …],
  "dispatch": "<regex>",
  "cwe": "CWE-290",
  "severity_score": 9.1,
  "title": "…", "description": "…", "recommendation": "…"
}
```

## 2. Matching semantics (deterministic)

A rule fires on a function symbol of a matching file when ALL hold:

1. `identity_read` matches the function body,
2. NO pattern in `requires_absent` matches the function body,
3. `dispatch` matches the function body.

Match shape is reported, never values (Principle III): the finding carries file,
symbol, line span, rule id.

## 3. Finding shape

- `detection: "format"` (clarify Q2): the shape itself is valid presence evidence.
- `confidence: 0.9`; CWE from the shipped dataset (CWE-290 etc.).
- Enters the pipeline per segment alongside deterministic secret findings.
- `verification`: `status: "verified", basis: "presence"`.
- Triage: `refuted` is invalid for findings whose CWE is in the rule pack's CWE set
  (same gate family as credential findings); `downgraded`/`flagged` remain allowed
  with verified citations as usual — subject to the FR-020 implicated-perimeter
  rejection.
- Band gating: enters the triage round only at/above the profile's minimum severity
  band (standard selection).

## 4. Versioning

`version` + `dataset_date` required and recorded in findings carrying `tool_ref`
(`identity-archetype@<version>:<rule-id>`), so a rule change is auditable and a
re-scan reproduces decisions bit-for-bit given the same data version.
