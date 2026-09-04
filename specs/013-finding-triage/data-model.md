# Data Model: Finding Triage Reasoning Round

**Feature**: `013-finding-triage` | **Date**: 2026-09-04

Entities, their fields, validation rules, and lifecycles. Schema-conformant shapes
ship in the payload (`skill_core/schemas/`); everything persists under `.secscan/`
as canonical JSON (sorted keys, trailing newline), per the determinism invariant.

---

## Triage Request

The reasoning invitation for one finding. Built deterministically after
`correlate_findings`; one per candidate finding.

| Field | Type | Notes |
|---|---|---|
| `request_id` | string | `triage-<finding_id>` — stable across re-runs |
| `stage` | string | constant `"finding_triage"` |
| `prompt` | string | rendered payload prompt (`prompts/triage_finding.md`) |
| `finding` | object | the full finalized finding (location, evidence, verification, grading) |
| `excerpt` | object | redacted excerpt window around the finding location |
| `candidate_controls` | list | deterministically collected candidate-control locations (see R4): `{repo, file, symbol?, reason, excerpt}` |
| `consultable_files` | list[string] | agent-mediated mode only: repository-relative paths with zero redaction hits (FR-006). Empty list = packet-only |
| `budget` | object | same shape as other analysis requests; enforced against the serialized request |

**Identity/persistence**: the answer reuse key is `hash(serialized request +
model tier)` via the existing `answer_key` mechanism — the byte-identical rerun
guarantee (FR-015) follows from the packet being deterministic.

**Validation**: packet build MUST NOT include any string the redactor classifies
as a secret; `consultable_files` is computed from the redactor's per-file hit
record, never from model or user input.

---

## Triage Verdict (answer content)

The `content` string of a persisted answer; strict JSON per
`schemas/triage_answer.json`.

| Field | Type | Rule |
|---|---|---|
| `finding_id` | string | MUST equal the request's finding id |
| `verdict` | enum | one of `confirmed`, `downgraded`, `refuted`, `flagged` |
| `rationale` | string | required for all except `confirmed` |
| `citations` | list | required non-empty for `refuted` and `downgraded`; MUST be empty for `flagged` and `confirmed` |
| `user_question` | string | required for `flagged`; absent otherwise |
| `settling_evidence_hint` | string, optional | allowed for `flagged` only; named evidence that would settle the question |

Validation (whole-answer rejection on any failure — the finding is untriaged):
finding-id mismatch, unknown verdict, citations missing/present against the rules
above, unparseable JSON, or any citation pattern failing the credential sweep.

## Evidence Citation

Member of `citations[]`.

| Field | Type | Rule |
|---|---|---|
| `repo` | string | MUST be a workspace member |
| `file` | string | MUST resolve under that member |
| `line_start` / `line_end` | int | MUST be within the file's line count |
| `symbol` | string, optional | if present MUST resolve against the code model |
| `pattern` | string | exact text the verdict relies on; MUST occur within `[line_start, line_end]`; MUST NOT classify as credential-like under the redactor |

All rules are enforced by the deterministic re-verifier (R6); a verdict lives or
dies as a whole.

## State transitions

```
unanswered ──handoff/endpoint/batch──▶ answered
answered ──parse ok──▶ parsed
answered ──parse fail──▶ rejected (= untriaged, recorded)
parsed:refuted/downgraded ──all citations verify──▶ applied
parsed:refuted/downgraded ──any citation fails──▶ degraded-to-flagged (recorded)
parsed:confirmed/flagged ──always──▶ applied
unanswered at report time ──▶ untriaged (finding unchanged; coverage gap declared)
```

## Triage Decision (audit record)

One entry per attempted verdict in `triage/decisions.json` (FR-014):

| Field | Notes |
|---|---|
| `finding_id`, `verdict_attempted`, `outcome` | outcome ∈ `applied`, `rejected-malformed`, `rejected-unverified`, `degraded-flagged`, `unanswered` |
| `citations` | as given (swept), plus per-citation verification results |
| `reason` | for rejected/degraded outcomes |
| `applied_effect` | for applied: `suppression-added` | `grading-adjusted` | `flag-attached` | `none` |

## Triage Suppression (extension of the existing suppression record)

Records carried in the stage-owned `findings/triaged.json` envelope and merged
with `tooling/suppressions.json` (cross-check) records for the report — never by
appending to the shared file, which would double-append on resume (triage runs
after the artifact is loaded). Records carry:

| Field | Notes |
|---|---|
| `disproof_ground` | new value family: `triage-control-present` |
| `evidence` | citation set with per-citation re-verification results |
| `finding` | existing shape (tool_ref, description, location) |

Rendered by the report's existing suppressions section; excluded from the findings
stream and headline bands (FR-010, FR-013).

## Finding annotations (additive fields on the existing finding shape)

| Field | Present when | Content |
|---|---|---|
| `triage` | verdict applied | `{verdict, rationale, citations, previous_severity, previous_confidence}` (downgrade carries previous grading) |
| `awaiting_verification` | verdict `flagged` | `{question, settling_evidence_hint}` |
| `triage_unresolved` | round ran but finding unanswered/rejected | `{reason}` — honest third state, never silence |

## Awaiting-Verification Item (report entity)

Derived, not stored separately: findings with `awaiting_verification` render in
the report section with `finding_id`, location, `question`, and current
(proven-only) grading.

## User Declaration (`.secscan/triage/declarations.json`)

User-written input consumed at triage start.

| Field | Rule |
|---|---|
| `finding_ref` | identity bind: `{repo, file, cwe, symbol?}` — line drift tolerated, CWE/file change lapses |
| `question` | echo of the flag's question (drift-checked; mismatch lapses) |
| `answer` | free text, ≤ 2000 chars, redaction-swept |
| `resolution` | enum: `downgrade` \| `refute` |

Lifecycle: **recorded** (user writes) → **matched** (open flag with same identity)
→ **applied** (resolution effect with `user-declared` provenance on the finding /
suppression record) → **lapsed** when identity or question no longer matches a live
flag (declaration ignored, finding re-flagged, lapse recorded in decisions). A
declaration whose resolution is `refute` MUST NOT apply to credential-class
findings (FR-008 parity for user input; provenance/lapse rules FR-019/FR-020).
