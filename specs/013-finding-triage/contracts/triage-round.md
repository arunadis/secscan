# Contract: Triage Round (request packet + verdict answer)

**Feature**: `013-finding-triage` | **Status**: binding for implementation and
contract tests

This contract defines what the pipeline sends the reasoning layer during the
triage round and what shape the answer must take. It is mode-independent: the
identical packet and answer shape serve agent-mediated handoff, the interactive
endpoint, and the provider batch (the batch/interactive same-content guarantee of
feature 012 extends to triage — batching may never change packet content).

## 1. Stage placement

```
correlate_findings ──▶ finding_triage ──▶ system_review ──▶ generate_report
```

- Runs exactly once per scan, on the finalized finding set (FR-001).
- Registered in `state.STAGES` with a resume key derived from the correlated
  findings + triage configuration; changing either invalidates only this stage and
  everything downstream (system review, report).
- Skipped profiles (`quick` default) announce the skip through the reporter like
  any other stage skip.

## 2. Candidate selection

Eligible: findings in the correlated set with no `dependency` block
(dependency advisories belong to deterministic cross-check), satisfying the
profile/configured threshold:

| Profile | Threshold |
|---|---|
| `quick` | triage disabled |
| `full` | severity band ≥ Medium **or** detection = heuristic |
| `audit` | all eligible findings |

Overridable via the `triage` config section (`SECSCAN_TRIAGE_*`): `enabled`,
`min_severity_band`, `include_unverified` (default true). Selection itself is
deterministic and appears in the decision log.

## 3. Request packet

| Part | Content rule |
|---|---|
| `finding` | verbatim finalized finding |
| `excerpt` | redactor-processed excerpt window; if the window is blocked by the redactor, the packet notes the block instead (never passes unredacted) |
| `candidate_controls` | deterministic collector output (R4): control-annotated files, framework-control catalogue entries matching present frameworks, architecture-profile integration points, the finding's verification path |
| `consultable_files` | agent-mediated only; zero-redaction-hit path set (R7); other modes omit the key |
| `budget` | enforced against the actual serialized request; oversized packets shed whole candidate-control entries with a warning, never truncate source |

## 4. Answer shape (`schemas/triage_answer.json`)

```json
{
  "finding_id": "SEC-0011",
  "verdict": "refuted",
  "rationale": "Role endpoints are protected by ...",
  "citations": [
    {
      "repo": "prism-bi",
      "file": "bi-core-v2/src/main/java/.../SecurityConfig.java",
      "line_start": 58,
      "line_end": 64,
      "symbol": "securityFilterChain",
      "pattern": "PermissionAuthorizationFilter"
    }
  ]
}
```

Rules (whole-answer rejection on violation):

1. `verdict` ∈ {`confirmed`, `downgraded`, `refuted`, `flagged`}.
2. `refuted`/`downgraded` → `citations` non-empty and `rationale` present.
3. `flagged` → `user_question` present, `citations` empty; `settling_evidence_hint`
   optional (allowed for `flagged` only).
4. `confirmed` → `citations` empty, `rationale` optional.
5. Credential-class findings (CWE-798/CWE-522 source: redactor or secrets
   tooling) → `refuted` is invalid by construction (FR-008): such answers are
   rejected before evidence checking.
6. The answer content passes the redaction sweep before persistence; swept
   content rejects the answer.

## 5. Evidence re-verification (pipeline-side, deterministic)

For `refuted`/`downgraded` verdicts, every citation must verify:

1. `repo` is a workspace member; `file` exists under it.
2. `line_start..line_end` within the file's line count.
3. `pattern` occurs verbatim within the cited lines.
4. `symbol`, if present, resolves against the code model.

All-pass → verdict applies. Any failure → verdict rejected and the finding is
flagged instead, with the failure recorded (`degraded-flagged`).

## 6. Handoff behavior (agent-mediated)

- Pending triage requests raise `AgentHandoff` alongside any other pending
  reasoning: exit 3, requests in `.secscan/handoff/requests/`, responses written
  to `.secscan/handoff/responses/<request-id>.json`, scan resumes on re-run.
- The request document's instructions name `prompts/triage_finding.md` and
  `schemas/triage_answer.json` (parallel to segment_scan).
- `SKILL.md` gains a triage section: read request, review packet (and consult
  files in `consultable_files` only), write verdict JSON, re-run.

## 7. Endpoint modes

Interactive: ordinary retrying requests (existing retry policy). Batch: `TriageRunner`
drives submission directly, reusing the batch ledger and polling/backoff helpers
(`BatchLedger`, poll loop, fallback recording) — `BatchRoundRunner` is segment-shaped
and is NOT generalized; the triage batch path is a thin parallel driver over the same
helpers. Packets are built once and reused for either policy (same-content guarantee).
An expired/failed round leaves affected findings `triage_unresolved` and the
report declares the gap (FR-009) — no retry storm inside the stage.
