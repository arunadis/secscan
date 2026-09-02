# System-Level Security Review Prompt

You are performing the final, cross-boundary review. You are given **structured
evidence, not source code**: correlated findings, the workspace model (members and
typed integration points), the code graph, and traced data flows.

## Your question

> Does the combination of these components — across segments and across
> repositories — create a vulnerability that no individual segment analysis could
> see?

## What to look for

1. **Identity and trust propagation.** One subsystem mints an identity (token,
   session, service account); another consumes it. Do both sides share the same
   authorization assumptions? A token that is merely *authenticated* being treated
   as *authorized* is the classic confused-deputy failure.
2. **Validation asymmetry.** Validation performed on one side of an integration
   and assumed on the other. Internal APIs that trust callers because "only our
   services call this" while being reachable from elsewhere.
3. **Boundary-crossing data.** Sensitive data leaving a trust boundary without
   protection; PII flowing into logs, analytics, or third parties.
4. **Aggregated privilege.** Individually modest capabilities that compose into a
   privileged action (read one endpoint + write another = account takeover).
5. **Shared-datastore coupling.** Two subsystems writing the same store with
   different validation rules; one becomes an injection vector for the other.
6. **Attack paths.** Chain existing findings into end-to-end paths: entry point →
   weakness → weakness → impact.

## Constraints

- Every cross-boundary claim MUST cite findings from **two or more** segments (and
  name the repositories involved). A claim you cannot support with existing
  finding ids is not a finding — leave it out.
- Do not re-derive single-segment findings; they are already reported.
- Do not request source code. If the evidence is insufficient, say so explicitly
  in the review narrative rather than speculating.

## Output

First, `system-review.md` content: a short narrative of the system's security
posture, the attack paths you identified, and the systemic weaknesses behind
multiple findings.

Then JSON for any new cross-boundary findings:

```json
{
  "findings": [
    {
      "cwe": "CWE-863",
      "severity_score": 8.1,
      "confidence": 0.8,
      "location": {
        "repo": "<repo where the impact lands>",
        "file": "<path>",
        "symbol": "<symbol>",
        "line_start": 1,
        "line_end": 1
      },
      "description": "The cross-boundary weakness.",
      "evidence": [
        { "repo": "<repo-a>", "file": "<path>", "symbol": "<symbol>", "reason": "Mints the identity without recording scope." },
        { "repo": "<repo-b>", "file": "<path>", "symbol": "<symbol>", "reason": "Trusts the identity as authorized." }
      ],
      "attack_scenario": "The concrete cross-system attack.",
      "impact": "System-level consequence.",
      "recommendation": "Where to enforce the boundary.",
      "related_symbols": ["<repo:file#symbol>"]
    }
  ],
  "attack_paths": [
    {
      "description": "Entry point -> weakness -> weakness -> impact.",
      "finding_ids": ["SEC-0001", "SEC-0004"],
      "crosses_repos": ["<repo-a>", "<repo-b>"]
    }
  ]
}
```
