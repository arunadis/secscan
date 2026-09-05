---
name: secscan
description: >-
  Perform a hierarchical security assessment of a large codebase or multi-repository
  workspace while keeping LLM context bounded. Use when the user asks to scan for
  vulnerabilities, run a security review, audit a repository, triage scanner findings,
  or check a codebase for security issues.
license: Apache-2.0
metadata:
  version: "0.1.0"
---

# Security Scan

## Objective

Assess the security of a workspace (one or more repositories) while never loading
the whole codebase into a single context. Deterministic scripts build the model
and collect evidence; you reason over small, bounded context packets.

## Rules (non-negotiable)

1. **Never** load the entire repository into context. Work only from the context
   packets the pipeline gives you.
2. Prefer references (file#symbol) over pasting unrelated code.
3. Every finding MUST have evidence — file, symbol, and why it matters.
4. Every finding MUST have a CWE id from the shipped dataset, a CVSS-style
   severity score, and a numeric confidence.
5. Emit **only** JSON conforming to the finding schema. No prose, no commentary,
   no markdown outside the JSON. Free-form output is rejected by the pipeline.
6. Do not duplicate findings; do not invent CWE ids.
7. Cross-segment claims must cite findings from more than one segment.
8. Never execute attacks against a running system. Verification is static.
9. Reproduction steps use benign canary values only, contain no real secrets, and
   target a local/test deployment.

## Workflow

Run each stage in order. Every stage writes durable artifacts under
`.secscan/`, so an interrupted scan resumes where it stopped — re-invoke
the scan command to continue.

```
0. init                    # config + environment check (first run only)
1. discover_repo           # workspace + per-repo manifests
2. build_code_graph        # symbols, calls, entry points, data access
2a. business_flow_model    # business flows, only when enabled (off by default)
3. partition_repo          # security-boundary segments
4. build_context           # bounded, redacted context packets
5. ingest_findings         # external scanner output (when tools present)
6. SEGMENT ANALYSIS        # <- your reasoning, per packet
6a. BUSINESS-FLOW ANALYSIS # <- your reasoning, per flow (only when enabled)
7. normalize_findings      # schema enforcement + CWE/OWASP mapping
8. verify + reproduce      # static verification, reproduction blocks
9. correlate_findings      # dedupe, relate, group
10. FINDING TRIAGE         # <- your reasoning, per finding (full/audit profiles)
11. SYSTEM REVIEW          # <- your reasoning, cross-segment
12. generate_report        # unified report + usage summary
```

## Before you run: the business-flow question

Business-flow analysis (steps 2a/6a) finds *functional* gaps — missing enforcement
between flow steps, skippable enforced steps, cross-role or cross-tenant transitions,
and flows that breach declared regulatory obligations. It costs extra reasoning
tokens, so it is **off by default** and the user decides.

Before the first `run` of a project, check `.secscan/config.yaml`:

- If it has `business_flow.enabled` (true or false), honor it — ask nothing.
- If the key is absent, **ask the user** whether to run business-flow analysis for
  this scan, and pass the answer per run with
  `run --set analysis_depth.business_flow=true|false`.
- Offer "remember this choice"; only if the user explicitly accepts, write
  `business_flow.enabled: <answer>` into `.secscan/config.yaml`. If they decline,
  write nothing and ask again next time.
- When the user opted in, also offer the regulatory scope: declare applicable
  regimes via `business_flow.declared_regimes` (ids from the shipped dataset; the
  scan's flow-coverage section lists suggested candidates).

A direct non-interactive `run` with the key unset simply skips flow analysis — never
block automation on the question.

Run the pipeline with the scan command (resumes automatically as needed). From
this skill directory, put `scripts/` on `PYTHONPATH`:

```bash
export PYTHONPATH="$(dirname "$0")/scripts"          # or the skill's scripts/ path
python -m pipeline.scan_cli init   --workdir <scan-root>
python -m pipeline.scan_cli run    --workdir <scan-root> [--profile quick|full|audit] [--full] [-q|-v]
python -m pipeline.scan_cli status --workdir <scan-root>
python -m pipeline.scan_cli report --workdir <scan-root> [--repo <name>]
```

If the package is installed globally the same surface is `secscan run ...`.

Exit code 3 from `run` means your reasoning is required — see the next section.

`run` reports progress on **stderr** as it works (each stage, segment `i/N`,
external tool, and coverage note, plus a heartbeat during long steps); relay it to
the user so a long scan does not look stuck. The summary stays on **stdout**. The
full trace of the latest run is always in `.secscan/scan.log` — read it first when a
scan stopped unexpectedly (its last line names the stage that was in progress).
Pass `-q` if you only want the summary.

When the project is configured with an external analysis endpoint (`llm.endpoint`),
you do not perform the reasoning; the provider does, through its **batch API by
default**. Expect `batch k/m submitted` / `processing c/N` / `ended` lines and a wait
in the foreground that can last minutes to hours. Do not kill and restart the scan to
"speed it up": the batch reference is persisted and a re-run resumes the same batch.
Exit code 1 with `re-run to resume` on stderr means the endpoint kept refusing after
all retries (typically rate limiting); segments already analysed are kept, so re-run
later rather than starting over. `--policy interactive` opts into live per-segment
requests for small repositories.

## Your part: segment analysis (step 6)

When the driver needs your reasoning it exits with status 3 and leaves one file
per pending request in `.secscan/handoff/requests/`. For **each** request:

1. Read `handoff/requests/<request-id>.json`. It contains `prompt` (the analysis
   instructions) and `context_packet` — purpose, entry points, call-graph summary,
   data flows, security-relevant symbols, and redacted source excerpts.
2. Consider only the vulnerability domains in `context_packet.domains`, using the
   matching guidance in `prompts/segment_scan.md`.
3. Ask, at the local level: does any single function contain a flaw?
4. Ask, at the segment level: does the *combination* create a flaw that no single
   component shows? (controller validates X → service assumes X → repository
   performs a dangerous operation)
5. Write your findings JSON to
   `.secscan/handoff/responses/<request-id>.json` — the same id as the
   request — conforming to `schemas/finding.json`.
6. Re-run the scan command. Completed stages are skipped, your answers are
   consumed, and the scan continues from the checkpoint.

If the evidence in the packet is insufficient for a confident verdict, say so by
setting `"needs_escalation": true` in your response instead of guessing. The
pipeline will build a larger packet (next escalation level) and ask again.

Because requests and responses are files, a large scan can span **multiple agent
sessions**: answer what you can, re-run, repeat.

## Your part: business-flow analysis (step 6a)

When flow analysis is enabled, the scan exits with status 3 and leaves
`flow-<flow-hash>-l<level>` requests in `.secscan/handoff/requests/` — one per
reconstructed business flow. For **each**:

1. Read the request — `context_packet.flow` carries the journey: actor posture,
   ordered steps (repo-attributed node ids, operation kinds, security annotations,
   regulated-data categories), any partial-flow gap reasons, and related data flows.
2. Follow `prompts/business_flow.md`: walk the steps and, at **every** step, ask who
   is allowed to be here and whether that is enforced. When the packet lists
   evaluated regimes, also evaluate the flow against each named obligation.
3. Answer conforming to `schemas/flow_answer.json` — a closed `assessment`
   (`clean` | `gap` | `violation` | `undetermined`); `undetermined` always names its
   reasons. Findings carry `missing_check` and `compromise` (who gains what they are
   not allowed to do), plus `regulatory_refs` for obligation breaches. Regulatory
   findings describe *potential compliance risk* with evidence — never a legal
   determination.
4. Write the answer to `.secscan/handoff/responses/<request-id>.json` and re-run. An
   `undetermined` assessment escalates to a deeper packet (up to the profile
   ceiling), exactly like segment analysis; never guess to avoid escalation.

## Your part: finding triage (step 10)

After findings are correlated, the driver re-examines each candidate finding by
handing it back to you: the scan again exits with status 3 and leaves
`triage-SEC-NNNN` request files in `.secscan/handoff/requests/`. For each:

1. Read the request — it carries the finalized `finding`, its redacted
   `excerpt`, and `candidate_controls` the deterministic scan flagged as possibly
   relevant (security-config registrations, route maps, integrity helpers, the
   finding's own traced path).
2. Follow `prompts/triage_finding.md`: answer from the closed verdict vocabulary
   — `confirmed`, `downgraded`, `refuted`, or `flagged` — conforming to
   `schemas/triage_answer.json`.
3. You may open repository files listed in `consultable_files` to confirm the
   structure your verdict relies on; files outside that list are off-limits (they
   may contain credential values you must never see — the pipeline classifies
   this deterministically, it is not asking for restraint).
4. Every `refuted` or `downgraded` verdict MUST cite exact text (`pattern`)
   within cited lines of a real file; the pipeline re-verifies each citation
   mechanically before the verdict counts. An unverifiable citation degrades the
   verdict to a flag — the finding is never removed on your say-so alone.
5. Credential findings (CWE-798/522) can never be refuted: you cannot see the
   matched value. Downgrade from context or flag with a question instead.
6. Write the verdict JSON to `.secscan/handoff/responses/<request-id>.json`;
   re-run the scan command to continue.

Findings you flag land in the report's **Awaiting Verification** section with
your question. The operator answers by recording
`.secscan/triage/declarations.json` entries; the next scan applies them as
user-declared evidence (reversible — removing the entry restores the flag).

## Your part: system review (step 11)

Read `.secscan/findings/correlated.json`, `workspace.json`, and
`code-graph.json` — **not** the source. Look for vulnerabilities that span
security boundaries:

- an identity minted in one segment/repo and trusted in another under different
  authorization assumptions;
- validation performed on one side of an integration but assumed on the other;
- sensitive data crossing a trust boundary without protection.

Write your conclusions to `.secscan/system-review.md` and any new
cross-boundary findings (citing evidence from ≥2 segments) as JSON.

## Output contract

The scan produces `.secscan/reports/<scan-id>.md` and `.json` containing an
executive summary, findings grouped by severity (verified before plausible within
each band), inline reproduction blocks, attack paths, a coverage statement, and a
usage/cost summary.
