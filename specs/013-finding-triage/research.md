# Research: Finding Triage Reasoning Round

**Feature**: `013-finding-triage` | **Date**: 2026-09-04

All Technical Context items resolved against the existing codebase. No unknowns
remain; every decision below names the seam it reuses.

---

## R1. Where the triage stage slots in

**Decision**: New stage `finding_triage` inserted in `state.STAGES` immediately
after `correlate_findings` and before `system_review`; driver wiring in `run.py`
consumes the `(correlated, disproven, reclassifications)` tuple from
`correlate_findings.finalize` and mutates the correlated set before
`system_review`/`generate_report`.

**Rationale**: clarified in spec (single round on finalized findings). At this
point every finding is normalized, located, verified (with traced paths), scored
against applicability, and calibrated — exactly the state a reviewer would judge,
and the state that supplies triage's candidate citations. `system_review` then
naturally reviews the *post-triage* set, so cross-boundary reasoning never chains
findings that triage has refuted.

**Alternatives considered**: triage inside `correlate_findings.finalize` (rejected:
correlation must stay deterministic; an LLM call inside it would violate Principle
I's stage discipline) ; triage after report generation as report post-processing
(rejected: verdicts must change findings *before* bands are computed, FR-013).

## R2. Reasoning transport: one client surface for all three modes

**Decision**: Triage issues `AnalysisRequest`s through the same `AnalysisClient`
used by segment analysis. Agent-mediated mode raises the existing `AgentHandoff`
(exit code 3, `.secscan/handoff/requests|responses/`, resume on re-run);
interactive endpoint mode goes through the retrying client; batch mode submits the
triage round as one additional round through the existing round runner.

**Rationale**: feature 012 already abstracted "a round of requests" behind
`EscalationRunner.prepare`/`absorb` parity and provider adapters; AGENTS.md makes
the same-content guarantee ("batch items reuse the interactive body builder") a
non-negotiable. Reusing the surface gives triage budgets, retries, rate-limit
handling, answer persistence, and progress reporting for free and keeps one
answer-judgment path.

**Alternatives considered**: a triage-specific transport (rejected: would duplicate
retry/batch/handoff logic and create a second way answers get judged — the exact
trap feature 012's FR-012 eliminated); agent-mediated-only (rejected: spec
assumption requires all modes).

## R3. Triage runner shape

**Decision**: A thin `TriageRunner` module mirrors the `EscalationRunner` contract
(packets recorded via the same context-packet writer, answers through
`AnswerStore`, usage through `UsageTracker`) but one request per finding with no
escalation ladder. In batch mode `TriageRunner` drives submission directly,
reusing the *helpers* (`BatchLedger`, the poll/backoff loop, fallback recording);
`BatchRoundRunner` itself stays segment-shaped and is NOT generalized. The
verdict-parse outcome path is shared so batch and interactive answers are judged
identically.

**Rationale**: findings are not segments — reusing `EscalationRunner` verbatim
would invent a fake segment identity per finding and drag along ladder semantics
triage does not have. A sibling runner reuses the parts that matter (budget
fitting against the serialized request, answer reuse keys, usage recording)
without the segment assumptions.

**Alternatives considered**: subclassing `EscalationRunner` (rejected: level/ladder
state would be dead weight and a source of divergent behavior); sending all
findings in one mega-request (rejected: violates Principle II — unbounded context,
no per-finding budget enforcement).

## R4. Candidate-control collection (the deterministic seed)

**Decision**: Deterministic collector over the code graph and control data already
computed in the scan: files carrying control annotations (`authorization_required`,
`authentication_required` etc.), the shipped framework-control catalogue used by
`controls.evaluate`, architecture-profile integration points from the member
manifest, and the finding's own traced verification path. Collected per finding,
capped, redacted, and embedded in the triage packet as candidate evidence.

**Rationale**: FR-003 requires the reasoner to never hunt unguided; the four
sources above are exactly where the baseline FPs' disproofs lived (security-config
registration, integrity-verification helper, URL-validation allowlist). All four
exist today as graph annotations or manifest fields — the collector reads, never
re-analyzes (Principle I).

**Alternatives considered**: free agent search with no seed (rejected: silent FP
recall risk — an unsearched control reads as "no control exists", violating
Principle V); sending whole security-config files unconditionally (rejected:
unbounded, and cred-bearing config must stay out of packets).

## R5. Verdict grammar and evidence citations

**Decision**: The answer `content` is strict JSON conforming to a new payload
schema `schemas/triage_answer.json`: closed `verdict` enum, optional `rationale`,
`citations[]` (`repo`, `file`, `line_start`, `line_end`, optional `symbol`,
`pattern` — the exact text the verdict relies on), and `user_question` for
`flagged`. Malformed content, unknown verdicts, or missing required fields reject
the whole answer for that finding.

**Rationale**: mirrors how segment answers are parsed (`FindingNormalizer.parse`
rejects non-conforming output) and keeps the answer-schema discipline of feature
012 (answer file holds exactly `{request_id, answer_key, content}`).

**Alternatives considered**: free-text rationale-only answers (rejected: Principle
IV — prose is not evidence); allow citations without `pattern` (rejected:
re-verification needs a concrete check, and line-existence alone proves nothing).

## R6. Deterministic evidence re-verification

**Decision**: `triage_evidence` re-verifies each citation: file resolves under the
cited repo member, line range within the file, `pattern` occurs within the cited
lines, (optional) symbol resolves against the code model. Every citation must pass
for a `refuted` or `downgraded` verdict to apply; any failure rejects the verdict
and degrades it to `flagged` (records the failure reason).

**Rationale**: same standard as `crosscheck.evaluate` — suppression only on
deterministic, checkable structure — extended from "absence disproof" to "presence
proof". All checks reuse existing resolution helpers (`locate`-style code-model
authority for ranges).

**Alternatives considered**: semantic control judgment in the verifier (rejected:
"does this filter actually cover this route" is undecidable without the graph —
so the collector's seed (R4) is what makes re-verified presence meaningful, and
anything beyond presence is accepted only as downgrade/flag, not refutation);
trusting a single citation when several were given (rejected: partial proof is
not proof — FR-005 requires every claim be cited, FR-007 requires every citation
to verify).

## R7. Enforcing the hybrid consultation boundary

**Decision**: The deterministic side enumerates, at code-graph build time, the set
of files with zero redaction hits; the agent-mediated triage request embeds the
allowed consult set (paths only). Enforcement is artifact-level and
deterministic: every reasoner response is redaction-swept before persistence
(Safety Invariants' existing sweep extended to triage outputs), and citation
patterns that classify as credential-like are invalid by construction (R5/R6).

**Rationale**: the agent physically *can* open any file; Principle III is
preserved by guaranteeing no path from raw file to persisted artifact survives
unswept, and by making the allowed set explicit and machine-derived rather than
instructional.

**Alternatives considered**: instruction-only ("do not read files with secrets")
(rejected: not deterministic); packet-only in agent mode (rejected by the user in
clarification Q1: raw consultation is what makes control-elsewhere refutation
effective).

## R8. Where verdicts land: artifacts and report surface

**Decision**: (a) Verified refutations produce suppression records of the
established shape under a new disproof ground family (`triage-control-present` +
citation set + re-verification result); they persist in the stage-owned
`findings/triaged.json` envelope (writing into `tooling/suppressions.json` would
double-append on resume — the artifact loads at dependency-audit time, triage
runs later). The report merges both channels, so shape, rendering, and
auditability are identical regardless of the file; the finding is excluded from
the findings stream only after verification. (b) Downgrades annotate the finding (`triage` block: previous +
adjusted scores, rationale, citations) and pass through `calibrate` ordering
invariants. (c) Flags attach an `awaiting_verification` block (question +
settling-evidence hint) and render both in the finding stream and a new report
section. (d) Every attempt — applied or rejected — is appended to
`triage/decisions.json`.

**Rationale**: reuses two existing audit surfaces (suppressions list, per-finding
record) rather than inventing parallel channels (spec assumption), and the
decision log satisfies FR-014 auditability including rejected verdicts.

**Alternatives considered**: separate triage-suppression file (rejected: splits
the audit trail the report must consolidate); refuted findings kept in the stream
with a badge (rejected: headline-inflation was a baseline complaint — bands must
reflect verdicts, FR-013).

## R9. User declarations storage and lifecycle

**Decision**: `.secscan/triage/declarations.json` — user-written, scanner-owned
directory (write access is the scanner's own artifact tree, not the scanned
project; Principle VI intact). Each declaration binds a finding identity
(repo + file + weakness + symbol), carries `question` echo, `answer`, and
`resolution` (`downgrade` | `refute`). At triage start, declarations load, match
open flags, apply with `user-declared` provenance recorded on the finding, and
lapse (ignored + re-flagged) when the identity no longer matches a live finding.

**Rationale**: clarification Q2 (persisted, applied on re-scan, reversible,
non-interactive). Binding by identity rather than line number survives line drift
but lapses on meaningful change (finding moved CWE or file → the question must be
re-asked).

**Alternatives considered**: declarations in scan config (rejected: config is
environment/portable; declarations are per-scan-state); interactive mid-scan
prompting (rejected in clarification Q2).

## R10. Profile/config surface

**Decision**: `analysis_depth.finding_triage` in profiles (`false` for `quick`,
`true` for `full`/`audit`) plus a `triage` config section
(`SECSCAN_TRIAGE_*` env override) carrying the selection threshold
(minimum severity band; include-unverified toggle). Defaults: `full` triages
findings at Medium+ and all heuristic secret findings; `audit` triages everything
eligible; `quick` skips the round.

**Rationale**: follows the established pattern (profiles control cost/depth;
config holds overridable knobs; env prefix convention). Absolute cost ceilings
stay with the existing per-request budget mechanism rather than a new knob —
triage requests are ordinary bounded requests (R3).

**Alternatives considered**: a global token ceiling for the whole round (rejected:
a new budget class would need new accounting; per-request budgets already compose
into usage reporting, and profile depth is the cost lever everywhere else).

## R11. Benchmark integration

**Decision**: extend `tests/benchmark/cases` with triage ground truth — cases
annotated `triage: expect-refuted` (with the disproof control present in fixture),
`expect-flagged`, and `must-survive`; the accuracy benchmark gains a
`triage_correctness` defect class, release-blocking like the others.

**Rationale**: FR-016 + constitution quality gate ("accuracy regressions are
release-blocking... asserted per defect class"). Fixture corpora already declare
deliberate false positives, so the harness pattern exists.

**Alternatives considered**: measuring triage quality via the baseline scan only
(rejected: a live-scan number is not a regression gate; corpus entries are).
