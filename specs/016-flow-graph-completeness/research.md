# Phase 0 Research — Flow & Graph Completeness (feature 016)

All NEEDS CLARIFICATION items resolved. Each decision is reuse-first per the
stable-release constraint in the spec, and every recognition is data/deterministic
per Constitution Principle I.

## R1 — Middleware wiring recognition

**Decision.** Registration facts extracted during enrichment (midexpression regex
over the already-read file text), resolved to edges in a second graph pass —
mirroring the existing two-pass precedent (`template_bindings` →
`resolve_template_bindings`). New fact type `Wiring(target, route, line)` on
`FileFacts`; `GraphBuilder.resolve_wiring()` maps a registered name to in-repo
symbol nodes via the existing `by_symbol` index and adds (a) `calls` edge
file → guard, (b) `handler` edges from the scoped endpoints to the guard.

**Rationale.** The wiring idiom is surface syntax (`router.use(auth)`,
`app.before_request(fn)`, middleware args in `router.METHOD(path, …)`); a lexical
pattern is sufficient and deterministic. Tree-sitter query tables would be more
precise but multiply per-grammar work beyond stable scope.

**Alternatives considered.** Full route-mount resolution (`app.use("/api", router)` →
cross-module guard inheritance) — deferred: needs import-to-module resolution, which
is the "later deep-analysis tier" the extractor already documents. Programmatic
composition (wrappers/spreads) — degraded to *undetermined* coverage per FR-010, not
guessed.

**Rules for the matcher.** Only whole-argument bare identifiers count
(`authenticateUser` yes; `(req,res)=>{}`, `mw.bind(x)`, `mod.auth` no). Unrecognized
registration shapes produce no edge and — when a security-meaningful name is
involved — feed FR-006 rather than silence.

## R2 — Attacker-controlled source channels

**Decision.** Extend `_USER_INPUT_HINTS` in-place with header/cookie channels per
supported stack: `request.headers|request.cookies`, `req.headers|req.cookies`,
`@RequestHeader|@CookieValue`, `.getHeader(`/`getCookie(`, `c.Cookie(`/`c.GetHeader(`/
`r.Header.Get(`.

**Decision (drivers, FR-004).** Extend `_SQL_EXECUTE` with a *receiver-scoped*
convenience alternative: `(db|conn|cursor|stmt).(get|run|all|prepare|first)(` —
data-store receivers only, so `session.get(...)` (Flask's dict read) stays clean.

**Rationale.** Both are additions to existing pattern tuples — the mechanism the
codebase already uses; recall n(ε) per Principle III/V outweighs pattern FP cost
because duplicate-datastore nodes dedupe by id and annotations only add candidate
material, never findings.

**Alternatives considered.** Versioned stack-rule data for every hint — rejected for
this release: annotations feed partitioning/verification hard-coded sets; lifting the
mechanism is a larger contract change. Deferred as noted in plan Complexity/limits.

## R3 — Flow integrity fix

**Decision.** `Flow.complete` reports structural truth: `trace()` only emits a path
that begins at the traced source and terminates at a sink, so completeness is
construction-true.

**Rationale.** The current implementation compares node ids against display labels;
endpoint-sourced flows get route labels (`GET /x [repo]`) so `complete` returns False
for every endpoint-anchored flow. Effect on the missed issue: even with wiring edges
fixed, the middleware path endpoint → guard → datastore would still be graded
`plausible`, not `verified`. Truncated mid-path walks (budget limit) are never
emitted, so no false completeness results.

**Alternatives considered.** Comparing labels to ids — fragile indirection through
rendering; rejected.

## R4 — Verification basis (FR-008/FR-009, clarify Q3)

**Decision.** Additive `basis: "traced" | "presence"` on the verification record;
status vocabulary frozen. `finding.json`'s verification object is
`additionalProperties: false` → schema gets the additive field (contract documented,
no version bump — additive per policy). Insertion points: `Verifier` presence
shortcut and flow-based verified path set the basis; `apply_verification` gains a
`reachability_unconfirmed` flag computed once per run; under it, presence-confirmed
CWE-306 (the reachability-sensitive presence class) demotes to `plausible` with the
named gap; secret/config presence classes (CWE-798/259/256/522/532/352/942/489/1188/
295/1004) are unaffected.

**Consumers unchanged.** Triage admission (`status`), calibration caps (`status`),
answer/resume keys (payload hashes) — see clarify Q3.

**Summary rendering.** `generate_report` lead sentence splits counts by basis; text
claims a complete path only for `basis == "traced"`.

## R5 — Reachability gap declaration (FR-007)

**Decision.** Compute once after `trace_flows`: positive evidence = any `endpoint`
node AND any data-access fact in the graph; condition = zero traced flows. Emit via
the existing warning channel (`run.py` `_warn`, stage `segment_analysis`) so it
rides the established path into the report's coverage section, progress output, and
`triage`/`business_flow` gating decisions. Single fixed message template with
counts — no new artifact kind.

**Rationale.** Reuses the exact mechanism existing coverage gaps use; report JSON
and markdown both pick it up with no renderer change.

## R6 — Role digest & guard-attachment evidence (FR-013/FR-016, clarify Q4)

**Decision.** Extend the packet's existing `call_graph_summary` (build_context.py)
with two derived, deterministic line families: per-file inbound-reference lines
(`file ← referenced from: callers…`, wiring edges included) and guard-attachment
lines (`file; guards: [names]` / `guards: none recorded` when the segment's other
route files attach guards). Bounded like the existing summary.

**Rationale.** Pure projection of graph edges the builder already has; no new memory
or artifact kind. Comparative guard absence stays evidence (no finding) per Q4.

## R7 — Client-asserted-identity archetype rules (FR-014, clarify Q2)

**Decision.** Reuse the feature-004 misconfig machinery: a new versioned rule pack
`identity_archetype_rules.json` (same validated-data discipline:
id/stacks/file_globs/cwe/title/…), extended with two additive fields:
`scope: "function"` plus a `requires_absent` list of credential-verification patterns
(`jwt.verify`, `passport.authenticate`, `bcrypt.compare|checkpw`, `verify*Token(`,
password compares). A rule matches when the identity-read pattern is present in the
function body and every `requires_absent` pattern is absent, and the body dispatches
(e.g. `next(`, returns handler result). Findings are `detection: "format"`,
seat the CWE dataset (CWE-290), land via the same per-segment append path as
deterministic secret findings, and refill `CREDENTIAL_CWES`-style refutation
gating (refuted disallowed) — implemented by extending that gate's membership from an
immutable frozenset to the shipped rule pack's cwe set.

**Rationale.** The machinery (load-time validation, InvalidRuleData-fail-the-build,
value-free findings, per-stack globs) already embodies the constitution's data-rule
requirements; inventing a second rules engine is the complexity to avoid.

**Alternatives considered.** Semgrep custom rules — rejected for core detection
(tool availability/attestation becomes a runtime dependency for a header-authored
class the pipeline can prove itself); acceptable later as data-driven extra signals.
LLM-proposed rules at scan time — rejected outright (Principle I).

## R8 — FR-006 unattached-guard signal

**Decision.** Guard-name catalogue ships in the new rule pack (shared list consumed
by both `annotate_unattached_guards()` in build_code_graph and the archetype
presence pattern). Inbound edges from test paths (`__tests__`, `/tests?/`,
`.test.|.spec.|_test.`) and self-containment don't count as attachment; only the
annotation is extended (`code_graph.json` additive enum value
`unattached_security_guard`). Mapped to domains in `partition_repo.DOMAIN_BY_ANNOTATION`
and to triage's `CONTROL_ANNOTATIONS` so the reasoning round sees the file.

## R9 — Triage citation-perimeter rejection (FR-020, clarify Q1)

**Decision.** `triage.apply` gets a perimeter check alongside the existing citation
re-verification: a `refuted`/`downgraded` verdict is rejected if any citation's
(repo, file[, symbol]) intersects the finding's implicated set — built with the same
helper verify.py uses (location file+symbol, every evidence file+symbol,
related_symbols stems). Verify-side half already landed (feature 016 task T008A).

**Rationale.** Reuses `triage_evidence` citation verification's data extraction;
whole-answer rejection keeps parity with existing rules 1–6.

## R10 — Prompt guidance (FR-015)

**Decision.** One sentence each in `segment_scan.md` (authentication domain bullet:
identity asserted from a client-controlled channel with no credential verification
is report-worthy), `triage_finding.md` (a control the finding implicates is never a
refutation; note format-detections can't be refuted), `final_review.md` (guard-
attachment digest lines are evidence for unguarded-module observations). No new
prompt files.

## Constitution-sensitive deferred item

Runtime LLM-proposed graph edges (model as proposer even with deterministic gating)
strain Principle I's determinism invariant and the answer-persistence semantics.
**Deferred**: not in this feature; tracked as a follow-up decision. Off-scan,
model-assisted *catalogue growth* (R7 data) is compliant and encouraged.
