# Security model

A security scanner must be safe to run *where it is most needed* — on production
code, by someone who does not yet trust it. secscan's safety properties are
enforced by tests, not intent (the enforcement table lives in the
[constitution](../.specify/memory/constitution.md#safety-invariants)).

## Secrets never reach a model

- A deterministic, **layered redactor** (rule packs + entropy scoring + custom
  patterns) runs before any context packet is constructed. No model participates in
  deciding what to redact.
- Content the redactor cannot confidently classify is **blocked, not passed
  through**. Blocked values become declared coverage gaps — a silent hole would be
  worse than a stated one.
- **Recall takes absolute precedence over precision**: no change may reduce
  detection of a known credential to reduce false positives.
- Because the redactor must locate every credential anyway, it doubles as the
  authoritative hard-coded-secret detector — secrets are *reported* while their
  values appear nowhere: not in context packets, not in artifacts, not in logs.
- Credentials are supplied by environment-variable **name** only. A key value
  anywhere under `llm.endpoint` is rejected by config validation outright.
- **Runtime references are wiring, not credentials.** A credential-named key
  assigned from an indirection expression — bare or braced shell (`"$VAR"`,
  `"${VAR}"`), Windows batch (`"%VAR%"`), template placeholders (`"{{ var }}"`),
  CI expressions (`"${{ secrets.X }}"`), or command substitution (`"$(…)"`) — is
  left visible in context and recorded as an `exempt-reference` decision, never
  reported as CWE-798. The rule is a single structural test: *every letter and digit
  must lie inside a well-formed reference*. Punctuation between references
  (`"$USER:$PASS"`) is fine; any literal character outside one (`"$PREFIX-hunter2"`,
  `"pa$$w0rd"`, an unbalanced `"${NAME"`) makes the whole value a literal that is
  redacted and reported. Shell expansion operands of `:-`, `:=`, `:+` can become
  the value and are evaluated as literals — so `"${DB_PASSWORD:-hunter2hunter2}"`
  *is* a finding (this closed a gap where the old blanket `${…}` placeholder
  exempted it) — while `:?` operands are diagnostics and are ignored.
- **Report prose never redacts its own locations.** Tokens the report composed
  from the finding's structured location (repo, file path, symbol) are protected
  from the entropy heuristic in reproduction text, so the reader is never told to
  inspect `[REDACTED:high-entropy-secret].sh`. Rule-pack format matches are never
  protected: a path that literally contains a key pattern is still redacted.

## Offline by default, read-only always

- **No network in the default path.** Standards data (CWE map, applicability rules,
  framework controls, advisory snapshots, end-of-support windows) ships versioned
  inside the payload. Refreshing pinned data is an explicit operator action.
- **Nothing is installed, upgraded, or written into the scanned project.**
  Dependency audits run native ecosystem tooling with no install, upgrade, or
  lockfile write — asserted by hashing every manifest before and after. External
  tools are fingerprint-guarded and timed out.
- **The scanner ignores itself.** Installed skill payloads and tooling directories
  are excluded from scanning (all hidden directories — `.claude/`, `.devin/`,
  `.secscan/` itself — are skipped wholesale).

## Observe, never attack

- Verification is **static**: a traced source→sink path decides `verified` /
  `plausible` / `disproven`. No attack is ever executed.
- Reproduction steps are **benign**: non-destructive canary values, no real
  credentials, local/test deployment scope only. A step is only emitted when its
  success criterion is achievable against the code as written.
- A reproduction block states an *observation* only for a finding verified end to
  end; everything else states the outcome to check and says the scanner did not
  observe it.

## Honest uncertainty

Undetermined states are first-class — they are recorded, named, and can never buy
silence:

| Third state | Where it appears | Why |
|---|---|---|
| `undetermined` | architecture | an unknown architecture must never satisfy a structural requirement |
| `undetermined` | applicability / reachability | may not suppress a finding |
| `unassessed` | framework control | a config-dependent control is not credited until found |
| `could-not-check` | dependency audit | an unavailable tool never reads as clean |
| coverage gap | blocked values, budget-dropped files | cause, criticality, and impact are declared; security-critical gaps rank first |

The symmetrical rule also holds: an unknown never **inflates** either — absence of
an established control is not evidence none exists, and never raises severity. An
unproven finding never outranks a proven one.

## Budgets are never exceeded

- Token budgets are enforced against the **actual serialized request**, never an
  estimate. This is asserted in scale-scan tests.
- Oversized segments are **subdivided along security boundaries**; files that
  cannot fit are dropped whole and reported as coverage gaps — source is never
  silently truncated (truncated source produces confident answers about code the
  model never saw).
- Every blocked value or dropped file ends up in the report's coverage section with
  cause and criticality.

## Determinism

Identical input plus identical tool version produces **byte-identical artifacts**:
sorted, canonical JSON with trailing newlines; stable ids
(`<repo>:<path>#<symbol>`); third-party tool output normalized into a stable
projection with fields known to vary between runs discarded. This is what makes a
security report auditable — a finding that cannot be regenerated cannot be defended.

## Nothing is claimed that was not established

- Locations resolve against the code model, not model output; unresolvable
  locations are rejected, not published.
- A trail rendered with dataflow arrows contains **only traced edges** — supporting
  evidence is presented as evidence, never dressed as a path.
- A pre-write **consistency gate** withholds a self-contradicting report entirely,
  rather than publishing it with a warning.

## Related pages

- [Architecture](architecture.md) — where in the pipeline each guarantee lives
- [Artifacts](artifacts.md) — how gaps and third states surface on disk
- [Configuration](configuration.md) — credential and budget configuration
