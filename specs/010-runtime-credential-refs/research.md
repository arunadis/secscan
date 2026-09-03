# Research: Runtime Credential References

**Feature**: 010-runtime-credential-refs | **Date**: 2026-09-02

No `NEEDS CLARIFICATION` markers remained after `/speckit-clarify`; this document records the
design decisions the plan depends on, each verified against the current detector.

## Baseline measurements (current `Redactor`, rules v1)

| Line | Today | Note |
|------|-------|------|
| `export AWS_SECRET_ACCESS_KEY="$AWS_DEVIN_PROD_SECRET_ACCESS_KEY"` | `assigned-secret` | the reported FP |
| `export AWS_SECRET_ACCESS_KEY="${AWS_DEVIN_PROD_SECRET_ACCESS_KEY}"` | clean | `${…}` placeholder |
| `export DB_PASSWORD="${SKILLHUNT_PORTAL_BACKEND_PROD_DB_PASSWORD_2024_v3}"` | `high-entropy-secret` | placeholder exempts the assignment rule, but the **entropy path** still fires on the 43-char name (H=4.26) |
| `password: "%DB_PASSWORD%"` / `"{{ vault_secret }}"` / `"${{ secrets.X }}"` / `"$(cat …)"` | `assigned-secret` | same FP class |
| `AUTH="$DB_USER:$DB_PASSWORD"` | clean | too short for the rule today; must stay clean |
| `password: "${DB_PASSWORD:-hunter2hunter2}"` | **clean** | existing **recall hole**: `\$\{[^}]*\}` placeholder swallows the literal default |
| `password: "${DB_PASSWORD:?DB_PASSWORD is required}"` | clean | correct, by accident of the same placeholder |

Two conclusions drive the design: (1) the fix must apply on **both** the assignment path and the
entropy path; (2) the blanket `${…}` placeholder must be **replaced**, not extended — it is the
source of a recall gap the constitution forbids.

## R1 — Reference grammar

**Decision**: a closed set of six indirection expression families, each a regex over the quoted
value, evaluated by a single `classify_runtime_reference(value) -> RuntimeReference | None`:

| Family | Pattern (informal) | Example |
|--------|--------------------|---------|
| `shell-bare` | `$` + identifier `[A-Za-z_][A-Za-z0-9_]*` | `$AWS_SECRET_ACCESS_KEY` |
| `shell-braced` | `${` identifier [ operator operand ] `}` | `${DB_PASSWORD}`, `${DB_PASSWORD:-…}` |
| `shell-subst` | `$(` … balanced … `)` or backticks | `$(cat /run/secrets/key)` |
| `batch` | `%` identifier `%` | `%DB_PASSWORD%` |
| `template` | `{{` … `}}` (Jinja/Helm/Ansible/Go) | `{{ vault_secret }}`, `{{ .Values.pw }}` |
| `ci-expr` | `${{` … `}}` (GitHub/Azure) | `${{ secrets.GH_TOKEN }}` |

Identifiers inside `template` and `ci-expr` may contain `.`, `[`, `]`, quotes, and whitespace
(they are expression languages); the family is well-formed when its delimiters balance.

**Rationale**: these are the forms that actually appear in shell, Compose, Kubernetes, Helm,
Ansible, GitHub/Azure/GitLab CI, Terraform-adjacent and `.env`-style files — the surfaces feature
002 brought into scope. Language-level accessors (`os.environ["X"]`, `process.env.X`) never enter
the `assigned-secret` rule because they are not quoted values, so they need no handling.

**Alternatives considered**: (a) extend the placeholder regex with `\$[A-Za-z_]\w*` — rejected:
does not cover `%X%`/`{{ }}`/`$( )`, keeps the `${…}` recall hole, and cannot express the
"all alphanumerics inside" rule. (b) Language-aware parsing per file type — rejected: the redactor
is deliberately file-type agnostic (FR-000) and must stay a single pass over text.

## R2 — Classification invariant: every letter and digit inside a reference

**Decision**: scan the value left to right; at each position, if a family matches, consume it and
record the reference; otherwise the character must be non-alphanumeric (punctuation or whitespace)
or classification fails. Unbalanced delimiters fail (FR-003). The value is a `RuntimeReference`
iff the scan completes with ≥1 reference and no alphanumeric character was consumed outside one.

**Rationale**: this single invariant delivers every clarified behaviour without special cases:
`"$A:$B"` passes (Q2), `"$PREFIX-hunter2hunter2"` fails, `"pa$$w0rd"` fails (`pa` outside),
`"${NAME"` fails (unbalanced), `"%NAME"` fails (unterminated). It is also the structural argument
for Principle III: no literal alphanumeric material can be exempted, by construction.

**Alternatives considered**: whitespace-only joiners (spec's original wording) — rejected in
clarification because `"$USER:$PASS"` is a common idiom; fixed joiner set — rejected as an
arbitrary list that would need maintenance.

## R3 — Shell expansion operands

**Decision**: inside `shell-braced`, recognise operators `:-`, `-`, `:=`, `=`, `:+`, `+`, `:?`,
`?`. For `:?`/`?` the operand is a diagnostic — discarded, the reference is well-formed. For the
others the operand is **evaluated recursively as an assigned value**: it passes if it is empty, a
placeholder (`_is_placeholder`), or itself classifies as a reference; otherwise the whole value
fails classification and is treated as a literal (redacted + reported as today).

Consequence: `"${DB_PASSWORD:-hunter2hunter2}"` becomes a **finding** where today it is silently
clean — a recall gain that must be added to `credential_corpus.py` as a must-find entry.

**Rationale**: matches Q3. Operator semantics are deterministic shell grammar, not a heuristic.

**Alternatives considered**: keep operand handling out of scope — rejected because removing the
`${…}` placeholder (R1) forces a decision and "treat everything as literal" would report `:?`
messages, a new FP class.

## R4 — Apply on both detector paths

**Decision**:
- **Assignment path**: in `Redactor.redact`, when a rule match has `label == "assigned-secret"`
  and `classify_runtime_reference(value)` succeeds, append an `ExemptionDecision(rule=
  "assigned-secret", classification="runtime-reference:<family>", decision="exempt-reference")`
  and skip the span. Format-rule labels never consult the classifier (FR-008).
- **Entropy path**: before `_has_credential_context`, check whether the candidate is the
  identifier of an enclosing well-formed reference (preceded by `$`, `${`, `%`, `{{`/`${{`
  and correctly terminated). If so, record the same exemption and skip. This closes the
  `${SKILLHUNT_…_v3}` case measured above.

**Rationale**: one classifier, two call sites; the entropy path check is "is this token the
*name* inside a reference", which is a sub-question of R2.

## R5 — Known-safe location tokens in reproduction text

**Decision**: add `known_safe: Sequence[str] = ()` to `Redactor.redact`. Occurrences of each
token in the text form protected spans. **Heuristic** spans (`high-entropy-secret`,
`unclassified`) overlapping a protected span are dropped and recorded as
`ExemptionDecision(rule="entropy-candidate", classification="location-token",
decision="exempt-location")`. **Format-rule** spans are never dropped (a path that literally
contains an AWS key pattern is still redacted; the structured `location` field remains readable).
`build_reproduction` passes `(location.file, location.symbol)` as `known_safe` for every field it
redacts. `excerpts.py`, `build_context.py`, `agent_config.py` and the tooling runner are **not**
changed — they redact source or third-party text where no token is known-safe.

**Rationale**: the file path is already published unredacted in `location.file`; protecting the
same string in prose adds no exposure. Token-level protection avoids any change to detector
patterns (a "contains `/` ⇒ path" rule would exempt base64 secrets, which contain `/`).

**Alternatives considered**: (a) compose-after-redact (redact the template, then substitute
tokens) — rejected: fragile against tokens appearing in multiple fields and loses the audit
record. (b) skip redaction of reproduction text entirely — rejected: the backstop exists because
descriptions can carry model-authored text.

## R6 — Artifact surface

**Decision**: `context_packet.json` `redaction.exempted_items[].decision` enum gains
`"exempt-reference"`. `exempt-location` decisions arise only inside `build_reproduction`, whose
`RedactionResult.exempted` is not serialised, so no schema change is needed for it. No
`schema_version` bump: the change is additive in the same sense feature 003 added
`exempt-message`.

**Rationale**: constitution "Additive schemas" gate; precedent from 003.

## R7 — Corpora and benchmark

**Decision**:
- New `tests/fixtures/runtime_reference_corpus.py` (`REFERENCES: (origin, line, why)`), seeded
  with the three `skh` lines (values are already references — no anonymisation needed), one entry
  per family in R1, punctuation-joined compositions, `${X:-}`, `${X:-$Y}`, `${X:?msg}`,
  `${X:-changeme}`. Expectation: zero hits, zero blocked, one `exempt-reference` decision each.
- `credential_corpus.py` gains must-find entries: `${X:-hunter2hunter2}`, `${X:=…}`, `${X:+…}`,
  `"$PREFIX-hunter2hunter2"`, `"hunter2hunter2$SUFFIX"`, `"pa$$w0rd-really-long"`, `"${NAME"`,
  `"%NAME"` (as assigned values), and an AWS key literal inside `${…}` (format bypass).
- `audited_credential_baseline.json` gains a `follow_up_scans` block for SEC-0080/0082/0084 as
  `false-positive` entries (their labels collide with the 2026-08-31 baseline's, so they cannot
  join `entries`); the 23-entry integrity assertion is unchanged.
- `credential_precision.json` gains a runtime-reference expectation line.

**Rationale**: FR-012–FR-014 and Q4 (build-independent of `skh`; re-scan recorded in spec).
