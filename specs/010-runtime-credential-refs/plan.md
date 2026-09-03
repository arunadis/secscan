# Implementation Plan: Runtime Credential References Are Not Hard-Coded Credentials

**Branch**: `010-runtime-credential-refs` | **Date**: 2026-09-02 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/010-runtime-credential-refs/spec.md`

## Summary

The deterministic credential detector publishes a verified, 0.95-confidence CWE-798 finding for
`export AWS_SECRET_ACCESS_KEY="$AWS_DEVIN_PROD_SECRET_ACCESS_KEY"` because the `assigned-secret`
rule accepts any 6+ character quoted value and the placeholder allow-list recognises only the
braced `${NAME}` shell form. The same braced allow-list is simultaneously *too broad*: it exempts
`"${DB_PASSWORD:-hunter2hunter2}"` wholesale, hiding a literal default (an existing recall hole).
The fix is a single deterministic **runtime-reference classifier** in the redactor that replaces
the blanket `${…}` placeholder: a quoted value is a reference when every letter and digit lies
inside a well-formed indirection expression (bare/braced shell, batch `%X%`, template `{{ }}`,
CI `${{ }}`, command substitution `$( )`), with shell expansion operands of `:-`/`:=`/`:+`
evaluated recursively as assigned values and `:?` operands discarded as diagnostics. A classified
reference is exempted at the redaction layer — left visible, recorded as an `exempt-reference`
decision — on both the `assigned-secret` path and the entropy path (FR-000–FR-008). Separately,
the reproduction builder gains the ability to declare scanner-composed location tokens
(file path, symbol) as known-safe so the heuristic pass cannot redact `verify-account.sh` out of
its own "Inspect …" instruction while format-rule redaction still applies (FR-009–FR-011). Both
are gated by corpus extensions and the credential-precision benchmark class (FR-012–FR-014).

## Technical Context

**Language/Version**: Python 3.11+ (constitution technology constraint)

**Primary Dependencies**: stdlib `re` only; no new runtime dependencies (the classifier is pure pattern matching, like the identifier-shape gate it sits beside)

**Storage**: N/A — artifacts are canonical JSON under `.secscan/`; exemption decisions land in the existing `context_packet.redaction.exempted_items` array

**Testing**: pytest (unit / contract / integration / benchmark), ruff; existing corpora `tests/fixtures/credential_corpus.py` (recall floor) and `tests/fixtures/identifier_corpus.py` (false positives)

**Target Platform**: CLI tool (`secscan`) run locally or in CI on macOS/Linux

**Project Type**: CLI security scanner (offline, deterministic pipeline + bounded LLM analysis)

**Performance Goals**: no regression in scan wall-time; the classifier is O(len(value)) and runs only on values that already matched `assigned-secret` or an entropy candidate

**Constraints**: fully offline; byte-identical artifacts for identical input; recall may never regress (Principle III); exemptions must be recorded, never silent (Principles IV/V); schema changes additive only

**Scale/Scope**: two source modules (`redact.py`, `reproduce.py`), one schema enum extension, two corpora, one benchmark class; reference baseline is the `skh` scan that produced SEC-0080/0082/0084 (3 findings to remove, 0 to lose)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Evaluation | Result |
|-----------|-----------|--------|
| I. Determinism Before Intelligence | The reference classifier is a pure function of the quoted value (regex + structural scan); no model participates; results are byte-reproducible. Location-token protection is a pure function of (text, tokens). | PASS |
| II. Context Is a Managed Resource | No budget or partitioning changes. Leaving `$VAR` visible slightly *reduces* marker noise in packets. | PASS |
| III. Secrets Never Reach a Model | The exemption fires only when **every letter and digit** is inside a well-formed reference, so no literal credential material can be exempted (FR-002/FR-003). Format-rule matches bypass the exemption entirely (FR-008). Replacing the blanket `${…}` placeholder with the structured classifier *closes* a recall hole (`${X:-literal}`), so recall strictly improves. Protected location tokens are exempt only from heuristic redaction, never from format rules. | PASS |
| IV. Evidence Over Assertion | Every exemption is an `ExemptionDecision` with origin/line/rule/classification/reason (FR-005), surfaced through the existing `exempted_items` artifact field. Reproduction text will now name the same file the structured location names (FR-011). | PASS |
| V. Honest Uncertainty | A value that is *not* provably a reference is treated exactly as today (redacted, reported). Malformed references are literals (FR-003). Nothing undetermined is silenced. | PASS |
| VI. Observe, Never Attack | No verification or probing changes; reproduction text becomes more accurate, not more active. | PASS |

No violations. Complexity Tracking is empty.

**Post-design re-check (2026-09-02)**: Phase 0/1 artifacts confirm the gate results. The
classifier grammar (R1) is closed and deterministic; the "all alphanumerics inside a reference"
invariant (R2) is what makes Principle III hold structurally rather than by enumeration — no
literal character can survive classification, so recall cannot regress via the new exemption,
and the removal of the over-broad `${…}` placeholder (R3) is a measured recall *gain* asserted by
new `must-find` corpus entries. The entropy-path exemption (R4) reuses the same classifier on the
enclosing reference, so there is one decision procedure, not two. Location-token protection (R5)
is token-level and heuristic-only, never a pattern change to the redactor's rules. Schema change is
a single additive enum value (R6) — no `schema_version` bump.

## Project Structure

### Documentation (this feature)

```text
specs/010-runtime-credential-refs/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/
│   └── detection-contracts.md
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created here)
```

### Source Code (repository root)

```text
src/pipeline/
├── redact.py                        # MOD  runtime-reference classifier; replace `${…}` placeholder;
│                                    #      exempt-reference on assigned-secret + entropy paths;
│                                    #      `known_safe` tokens on redact() (FR-000..FR-009)
├── reproduce.py                     # MOD  pass location tokens (file, symbol) as known-safe (FR-009..FR-011)
└── build_context.py                 # —    unchanged: already serialises `exempted_items`

src/skill_core/schemas/
└── context_packet.json              # MOD  additive: `decision` enum gains "exempt-reference" (R6)

tests/
├── fixtures/
│   ├── runtime_reference_corpus.py  # NEW  must-NOT-find: SEC-0080/0082/0084 lines + one per syntax family
│   │                                #      + punctuation-joined + `:?` operand (FR-012)
│   └── credential_corpus.py         # MOD  must-find: reference-look-alike literals, `${X:-literal}`,
│                                    #      `${X:=literal}`, `${X:+literal}`, concatenations, malformed refs (FR-013)
├── unit/
│   ├── test_redact.py               # MOD  classifier unit cases; placeholder test updated for narrowed `${…}`
│   ├── test_false_positive_corpus.py# MOD  iterate the new corpus; decision == "exempt-reference"
│   └── test_reproduce_honesty.py    # MOD  path survives in trigger text; seeded value still redacted
├── contract/                        # MOD  context_packet enum accepts exempt-reference; redaction sweep unchanged
├── benchmark/
│   ├── cases/credential_precision.json          # MOD  add runtime-reference expectation
│   ├── cases/audited_credential_baseline.json   # MOD  append SEC-0080/0082/0084 as false-positive entries
│   └── test_accuracy_benchmark.py               # MOD  credential-precision class iterates new corpus
└── integration/                     # MOD  end-to-end scan over a fixture shell script asserting SC-001/SC-005
```

**Structure Decision**: single Python project; all changes confined to two existing deterministic
pipeline modules, one schema file, and the test tree. No new top-level packages. Documentation
currency (constitution quality gate): `README.md` / `docs/` credential-detection section gains a
sentence on runtime references, and this spec records the `skh` re-scan outcome (SC-003).

## Complexity Tracking

> No constitution violations; nothing to justify.
