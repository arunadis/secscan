# Phase 0 Research: Reduce Hard-Coded-Credential False Positives

All technical-context items were resolvable from the codebase and prior feature research; no
NEEDS CLARIFICATION remained. Decisions below are verified against the shipped implementation
(`src/pipeline/redact.py`, `secret_findings.py`, `verify.py`) and the feature 002 research
(`specs/002-scan-accuracy-hardening/research.md`, A4).

## R1 — How to stop identifier-internal substrings from creating credential context

**Decision**: Evaluate the credential-context rule against the line with the candidate span
*masked out* (replaced by a fixed placeholder) before matching.

**Rationale**: Today `_SECRET_CONTEXT.search(line)` sees the whole line, so the substring `Token`
inside the matched identifier `openaiModelInputTokenCostGpt51ChatLatest` satisfies the context
check and short-circuits the identifier-shape gate (redact.py:311). Masking the candidate span
first means context can only come from *other* tokens on the line — the structural role of the
match (FR-003). A genuine assignment (`apiKey = "wJalrXUtnFEMI..."`) still matches, because
`apiKey` survives masking. This is a one-line change in evaluation order, fully deterministic,
and it composes with the existing FR-036 identifier-shape gate, which then sees the field
declaration line and exempts the identifier.

**Alternatives considered**: (a) Word-boundary context matching — rejected: `Token` inside
`InputTokenCost` *has* no boundary violation from regex's perspective at the identifier level
(camelCase humps are not boundaries), so this cannot work without tokenizing identifiers, which
is what the shape gate already does; (b) raising the entropy threshold — rejected in feature 002
(research A4): the four benchmark false positives sit at 4.025–4.208, and clearing them starts
discarding genuine base64 secrets; (c) exempting camelCase unconditionally — rejected: a readable
passphrase assigned to a password variable must still be caught (FR-006), so exemption may only
happen when the *line* is structurally a declaration, which is exactly the existing gate.

## R2 — Where suppression lives: the redactor, not the findings stage

**Decision**: Identifier and message-string discrimination happens in the redactor's entropy
path, extending the existing shape-and-context gate; suppressed matches are recorded through the
existing `exempted` mechanism (FR-038 precedent), which already carries (origin, line, value,
shape) and is inspectable in artifacts.

**Rationale**: `secret_findings.py` converts redaction hits to findings; if a non-credential
never becomes a hit, no finding can be emitted and no model ever sees a spurious REDACTED marker.
Suppressing downstream instead would leave the value redacted in context packets — degrading
analysis quality for no safety benefit — and would split the decision across two stages.
The redactor is also where the recall guarantees are enforced by existing tests, so the
precision/recall pair stays asserted in one place.

**Alternatives considered**: post-hoc filtering in `secret_findings.py` or `correlate_findings.py`
— rejected: finding-stage filtering cannot undo the redaction marker the model already tripped
over (the `[BLOCKED:...]`-as-filename artifact in the reference report shows the downstream cost),
and it separates the suppression decision from its audit record.

## R3 — Message-string discrimination

**Decision**: A quoted literal that reads as natural language — contains spaces, multiple
dictionary-plausible words, or sentence punctuation — and is not assigned to a credential-named
key is classified as a message string and exempted, with the decision recorded.

**Rationale**: UI constants like `INVALID_PASSWORD = "Invalid password"` carry entropy-ish shape
only in their *name*; the name is an identifier (R1 handles it). Where a string *value* itself is
long and unbroken (e.g. a prose fragment), the natural-language shape test parallels the
identifier-shape test. Credential context still wins: `password = "correct horse battery
staple"` has spaces but is assigned to a credential-named key, so FR-006 reports it — the
assignment check runs first, unchanged.

**Alternatives considered**: a dictionary/wordlist check — rejected: nondeterministic data
dependency, and the shape heuristics above cover the evidenced cases without one.

## R4 — Detection provenance and honest confidence

**Decision**: Findings emitted from redaction hits carry two new additive fields:
`detection` (`format` for rule-pack labels, `heuristic` for `high-entropy-secret`) and
`code_context` (`production` | `test`). `secret_findings.py` assigns confidence per label class
(format ≈ current 0.95; heuristic markedly lower, ~0.6; test-code findings reduced further).
`verify.py`'s auto-verify shortcut for CWE-798/259/256/522/532 applies only to
`detection == "format"`; heuristic findings fall through to the standard trace-based verdict
path, which yields `plausible` when no flow exists.

**Rationale**: verify.py:130-136 auto-verifies CWE-798 because "presence in source is itself the
finding" — true only when the *presence* is confirmed, i.e. format-matched. For heuristic
matches, presence is precisely what is in doubt, so the shortcut is exactly the bug behind
SEC-0085's `[verified]` badge. Additive fields keep schema compatibility (constitution: additive
schemas by default); `correlate_findings.py` and the report need only to propagate and render
them.

**Alternatives considered**: encoding provenance implicitly in the evidence `reason` string —
rejected: Principle IV requires structured evidence, and downstream ranking (report ordering,
thresholds) must key on a field, not a substring.

## R5 — Test-code classification

**Decision**: Deterministic path-based classification shipped as versioned data per stack:
`src/test/`, `tests/`, `test/`, `*_test.go`, `*.test.*`, `*.spec.*`, `conftest.py`, etc.,
resolved against the code model's file records.

**Rationale**: Every supported stack has stable test-path conventions; stack descriptors already
ship as data (constitution: extensibility as data), so test-path patterns join them. A
production file can never be reclassified by content, which keeps the rule deterministic and
auditable. FR-010 then reduces severity/confidence and states the context — recall untouched.

**Alternatives considered**: content-based heuristics (imports of test frameworks) — rejected:
requires parsed imports for every file class and is nondeterministic across partial parses;
path conventions are simpler and cover the evidenced cases.

## R6 — Precision benchmark and ground-truth baseline

**Decision**: Extend `tests/fixtures/identifier_corpus.py` with credential-word identifiers and
message strings (the SEC-0085/0091/0092/0093 patterns), add a seeded `credential_corpus.py`
(readable passphrases, credential-keyed assignments, format-matched keys — including in test
paths), and add a `credential-precision` defect class to the accuracy benchmark. The one-time
manual audit of the baseline scan's 23 CWE-798 findings lands as labelled entries under
`tests/benchmark/cases/`, giving SC-003 its measured baseline.

**Rationale**: the constitution requires fixtures to declare ground truth — including deliberate
false positives that must not be reported — and accuracy regressions are release-blocking per
defect class. The audited baseline turns "80% reduction" from a hope into an asserted pair of
numbers.

**Alternatives considered**: reusing the existing identifier corpus unmodified — rejected: it
covers *coverage-gap* false positives (002), not *finding* false positives; the SEC-0085 class
(identifier embedding a credential word on a declaration line) is not in it.
