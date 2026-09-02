# Implementation Plan: Reduce Hard-Coded-Credential False Positives

**Branch**: `003-reduce-secret-false-positives` | **Date**: 2026-08-31 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/003-reduce-secret-false-positives/spec.md`

## Summary

The deterministic credential detector converts redaction hits into CWE-798 findings, and three
defects make it over-report: (1) the credential-context check matches the whole line, so a
credential word *inside the matched identifier itself* (`openaiModelInputTokenCost...`) counts as
context; (2) `secret_findings.py` emits every non-blocked hit at a hardcoded 0.95 confidence with
no provenance distinction; (3) `verify.py` auto-marks every CWE-798 as `verified` ("presence in
source is itself the finding"), so heuristic guesses publish as confirmed exposures. The fix is
three-layered, all deterministic: evaluate credential context against the line with the candidate
span masked out and extend the identifier/message-string discrimination in the redactor
(FR-001–FR-004); carry detection provenance (`format` vs `heuristic`) and code context
(`production` vs `test`) as additive finding fields, driving per-label confidence and a narrowed
auto-verify rule (FR-007–FR-010); and gate it all with an extended false-positive corpus plus a
ground-truth audit of the baseline scan's 23 CWE-798 findings (FR-011, FR-012). Recall is
constitutionally non-negotiable: every change is proven against a seeded credential corpus
(FR-005, FR-006).

## Technical Context

**Language/Version**: Python 3.11+ (constitution technology constraint)

**Primary Dependencies**: pinned tree-sitter grammar wheels (existing); no new runtime dependencies

**Storage**: N/A — artifacts are JSON files under `.security-scan/`; rule data ships as versioned in-repo data

**Testing**: pytest (unit / contract / integration / benchmark), ruff for lint; existing fixture corpora in `tests/fixtures/`

**Target Platform**: CLI tool (`secscan`) run locally or in CI on macOS/Linux

**Project Type**: CLI security scanner (offline, deterministic pipeline + bounded LLM analysis)

**Performance Goals**: no regression in scan wall-time; redactor remains single-pass regex over source

**Constraints**: fully offline default path; byte-identical artifacts for identical input; no credential value in any artifact; recall may never regress (constitution Principles I, III)

**Scale/Scope**: workspaces of ~10⁵ LOC across JVM/Node/Python/Go; reference scan `20260831T081536Z-438706` (23 CWE-798 findings) is the evaluation baseline

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Evaluation | Result |
|-----------|-----------|--------|
| I. Determinism Before Intelligence | All precision discrimination (identifier shape, message strings, credential context, test-code classification) is deterministic and rule/data-driven; no model output influences what becomes a finding | PASS |
| II. Context Is a Managed Resource | No context-packet or budget changes; reduced spurious redaction slightly *shrinks* redaction noise in packets | PASS |
| III. Secrets Never Reach a Model | Recall precedence is the binding constraint (FR-005/006/007): format matches and credential-keyed assignments bypass all precision gates; suppressed-finding values remain redacted whenever any doubt remains; the artifact redaction sweep is unchanged | PASS |
| IV. Evidence Over Assertion | Every suppression is recorded with file/line/rule/reason (FR-004) via the existing `exempted` mechanism; findings gain explicit detection provenance instead of a bare 0.95 | PASS |
| V. Honest Uncertainty | The core of this feature: heuristic-only findings can no longer publish as verified or outrank format-confirmed ones (FR-008/FR-009); test-code findings are calibrated, not silenced (FR-010) | PASS |
| VI. Observe, Never Attack | No verification or reproduction behavior changes | PASS |

No violations. Complexity Tracking is empty.

**Post-design re-check (2026-08-31)**: Phase 0/1 artifacts confirm the gate results. The
mask-then-match context rule (R1), redactor-level suppression with recorded decisions (R2), and
additive `detection`/`code_context` fields (R4) are all deterministic, offline, and
byte-reproducible (Principle I). Recall precedence is preserved structurally: exemption requires
the conjunction of shape, masked-context, non-assignment, and non-format conditions, so a real
credential cannot satisfy it (Principle III; contracts C2/C3). Heuristic findings losing
auto-verify is the Principle V fix; every exemption is a recorded, locatable decision, so
precision gains are auditable rather than silent (Principles IV/V; contract C2). Schema change
is additive only — no version bump.

## Project Structure

### Documentation (this feature)

```text
specs/003-reduce-secret-false-positives/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created here)
```

### Source Code (repository root)

```text
src/pipeline/
├── redact.py                  # MOD  credential-context masking; message-string discrimination (FR-001..FR-003)
├── secret_findings.py         # MOD  per-label confidence; detection-provenance + code-context fields (FR-007..FR-010)
├── verify.py                  # MOD  auto-verify narrowed to format-matched detections (FR-008)
├── stacks.py / stack data     # MOD  test-path conventions per stack, as versioned data (FR-010)
└── correlate_findings.py      # MOD  propagate new fields through normalization/correlation (additive)

tests/
├── fixtures/
│   ├── identifier_corpus.py   # MOD  extend with credential-word identifiers + message strings (FR-011)
│   └── credential_corpus.py   # NEW  seeded credentials incl. readable passphrases + test-code cases (FR-005/006)
├── benchmark/cases/           # MOD  credential-precision defect class + audited baseline labels (FR-012, SC-003)
├── unit/test_redact.py        # MOD  suppression + recall-regression cases
├── unit/test_secret_findings.py # MOD  provenance/confidence/test-code behavior
├── contract/                  # MOD  additive finding-field contract tests; artifact redaction sweep unchanged
└── integration/               # MOD  end-to-end scan over reference fixtures asserting SC-001/SC-002
```

**Structure Decision**: single Python project; all changes confined to the existing deterministic
pipeline stages and the test tree. No new top-level packages. The ground-truth audit of the
baseline scan lands as labelled data under `tests/benchmark/cases/`.

## Complexity Tracking

> No constitution violations; nothing to justify.
