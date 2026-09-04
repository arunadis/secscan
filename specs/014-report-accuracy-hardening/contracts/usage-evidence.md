# Contract: Usage Evidence (FR-001 – FR-003)

Title: Dependency usage evidence contract (feature 014)
Owner stage: `src/pipeline/usage_evidence.py`, invoked in `correlate_findings.finalize()` before calibration.

## Surface

- **Input**: normalized + deduped findings; persisted code graph (file nodes with optional `imports`); shipped `usage_patterns.json` (versioned).
- **Output**: every advisory finding and every currency finding carries a `usage` block per data-model.md §2.
- **Artifacts touched**: `graph/code_graph.json` (additive `imports` on file nodes), `findings/*` (additive `usage`), report JSON (renders usage state + locations).

## Deterministic guarantees

1. Same input + same `usage_patterns.json` version ⇒ byte-identical `usage` blocks.
2. `imports` on file nodes: sorted, deduplicated, absent (not `[]`) when the file had no parser.
3. `none-found` only when ALL applicable detection forms completed:
   - the member root is readable (absent/unreadable ⇒ file-text forms unrun),
   - static imports scanned for the member's parsed source files,
   - every shipped config rule for the member's config file classes evaluated,
   - every shipped dynamic form for the member's languages evaluated.
   Any incomplete form ⇒ `undetermined` with `reason` naming the gap.
4. Unmapped module name (no module↔package rule) ⇒ `undetermined`, never `none-found`.
5. `locations` sorted by `(repo, file, line_start, kind, role)`; `role` is `development` when all matched locations are in test/build files per shipped markers, else `runtime`.

## Policy invariants (Honest Uncertainty)

- `usage` state NEVER suppresses a finding and never changes `severity_score`/`severity_band`.
- `state == "none-found"` ⇒ confidence ≤ existing unproven-reachability ceiling (0.5) applied at calibration; impact narrative uses conditional framing ("if the package is exercised …").
- `state == "undetermined"` ⇒ no confidence or narrative change beyond existing plausible-with-gap handling.

## Failure modes

| Condition | Behavior |
|---|---|
| Member lacks parsed source files at all | `undetermined`, reason: no parse coverage |
| `usage_patterns.json` missing/invalid | Hard scan failure (malformed shipped data is a build defect, validated by contract tests) |
| Config rule matches no files | Not an error; that form simply contributes nothing |

## Versioning

Field additions only; consumers must tolerate absent `usage` (pre-014 reports).
`usage_patterns.json` carries a `version` string like other shipped data.
