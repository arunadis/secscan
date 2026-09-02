# Research: HTML Report with Code Snippets

All Technical Context entries were resolvable from the codebase; no NEEDS CLARIFICATION remained. The decisions below are the ones the spec left open.

## R1: Where do code excerpts come from?

**Decision**: At report-build time, resolve the finding's `location.repo` → member directory from `workspace.json`, read the cited file once, slice the window `[line_start − ctx, line_end + ctx]`, and run the existing `Redactor.redact()` over that window. If the redactor reports any `blocked` value in the window, withhold the excerpt and record `unavailable_reason = "contains a value that could not be confirmed as a non-credential"`. If the file is missing/unreadable, record an explicit unavailable reason.

**Rationale**: The redactor is the sole authority on what may be shown (Constitution III); running it over the excerpt guarantees the report shows exactly the redacted view the pipeline analyzed. Withholding on `blocked` matches the "blocked, not passed through" rule. Building excerpts inside `build_report` keeps JSON as the single source of truth (FR-012) and keeps both renderers dumb.

**Alternatives considered**:
- *Persist fully-redacted copies of every source file during the scan* — rejected: duplicates the workspace, grows artifact storage unboundedly, and the report only ever needs a ±3-line window per finding.
- *Reuse segment/context-packet source text already sent to the model* — rejected: packets are budget-shaped subsets, not guaranteed to contain a given finding's lines; re-reading the file at report time is simpler and always correct.
- *Embed excerpts without re-running the redactor* — rejected outright: violates Constitution III.

## R2: HTML rendering approach

**Decision**: New pure module `pipeline/render_html.py` exposing `render_html(report: dict) -> str`, mirroring `render_markdown`'s role. Stdlib-only: string building + `html.escape` on every dynamic value, a constant inline `<style>` block, and **no JavaScript** — navigation is pure anchor links (`#finding-<id>`), which fully satisfies the spec's "easy navigation with ref links" (assumption: no filtering/search UI in v1).

**Rationale**: Self-containment (FR-002) and byte-identity (FR-011/SC-007) are trivially satisfiable when output is a pure function of the report dict with a fixed CSS constant. No JS removes an entire class of escaping/XSS risk in a document whose content is attacker-influenced source code.

**Alternatives considered**:
- *Jinja2 templates* — rejected: new runtime dependency for zero capability gain over string building at this scale; also adds an escaping-discipline risk stdlib `html.escape` handles uniformly.
- *Client-side JS for collapsible sections/filtering* — rejected for v1: not requested, breaks the no-external-behavior simplicity, and static anchors already meet SC-006 (≤2 clicks).

## R3: Anchor scheme and link integrity

**Decision**: Anchors are `finding-<finding_id>` (IDs are already stable, `<repo>:<path>#<symbol>`-style, sanitized to `[a-zA-Z0-9-_]` by replacing other chars deterministically). The index is grouped by severity band in `BANDS` order, findings in the existing verification-aware rank order — identical ordering to the Markdown body. `render_html` collects the set of emitted ids while rendering and asserts every generated `href="#..."` resolves before returning; an unresolved reference raises, mirroring the consistency gate's "never publish a reference that does not resolve" (Constitution IV, FR-006).

**Rationale**: reusing the finding id keeps cross-format identity (FR for US3) free; a render-time integrity check turns SC-002 into a build-time guarantee rather than a test-only hope.

**Alternatives considered**: sequential numeric anchors (`#f-1`) — rejected: unstable under any ranking change and meaningless when correlating across formats.

## R4: Markdown rendering of excerpts

**Decision**: In `_render_finding`, after the Location bullet, emit a label line `**Code** — \`repo:file:Lstart-Lend\`` followed by a fenced block with the file's language as the info string (from the code model / extension mapping already used by `stacks`), line numbers omitted (Markdown convention; the label carries the range). Markdown excerpt lines are verbatim redacted source — **no** inline markers appended — so the excerpt text matches the redacted source exactly (SC-003); highlighting/line-numbering is HTML-only per FR-009.

**Rationale**: FR-007 requires the excerpt in both human formats; keeping Markdown lines byte-equal to the redacted source keeps SC-003 ("content matches the redacted source at the cited location") assertable in both formats and preserves copy-paste fidelity.

**Alternatives considered**: line-numbered Markdown (` 12 | code`) and trailing `# <-- cited` comment markers — both rejected: they mutate excerpt text so it no longer matches the redacted source, break copy-paste, and render poorly in narrow terminals.

## R5: Window size and truncation bounds

**Decision**: defaults on `ScanProfile`: `excerpt_context_lines = 3`, `excerpt_max_lines = 40` (window hard cap; cited range always fully included, context reduced first), `excerpt_max_line_length = 200` (per-line truncation with an explicit `… [truncated]` marker). Fixed defaults, overridable via profile like other knobs.

**Rationale**: ±3 lines shows the enclosing statement/call in the languages this scanner targets; the caps implement FR-013 for minified/generated files. Keeping values on the profile follows the project's existing configuration pattern.

## R6: Artifact layout and view command

**Decision**: `write()` emits a third file `reports/{scan_id}.html` via `store.write_text` after the consistency gate passes (gate still guards all three). `report_view.render(..., output_format="html")` gains HTML so per-repo projections can also be rendered as HTML; `latest_report` already reads the JSON payload, so projections inherit excerpts with no extra work.

**Rationale**: identical naming/location convention to the existing two artifacts; gate-before-write ordering preserved (FR-042 philosophy).

## R7: Schema change

**Decision**: additive optional `code_excerpt` property on `finding.schema.json` (see data-model.md and contracts/). `finding.json` uses `additionalProperties: false`, so the property must be declared — but adding an optional property is additive per the constitution's schema rule; no `schema_version` bump.

**Rationale**: optional field means historical reports re-render fine (`strict=False` path unchanged) and consumers ignoring unknown fields are unaffected.
