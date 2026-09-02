# Implementation Plan: HTML Report with Code Snippets

**Branch**: `005-html-report-code-snippets` | **Date**: 2026-09-01 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/005-html-report-code-snippets/spec.md`

## Summary

Add a third rendering of the unified security report — a self-contained, offline-openable HTML document with a severity-grouped navigation index and stable per-finding anchors — and enrich every admitted finding with a redacted code excerpt of the cited lines. Excerpts are produced once at report-build time from the redacted source view and stored as additive structured data on the finding (JSON), then rendered as fenced blocks (Markdown) and highlighted, line-numbered blocks (HTML). No new runtime dependencies; rendering is stdlib-only with inline CSS and no JavaScript.

## Technical Context

**Language/Version**: Python 3.11+ (constitution constraint)

**Primary Dependencies**: none added — stdlib only (`html.escape`, string building). Existing: click, jsonschema, tree-sitter grammars, pyyaml

**Storage**: filesystem artifact store (`<scan_root>/.security-scan/reports/{scan_id}.{json,md,html}`)

**Testing**: pytest (+ `ruff check src tests` gate); existing contract tests for every schema

**Target Platform**: CLI tool, any OS; HTML consumed in any standard browser with network disabled

**Project Type**: cli

**Performance Goals**: report stage adds excerpt extraction for N findings; bounded by per-file single read + slice — negligible next to LLM analysis stages; HTML file must open comfortably in a browser at 500+ findings (SC-004)

**Constraints**: offline-only (no network, no external assets); byte-identical artifacts for identical input (no timestamps, fixed section order, canonical sorting); excerpt content MUST pass the existing redaction sweep over artifacts; schema changes additive only (constitution)

**Scale/Scope**: workspaces of multiple repos; hundreds of findings per report; excerpt window bounded (default ±3 context lines, hard cap with explicit truncation note)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Evaluation | Result |
|---|---|---|
| I. Determinism Before Intelligence | Excerpts are built deterministically (fixed window, sorted output, stable anchors `finding-<id>`); HTML/MD/JSON contain no wall-clock values; two-run byte-identity asserted in tests | PASS |
| II. Context Is a Managed Resource | Excerpt window bounded (±3 lines, hard cap, explicit truncation note); oversized single-line files truncated with note — never embedded whole | PASS |
| III. Secrets Never Reach a Model | Excerpt text is produced by running the existing `Redactor.redact()` over the excerpt window; a window the redactor blocks is withheld with a stated reason (FR-008/FR-010); the existing artifact redaction sweep gains the `.html` artifact | PASS |
| IV. Evidence Over Assertion | Excerpts derive only from code-model-verified locations (symbol/file tier); unresolvable → no excerpt + reason, never fabricated. Link integrity enforced: render-time check that every internal `href` resolves to an emitted anchor (FR-006) | PASS |
| V. Honest Uncertainty | Missing/unreadable/blocked excerpts render as an explicit "excerpt unavailable: <reason>" statement; file-tier locations keep their existing caveat; absence of excerpt never suppresses the finding | PASS |
| VI. Observe, Never Attack | Report stage reads source files only; no mutation of scanned projects; scanner's own payload excluded as today | PASS |

No violations; Complexity Tracking table not required.

**Post-design re-check (after Phase 1)**: the design below introduces no new principle exposure — excerpt generation reuses the existing Redactor and ArtifactStore, rendering is pure string building over the already-gated report dict, and the consistency gate still runs before any of the three files is written. All six principles remain PASS.

## Project Structure

### Documentation (this feature)

```text
specs/005-html-report-code-snippets/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
│   └── report-artifacts.md
└── tasks.md             # Phase 2 output (/speckit-tasks - NOT created here)
```

### Source Code (repository root)

```text
src/
├── pipeline/
│   ├── generate_report.py   # + excerpt attachment in build_report; + fenced blocks in
│   │                        #   _render_finding; write() emits the .html artifact
│   ├── excerpts.py          # NEW: redacted code-excerpt extraction (window, cap, reasons)
│   ├── render_html.py       # NEW: report dict -> self-contained HTML (index, anchors,
│   │                        #   highlighted excerpts, link-integrity check)
│   └── report_view.py       # + output_format="html" projection support
├── skill_core/schemas/
│   └── finding.json         # + optional additive "code_excerpt" property
└── config/profiles.py       # + excerpt window/cap knobs on ScanProfile (defaults only)

tests/
├── unit/
│   ├── test_excerpts.py         # NEW: window math, redaction, blocked/truncated cases
│   └── test_render_html.py      # NEW: anchors, index, escaping, link integrity
├── contract/
│   └── test_report_schema.py    # + code_excerpt round-trip (additive)
└── integration/
    └── test_report_artifacts.py # NEW: three artifacts from one scan; byte-identity;
                                 #   cross-format finding-id equality; redaction sweep incl. HTML
```

**Structure Decision**: single-project layout (existing convention). The feature extends the report stage in place: excerpt extraction is a new module consumed by `build_report` so JSON stays the single source of truth (FR-012); HTML rendering is a new pure module mirroring `render_markdown`'s role. No new top-level packages.

## Complexity Tracking

> No constitution violations — table intentionally empty.
