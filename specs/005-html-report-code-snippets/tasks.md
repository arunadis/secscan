---

description: "Task list for feature implementation"
---

# Tasks: HTML Report with Code Snippets

**Input**: Design documents from `/specs/005-html-report-code-snippets/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/report-artifacts.md, quickstart.md

**Tests**: INCLUDED — the project constitution mandates test-first ("Tests are written before implementation and MUST fail first") and contract tests for every schema.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- Single project: `src/`, `tests/` at repository root; package root is `src/` (pytest `pythonpath = ["src"]`)
- New modules: `src/pipeline/excerpts.py`, `src/pipeline/render_html.py`
- New tests: `tests/unit/test_excerpts.py`, `tests/unit/test_render_html.py`, `tests/integration/test_report_artifacts.py`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: No project initialization needed (existing codebase, no new dependencies per plan.md). This phase only adds the configuration knobs both stories build on.

- [X] T001 Add excerpt configuration knobs (`excerpt_context_lines=3`, `excerpt_max_lines=40`, `excerpt_max_line_length=200`) with defaults to `ScanProfile` in `src/config/profiles.py`, overridable via profile YAML like existing knobs

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Schema contract and redaction-sweep coverage that BOTH user stories depend on

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T002 Write FAILING contract test for the additive `code_excerpt` property (round-trip: finding with `status="ok"` + lines validates; `status="unavailable"` + `reason` and no `lines` validates; excerpt missing entirely still validates) in `tests/contract/test_report_schema.py`
- [X] T003 Add the optional `code_excerpt` property to `src/skill_core/schemas/finding.json` exactly as specified in `specs/005-html-report-code-snippets/contracts/report-artifacts.md` so T002 passes
- [X] T004 Extend the artifact redaction sweep (Safety Invariants enforcement test) to cover `reports/*.md` and `reports/*.html` in addition to existing artifacts, in the test that sweeps artifacts using the redactor's own rules (locate under `tests/`, e.g. `tests/integration/`)

**Checkpoint**: Schema accepts excerpts; redaction sweep will cover the new artifacts — story implementation can now begin

---

## Phase 3: User Story 1 - Navigate findings in a browser-friendly HTML report (Priority: P1) 🎯 MVP

**Goal**: Every scan emits `reports/{scan_id}.html` — self-contained, offline-renderable, with a band-grouped navigation index, stable `finding-<id>` anchors, back-to-index links, and clickable cross-references

**Independent Test**: Run a scan against a fixture repo with known findings; open the produced HTML with network disabled; verify index lists all findings, every index entry jumps to its finding detail, back-links return, and no external asset is requested

### Tests for User Story 1 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T005 [P] [US1] Unit tests for anchor generation and sanitization (`finding-<id>`, charset `[A-Za-z0-9-_]`, uniqueness across a finding set) in `tests/unit/test_render_html.py`
- [X] T006 [P] [US1] Unit test that rendered HTML contains an index grouped in `BANDS` order with one entry per admitted finding, each entry `href="#finding-…"` resolving to an emitted `id`, each finding section carrying a back-to-index link, and any finding reachable from the index in ≤2 clicks (SC-006), in `tests/unit/test_render_html.py`
- [X] T007 [P] [US1] Unit test for self-containment: rendered HTML has no `<script src>`, no `<link>`, no `@import`, no `http://`/`https://` asset references, and no JavaScript; all dynamic content (including attacker-influenced code text) is `html.escape`d, in `tests/unit/test_render_html.py`
- [X] T008 [US1] Integration test that `generate_report.write()` emits `reports/{scan_id}.html` alongside `.json`/`.md`, and that two identical runs produce byte-identical HTML (SC-007), in `tests/integration/test_report_artifacts.py`
- [X] T009 [P] [US1] Scale test: synthesize a report dict with ≥500 findings, assert `render_html` succeeds, every internal link resolves, and the output size stays reasonable for browser rendering (SC-004), in `tests/integration/test_report_artifacts.py`

### Implementation for User Story 1

- [X] T010 [US1] Create `render_html(report: dict, system_review: str = "") -> str` in new module `src/pipeline/render_html.py`: fixed section order (header → index → executive summary → findings by band → cross-system/attack paths/system review/recommendations/coverage/usage mirroring `render_markdown`), constant inline `<style>`, no JavaScript, `html.escape` on every dynamic value
- [X] T011 [US1] Implement navigation index + per-finding `<section id="finding-…">` with "↑ index" back-link and clickable evidence/coverage cross-references in `src/pipeline/render_html.py`; collect emitted ids during render and raise on any unresolved `href="#…"` (FR-006 link-integrity guarantee)
- [X] T012 [US1] Wire `write()` in `src/pipeline/generate_report.py` to emit `reports/{scan_id}.html` via `store.write_text` AFTER `consistency.enforce` passes; update the return value to include the html path and update BOTH call sites: `main()` in `src/pipeline/generate_report.py` (printout mentions the html path) and the `markdown_path, json_path = generate_report.write(...)` unpacking at `src/pipeline/run.py:373`
- [X] T013 [US1] Add `output_format="html"` support to `render()` in `src/pipeline/report_view.py` so repo-filtered projections render to HTML (index reflects the filtered finding set), and add `"html"` to the `--format` choices of the `report` subcommand in `src/pipeline/scan_cli.py`

**Checkpoint**: US1 fully functional — a scan produces a navigable, self-contained HTML report testable independently of excerpts; `security-scan report --format html` works

---

## Phase 4: User Story 2 - See the vulnerable code inline in each finding (Priority: P1)

**Goal**: Every admitted finding carries a `code_excerpt` (redacted cited lines ±context in JSON; fenced block in Markdown; highlighted, line-numbered block in HTML); unproducible excerpts carry `status="unavailable"` with a stated reason

**Independent Test**: Scan a fixture with a known vulnerability at a known `file:line`; verify the finding shows the cited lines ±3 context lines labeled `repo:file:Lstart-Lend` in both HTML and Markdown, content byte-equal to the redacted source at that location

### Tests for User Story 2 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T014 [P] [US2] Unit tests for excerpt window math (`window_start=max(1, cited−3)`, cap at 40 lines reducing context before cited range, per-line truncation at 200 chars with explicit marker) in `tests/unit/test_excerpts.py`
- [X] T015 [P] [US2] Unit tests for redaction behavior: excerpt text equals `Redactor.redact()` output for the window; a window containing a planted credential shows the placeholder; a window the redactor blocks yields `status="unavailable"` with the "could not be confirmed as a non-credential" reason and no `lines`, in `tests/unit/test_excerpts.py`
- [X] T016 [P] [US2] Unit tests for unavailable cases: missing/unreadable source file at report time produces `status="unavailable"` with a specific reason; the finding itself still renders (note: "no line range" is NOT a case — reported findings always carry verified line bounds at both tiers), in `tests/unit/test_excerpts.py`
- [X] T017 [US2] Integration test on a fixture with planted secrets: scan → all three artifacts contain zero credential values (extended sweep from T004), excerpt content matches the redacted source byte-for-byte at the cited location (SC-003, SC-005), and pre-existing Markdown/JSON content is unchanged apart from the additive excerpt data (FR-014), in `tests/integration/test_report_artifacts.py`

### Implementation for User Story 2

- [X] T018 [US2] Create `src/pipeline/excerpts.py`: `build_excerpt(finding, workspace, profile, redactor) -> dict` resolving `location.repo` → member directory from workspace data, reading the cited file once, slicing the window, running `Redactor.redact()` over it, and returning the `code_excerpt` dict per `specs/005-html-report-code-snippets/data-model.md` (never raises on file errors — returns `unavailable` with reason)
- [X] T019 [US2] Attach excerpts in `build_report()` in `src/pipeline/generate_report.py`: for every admitted finding, set `finding["code_excerpt"] = build_excerpt(...)` (status ok or unavailable — never omitted) before grouping, using the profile knobs from T001
- [X] T020 [US2] Render the excerpt in `_render_finding()` in `src/pipeline/generate_report.py`: label line `**Code** — \`repo:file:Lstart-Lend\`` + fenced block with language info string when `status="ok"` (lines verbatim from redacted source — no inline markers), else `*Code excerpt unavailable: <reason>*` (research.md R4; no fabricated content)
- [X] T021 [US2] Render the excerpt block in `src/pipeline/render_html.py`: `<pre>` rows with 1-based line numbers, `cited=true` rows highlighted via CSS class, truncation markers visible, `unavailable` rendering the reason text (contract §5)

**Checkpoint**: US1 AND US2 both work — findings in all three formats show redacted vulnerable code or an explicit reason

---

## Phase 5: User Story 3 - Correlate findings across formats via stable references (Priority: P2)

**Goal**: Identical finding identifiers across JSON/Markdown/HTML, and every internal reference in every format resolves to a real target

**Independent Test**: Generate all three formats from one scan; assert finding-id equality across files and zero unresolved internal references (render-time raise from T011 plus automated checks)

### Tests for User Story 3 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T022 [P] [US3] Integration test asserting the same finding carries the same `id` in `.json`, `.md`, and `.html` outputs of one scan (SC-001), in `tests/integration/test_report_artifacts.py`
- [X] T023 [P] [US3] Integration test asserting 100% of internal links resolve: HTML `href="#…"` targets exist (SC-002; also guaranteed by the T011 render-time raise), and Markdown section references (recommendations → band sections) point at sections present in the document, in `tests/integration/test_report_artifacts.py`

### Implementation for User Story 3

- [X] T024 [US3] Fix any reference/identity gaps the failing tests expose (e.g., anchor sanitizer divergence between index and section emission, recommendation pointers to absent sections) in `src/pipeline/render_html.py` and/or `src/pipeline/generate_report.py`

**Checkpoint**: All three stories independently functional; cross-format auditability holds

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Validation and documentation affecting the whole feature

- [X] T025 [P] Update `README.md` and `docs/` to state the scanner emits JSON + Markdown + HTML reports (honest documentation gate; remove/adjust any claim that only two formats exist)
- [X] T026 Run all quickstart.md scenarios end-to-end (three artifacts, offline navigation, inline code, cross-format identity, repo projection in HTML) and record results
- [X] T027 Run merge gates: `pytest` green (including new unit/contract/integration tests, the accuracy benchmark with no per-class regression, and all PRE-EXISTING report tests unchanged — FR-014), `ruff check src tests` clean, two-run byte-identity check across all artifacts

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on T001 (profile knobs referenced by excerpts) — BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Phase 2 completion
  - US1 and US2 are both P1; US2 touches `render_html.py` (T021) created by US1 (T010/T011), so run US1 before US2 if sequential, or serialize those two file-touches if parallel
  - US3 (P2) validates outputs of US1+US2 — run last among stories
- **Polish (Phase 6)**: Depends on all user stories complete

### User Story Dependencies

- **US1 (P1)**: After Phase 2 — no dependency on other stories
- **US2 (P1)**: After Phase 2 — excerpt data/rendering is independently testable; only its HTML excerpt block (T021) depends on US1's `render_html.py`
- **US3 (P2)**: After US1+US2 outputs exist to validate

### Within Each User Story

- Tests MUST be written and FAIL before implementation (constitution: test-first)
- Schema/excerpt model before renderers
- Story checkpoint before moving to next priority

### Parallel Opportunities

- T005, T006, T007, T009 (US1 tests) can be written in parallel; T008 after T005–T007 exist (same integration file as T009 — coordinate)
- T014, T015, T016 parallel (same file — parallelize by test function authorship or run sequentially); T017 parallel (different file)
- T022, T023 parallel
- T025 parallel with anything in Phase 6

---

## Parallel Example: User Story 2

```bash
# Write all US2 test tasks together (must FAIL first):
Task: "Unit tests for excerpt window math in tests/unit/test_excerpts.py"
Task: "Unit tests for redaction behavior in tests/unit/test_excerpts.py"
Task: "Integration test: planted-secret fixture sweep in tests/integration/test_report_artifacts.py"

# Then implement:
Task: "Create src/pipeline/excerpts.py"   # T018 — unblocks T019/T020/T021
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (T001)
2. Complete Phase 2: Foundational (T002–T004)
3. Complete Phase 3: User Story 1 (T005–T013)
4. **STOP and VALIDATE**: open the HTML offline, click through the index
5. Demo-able increment: navigable HTML report alongside existing formats

### Incremental Delivery

1. Setup + Foundational → schema ready, sweep extended
2. + US1 → navigable HTML report (MVP)
3. + US2 → redacted code excerpts in all three formats
4. + US3 → cross-format reference integrity proven by tests
5. Polish → docs, quickstart validation, merge gates

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Every excerpt line is redactor output — never bypass `Redactor.redact()` (Constitution III)
- `write()` must keep gate-before-write ordering for all three artifacts (FR-042 philosophy)
- Commit after each task or logical group
- Stop at any checkpoint to validate the story independently
