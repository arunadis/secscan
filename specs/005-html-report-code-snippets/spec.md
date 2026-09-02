# Feature Specification: HTML Report with Code Snippets

**Feature Branch**: `005-html-report-code-snippets`

**Created**: 2026-09-01

**Status**: Draft

**Input**: User description: "in additon to the final report in markdown and json format, i need to generate a html report as well with easy canigations with ref links. also i need to impreve the report to have the respective code blocks that has the vulnerability so that the user can easily have a look."

## Clarifications

### Session 2026-09-01

- Q: Should the HTML report be generated automatically on every scan, or only when the user explicitly requests it? → A: Always generated — every scan produces JSON + Markdown + HTML unconditionally
- Q: Which report formats should include the vulnerable code blocks — all three renderings, or only the new HTML report? → A: All three formats — JSON carries excerpt data, Markdown gets fenced blocks, HTML gets highlighted blocks

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Navigate findings in a browser-friendly HTML report (Priority: P1)

A security reviewer receives a scan report and opens it in a web browser. Instead of scrolling through a long flat document, they see a structured HTML report with a summary header (severity counts, scan metadata) and a navigation index listing every finding. Clicking a finding in the index jumps directly to that finding's detail section. Each finding detail links back to the index, and cross-references (e.g., related findings, shared files, coverage-gap references) are clickable links rather than plain text.

**Why this priority**: The user explicitly asked for an HTML report with easy navigation and reference links. For large scans, a flat Markdown document is hard to traverse; a navigable HTML rendering is the core ask and delivers immediate value on its own.

**Independent Test**: Run a scan against any fixture repository with known findings, open the produced HTML file in a browser offline, and verify that the index lists all findings, every index entry jumps to the correct finding detail, and the report renders without any network access or external assets.

**Acceptance Scenarios**:

1. **Given** a completed scan with findings across multiple severity bands, **When** the report is generated, **Then** an HTML report file is produced alongside the existing Markdown and JSON reports, containing a summary of findings per severity band and a navigation index of all findings.
2. **Given** the HTML report is open, **When** the user clicks a finding entry in the navigation index, **Then** the view jumps to that finding's detail section and the entry is unambiguously identifiable (stable anchor per finding).
3. **Given** the HTML report is open, **When** the user clicks a finding's link back to the index (or a cross-reference to another finding or file), **Then** the view jumps to the referenced target.
4. **Given** the HTML report file, **When** it is opened on a machine with no network access, **Then** it renders completely and correctly (self-contained; no external stylesheets, scripts, fonts, or images required).

---

### User Story 2 - See the vulnerable code inline in each finding (Priority: P1)

A developer reading a finding wants to see the actual code the finding refers to without opening the repository in an editor. Each finding in the report displays the relevant source code block — the vulnerable lines highlighted with surrounding context — labeled with file path and line range, so the reader can immediately judge the finding. The code shown is exactly the redacted code the scanner analyzed: secret values never appear in the report.

**Why this priority**: The user explicitly asked for code blocks showing the vulnerability "so that the user can easily have a look." This is equal in importance to the HTML rendering itself: a navigable report without the code still forces the reader to leave the report to understand each finding.

**Independent Test**: Scan a fixture repository with a known vulnerability at a known file and line range, generate the report, and verify the finding's detail section contains a code block whose content matches the source file at the cited location (with redaction applied), with the vulnerable line(s) visually distinguished.

**Acceptance Scenarios**:

1. **Given** a finding with a resolved file/line location, **When** the report is generated, **Then** the finding's detail section includes a code block excerpted from that file covering the cited lines plus surrounding context, labeled with the file path and line range.
2. **Given** a finding whose cited code contains a redacted credential, **When** the code block is rendered, **Then** the credential value does not appear; the redaction placeholder is shown instead.
3. **Given** a finding, **When** its code block is displayed in the HTML report, **Then** the line(s) the finding cites are visually highlighted and carry line numbers so the reader can correlate with the file.
4. **Given** the Markdown report, **When** a finding is rendered, **Then** it also contains the same code block (as a fenced code block with path and line range), so both human-readable formats are equally inspectable.

---

### User Story 3 - Correlate findings across formats via stable references (Priority: P2)

A user working across the JSON, Markdown, and HTML renderings wants consistent identity: every finding has a stable identifier, and references between report sections (finding → evidence entries, finding → coverage gap, finding → file location) resolve correctly in every format — as anchors/links in HTML, as resolvable references in Markdown, and as identifier fields in JSON.

**Why this priority**: Cross-format consistency is what makes the report auditable (constitution Principle IV: no internal references that do not resolve). It matters once HTML and code snippets exist, but the scanner already has stable finding IDs, so this is a consistency layer on top of P1 stories.

**Independent Test**: Generate all three report formats from one scan and verify that every internal reference in the HTML (index → finding, finding → evidence, finding → coverage gap) resolves to an existing target, and that finding IDs are identical across the three files.

**Acceptance Scenarios**:

1. **Given** a report set (HTML, Markdown, JSON) from a single scan, **When** any internal reference in the HTML report is followed, **Then** the target exists and is the correct section.
2. **Given** the three report formats, **When** finding identifiers are compared, **Then** the same finding carries the same identifier in all three.

---

### Edge Cases

- Findings with file-level (not symbol-level) location tiers still get a code block anchored to the cited line range — both tiers carry verified line bounds, so a reported finding never lacks a line range (honest uncertainty — never fabricate a snippet).
- A cited file that no longer exists or is unreadable at report time: the finding renders without a code block and declares that the excerpt was unavailable, rather than failing report generation.
- Code excerpts overlapping redacted regions show redaction placeholders, never raw values; if a snippet cannot be confidently redacted it is withheld, consistent with redactor recall-over-precision rules.
- Very large findings counts (hundreds+) must not make the HTML report unusable: the index remains navigable (grouped by severity band) and the file size stays reasonable for browser rendering.
- Snippets spanning multiple files or segments (cross-system findings) show one labeled block per evidence location, not a merged block.
- Binary, minified, or extremely long single-line files: excerpt is truncated at a bounded length with an explicit truncation note rather than embedding megabytes of code.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST produce an HTML rendering of the final security report on every scan — unconditionally, with no opt-in or opt-out flag — in addition to the existing Markdown and JSON renderings, from the same single report data set.
- **FR-002**: The HTML report MUST be fully self-contained: opening it must require no network access and no external assets (styles, scripts, fonts).
- **FR-003**: The HTML report MUST contain a navigation index listing every admitted finding, grouped consistently with the report's severity-band grouping and verification-aware ranking.
- **FR-004**: Every index entry in the HTML report MUST link to its finding's detail section via a stable, unique anchor derived from the finding identifier.
- **FR-005**: Every finding detail section in the HTML report MUST provide a link back to the navigation index.
- **FR-006**: Internal references in the HTML report (finding ↔ evidence, finding ↔ coverage gap, finding ↔ file location) MUST be rendered as clickable links, and every such link MUST resolve to an existing target in the document.
- **FR-007**: Every admitted finding with a resolvable line-level location MUST display, in both the HTML and Markdown renderings, a code excerpt from the cited file covering the cited lines plus a bounded amount of surrounding context, labeled with file path and line range.
- **FR-008**: Code excerpts MUST be sourced from the redacted view of the source: credential values MUST NOT appear in any report rendering; redaction placeholders are shown in their place.
- **FR-009**: In the HTML rendering, code excerpts MUST show line numbers and visually distinguish the cited (vulnerable) lines from surrounding context.
- **FR-010**: When a code excerpt cannot be produced (source file unavailable at report time, or excerpt cannot be confidently redacted), the finding MUST render without the excerpt and MUST state the reason — the report MUST NOT fabricate or silently omit this fact. (Every reported finding carries verified line bounds at both location tiers, so "no line range" is never a reason.)
- **FR-011**: Code excerpt content MUST be deterministic: identical scan input and tool version MUST produce byte-identical excerpts across all three renderings, consistent with the byte-identical-artifacts invariant.
- **FR-012**: The JSON rendering MUST carry the excerpt data (path, line range, redacted content) as structured fields so the HTML and Markdown renderings derive from the same source of truth; schema changes MUST be additive per the additive-schema rule.
- **FR-013**: Individual code excerpts MUST be bounded in size; oversized excerpts (e.g., minified single-line files) MUST be truncated with an explicit note.
- **FR-014**: Generating the HTML report MUST NOT change the content or determinism of the existing Markdown and JSON reports beyond the additive excerpt fields.

### Key Entities

- **Report**: the unified scan output; rendered as JSON (machine-readable source of truth), Markdown, and now HTML. Contains summary, findings grouped by severity band, coverage gaps, and metadata.
- **Finding**: a vulnerability claim with stable identifier, weakness identifier, severity band/score, confidence, verification status, location (file/symbol/line tier), evidence, and (new) code excerpt.
- **Code Excerpt**: a labeled, redacted slice of source — file path, line range, excerpt lines with line numbers, the cited (highlighted) sub-range, and truncation/unavailability status.
- **Navigation Index**: the HTML report's table of contents of findings, keyed by stable finding anchors, grouped by severity band.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of scans produce three report files (JSON, Markdown, HTML) from a single run, with identical finding identifiers across all three.
- **SC-002**: 100% of internal links in the HTML report resolve to an existing target (verified automatically; zero broken anchors).
- **SC-003**: 100% of findings with line-resolved locations display a code excerpt whose content matches the redacted source at the cited location, in both HTML and Markdown renderings.
- **SC-004**: The HTML report opens and renders completely with network disabled, in a standard browser, for scans of at least 500 findings.
- **SC-005**: 0 credential values appear in any code excerpt across all renderings (verified by the redaction sweep over every artifact).
- **SC-006**: A reviewer can reach any finding's detail (including its code) from the report index in at most 2 clicks.
- **SC-007**: Two runs over identical input produce byte-identical HTML, Markdown, and JSON report files.

## Assumptions

- The HTML report is a single self-contained file (inline styles and behavior), matching the offline/determinism constraints of the project; multi-page output is out of scope.
- (Confirmed in Clarifications, Session 2026-09-01) Code excerpts are included in all three renderings: JSON carries the excerpt as structured data, Markdown renders fenced blocks, and HTML renders highlighted blocks — all derived from one data set.
- Default surrounding context is a small fixed number of lines above and below the cited range (exact value is an implementation decision); oversized excerpts are truncated per FR-013.
- Excerpts are taken from the redacted source the pipeline already holds; no new repository read path that bypasses the redactor is introduced.
- No interactivity beyond navigation (no filtering/search UI) is required for v1; static anchors and links satisfy "easy navigation with ref links".
- Syntax highlighting, if present, must be self-contained and deterministic (inline, no runtime fetching); it is a nicety, not a requirement.
