# Contract: Report Artifacts (HTML + Code Excerpts)

## Artifact set

`generate_report.write()` writes three files per scan, after the consistency gate passes:

| Artifact | Producer | Contract |
|---|---|---|
| `reports/{scan_id}.json` | `ArtifactStore.write(..., schema="report")` | existing envelope; payload gains optional `code_excerpt` on findings |
| `reports/{scan_id}.md` | `render_markdown` via `write_text` | existing sections; findings gain a fenced code block when `code_excerpt.status == "ok"`, else an "excerpt unavailable: \<reason\>" line |
| `reports/{scan_id}.html` | `render_html` via `write_text` | **new**; self-contained document (below) |

All three are byte-identical across runs for identical input and tool version (no timestamps; fixed ordering; constant inline CSS).

## Schema addition (additive, no version bump)

`src/skill_core/schemas/finding.json` gains one optional property:

```json
"code_excerpt": {
  "type": "object",
  "additionalProperties": false,
  "required": ["repo", "file", "cited_start", "cited_end", "window_start", "window_end", "truncated", "status"],
  "properties": {
    "repo": { "type": "string" },
    "file": { "type": "string" },
    "cited_start": { "type": "integer", "minimum": 1 },
    "cited_end": { "type": "integer", "minimum": 1 },
    "window_start": { "type": "integer", "minimum": 1 },
    "window_end": { "type": "integer", "minimum": 1 },
    "language": { "type": "string" },
    "lines": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["number", "text", "cited", "truncated"],
        "properties": {
          "number": { "type": "integer", "minimum": 1 },
          "text": { "type": "string" },
          "cited": { "type": "boolean" },
          "truncated": { "type": "boolean" }
        }
      }
    },
    "truncated": { "type": "boolean" },
    "status": { "enum": ["ok", "unavailable"] },
    "reason": { "type": "string" }
  }
}
```

Rules: `status="unavailable"` ⇒ `reason` present and `lines` absent. Existing reports without `code_excerpt` remain valid.

## HTML document contract

1. **Self-contained**: no `<script src>`, `<link>`, `@import`, `url(http…)`, or fetch of any kind; styling is one inline `<style>` constant; no JavaScript.
2. **Structure** (fixed order): header (workspace id, scan id, mode, profile, band counts) → navigation index (grouped by band, one entry per finding) → executive summary → findings by band (each `<section id="finding-<sanitized-id>">` with a "↑ index" back-link) → cross-system/attack paths/recommendations/coverage/usage sections mirroring Markdown.
3. **Anchors**: `finding-<id>` with `id` sanitized to `[A-Za-z0-9-_]`; unique within the document.
4. **Link integrity**: every `href="#…"` in the output resolves to an emitted `id`; `render_html` raises otherwise (never publishes a dangling reference).
5. **Excerpt block**: `<pre>` with one row per line showing the 1-based line number; rows with `cited=true` carry a highlight class; truncated lines end with the truncation marker; `unavailable` excerpts render the reason text.
6. **Escaping**: all dynamic content passes through `html.escape`; code content is never injected as markup.
7. **Offline rendering**: opens correctly with network disabled at ≥500 findings (SC-004).

## CLI surface

- `security-scan run` — unchanged invocation; now always emits the `.html` artifact (FR-001, clarified unconditional).
- `report_view.render(report, repo=None, output_format="html")` — new format value alongside `"markdown"`/`"json"`; repo-filtered projections render to HTML identically (index reflects the filtered set).

## Redaction guarantee

Every excerpt line is `Redactor.redact()` output; the existing artifact redaction sweep is extended to cover `reports/*.html` and `reports/*.md` so SC-005 is enforced by the Safety Invariants table mechanism, not by intent.
