# Data Model: HTML Report with Code Snippets

## Entities

### CodeExcerpt (new, additive to Finding)

A labeled, redacted slice of source attached to a finding. `code_excerpt` is attached to **every** admitted finding; the `status` field distinguishes a produced excerpt (`ok`) from an unproducible one (`unavailable` + `reason`) — it is never absent silently (see FR-010).

| Field | Type | Required | Notes |
|---|---|---|---|
| `repo` | string | yes | mirrors `location.repo` |
| `file` | string | yes | mirrors `location.file` |
| `cited_start` | integer ≥ 1 | yes | first cited line (`location.line_start`) |
| `cited_end` | integer ≥ cited_start | yes | last cited line (`location.line_end`) |
| `window_start` | integer ≥ 1 | yes | first excerpted line (`max(1, cited_start − context)`) |
| `window_end` | integer ≥ cited_end | yes | last excerpted line (after cap) |
| `language` | string | no | fence info string / CSS class hint; from code model or extension map |
| `lines` | array of ExcerptLine | yes (when `status="ok"`) | ordered, contiguous, redacted |
| `truncated` | boolean | yes | true when cap or per-line truncation applied |
| `status` | enum: `ok`, `unavailable` | yes | `unavailable` carries `reason`, never fabricated content |
| `reason` | string | when `unavailable` | e.g. "source file not found at report time", "contains a value that could not be confirmed as a non-credential" |

### ExcerptLine

| Field | Type | Notes |
|---|---|---|
| `number` | integer ≥ 1 | 1-based source line number |
| `text` | string | redacted content; redaction placeholders preserved verbatim |
| `cited` | boolean | true when `cited_start ≤ number ≤ cited_end` (drives HTML highlight) |
| `truncated` | boolean | true when per-line length cap applied |

### Report (existing, unchanged shape)

`reports/{scan_id}.{json,md,html}` — three renderings of one report dict. JSON gains excerpt data only via the finding-level `code_excerpt` property; no top-level report fields change.

### Navigation Index (HTML-only derived view)

Not persisted: derived at render time from `findings_by_band`. Entries: `(anchor, finding_id, cwe, band, verification_status)` grouped in `BANDS` order; anchor = `finding-<sanitized id>`.

## Validation Rules

- `code_excerpt` present ⇒ `status` present; `status="ok"` ⇒ `lines` non-empty and `window_start ≤ cited_start ≤ cited_end ≤ window_end`.
- Every `lines[].text` MUST equal the redactor's output for that source line (artifact redaction sweep enforces zero credential values — SC-005).
- `unavailable` excerpts MUST NOT include `lines`.
- Additive-only: `finding.json` gains the optional `code_excerpt` property; no existing field changes; no `schema_version` bump.
- HTML anchors MUST be unique per report; every emitted `href="#…"` MUST resolve to an emitted anchor (render-time assertion, SC-002).

## State Transitions

None — excerpts are immutable derived data produced once during `build_report`.
