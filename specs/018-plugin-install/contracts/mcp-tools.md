# Contract: MCP tool provider (`secscan mcp`)

**Feature**: 018-plugin-install | **Transport**: stdio (MCP, via the official `mcp` SDK)
| **Server name**: `secscan` | **Server version**: `TOOL_VERSION`

The server is stateless: every tool takes `workdir` and reads/writes only that root's
`.secscan/`. It never writes to stderr during a tool call, never opens a network
connection, and never reads a project file other than through the pipeline (FR-021/022).

Tool names are prefixed `secscan_` so they remain unambiguous when a host merges tools
from several servers.

Glossary: the spec's **tool provider** is this **server**; a spec **operation** is an
MCP **tool**; the implementing function in `pipeline/mcp_server.py` is a **handler**.

## 1. Common shapes

### 1.1 Result envelope

Every tool returns one JSON object (as the single `text` content item **and** as
`structuredContent`).

```json
{
  "state": "ok",
  "tool_version": "0.1.0",
  "driver": {"form": "plugin", "tool_version": "0.1.0", "plugin_version": "0.1.0", "delegated": false},
  "message": "optional, redacted, human-readable"
}
```

`state` vocabulary (closed): `ok` · `not_ready` · `awaiting_reasoning` · `in_progress` ·
`locked` · `report_defect` · `endpoint_failed` · `rejected` · `error`.
See data-model.md §6 for the mapping to CLI exit codes.

`driver` (FR-015): when the project carries a skill install, `form` is `"skill"`,
`tool_version` is the pinned payload's version, `delegated` is `true`, and
`plugin_version` is this server's version. Otherwise `form` is `"plugin"` and the two
versions are equal.

### 1.2 Errors

Argument/config/IO failures are returned as `state: "error"` results (not JSON-RPC
errors) so hosts render them to the model. `message` is passed through `Redactor`
before it leaves the server, exactly as `cmd_run` does for exceptions. Tracebacks never
leave the server.

### 1.3 Progress

During `secscan_run` the server emits, per progress event:

- `notifications/message` — `level: "info"` (`"warning"` for warning/failed events),
  `logger: "secscan"`, `data: "<rendered line>"` — the same line `scan.log` receives;
- `notifications/progress` — only when the client supplied `_meta.progressToken`;
  `progress`/`total` from segment `i/N` events, `message` the rendered line.

Nothing about progress appears in the result object (FR-009).

## 2. Tools

All `workdir` arguments: absolute or relative path to the scan root; resolved with
`Path(workdir).resolve()`; the same meaning as the CLI `--workdir`.

### 2.1 `secscan_init`

Generate config and check the environment (wraps `pipeline.init_cmd.run_init`).

| Input | Type | Required | Notes |
|---|---|---|---|
| `workdir` | string | yes | |
| `install` | string | no | `"all"` or comma-separated tool ids (same as CLI `--install`) |
| `yes` | boolean | no | confirm the presented install list |

Never prompts: the tool always behaves as CLI `--no-input` unless `install`/`yes` is
given. Result: `state: ok | not_ready`, plus `report: "<run_init report text>"` and
`config_schema_changed: bool` (data-model.md §3).

### 2.2 `secscan_run`

Run or resume the scan (wraps `pipeline.run.run_scan` with a deadline; research R4).

| Input | Type | Required | Notes |
|---|---|---|---|
| `workdir` | string | yes | |
| `profile` | string | no | `quick` \| `full` \| `audit` \| custom |
| `full` | boolean | no | ignore checkpoints |
| `segment` | string | no | re-run one segment |
| `set` | object | no | `{"analysis_depth.business_flow": true}` → same nesting as `--set` |
| `policy` | string | no | `auto` \| `interactive` \| `batch` \| `batch-offpeak` |
| `time_budget_s` | integer | no | overrides `plugin.run_bound_s`; 5..3600 |

Result by `state`:

| `state` | Extra fields |
|---|---|
| `ok` | `scan_id`, `report_path`, `findings_reported` (int), `coverage_notes` (int), `summary` (the three frozen stdout lines, verbatim) |
| `report_defect` | as `ok` plus `quarantined_sections` (int) |
| `awaiting_reasoning` | `pending` (sorted request ids), `requests_dir`, `next: "call secscan_get_request for each id, secscan_submit_answer, then secscan_run"` |
| `in_progress` | `checkpoint: {"stage": "...", "subject": "..." \| null}`, `elapsed_s`, `overran_bound` (bool), `next: "call secscan_run again"` |
| `locked` | `lock: {"pid", "driver", "started_at", "scan_id"}` |
| `endpoint_failed` | `message` (redacted), `resume: true` |
| `error` | `message`; for a corrupt delegated install also `reason: "corrupt skill install"`, `repair: "secscan init <workdir> --ai <host>"` |

When delegated (§1.1) and the pinned payload predates bounded runs, the result carries
`bound: "unsupported by pinned payload v<X>"` and the call runs to that payload's
natural completion.

### 2.3 `secscan_status`

| Input | Type | Required |
|---|---|---|
| `workdir` | string | yes |

Result: data-model.md §5 (`state: ok | not_ready`).

### 2.4 `secscan_list_requests`

| Input | Type | Required |
|---|---|---|
| `workdir` | string | yes |

Result: `state: ok`, `requests: [{"request_id", "stage", "escalation_level",
"estimated_tokens", "answered": bool}]` sorted by `request_id`. Reads only the two
handoff directory listings and each request's top-level fields (never the packet).

### 2.5 `secscan_get_request`

| Input | Type | Required |
|---|---|---|
| `workdir` | string | yes |
| `request_id` | string | yes |

`request_id` must equal the stem of an existing file in `handoff/requests/` (matched
against the listing, never path-joined — research R10). Result: `state: ok`,
`request: <the request document, verbatim>`, `answered: bool`,
`answer_schema: "finding" | "flow_answer" | "triage_answer"`,
`guidance: "prompts/segment_scan.md" | "prompts/business_flow.md" | "prompts/triage_finding.md"`.
Unknown id → `state: error`. Already answered → `state: ok` with `answered: true` (the
packet is returned unchanged; it is never regenerated).

### 2.6 `secscan_submit_answer`

| Input | Type | Required | Notes |
|---|---|---|---|
| `workdir` | string | yes | |
| `request_id` | string | yes | as §2.5 |
| `content` | string **or** object | yes | the answer; a string is written verbatim, an object as canonical JSON |
| `overwrite` | boolean | no | default `false`; an existing response is otherwise `error` |

Validation per request `stage` (research R12); on failure `state: rejected`,
`errors: [{"path": "findings/0/cwe", "message": "..."}]`, and **no file is written**.
On success `state: ok`, `response_path`, and `next: "call secscan_run to resume"`.
The written file is byte-identical to what an agent following SKILL.md would write.

### 2.7 `secscan_report`

| Input | Type | Required | Notes |
|---|---|---|---|
| `workdir` | string | yes | |
| `repo` | string | no | filter to one member |
| `format` | string | no | `markdown` (default) \| `json` \| `html` |

Result: `state: ok`, `report_path`, `content` (rendered report text). Missing report →
`state: error`.

## 3. Prompt

| Name | Arguments | Returns |
|---|---|---|
| `secscan` | none | one `user` message whose text is the plugin-form skill body (`skills/secscan/SKILL.md` render) |

Hosts that surface prompts as slash commands get `/secscan` with the same guidance a
skill install provides (FR-011). Byte-equal to the committed `skills/secscan/SKILL.md`
body (asserted in `test_mcp_server.py`).

## 4. Resources (read-only)

| URI | Content |
|---|---|
| `secscan://prompts/{name}` | `skill_core/prompts/<name>.md` (`segment_scan`, `business_flow`, `triage_finding`, …) |
| `secscan://schemas/{name}` | `skill_core/schemas/<name>.json` (`finding`, `flow_answer`, `triage_answer`, …) |

`name` is matched against the payload directory listing (R10). No resource exposes
anything under a scan root.

## 5. JSON Schemas (contract tests)

`tests/contract/test_mcp_tool_schemas.py` validates every result produced by the
lifecycle test against these; they are also the `outputSchema` advertised by each tool.

```json
{
  "$id": "secscan://contracts/018/result-envelope",
  "type": "object",
  "required": ["state", "tool_version", "driver"],
  "properties": {
    "state": {"enum": ["ok","not_ready","awaiting_reasoning","in_progress","locked",
                       "report_defect","endpoint_failed","rejected","error"]},
    "tool_version": {"type": "string"},
    "driver": {
      "type": "object",
      "required": ["form", "tool_version", "plugin_version", "delegated"],
      "properties": {
        "form": {"enum": ["plugin", "skill"]},
        "tool_version": {"type": "string"},
        "plugin_version": {"type": "string"},
        "delegated": {"type": "boolean"}
      },
      "additionalProperties": false
    },
    "message": {"type": "string"}
  }
}
```

```json
{
  "$id": "secscan://contracts/018/run-result",
  "allOf": [{"$ref": "secscan://contracts/018/result-envelope"}],
  "properties": {
    "scan_id": {"type": "string"},
    "report_path": {"type": "string"},
    "findings_reported": {"type": "integer", "minimum": 0},
    "coverage_notes": {"type": "integer", "minimum": 0},
    "quarantined_sections": {"type": "integer", "minimum": 0},
    "summary": {"type": "array", "items": {"type": "string"}, "minItems": 2, "maxItems": 3},
    "pending": {"type": "array", "items": {"type": "string"}},
    "requests_dir": {"type": "string"},
    "checkpoint": {"type": "object", "required": ["stage"],
                   "properties": {"stage": {"type": "string"}, "subject": {"type": ["string","null"]}}},
    "elapsed_s": {"type": "number"},
    "overran_bound": {"type": "boolean"},
    "bound": {"type": "string"},
    "lock": {"type": "object"},
    "resume": {"type": "boolean"},
    "reason": {"type": "string"},
    "repair": {"type": "string"},
    "next": {"type": "string"}
  }
}
```

```json
{
  "$id": "secscan://contracts/018/submit-answer-result",
  "allOf": [{"$ref": "secscan://contracts/018/result-envelope"}],
  "properties": {
    "response_path": {"type": "string"},
    "errors": {"type": "array",
               "items": {"type": "object", "required": ["path", "message"],
                         "properties": {"path": {"type": "string"}, "message": {"type": "string"}},
                         "additionalProperties": false}},
    "next": {"type": "string"}
  }
}
```

Frozen interface notes: the `state` enum and the required envelope fields are additive
from here on; a removal or rename needs a contract version bump (`018` in the `$id`).
