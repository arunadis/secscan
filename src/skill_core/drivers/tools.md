Drive the pipeline through the **secscan tools** your host exposes (installed as a
plugin, the tool provider is already running; never run scripts yourself). Every
tool takes the scan root as `workdir`:

| Tool | Purpose |
|---|---|
| `secscan_init` | generate config and check the environment (first run only) |
| `secscan_run` | run or resume the scan (`profile`, `full`, `set`, `policy`) |
| `secscan_status` | stages, pending requests, lock, active engine version |
| `secscan_list_requests` | pending reasoning requests (`answered` flag per id) |
| `secscan_get_request` | one request: prompt + bounded, redacted context packet |
| `secscan_submit_answer` | your answer JSON for one request (validated before it is written) |
| `secscan_report` | the latest report (`repo` filter; markdown, json or html) |

Every result carries a closed `state`. Act on it:

- `ok` — the scan settled; `summary` holds the report path and finding count.
- `awaiting_reasoning` — your reasoning is required (this is what exit code 3 means
  in the sections below): for each id in `pending`, call `secscan_get_request`,
  reason, call `secscan_submit_answer`, then call `secscan_run` again. A rejected
  submission (`state: rejected`) lists `errors`; fix the answer and resubmit.
- `in_progress` — the bounded call paused at a checkpoint (`checkpoint.stage`);
  nothing keeps running in the background. Simply call `secscan_run` again; each call
  advances the scan. Relay `checkpoint` to the user so a long scan does not look stuck.
- `locked` — another scan holds this root (`lock.pid`, `lock.driver`); wait for it.
- `endpoint_failed` — the configured provider kept refusing; call `secscan_run` later,
  analysed segments are kept.
- `report_defect` — the report published with quarantined section(s); read it.
- `error` — `message` says why (unconfigured project, corrupt install, bad argument).

Wherever the sections below say "re-run the scan command", call `secscan_run`;
wherever they say "write your answer to `.secscan/handoff/responses/<id>.json`", call
`secscan_submit_answer` with that id — it writes exactly that file.

Progress arrives as host notifications while `secscan_run` works (each stage, segment
`i/N`, external tool, coverage note); the full trace of the latest run is always in
`.secscan/scan.log`. The `driver` field of every result names the engine that ran:
when the project already carries a skill install of secscan, that pinned version is
used (`driver.form: skill`) and the plugin only delegates.

When the project is configured with an external analysis endpoint (`llm.endpoint`),
you do not perform the reasoning; the provider does, through its **batch API by
default**. `secscan_run` then returns `in_progress` while batches are processing —
keep calling it; the batch reference is persisted and each call resumes the same
batch. `policy: "interactive"` opts into live per-segment requests for small
repositories.
