# Tasks: Plugin Install

**Input**: Design documents from `/specs/018-plugin-install/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/ (mcp-tools.md,
plugin-manifests.md, cli-plugin.md), quickstart.md

**Tests**: INCLUDED — the constitution mandates test-first (write, watch fail, then
implement). Each test task names the requirement it discharges.

## Format: `[ID] [P?] [Story] Description` — paths repository-relative

Story map (spec.md): **US1** install as a plugin on a supported host (P1) · **US2** drive
the scan through tool calls on any host (P1) · **US3** skill and plugin surfaces stay one
product (P2). US2 is the engine every other story packages, so it is built first; US1
packages it; US3 hardens the single source and precedence.

---

## Phase 1: Setup

- [X] T001 Add the optional extra `plugin = ["mcp>=2.1,<3"]` under `[project.optional-dependencies]` and `"drivers/*.md"` to `skill_core` package-data in pyproject.toml; run `uv sync --extra dev --extra plugin` and confirm `python -c "import mcp"` works while a base-only venv (`uv pip install -e .`) still imports `pipeline.scan_cli` without `mcp` (FR-023)
- [X] T002 [P] Vendor the Agent Plugins 1.0.0 schemas as tests/fixtures/agent_plugins/plugin.schema.json and tests/fixtures/agent_plugins/mcp.schema.json (fetched once from agent-plugins.org/schemas/1.0.0/, committed; tests never fetch — research R1, constitution "no network")
- [X] T003 [P] Add `RUN_LOCK_NAME = "run.lock"` and `PLUGIN_INSTALLS_RECORD = "plugin-installs.json"` constants plus a `user_config_dir()` helper (`$XDG_CONFIG_HOME`/`~/.config`/`%APPDATA%` → `secscan/`) in src/pipeline/state.py (data-model.md §3, §4)

---

## Phase 2: Foundational — engine changes every story depends on

**Purpose**: cooperative deadline, run lock, answer I/O, progress sink and the skill-source
split. All additive; the CLI path must be provably unchanged.

**Tests (fail first)**

- [X] T004 [P] tests/unit/test_run_deadline.py: with an injected `clock`, `run_scan(deadline=...)` raises `ScanPaused(stage, checkpoint)` at each boundary in research R4 (before a checkpointed stage; each batch-poll iteration after the first poll of the call); never between segments/flows/packets or between un-checkpointed deterministic passes (corrected during implementation: those re-drive on resume, so a pause there livelocks); an already-expired deadline still completes one checkpointed stage per call (guaranteed progress); `state.json` is saved before the raise; `run_scan(deadline=None)` never raises; the artifacts written before the pause are byte-identical to an uninterrupted run's for the same stages (FR-007, Principle I)
- [X] T005 [P] tests/unit/test_run_lock.py: `acquire_run_lock` creates `.secscan/run.lock` with `{pid, started_at, scan_id, driver, tool_version}`; a live lock raises `ScanLocked`; a dead-pid lock is reclaimed; `run_scan` releases the lock on success, on `AgentHandoff`, on `ScanPaused` and on exception; `cmd_run` exits 1 with the "scan already running in …" stderr message and empty stdout when locked (FR-008, contracts/cli-plugin.md §5)
- [X] T006 [P] tests/unit/test_answers_io.py: `validate_answer` per request `stage` — segment: non-JSON prose rejected, `{"findings": [...]}` and `{"needs_escalation": true}` accepted; flow: fails `flow_answer` → errors with `path`/`message` and no instance text; triage: same for `triage_answer`; `write_response` writes `handoff/responses/<id>.json` byte-identical to `Path.write_text(content)` for strings and canonical JSON for objects; a rejected submission leaves no file; unknown id and already-answered-without-overwrite are errors (FR-006, research R12)
- [X] T007 [P] tests/unit/test_progress.py additions: `McpSink.write` forwards the rendered line to an injected `notify(level, text)` callable with `info`/`warning` levels, forwards `progress/total` for segment events only when a progress token is present, never writes to a stream; `build_reporter(..., mcp_notify=...)` omits the terminal sink (FR-009, research R6)
- [X] T008 [P] tests/integration/test_install_matrix.py golden files: capture today's rendered entrypoint for every adapter under tests/fixtures/skill_renders/<agent>.golden **before** the split and add a test asserting byte-equality after it (FR-001 "unchanged in behaviour", data-model.md §10)
- [X] T009 [P] tests/unit/test_config_plugin.py: `plugin.run_bound_s` default 45, accepts 5..3600, rejects 4/3601/non-int with the strict `ConfigError` wording, env `SECSCAN_PLUGIN_RUN_BOUND_S` overrides (data-model.md §9)

**Implementation**

- [X] T010 src/pipeline/run.py: add `ScanPaused` (fields `stage`, `checkpoint`, `reason="deadline"`) beside `AgentHandoff`; `run_scan(..., deadline: float | None = None)`; a `_check_deadline(stage, subject)` closure that calls `store.save_state()` then raises, invoked before `_stage`/`_stage_list` and the checkpointed flow/triage rounds only once a `progressed` flag is set by a non-reused stage (guaranteed progress; no checks between segments/flows/packets or between un-checkpointed deterministic passes — see R4 correction); thread `deadline` into `BatchRoundRunner` and `triage.run_batch` (T011) — makes T004 pass (FR-007)
- [X] T011 src/pipeline/batch_runner.py and src/pipeline/triage.py (`run_batch`): accept `deadline` and check it at the top of every poll iteration using the injected `clock`, raising `ScanPaused("segment_analysis" | "finding_triage", checkpoint="batch-poll")`; the batch reference stays in the ledger so the re-run resumes it (research R4)
- [X] T012 src/pipeline/state.py: `acquire_run_lock(store_dir, *, driver, scan_id) -> Lock`, `release_run_lock`, `read_run_lock` (stale-pid aware via `os.kill(pid, 0)`), `ScanLocked` exception; src/pipeline/run.py acquires on entry and releases in `finally` — makes T005 pass (FR-008)
- [X] T013 src/pipeline/scan_cli.py: `cmd_run` catches `ScanLocked` → stderr message per contracts/cli-plugin.md §5, exit `EXIT_ERROR`, stdout untouched; `cmd_status` prints the `Running: pid N via <driver> since <time>` line when a live lock exists; the three summary lines and all exit codes unchanged (FR-010)
- [X] T014 src/pipeline/answers_io.py (NEW): `answer_kind(request_doc) -> "finding" | "flow_answer" | "triage_answer"` from `stage`; `validate_answer(request_doc, content) -> list[dict]` using `FindingNormalizer.parse` / `escalate.needs_escalation`, `schemas.validate("flow_answer")`, `schemas.is_valid("triage_answer")` with jsonschema errors rendered as `{"path": "/".join(map(str, e.path)), "message": e.message}`; `write_response(handoff_dir, request_id, content, *, overwrite=False)`; `resolve_request(handoff_dir, request_id)` matching against the directory listing (research R10) — makes T006 pass (FR-006, FR-022)
- [X] T015 src/pipeline/progress.py: `McpSink(notify, *, progress_token=None, verbose=False)` implementing the `Sink` protocol; `build_reporter(..., mcp_notify=None)` — when given, sinks are `[McpSink, FileSink]` with no terminal sink — makes T007 pass (FR-009)
- [X] T016 src/config/loader.py: `plugin.run_bound_s` in `_ALLOWED`, `validate_config` (int, 5..3600), `Config.plugin_run_bound_s`, `SECSCAN_PLUGIN_RUN_BOUND_S` env mapping — makes T009 pass (data-model.md §9)
- [X] T017 Split the skill source: move the "Run the pipeline with the scan command…" section (SKILL.md lines 84–115 today) verbatim into src/skill_core/drivers/shell.md, leave a `<!-- driver -->` marker in src/skill_core/SKILL.md, author src/skill_core/drivers/tools.md (call `secscan_run`; on `awaiting_reasoning` → `secscan_list_requests`/`secscan_get_request`/`secscan_submit_answer`/`secscan_run`; on `in_progress` → `secscan_run` again; on `locked` wait; endpoint mode note; never run scripts); add `render_skill(driver: "shell" | "tools") -> str` in src/installer/agents/base.py and make `Adapter.render_entrypoint` use `driver="shell"` — makes T008 pass byte-for-byte (FR-018, research R7)

**Checkpoint**: `pytest -q tests/unit/test_run_deadline.py tests/unit/test_run_lock.py tests/unit/test_answers_io.py tests/unit/test_progress.py tests/unit/test_config_plugin.py tests/integration/test_install_matrix.py` green; full suite still green (nothing else changed behaviour).

---

## Phase 3: US2 — Drive the scan through structured tool calls on any host (P1) 🎯 MVP

**Goal**: `secscan mcp` exposes the lifecycle as MCP tools; an agent with no secscan
adapter completes init → run → answer → resume → report with zero shell steps.

**Independent Test**: tests/integration/test_mcp_lifecycle.py drives a fixture end to end
through the SDK stdio client against a `secscan mcp` subprocess; artifacts equal a
skill-driven run (T028). quickstart.md §3–§4.

**Tests (fail first)**

- [X] T018 [P] [US2] tests/contract/test_mcp_tool_schemas.py: transcribe the three JSON schemas from contracts/mcp-tools.md §5 into tests/contract/schemas_018/*.json and assert every result envelope produced by T020's handlers (called in-process) validates; `state` enum closed; `driver` has exactly the four fields (FR-010)
- [X] T019 [P] [US2] tests/unit/test_mcp_server.py: in-process handler tests over a small built fixture (`tests/fixtures/single_repo_shop.build`) with a scripted `responder`-free agent path — `init` → `ok`/`not_ready`, and on a project whose `.secscan/config.yaml` predates the current `CONFIG_VERSION` returns `config_schema_changed: true` with the note text (`false` for a current one — FR-016); `run` → `awaiting_reasoning` with sorted `pending` and `requests_dir`; `run` with `time_budget_s` and a tiny injected bound → `in_progress` with `checkpoint.stage`, no process/lock left; `run` while a fake live lock exists → `locked`; `list_requests`/`get_request` return the on-disk document verbatim and `answer_schema`/`guidance`; `get_request("../x")` → `error`; `submit_answer` rejected leaves no file, accepted writes the file; `report` returns content; exception text in `message` passes through `Redactor` (a planted `AKIA…` token in the exception never appears); the `secscan` prompt text == committed skills/secscan/SKILL.md body; resources list only payload prompts/schemas (FR-004–FR-012, FR-021, FR-022)
- [X] T020 [P] [US2] tests/integration/test_mcp_lifecycle.py: start `python -m pipeline.mcp_server` as a stdio subprocess via `mcp.client.stdio`; `initialize`, `list_tools` (7 tools, prefixed `secscan_`), `list_prompts` (1), `list_resources`; run the full lifecycle on the fixture with hand-written conforming answers; assert progress arrived as `notifications/message` and never in results; the subprocess wrote nothing to stderr during tool calls; every tool call runs inside a network-guard fixture that monkeypatches `socket.socket` and `urllib.request.urlopen` to raise (FR-021); an endpoint case configures `llm.endpoint` and injects the fake `HttpTransport` from tests/integration/test_batch_scan.py through the `tool_run(..., transport=...)` seam — the result is never `awaiting_reasoning` and `handoff/requests/` stays empty (FR-012); extend the redaction sweep from tests/contract/test_artifact_redaction.py over every result and notification text (SC-002, SC-008)
- [X] T021 [P] [US2] tests/integration/test_installed_payload.py additions: `python -m pipeline.scan_cli --help` from an installed payload in a venv **without** `mcp` lists no `mcp` command and importing `pipeline.mcp_server` does not import `mcp` until `main()`/serve is called (FR-023, contracts/cli-plugin.md §1)

**Implementation**

- [X] T022 [US2] src/pipeline/mcp_server.py (NEW), handler layer: pure functions `tool_init`, `tool_run`, `tool_status`, `tool_list_requests`, `tool_get_request`, `tool_submit_answer`, `tool_report`, each `(args: dict, *, notify=None, clock=None, transport=None) -> dict` returning the envelope (data-model.md §6; `transport` is a test seam passed through to `run_scan`); `tool_init` computes `config_schema_changed` with `installer.upgrade.plan_upgrade` semantics against the project's config version and returns it with `report` (FR-016); `tool_run` loads config, computes `deadline = clock() + (time_budget_s or config.plugin_run_bound_s)`, builds the reporter with `mcp_notify`, calls `run_scan`, maps `ScanResult`/`AgentHandoff`/`ScanPaused`/`ScanLocked`/`EndpointError`/config errors to states, fills `summary` with the same three lines `cmd_run` prints, redacts `message`; `driver` filled by `_detect_driver(workdir)` (form `plugin`, `delegated: false` in this phase) — makes T018/T019 pass (FR-004–FR-010, FR-012)
- [X] T023 [US2] src/pipeline/mcp_server.py, serving layer: `build_app()` lazily imports `mcp.server.fastmcp.FastMCP`, registers the seven tools with JSON input schemas and the contract `outputSchema`, the `secscan` prompt (body = `render_skill("tools")`), and `secscan://prompts/{name}` / `secscan://schemas/{name}` resources resolved against `resources.prompt_dir()`/`schema_dir()` listings; `McpSink` notify bound to `ctx.session.send_log_message` and `ctx.report_progress`; `main()` runs stdio; `--oneshot <tool> <json>` mode calls the handler and prints the envelope to stdout without importing `mcp` (contracts/cli-plugin.md §7) — makes T020/T021 pass (FR-009, FR-011, FR-021)
- [X] T024 [US2] src/installer/cli.py: `secscan mcp` command → `pipeline.mcp_server.main()`; on `ImportError` of `mcp` print the one-line install hint to stderr and exit 1 with empty stdout (contracts/cli-plugin.md §1)
- [X] T025 [US2] src/skill_core/drivers/tools.md final wording pass against the implemented tool names/states (T017 authored the draft); regenerate nothing yet — the committed plugin skill is produced in Phase 4 (FR-018)

**Checkpoint**: an MCP Inspector session against `secscan mcp` completes quickstart.md §3 and §4 on a fixture; `pytest -q tests/unit/test_mcp_server.py tests/integration/test_mcp_lifecycle.py tests/contract/test_mcp_tool_schemas.py` green.

---

## Phase 4: US1 — Install secscan as a plugin on a supported platform (P1)

**Goal**: the repository root is an installable plugin (Agent Plugins 1.0.0 + Claude +
Gemini layouts); `secscan init --ai <host> --plugin` registers the tool provider at user
level and writes nothing into the project.

**Independent Test**: tests/integration/test_install_matrix.py::test_plugin_form under a
redirected HOME for all six hosts; committed plugin files validate and match their render;
quickstart.md §5 manual host checks.

**Tests (fail first)**

- [X] T026 [P] [US1] tests/unit/test_plugin_render.py: `installer.plugin.render_all(root)` produces exactly the seven files of contracts/plugin-manifests.md; each committed file equals its render; every `version` == `TOOL_VERSION`; every `description` == SKILL.md frontmatter description; `skills/secscan/SKILL.md` minus the driver section == each adapter's skill render minus the driver section; mutating SKILL.md in a tmp copy makes `check(root)` report `skills/secscan/SKILL.md` and `commands/secscan.toml` stale (FR-018, FR-019, SC-007)
- [X] T027 [P] [US1] tests/contract/test_plugin_manifests.py: `plugin.json` and `mcp.json` validate against tests/fixtures/agent_plugins/*.schema.json; `mcp.json` top-level keys are exactly `$schema`, `mcpServers`; `command` is a bare token; the server args in `mcp.json`, `.mcp.json`, `gemini-extension.json` differ only in the root placeholder; `.claude-plugin/plugin.json` name matches `^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$` (contracts/plugin-manifests.md §6)
- [X] T027a [P] [US1] tests/integration/test_plugin_launch.py: read the committed mcp.json, substitute `${PLUGIN_ROOT}` with the repository root and `${PLUGIN_DATA}` with a tmp dir, spawn exactly that argv as a stdio server (skip when `uv` is not on PATH) and complete `initialize` + `list_tools` — proves the committed launch reference works, not just the source-tree module (FR-019, research R11)
- [X] T028 [P] [US1] tests/integration/test_plugin_parity.py: scan the fixture once through the skill path (CLI + handwritten response files) and once through the in-process tool handlers submitting the same answers; compare every `.secscan/**/*.json`, `*.md`, `*.html` via `test_determinism._artifacts` → byte-identical; also with a 5 s bound forcing several `in_progress` rounds (FR-020, SC-003, SC-005)
- [X] T029 [P] [US1] tests/unit/test_plugin_register.py: with `HOME`/`XDG_CONFIG_HOME`/`APPDATA` redirected to tmp — `register(host, root)` for cursor/copilot/windsurf/devin merges `mcpServers.secscan` into the documented file, preserves an existing unrelated server, is idempotent; claude and gemini invoke the host CLI found on a fake `PATH` with the documented argv and fall back (gemini) or fail naming the command (claude) when absent; an unwritable target directory → `InstallError` naming the path and nothing written; `windsurf` entry has the absolute root substituted; the user install record gains the host entry with `form: plugin`; re-register with an older `TOOL_VERSION` monkeypatched → `DowngradeRefused` unless `force` (FR-013, FR-014, FR-016, research R2)
- [X] T030 [P] [US1] tests/integration/test_install_matrix.py::test_plugin_form: for every host with a plugin form run `secscan init <proj> --ai <host> --plugin --no-init --plugin-root <repo>` via `CliRunner` with redirected HOME and a fake `uv`/`claude`/`gemini` on PATH; assert `git status --porcelain <proj>` is empty, no `.<host>/skills` directory exists, the output matches the contracts/cli-plugin.md §3 shape; `--ai agents --plugin` → usage error; without `--plugin` the output is byte-identical to today's golden (FR-013, FR-014, FR-017, SC-006)

**Implementation**

- [X] T031 [US1] src/installer/agents/base.py + each adapter in src/installer/agents/{claude,cursor,copilot,windsurf,devin,gemini,agents}.py: add the plugin descriptor fields `plugin_layout`, `user_mcp_config`, `register_command`, `install_hint`, `root_placeholder` with the values in research R2 / data-model.md §2 (`agents` → `plugin_layout="none"`) (FR-002, FR-017)
- [X] T032 [US1] src/installer/plugin.py (NEW), render half: `launch_entry(placeholder) -> dict` (research R11), `render_all(root) -> dict[str, str]` producing plugin.json, mcp.json, .claude-plugin/plugin.json, .mcp.json, gemini-extension.json, commands/secscan.toml (via `GeminiAdapter.render_entrypoint(render_skill("tools"), "secscan")`), skills/secscan/SKILL.md (`render_skill("tools")`); canonical JSON via `store.canonical_json` with 2-space indent; `check(root) -> list[str]` of stale paths; `write_all(root)` — makes T026/T027 pass (FR-018, research R8)
- [X] T033 [US1] Run `python -c 'from installer.plugin import write_all; write_all(".")'` (T032; the `secscan plugin render` CLI arrives in T035) and commit the seven generated files at the repository root: plugin.json, mcp.json, .claude-plugin/plugin.json, .mcp.json, gemini-extension.json, commands/secscan.toml, skills/secscan/SKILL.md; add `commands/` and `skills/` to the scanner's own-payload exclusion list if `iter_source_files` would otherwise enumerate them when secscan scans itself (Principle VI "scanner ignores itself")
- [X] T034 [US1] src/installer/plugin.py, register half: `user_record_path()`, `read_record`/`write_record` (data-model.md §3), `register(host, root, *, force=False, env=os.environ, run=subprocess.run) -> RegisterResult` implementing JSON merge (`json-merge`) or host CLI (`host-cli`) per the adapter descriptor, Windsurf absolute-root substitution, downgrade check via `installer.upgrade.version_tuple`, `provision(root)` running `uv sync --extra plugin` when `uv` is on PATH else returning the manual hint — makes T029 pass (FR-013, FR-014, FR-016)
- [X] T035 [US1] src/installer/cli.py: `plugin` group with `render [--root]` and `check [--root]` (exit 1 listing `stale: <path>` + hint); `init` gains `--plugin` and `--plugin-root`; `--plugin` with `--ai agents` → `UsageError`; with `--plugin` call `plugin.provision` then `plugin.register`, print the contracts/cli-plugin.md §3 block, skip `core.install` entirely, then run today's init report unless `--no-init`; `secscan agents` gains the install-forms column and trailing generic-route line; `secscan status` prints user-level plugin installs from the record — makes T030 pass (FR-013, FR-017)
- [X] T036 [US1] Default `--plugin-root` discovery in src/installer/plugin.py: walk `Path(__file__).resolve().parents` for a directory containing `plugin.json` whose `name == "secscan"`; error "run from a secscan checkout or pass --plugin-root" otherwise (contracts/cli-plugin.md §3)

**Checkpoint**: `secscan plugin check` exits 0; `pytest -q tests/unit/test_plugin_render.py tests/contract/test_plugin_manifests.py tests/integration/test_plugin_parity.py tests/unit/test_plugin_register.py tests/integration/test_install_matrix.py` green; quickstart.md §5 manual checks performed on the hosts available and recorded in the PR.

---

## Phase 5: US3 — Skill and plugin surfaces stay one product (P2)

**Goal**: precedence and delegation when a project carries a skill install; corrupt
install handling; the drift gate is part of the verification routine.

**Independent Test**: tests/integration/test_plugin_delegation.py; quickstart.md §6–§7.

**Tests (fail first)**

- [X] T037 [P] [US3] tests/integration/test_plugin_delegation.py: install the skill form into a fixture project, then call the tool handlers — `status`/`run` report `driver: {form: "skill", delegated: true, tool_version: <pinned>, plugin_version: TOOL_VERSION}`; with `scripts/pipeline/mcp_server.py` removed from the skill payload (simulating a pre-feature pin) the payload is driven through `pipeline.scan_cli` and the result carries `bound: "unsupported by pinned payload v…"`; with the file present it is driven through `pipeline.mcp_server --oneshot` and honours `time_budget_s`; subprocess stderr lines arrive via `notify`; the plugin's own `run_scan` is never called (monkeypatched sentinel); deleting `scripts/` from the skill dir → `state: error`, `reason: "corrupt skill install"`, `repair` names `secscan init … --ai <host>`; `get_request`/`list_requests`/`submit_answer` behave identically with and without the skill install (FR-015, spec edge cases)
- [X] T038 [P] [US3] tests/unit/test_mcp_server.py additions: `_detect_driver` picks the newest manifest when several hosts have skill installs and reports all in `driver.installs`; a manifest whose `entrypoint` file is missing → corrupt (FR-015)

**Implementation**

- [X] T039 [US3] src/pipeline/mcp_server.py: `_detect_driver(workdir)` via `installer.core.detect_installs`; `_delegate(tool, args, manifest, notify)` per contracts/cli-plugin.md §7 — `--oneshot` path when `<skill_dir>/scripts/pipeline/mcp_server.py` exists (file presence, never a `TOOL_VERSION` comparison — the version does not change between commits), else `scan_cli` exit-code/stdout/stderr mapping with `bound: unsupported…`; corrupt-manifest detection (missing `entrypoint`/`scripts/pipeline`); `tool_init`/`tool_run`/`tool_status`/`tool_report` delegate when a manifest exists — makes T037/T038 pass (FR-015)
- [X] T040 [US3] src/installer/core.py: `InstallResult.form` field defaulting to `"skill"` and rendered in `render()` only when `"plugin"`; `detect_installs` unchanged (no version constant is needed — T039 detects capability by file presence)
- [X] T041 [US3] AGENTS.md: add `secscan plugin check` to the Verification list; extend the naming table with the plugin surfaces (`plugin.json`/`mcp.json` at repo root, `secscan mcp`, `secscan_*` tool prefix, `[plugin]` extra); note the SKILL.md driver split and that committed plugin files are generated (constitution "Documentation currency")

**Checkpoint**: quickstart.md §6 and §7 reproduce; full `pytest -q` green.

---

## Phase 6: Polish & cross-cutting

- [X] T042 [P] docs/agent-integration.md: "Two install forms" section; per-host table (layout loaded, install command, registration file, invocation) from research R2; precedence rule (project skill install wins, delegation, `bound` caveat); Windsurf MCP-only note; pre-provisioning with `uv sync --extra plugin` and offline note (FR-017, research R11)
- [X] T043 [P] docs/cli-reference.md: `secscan mcp`, `secscan plugin render|check`, `init --plugin/--plugin-root`, `agents` forms column, `status` plugin-installs line, the lock refusal message; exit codes table explicitly "unchanged" (FR-010)
- [X] T044 [P] docs/configuration.md: `plugin.run_bound_s` + `SECSCAN_PLUGIN_RUN_BOUND_S`; docs/artifacts.md: `run.lock` ("not an artifact", removed on exit, stale-pid reclaim) and `handoff/responses/` written by `secscan_submit_answer`; docs/getting-started.md: "install as a plugin" path beside the skill path
- [X] T045 [P] README.md: Status header, install section (skill or plugin, per-host one-liners), Roadmap entry for 018 marked shipped, `.secscan/` layout gains `run.lock`, exit-code list unchanged (constitution "Honest documentation")
- [X] T046 [P] src/skill_core/SKILL.md core body: **no change made** — the skill-form render is golden-frozen (T008, FR-001 "unchanged in behaviour"), so a sentence shared by both renders would break that guarantee; the plugin's own driver text (`drivers/tools.md`) already explains the tool surface, and the per-project skill keeps its exact pre-feature wording (FR-018 satisfied by the render/check gate)
- [X] T047 tests/integration/test_determinism.py and tests/contract/test_artifact_redaction.py: assert `run.lock` is absent after a completed run, exclude it from the two-run comparison glob like `scan.log`, include committed plugin files and every MCP result text in the redaction sweep (Safety Invariants table)
- [X] T048 `pytest -q -m slow` on the large-repository fixture through the tool handlers with the default 45 s bound: assert every `run` call returns within bound + one un-checkpointable stage, the scan settles over repeated calls, no lost work, artifacts equal a single CLI run (SC-005)
- [X] T049 Run the full quickstart.md end to end (`pytest -q` → 1540 passed, `pytest -q -m slow` → 2 passed, `ruff check src tests` clean, `secscan plugin check` clean, §2 base-venv payload check, §3–§4 via the lifecycle/parity tests, §6–§7 via delegation/render tests); `git status` shows only intended files. **§5 manual per-host loading checks are NOT done here** (no hosts in this environment) — to be recorded in the PR description by whoever runs them

---

## Dependencies & Execution Order

- **Phase 1 → Phase 2**: T001 (extra + package-data) before anything imports `mcp` or reads `drivers/`; T002/T003 parallel.
- **Phase 2 is blocking**: T010–T017 must be green before Phase 3 starts (the handlers call `run_scan(deadline=…)`, the lock, `answers_io`, `McpSink`, `render_skill`).
  - T010 → T011 (deadline threaded into batch/triage) → T013 (CLI lock message needs T012).
  - T017 depends on T008's golden capture happening **first** (capture before split).
- **Phase 3 (US2)** → **Phase 4 (US1)**: the committed plugin skill (T033) renders `drivers/tools.md`, whose wording is finalised against the implemented tools (T025); T032's `mcp.json` launch reference targets the `secscan mcp` command (T024).
- **Phase 4 → Phase 5 (US3)**: delegation (T039) reuses the handlers (T022) and `detect_installs`; `--oneshot` (T023) must exist for the same-version delegation path.
- **Phase 6** after all stories; T046 re-renders committed files, so it precedes T049.

### Parallel opportunities

- Phase 2 tests T004–T009 are independent files → run together; implementations T012, T014, T015, T016 touch different files → together; T010/T011 sequential.
- Phase 3: T018–T021 together; T022 then T023/T024 together.
- Phase 4: T026–T030 (incl. T027a) together; T031 and T032 together (T032 reads T031's descriptors only for `root_placeholder`, a constant — stub acceptable); T034 after T031; T035 after T032/T034.
- Phase 5: T037/T038 together; T039/T040 together.
- Phase 6: T042–T046 together; T047 after T046; T048/T049 last.

```bash
# Phase 2 tests in one go
Task: tests/unit/test_run_deadline.py   Task: tests/unit/test_run_lock.py
Task: tests/unit/test_answers_io.py     Task: tests/unit/test_progress.py (McpSink)
Task: tests/unit/test_config_plugin.py  Task: golden capture in tests/integration/test_install_matrix.py

# Phase 4 tests in one go
Task: tests/unit/test_plugin_render.py         Task: tests/contract/test_plugin_manifests.py
Task: tests/integration/test_plugin_parity.py  Task: tests/unit/test_plugin_register.py
Task: tests/integration/test_install_matrix.py::test_plugin_form
```

---

## Implementation Strategy

**MVP = Phase 1 + Phase 2 + Phase 3 (US2)**: after T024 any MCP-capable host can attach
`secscan mcp` by hand (the "generic route") and run the whole lifecycle through tools —
User Story 2 is independently valuable and demonstrable with the MCP Inspector before a
single plugin manifest exists.

**Increment 2 = Phase 4 (US1)**: commit the plugin files and ship `init --plugin`; the
repo becomes installable on Cursor, Copilot, Devin, Claude Code and Gemini CLI by URL or
path. Validate with quickstart §5 on whichever hosts are available.

**Increment 3 = Phase 5 (US3)**: precedence/delegation and the drift gate in the
verification routine. Then Phase 6 documentation — a constitution gate, not optional.

Stop at each checkpoint: the full suite must stay green and `secscan run` must be
byte-identical to today at every stop (T008 golden, T013 summary lines, T047).

---

## Notes

- Every task cites the FR/SC/research item it discharges; `/speckit-analyze` checks
  coverage against spec.md.
- No task edits `report.json`/`usage.json`/`state.json` schemas: the install form is
  reported only in tool results (spec planning amendment).
- Nothing here writes into a scanned project beyond `.secscan/` and the existing
  optional `.gitignore` line; T030 asserts it for every host.
