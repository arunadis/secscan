"""MCP tool provider — the plugin form of secscan (feature 018).

Two layers, deliberately separate:

* **handlers** (``tool_*``): plain functions ``(args, *, notify, clock, transport)
  -> envelope`` that call exactly what the CLI calls (``run_init``, ``run_scan``,
  ``latest_report``) and map the outcome onto the closed ``state`` vocabulary of
  contracts/mcp-tools.md. They import nothing from the ``mcp`` SDK, so a copied
  skill payload can run them (``--oneshot``) without the plugin extra (FR-023).
* **serving** (``build_app``/``main``): registers the handlers as MCP tools on the
  official SDK's ``MCPServer`` over stdio, plus the ``secscan`` prompt and read-only
  payload resources. Imported lazily.

The server is stateless: every tool takes ``workdir`` and all state lives in that
root's ``.secscan/``. It never writes to stderr during a tool call — progress goes
through ``McpSink`` as host notifications and to ``scan.log`` — and never opens a
network connection of its own (FR-009, FR-021).

When the project already carries a skill install, the tool provider *delegates*
to that pinned payload by subprocess and never runs its own engine against the
project (FR-015; research R9).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pipeline.state import SCAN_DIR_NAME, TOOL_VERSION

SERVER_NAME = "secscan"
TOOL_PREFIX = "secscan_"
TOOL_NAMES = (
    "init", "run", "status", "list_requests", "get_request", "submit_answer", "report",
)
STATES = (
    "ok", "not_ready", "awaiting_reasoning", "in_progress", "locked",
    "report_defect", "endpoint_failed", "rejected", "error",
)

Notify = Callable[[str, str], None]
ProgressFn = Callable[[float, float | None, str], None]


# ------------------------------------------------------------------ helpers


def _workdir(args: dict[str, Any]) -> Path:
    raw = args.get("workdir")
    if not raw or not isinstance(raw, str):
        raise ValueError("workdir is required (the scan root, same meaning as --workdir)")
    return Path(raw).expanduser().resolve()


def _redactor_for(store_dir: Path) -> Any:
    from pipeline import run as run_mod
    from pipeline.redact import Redactor

    try:
        from config.loader import load

        config = load(store_dir)
        return Redactor(config.redaction_patterns, **run_mod._entropy_kwargs(config))
    except Exception:  # noqa: BLE001 — unconfigured project: default rules only
        return Redactor([])


def _redact(store_dir: Path, text: str) -> str:
    return _redactor_for(store_dir).redact(text).text


def _envelope(state: str, driver: dict[str, Any], **fields: Any) -> dict[str, Any]:
    assert state in STATES, state
    return {"state": state, "tool_version": TOOL_VERSION, "driver": driver, **fields}


def _plugin_driver() -> dict[str, Any]:
    return {
        "form": "plugin",
        "tool_version": TOOL_VERSION,
        "plugin_version": TOOL_VERSION,
        "delegated": False,
    }


def _error(driver: dict[str, Any], store_dir: Path, message: str, **fields: Any) -> dict[str, Any]:
    return _envelope("error", driver, message=_redact(store_dir, message), **fields)


# ------------------------------------------------------------- delegation


class CorruptInstall(RuntimeError):
    def __init__(self, manifest: dict[str, Any], missing: str) -> None:
        self.manifest = manifest
        self.missing = missing
        super().__init__(f"corrupt skill install for {manifest.get('agent')}: missing {missing}")


MANIFEST_NAME = ".install-manifest.json"


def _find_installs(workdir: Path) -> list[tuple[Path, dict[str, Any]]]:
    """(skill_dir, manifest) for every per-project skill install of secscan.

    Deliberately independent of the ``installer`` package: this module ships in the
    copied payload, which must stay free of source-tree imports. The install layout
    is ``<agent dir>/skills/secscan/`` for every adapter except Gemini
    (``.gemini/commands/secscan/``); the manifest names the agent and entrypoint.
    """
    found: list[tuple[Path, dict[str, Any]]] = []
    candidates = sorted(
        {
            *workdir.glob(f".*/skills/secscan/{MANIFEST_NAME}"),
            *workdir.glob(f".gemini/commands/secscan/{MANIFEST_NAME}"),
        }
    )
    for path in candidates:
        try:
            manifest = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if isinstance(manifest, dict) and manifest.get("skill") == "secscan":
            found.append((path.parent, manifest))
    return found


def _version_tuple(value: str) -> tuple[int, ...]:
    out: list[int] = []
    for chunk in str(value).split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


def _detect_driver(
    workdir: Path, *, allow_delegation: bool = True
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """(driver envelope field, manifest to delegate to or None) — FR-015.

    ``allow_delegation=False`` is the ``--oneshot`` path: this process *is* the
    pinned payload, so it reports the skill form and never delegates again (which
    would recurse into itself).
    """
    installs = _find_installs(workdir)
    if not installs:
        return _plugin_driver(), None
    if not allow_delegation:
        driver = _plugin_driver()
        driver["form"] = "skill"
        return driver, None
    # Newest pinned version drives; every install is reported.
    skill_dir, manifest = max(
        installs, key=lambda item: _version_tuple(str(item[1].get("tool_version", "0")))
    )
    manifest = dict(manifest)
    manifest["_skill_dir"] = str(skill_dir)
    driver = {
        "form": "skill",
        "tool_version": str(manifest.get("tool_version", "")),
        "plugin_version": TOOL_VERSION,
        "delegated": True,
        "installs": [
            {"agent": m.get("agent"), "tool_version": m.get("tool_version")}
            for _d, m in sorted(installs, key=lambda item: str(item[1].get("agent")))
        ],
    }
    return driver, manifest


def _check_install(workdir: Path, manifest: dict[str, Any]) -> Path:
    skill_dir = Path(manifest["_skill_dir"])
    entrypoint = skill_dir / str(manifest.get("entrypoint") or "SKILL.md")
    if not entrypoint.exists():
        raise CorruptInstall(manifest, str(entrypoint))
    scripts = skill_dir / "scripts" / "pipeline"
    if not scripts.is_dir():
        raise CorruptInstall(manifest, str(scripts))
    return skill_dir


def _supports_oneshot(skill_dir: Path) -> bool:
    # File presence, never a TOOL_VERSION comparison: the version does not change
    # between commits, so it cannot tell a pre-feature payload from a current one.
    return (skill_dir / "scripts" / "pipeline" / "mcp_server.py").is_file()


def _delegate(
    tool: str,
    args: dict[str, Any],
    workdir: Path,
    manifest: dict[str, Any],
    driver: dict[str, Any],
    notify: Notify | None,
    *,
    run: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    store_dir = workdir / SCAN_DIR_NAME
    try:
        skill_dir = _check_install(workdir, manifest)
    except CorruptInstall as exc:
        return _error(
            driver, store_dir, str(exc),
            reason="corrupt skill install",
            repair=f"secscan init {workdir} --ai {manifest.get('agent')}",
        )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(skill_dir / "scripts")

    if _supports_oneshot(skill_dir):
        proc = run(
            [sys.executable, "-m", "pipeline.mcp_server", "--oneshot", tool, json.dumps(args)],
            capture_output=True, text=True, env=env, check=False,
        )
        for line in proc.stderr.splitlines():
            if notify is not None:
                notify("info", line)
        try:
            result = json.loads(proc.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return _error(driver, store_dir, "delegated payload returned no result envelope",
                          reason="delegation failed")
        result["driver"] = driver
        result["tool_version"] = driver["tool_version"]
        return result

    # Pre-feature payload: drive its CLI and map exit codes; the bound cannot be honoured.
    from pipeline import scan_cli

    bound_note = f"unsupported by pinned payload v{driver['tool_version']}"
    if tool == "init":
        cmd = ["init", "--workdir", str(workdir), "--no-input"]
        if args.get("install"):
            cmd += ["--install", str(args["install"])]
        if args.get("yes"):
            cmd.append("--yes")
    elif tool == "run":
        cmd = ["run", "--workdir", str(workdir), "-q"]
        if args.get("profile"):
            cmd += ["--profile", str(args["profile"])]
        if args.get("full"):
            cmd.append("--full")
        if args.get("segment"):
            cmd += ["--segment", str(args["segment"])]
        if args.get("policy"):
            cmd += ["--policy", str(args["policy"])]
        for key, value in _flatten(args.get("set") or {}):
            cmd += ["--set", f"{key}={value}"]
    elif tool == "status":
        cmd = ["status", "--workdir", str(workdir)]
    else:  # report
        fmt = str(args.get("format") or "markdown")
        cmd = ["report", "--workdir", str(workdir), "--format", fmt]
        if args.get("repo"):
            cmd += ["--repo", str(args["repo"])]
    proc = run([sys.executable, "-m", "pipeline.scan_cli", *cmd],
               capture_output=True, text=True, env=env, check=False)
    for line in proc.stderr.splitlines():
        if notify is not None:
            notify("info", line)
    stdout = proc.stdout.rstrip("\n")
    code = proc.returncode
    if tool == "run":
        if code == scan_cli.EXIT_OK:
            return _envelope("ok", driver, summary=stdout.splitlines(), bound=bound_note)
        if code == scan_cli.EXIT_REPORT_DEFECT:
            return _envelope("report_defect", driver, summary=stdout.splitlines(), bound=bound_note)
        if code == scan_cli.EXIT_AGENT_HANDOFF:
            return _awaiting(driver, store_dir, bound=bound_note)
        if "re-run to resume" in proc.stderr:
            return _envelope("endpoint_failed", driver, message=_redact(store_dir, proc.stderr),
                             resume=True, bound=bound_note)
        if "scan already running" in proc.stderr:
            from pipeline.state import read_run_lock

            return _envelope("locked", driver, lock=read_run_lock(store_dir) or {},
                             bound=bound_note)
        return _error(driver, store_dir, proc.stderr.strip() or f"exit {code}", bound=bound_note)
    if tool == "init":
        state = "ok" if code == scan_cli.EXIT_OK else "not_ready"
        return _envelope(state, driver, report=stdout, config_schema_changed=False,
                         bound=bound_note)
    if tool == "status":
        return _envelope("ok" if code == scan_cli.EXIT_OK else "not_ready", driver,
                         text=stdout, bound=bound_note)
    if code != scan_cli.EXIT_OK:
        return _error(driver, store_dir, proc.stderr.strip() or f"exit {code}", bound=bound_note)
    return _envelope("ok", driver, content=stdout, bound=bound_note)


def _flatten(node: dict[str, Any], prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    for key, value in sorted(node.items()):
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            out.extend(_flatten(value, path))
        else:
            out.append((path, json.dumps(value) if isinstance(value, bool) else value))
    return [(k, str(v).lower() if v in ("true", "false") else v) for k, v in out]


def _awaiting(driver: dict[str, Any], store_dir: Path, **fields: Any) -> dict[str, Any]:
    from pipeline import answers_io

    handoff = store_dir / "handoff"
    pending = sorted(
        r["request_id"] for r in answers_io.list_requests(handoff) if not r["answered"]
    )
    return _envelope(
        "awaiting_reasoning", driver,
        pending=pending,
        requests_dir=str(handoff / "requests"),
        next="call secscan_get_request for each id, secscan_submit_answer, then secscan_run",
        **fields,
    )


# ------------------------------------------------------------------ handlers


def tool_init(
    args: dict[str, Any], *, notify: Notify | None = None, clock: Any = None,
    transport: Any = None, allow_delegation: bool = True, run: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    workdir = _workdir(args)
    store_dir = workdir / SCAN_DIR_NAME
    driver, manifest = _detect_driver(workdir, allow_delegation=allow_delegation)
    if manifest is not None:
        return _delegate("init", args, workdir, manifest, driver, notify, run=run)

    from config.loader import CONFIG_VERSION
    from pipeline.init_cmd import run_init

    changed = False
    note = None
    config_path = store_dir / "config.yaml"
    if config_path.exists():
        try:
            import yaml

            found = str((yaml.safe_load(config_path.read_text()) or {}).get("version", ""))
        except Exception:  # noqa: BLE001
            found = ""
        if found and found != str(CONFIG_VERSION):
            changed = True
            note = (
                f"configuration schema changed ({found} -> {CONFIG_VERSION}); review "
                f"{config_path} — new defaults are not applied silently"
            )
    report = run_init(
        workdir, install=args.get("install"), yes=bool(args.get("yes")),
        no_input=not (args.get("install") or args.get("yes")),
    )
    fields: dict[str, Any] = {"report": report.render(), "config_schema_changed": changed}
    if note:
        fields["message"] = note
    return _envelope("ok" if report.ready else "not_ready", driver, **fields)


def tool_run(
    args: dict[str, Any], *, notify: Notify | None = None, clock: Any = None,
    transport: Any = None, allow_delegation: bool = True,
    progress_callback: ProgressFn | None = None, run: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    workdir = _workdir(args)
    store_dir = workdir / SCAN_DIR_NAME
    driver, manifest = _detect_driver(workdir, allow_delegation=allow_delegation)
    if manifest is not None:
        return _delegate("run", args, workdir, manifest, driver, notify, run=run)

    from config.loader import ConfigError, ConfigNotFound, load
    from pipeline import progress, scan_cli
    from pipeline import run as run_mod
    from pipeline.llm_client import AgentHandoff, ScanPaused
    from pipeline.providers import EndpointError
    from pipeline.state import LOG_FILE_NAME, ScanLocked, read_run_lock

    clock = clock or time.monotonic
    environ: dict[str, str] | None = None
    if args.get("policy"):
        environ = dict(os.environ)
        environ["SECSCAN_EXECUTION_POLICY_MODE"] = str(args["policy"])
    try:
        config = load(store_dir, environ=environ)
    except (ConfigNotFound, ConfigError) as exc:
        return _error(driver, store_dir, str(exc))

    live = read_run_lock(store_dir)
    if live is not None:
        return _envelope("locked", driver, lock=live)

    bound = args.get("time_budget_s")
    if bound is not None:
        if not isinstance(bound, int) or isinstance(bound, bool) or not (5 <= bound <= 3600):
            return _error(driver, store_dir, "time_budget_s must be an integer between 5 and 3600")
    else:
        bound = config.plugin_run_bound_s
    started = clock()
    deadline = started + float(bound)

    reporter = progress.build_reporter(
        progress.OutputLevel.from_str(config.output_level),
        log_path=store_dir / LOG_FILE_NAME,
        mcp_notify=notify or (lambda level, text: None),
        mcp_progress=progress_callback,
    )
    overrides = args.get("set") or None
    try:
        result = run_mod.run_scan(
            workdir,
            profile=args.get("profile"),
            overrides=overrides,
            full=bool(args.get("full")),
            only_segment=args.get("segment"),
            environ=environ,
            progress=reporter,
            transport=transport,
            clock=clock,
            deadline=deadline,
            driver="plugin",
        )
    except ScanLocked as exc:
        reporter.close()
        return _envelope("locked", driver, lock=exc.lock)
    except AgentHandoff as handoff:
        reporter.paused(len(handoff.pending))
        reporter.close()
        return _awaiting(driver, store_dir)
    except ScanPaused as paused:
        reporter.close()
        elapsed = clock() - started
        return _envelope(
            "in_progress", driver,
            checkpoint=paused.checkpoint(),
            elapsed_s=round(elapsed, 3),
            overran_bound=elapsed > float(bound) + 1e-9,
            bound_s=bound,
            next="call secscan_run again",
        )
    except EndpointError as exc:
        reporter.failed(_redact(store_dir, str(exc)))
        reporter.close()
        return _envelope("endpoint_failed", driver, message=_redact(store_dir, str(exc)),
                         resume=True)
    except (ConfigError, ValueError) as exc:
        reporter.failed(_redact(store_dir, str(exc)))
        reporter.close()
        return _error(driver, store_dir, str(exc))
    except Exception as exc:  # noqa: BLE001 — never a traceback to the host
        reporter.failed(_redact(store_dir, str(exc)))
        reporter.close()
        return _error(driver, store_dir, f"{type(exc).__name__}: {exc}")
    reporter.close()

    fields = {
        "scan_id": result.scan_id,
        "report_path": str(result.report_path),
        "findings_reported": len(result.reported_findings),
        "coverage_notes": len(result.warnings),
        "summary": scan_cli.summary_lines(result),
    }
    quarantined = scan_cli.quarantined_sections(result)
    if quarantined:
        return _envelope("report_defect", driver, quarantined_sections=quarantined, **fields)
    return _envelope("ok", driver, **fields)


def tool_status(
    args: dict[str, Any], *, notify: Notify | None = None, clock: Any = None,
    transport: Any = None, allow_delegation: bool = True, run: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    workdir = _workdir(args)
    store_dir = workdir / SCAN_DIR_NAME
    driver, manifest = _detect_driver(workdir, allow_delegation=allow_delegation)
    if manifest is not None:
        return _delegate("status", args, workdir, manifest, driver, notify, run=run)

    from pipeline import answers_io
    from pipeline.state import ArtifactStore, read_run_lock

    configured = (store_dir / "config.yaml").exists()
    fields: dict[str, Any] = {"workdir": str(workdir), "configured": configured}
    if not configured:
        return _envelope("not_ready", driver, message="run secscan_init first", **fields)
    store = ArtifactStore(workdir)
    listing = answers_io.list_requests(store_dir / "handoff")
    reports = sorted((store_dir / "reports").glob("*.md"))
    fields.update(
        scan_id=store.scan_id,
        stages=store.stage_summary(),
        handoff={
            "pending": sum(1 for r in listing if not r["answered"]),
            "answered": sum(1 for r in listing if r["answered"]),
        },
        lock=read_run_lock(store_dir),
        latest_report=str(reports[-1]) if reports else None,
    )
    return _envelope("ok", driver, **fields)


def tool_list_requests(args: dict[str, Any], **_: Any) -> dict[str, Any]:
    from pipeline import answers_io

    workdir = _workdir(args)
    driver, _manifest = _detect_driver(workdir)
    return _envelope(
        "ok", driver, requests=answers_io.list_requests(workdir / SCAN_DIR_NAME / "handoff")
    )


def tool_get_request(args: dict[str, Any], **_: Any) -> dict[str, Any]:
    from pipeline import answers_io

    workdir = _workdir(args)
    store_dir = workdir / SCAN_DIR_NAME
    driver, _manifest = _detect_driver(workdir)
    request_id = str(args.get("request_id") or "")
    handoff = store_dir / "handoff"
    try:
        doc = answers_io.resolve_request(handoff, request_id)
    except answers_io.UnknownRequest:
        return _error(driver, store_dir, f"unknown request id {request_id!r}")
    kind = answers_io.answer_kind(doc)
    return _envelope(
        "ok", driver,
        request=doc,
        answered=answers_io.is_answered(handoff, request_id),
        answer_schema=kind,
        guidance=answers_io.guidance_for(kind),
    )


def tool_submit_answer(args: dict[str, Any], **_: Any) -> dict[str, Any]:
    from pipeline import answers_io

    workdir = _workdir(args)
    store_dir = workdir / SCAN_DIR_NAME
    driver, _manifest = _detect_driver(workdir)
    request_id = str(args.get("request_id") or "")
    content = args.get("content")
    if content is None or (not isinstance(content, str | dict | list)):
        return _error(driver, store_dir, "content must be a string or a JSON object")
    handoff = store_dir / "handoff"
    try:
        outcome = answers_io.submit(handoff, request_id, content,
                                    overwrite=bool(args.get("overwrite")))
    except answers_io.UnknownRequest:
        return _error(driver, store_dir, f"unknown request id {request_id!r}")
    except answers_io.AlreadyAnswered:
        return _error(driver, store_dir,
                      f"request {request_id!r} already has a response; pass overwrite=true")
    if outcome.errors:
        return _envelope("rejected", driver, errors=outcome.errors,
                         answer_schema=outcome.kind)
    return _envelope("ok", driver, response_path=str(outcome.path),
                     next="call secscan_run to resume")


def tool_report(
    args: dict[str, Any], *, notify: Notify | None = None, clock: Any = None,
    transport: Any = None, allow_delegation: bool = True, run: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    workdir = _workdir(args)
    store_dir = workdir / SCAN_DIR_NAME
    driver, manifest = _detect_driver(workdir, allow_delegation=allow_delegation)
    if manifest is not None:
        return _delegate("report", args, workdir, manifest, driver, notify, run=run)

    from pipeline.report_view import latest_report, render, reports_dir

    fmt = str(args.get("format") or "markdown")
    if fmt not in ("markdown", "json", "html"):
        return _error(driver, store_dir, "format must be markdown, json or html")
    try:
        report = latest_report(workdir)
        content = render(report, repo=args.get("repo"), output_format=fmt)
    except FileNotFoundError as exc:
        return _error(driver, store_dir, str(exc))
    except ValueError as exc:
        return _error(driver, store_dir, str(exc))
    reports = sorted(reports_dir(workdir).glob("*.json"))
    return _envelope("ok", driver, report_path=str(reports[-1]) if reports else None,
                     content=content)


HANDLERS: dict[str, Callable[..., dict[str, Any]]] = {
    "init": tool_init,
    "run": tool_run,
    "status": tool_status,
    "list_requests": tool_list_requests,
    "get_request": tool_get_request,
    "submit_answer": tool_submit_answer,
    "report": tool_report,
}


def call_tool(name: str, args: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    """Dispatch by short name with argument errors mapped to ``state: error``."""
    handler = HANDLERS[name]
    try:
        return handler(args, **kwargs)
    except ValueError as exc:
        return _envelope("error", _plugin_driver(), message=str(exc))


# ------------------------------------------------------------ guidance text


def tool_descriptions() -> dict[str, str]:
    return {
        "init": "Generate .secscan/config.yaml for the scan root and check the environment "
                "(first run only). Never prompts.",
        "run": "Run or resume the security scan of the scan root. Returns a closed state: ok, "
               "awaiting_reasoning (answer the pending requests then call again), in_progress "
               "(bounded call paused at a checkpoint; call again), locked, endpoint_failed, "
               "report_defect or error.",
        "status": "Stage states, pending reasoning requests, run lock and the engine version "
                  "driving this scan root.",
        "list_requests": "Pending reasoning requests for the scan root, with an answered flag.",
        "get_request": "One reasoning request: prompt plus the bounded, redacted context "
                       "packet, and which answer schema applies.",
        "submit_answer": "Submit your answer JSON for one request. Validated against the "
                         "applicable schema before anything is written; a rejection lists "
                         "errors and writes nothing.",
        "report": "The latest report for the scan root (markdown, json or html), optionally "
                  "filtered to one repository.",
    }


# --------------------------------------------------------------- serving


def build_app() -> Any:
    """Assemble the MCP server (requires the ``plugin`` extra); see ``mcp_app``."""
    from pipeline.mcp_app import build_app as _build

    return _build()


MISSING_EXTRA_HINT = (
    "secscan mcp needs the plugin extra: install with  uv sync --extra plugin  "
    '(or  pip install "secscan[plugin]")'
)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--oneshot"]:
        if len(argv) != 3 or argv[1] not in HANDLERS:
            print(f"usage: --oneshot <{'|'.join(TOOL_NAMES)}> <json-args>", file=sys.stderr)
            return 2
        args = json.loads(argv[2])
        # Progress lines go to stderr for the delegating parent to forward.
        result = call_tool(
            argv[1], args,
            notify=lambda level, text: print(text, file=sys.stderr),
            allow_delegation=False,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    try:
        app = build_app()
    except ImportError:
        print(MISSING_EXTRA_HINT, file=sys.stderr)
        return 1
    app.run("stdio")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI wrapper
    sys.exit(main())
