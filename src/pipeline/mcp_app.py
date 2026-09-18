"""MCP serving layer for the plugin form (feature 018).

Kept apart from ``pipeline.mcp_server`` so that (a) the handler module never imports
the ``mcp`` SDK — a copied skill payload runs ``--oneshot`` without the plugin extra
(FR-023) — and (b) tool signatures carry real (non-deferred) annotations, which the
SDK evaluates at registration time.
"""

import warnings
from typing import Any

from installer.agents.base import render_skill, split_frontmatter
from pipeline.mcp_server import (
    SERVER_NAME,
    TOOL_PREFIX,
    Notify,
    ProgressFn,
    call_tool,
    tool_descriptions,
)
from pipeline.state import TOOL_VERSION


def prompt_text() -> str:
    """The plugin-form skill body — identical to the committed skills/secscan/SKILL.md."""
    _front, body = split_frontmatter(render_skill("tools"))
    return body.rstrip() + "\n"


def build_app() -> Any:
    """Assemble the MCP server (requires the ``plugin`` extra)."""
    import anyio
    from mcp.server.mcpserver import Context, MCPServer
    from mcp.shared.exceptions import MCPDeprecationWarning

    from pipeline import resources

    app = MCPServer(
        SERVER_NAME,
        version=TOOL_VERSION,
        instructions=(
            "secscan: hierarchical, context-bounded security scanning. Call the "
            "secscan prompt for the full workflow; every tool takes workdir."
        ),
    )
    descriptions = tool_descriptions()

    def _has_token(ctx: Context) -> bool:
        try:
            meta = ctx.request_context.meta or {}
        except ValueError:  # outside a request
            return False
        token = meta.get("progress_token", meta.get("progressToken"))
        return token is not None and not isinstance(token, bool)

    def _notifier(ctx: Context) -> Notify:
        # Every rendered line goes out as ``notifications/progress`` with a
        # monotonically increasing counter and the line as ``message`` — the
        # current-spec channel; the SDK makes it a no-op when the caller sent no
        # progress token. For callers without a token the logging capability is
        # the only remaining channel; it is deprecated as of 2026-07-28 (SEP-2577)
        # but still delivered, so it is used as the fallback with its deprecation
        # warning silenced — a warning printed to stderr mid-call would itself
        # violate the no-terminal-output rule (FR-009).
        has_token = _has_token(ctx)
        counter = [0]

        def notify(level: str, text: str) -> None:
            counter[0] += 1
            anyio.from_thread.run(ctx.report_progress, float(counter[0]), None, text)
            if has_token:
                return
            fn = ctx.warning if level == "warning" else ctx.info
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", MCPDeprecationWarning)
                anyio.from_thread.run(fn, text)

        return notify

    def _progress(ctx: Context) -> ProgressFn | None:
        # Indexed ``i/N`` events already travel through ``notify`` above; a second
        # progress stream would only interleave two counters.
        return None

    @app.tool(name=f"{TOOL_PREFIX}init", description=descriptions["init"])
    def secscan_init(workdir: str, ctx: Context, install: str | None = None,
                     yes: bool = False) -> dict[str, Any]:
        return call_tool("init", {"workdir": workdir, "install": install, "yes": yes},
                         notify=_notifier(ctx))

    @app.tool(name=f"{TOOL_PREFIX}run", description=descriptions["run"])
    def secscan_run(workdir: str, ctx: Context, profile: str | None = None, full: bool = False,
                    segment: str | None = None, set: dict[str, Any] | None = None,  # noqa: A002
                    policy: str | None = None, time_budget_s: int | None = None) -> dict[str, Any]:
        args = {"workdir": workdir, "profile": profile, "full": full, "segment": segment,
                "set": set, "policy": policy, "time_budget_s": time_budget_s}
        return call_tool("run", args, notify=_notifier(ctx), progress_callback=_progress(ctx))

    @app.tool(name=f"{TOOL_PREFIX}status", description=descriptions["status"])
    def secscan_status(workdir: str, ctx: Context) -> dict[str, Any]:
        return call_tool("status", {"workdir": workdir}, notify=_notifier(ctx))

    @app.tool(name=f"{TOOL_PREFIX}list_requests", description=descriptions["list_requests"])
    def secscan_list_requests(workdir: str) -> dict[str, Any]:
        return call_tool("list_requests", {"workdir": workdir})

    @app.tool(name=f"{TOOL_PREFIX}get_request", description=descriptions["get_request"])
    def secscan_get_request(workdir: str, request_id: str) -> dict[str, Any]:
        return call_tool("get_request", {"workdir": workdir, "request_id": request_id})

    @app.tool(name=f"{TOOL_PREFIX}submit_answer", description=descriptions["submit_answer"])
    def secscan_submit_answer(workdir: str, request_id: str, content: str | dict[str, Any],
                              overwrite: bool = False) -> dict[str, Any]:
        return call_tool("submit_answer", {"workdir": workdir, "request_id": request_id,
                                           "content": content, "overwrite": overwrite})

    @app.tool(name=f"{TOOL_PREFIX}report", description=descriptions["report"])
    def secscan_report(workdir: str, ctx: Context, repo: str | None = None,
                       format: str = "markdown") -> dict[str, Any]:  # noqa: A002
        return call_tool("report", {"workdir": workdir, "repo": repo, "format": format},
                         notify=_notifier(ctx))

    @app.prompt(name=SERVER_NAME, description="The secscan security-scan workflow "
                                              "(same guidance as the installed skill).")
    def secscan_prompt() -> str:
        return prompt_text()

    prompts_dir = resources.prompts_dir()
    schema_dir = resources.schema_dir()

    @app.resource("secscan://prompts/{name}", mime_type="text/markdown")
    def prompt_resource(name: str) -> str:
        files = {p.stem: p for p in sorted(prompts_dir.glob("*.md"))}
        if name not in files:
            raise ValueError(f"unknown prompt {name!r}")
        return files[name].read_text()

    @app.resource("secscan://schemas/{name}", mime_type="application/json")
    def schema_resource(name: str) -> str:
        files = {p.stem: p for p in sorted(schema_dir.glob("*.json"))}
        if name not in files:
            raise ValueError(f"unknown schema {name!r}")
        return files[name].read_text()

    return app


