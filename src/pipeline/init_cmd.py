"""Init command: default configuration plus environment checks (FR-024).

Generates `.secscan/config.yaml` if absent (never clobbering an existing
one), then reports what is ready and what is missing:

* configuration validity (strict validation, so problems surface here not mid-scan)
* which analysis model will be used (agent-mediated by default — no key needed)
* credential presence, without ever printing the value (FR-025)
* which optional external scanner tools are installed

A scan is *ready* in the zero-config case: agent-mediated mode needs nothing.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from config import mode as mode_mod
from config.loader import (
    Config,
    ConfigError,
    config_path_for,
    default_config_yaml,
    load,
)
from pipeline.state import SCAN_DIR_NAME
from pipeline.tooling import credentials, discover, ecosystem, provision, registry
from pipeline.tooling.state import write_availability


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    #: informational checks do not block readiness
    required: bool = True

    @property
    def symbol(self) -> str:
        if self.ok:
            return "ok"
        return "MISSING" if self.required else "not found"


@dataclass
class InitReport:
    scan_dir: Path
    config_created: bool
    execution_mode: str
    checks: list[Check] = field(default_factory=list)
    #: registry-driven tool availability records (data-model.md)
    tooling: list[dict] = field(default_factory=list)
    #: the exact install list presented to the user before any installation ran
    install_plan: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return all(check.ok for check in self.checks if check.required)

    def render(self) -> str:
        width = max(len(c.name) for c in self.checks) if self.checks else 0
        lines = [
            f"secscan init — {self.scan_dir}",
            "",
            f"Configuration: {'created' if self.config_created else 'already present'}"
            f" ({config_path_for(self.scan_dir).name})",
            f"Analysis will run in: {self.execution_mode}",
            "",
            "Environment:",
        ]
        for check in self.checks:
            lines.append(f"  [{check.symbol:>9}] {check.name.ljust(width)}  {check.detail}")
        if self.tooling:
            lines.extend(["", "External tools:"])
            for record in self.tooling:
                version = record.get("version") or "version undetermined"
                detail = f": {record['detail']}" if record.get("detail") else ""
                lines.append(
                    f"  {record['tool_id']:<24} {record['source']:<17} {version}"
                    f"  (network: {record['network']}) — {record['decision']}{detail}"
                )
        if self.install_plan:
            lines.extend(["", "Install list presented:"])
            lines.extend(f"  - {item}" for item in self.install_plan)
        lines.append("")
        if self.ready:
            lines.append("Ready to scan.")
        else:
            lines.append("Not ready — resolve the items marked MISSING above, then re-run init.")
        return "\n".join(lines)


def run_init(
    project_root: Path | str,
    *,
    environ: dict[str, str] | None = None,
    install: str | None = None,
    yes: bool = False,
    no_input: bool = False,
    allow_keyless_nvd: bool = False,
    prompt: Callable[[str], str] | None = None,
    echo: Callable[[str], None] | None = None,
) -> InitReport:
    """Generate default config (if absent) and check the environment.

    External-tool consent model (FR-003): ``install`` names the subset
    (``all`` or comma-separated ids/numbers), ``yes`` confirms the full list,
    ``no_input`` never prompts and installs nothing. Interactive mode presents
    the exact list through ``echo`` and waits for ``prompt`` before anything
    installs.
    """
    project_root = Path(project_root).resolve()
    scan_dir = project_root / SCAN_DIR_NAME
    scan_dir.mkdir(parents=True, exist_ok=True)

    config_path = config_path_for(scan_dir)
    created = False
    if not config_path.exists():
        config_path.write_text(default_config_yaml())
        created = True

    checks: list[Check] = []

    # ---------------------------------------------------------- configuration
    config: Config | None = None
    try:
        config = load(scan_dir, environ=environ)
        checks.append(Check("configuration", True, f"valid ({config_path})"))
    except ConfigError as exc:
        checks.append(
            Check(
                "configuration",
                False,
                f"{len(exc.problems)} problem(s): " + "; ".join(exc.problems),
            )
        )

    # ------------------------------------------------------------ model access
    execution_mode = "unknown"
    if config is not None:
        try:
            resolution = mode_mod.resolve(config, environ=environ)
            # Includes "(default policy)" when batch was chosen by mode: auto (012, FR-023).
            execution_mode = resolution.mode_label
            checks.append(Check("analysis model", True, resolution.reason))
        except mode_mod.MissingCredential as exc:
            execution_mode = "endpoint (credential missing)"
            checks.append(
                Check("analysis model", False, "configured endpoint is unusable without a key")
            )
            checks.append(Check("credentials", False, str(exc).splitlines()[0]))
        else:
            status = mode_mod.credential_status(config, environ=environ)
            if not status["required"]:
                checks.append(
                    Check(
                        "credentials",
                        True,
                        "not required — agent-mediated mode uses this agent's own model",
                    )
                )
            else:
                checks.append(
                    Check(
                        "credentials",
                        bool(status["present"]),
                        f"${status['variable']} is set"
                        if status["present"]
                        else f"${status['variable']} is not set",
                    )
                )
            if resolution.unavailable_features:
                checks.append(
                    Check(
                        "cost features",
                        True,
                        "unavailable in this mode: "
                        + ", ".join(resolution.unavailable_features),
                        required=False,
                    )
                )
    else:
        checks.append(Check("analysis model", False, "cannot resolve until config is valid"))
        checks.append(Check("credentials", False, "cannot check until config is valid"))

    # ------------------------------------------- external tooling (feature 008)
    tooling_records, install_plan, tooling_note = _tooling_flow(
        project_root,
        config,
        environ=environ,
        install=install,
        yes=yes,
        no_input=no_input,
        allow_keyless_nvd=allow_keyless_nvd,
        prompt=prompt,
        echo=echo,
    )
    if tooling_note is not None:
        checks.append(Check("external tooling", True, tooling_note, required=False))
    for record in tooling_records:
        checks.append(
            Check(
                f"tool: {record['tool_id']}",
                record["source"] != "missing" or record["decision"] == "installed",
                (
                    f"{record['source']}"
                    + (f" {record['version']}" if record.get("version") else "")
                    + f" (network: {record['network']})"
                ),
                required=False,
            )
        )
        credential = record.get("credential")
        if credential is not None:
            # informational only: an NVD-key outcome never flips readiness
            spec = registry.CredentialSpec(
                env_var=credential["variable"],
                obtain_url="",
                absence_impact="",
            )
            checks.append(
                Check(
                    f"tool credential: {record['tool_id']}",
                    True,
                    credentials.report_line(
                        record["tool_id"], spec, credential["state"]
                    ),
                    required=False,
                )
            )

    # ------------------------------------------------------------- workspace
    if config is not None:
        if config.workspace_members:
            detail = (
                f"{len(config.workspace_members)} member(s) declared: "
                + ", ".join(m["name"] for m in config.workspace_members)
            )
        else:
            detail = "no manifest — members will be auto-discovered from the scan root"
        checks.append(Check("workspace", True, detail, required=False))

    return InitReport(
        scan_dir=scan_dir,
        config_created=created,
        execution_mode=execution_mode,
        checks=checks,
        tooling=tooling_records,
        install_plan=install_plan,
    )


def _workspace_roots(project_root: Path, config: Config | None) -> dict[str, Path]:
    """Member roots as the scanner sees them: config members or the root itself."""
    roots: dict[str, Path] = {}
    if config is not None:
        for member in config.workspace_members:
            candidate = Path(member["path"])
            roots[str(member["name"])] = (
                candidate if candidate.is_absolute() else (project_root / candidate).resolve()
            )
    if not roots:
        roots[project_root.name] = project_root
    return roots


def _tooling_flow(
    project_root: Path,
    config: Config | None,
    *,
    environ: dict[str, str] | None = None,
    install: str | None,
    yes: bool,
    no_input: bool,
    allow_keyless_nvd: bool = False,
    prompt: Callable[[str], str] | None,
    echo: Callable[[str], None] | None,
) -> tuple[list[dict], list[str], str | None]:
    """Detect ecosystems, map/inspect tools, and provision with consent.

    Returns ``(availability records, install plan as presented, note)`` where
    ``note`` is the honest no-ecosystem declaration when applicable. Provisioning
    follows contracts/cli.md: nothing installs before the list is presented and
    confirmed; project-provided tools never appear on the list.

    Credential-bearing tools (feature 009: currently the NVD-backed
    ``owasp-dependency-check``) additionally carry a ``credential`` outcome on
    their record: ``available`` when the declared env var is present;
    ``awaiting-key``/``degraded-no-key`` for the interactive provide/proceed
    choices; ``skipped-no-key`` as the default everywhere a keyless install
    would otherwise require consent the user has not explicitly given.
    """
    echo = echo or print
    roots = _workspace_roots(project_root, config)
    detections = ecosystem.detect_ecosystems(roots)
    present = {d.ecosystem for d in detections}
    if not present:
        # spec edge case: declare "no external-tool coverage applies" honestly,
        # never an unexamined assumption that none is needed (FR-009 spirit)
        write_availability(project_root / SCAN_DIR_NAME, [])
        return [], [], "no ecosystems detected — no external tools apply"
    entries = registry.applicable_tools(present)
    # project-local discovery probes every member; first hit wins and members
    # are sorted so the result is deterministic
    availabilities = discover.discover_roots(roots, entries)
    records = [a.to_dict() for a in availabilities]

    # ----------------------------------------- credential presence (feature 009)
    # Presence is read from the injected environment only, by variable NAME.
    # The value is never read, echoed, or recorded anywhere.
    env = dict(os.environ) if environ is None else environ
    spec_of = {
        a.tool_id: a.entry.credential
        for a in availabilities
        if a.entry is not None and a.entry.credential is not None
    }
    for availability, record in zip(availabilities, records, strict=True):
        spec = spec_of.get(availability.tool_id)
        if spec is None:
            continue
        if credentials.key_present(spec, env):
            record["credential"] = {
                "variable": spec.env_var,
                "state": credentials.STATE_AVAILABLE,
            }
        elif availability.source != "missing":
            # already present but keyless: runs rate-limited; informational only
            record["credential"] = {
                "variable": spec.env_var,
                "state": credentials.KEYLESS_STATE_DEGRADED,
            }

    missing = [a for a in availabilities if a.source == "missing"]
    if not missing:
        for record in records:
            record["decision"] = "use"
        write_availability(project_root / SCAN_DIR_NAME, records)
        return records, [], None

    # Capability check BEFORE consent: a tool with no registry channel whose
    # package manager is on this machine can never be installed here, so it is
    # declared missing with the reason and never offered (nothing to consent to).
    not_installable = {
        a.tool_id: (
            provision.not_installable_reason(a.entry)
            if a.entry is not None
            else "no usable install channel on this machine"
        )
        for a in missing
        if a.entry is None or provision.usable_channel(a.entry) is None
    }
    missing = [a for a in missing if a.tool_id not in not_installable]

    # Keyless credential-bearing tools never leave this init keyless without an
    # explicit decision: interactive runs warn + offer provide/proceed/skip per
    # tool BEFORE consent; every non-interactive context skips them unless
    # --allow-keyless-nvd pre-authorizes the degraded install (FR-004..FR-010).
    keyless_missing = [
        a
        for a, record in zip(availabilities, records, strict=True)
        if a.source == "missing"
        and a.tool_id not in not_installable
        and a.tool_id in spec_of
        and record.get("credential", {}).get("state") != credentials.STATE_AVAILABLE
    ]
    skipped_no_key: set[str] = set()
    keyless_choice: dict[str, str] = {}  # tool_id -> "provide" | "proceed"
    will_prompt = not (
        install is not None
        or yes
        or no_input
        or (config is not None and config.tooling_install in ("all", "never"))
        or (prompt is None and not sys.stdin.isatty())
    )
    if keyless_missing:
        if will_prompt:
            for availability in keyless_missing:
                spec = spec_of[availability.tool_id]
                echo("")
                echo(credentials.warning_text(spec))
                answer = ""
                try:
                    answer = (
                        (prompt or input)(
                            f"{availability.tool_id}: provide an NVD API key now,"
                            " proceed without one (rate-limited), or skip this"
                            " tool? [provide/proceed/skip]: "
                        )
                        .strip()
                        .lower()
                    )
                except (EOFError, OSError):
                    pass  # unreadable stdin: fall through to the skip default
                if answer == "provide":
                    echo(credentials.guidance_text(spec))
                    keyless_choice[availability.tool_id] = "provide"
                elif answer == "proceed":
                    keyless_choice[availability.tool_id] = "proceed"
                else:
                    # anything but an explicit provide/proceed is a skip:
                    # keyless install requires an explicit decision (FR-010)
                    skipped_no_key.add(availability.tool_id)
        elif not allow_keyless_nvd:
            skipped_no_key.update(a.tool_id for a in keyless_missing)
        else:
            # explicit pre-authorization: a keyless install records as degraded
            for availability in keyless_missing:
                keyless_choice[availability.tool_id] = "proceed"
    missing = [a for a in missing if a.tool_id not in skipped_no_key]
    del keyless_missing

    install_plan = [
        f"{a.tool_id} — {a.display_name} (network: {a.network})"
        for a in missing
    ]

    selection: set[str] = set()
    decided_by = "skipped-no-consent"
    preference = config.tooling_install if config is not None else "ask"
    if install is not None:
        selection = provision.resolve_selection(install, missing)
        decided_by = "skipped-by-user"
    elif yes or preference == "all":
        selection = {a.tool_id for a in missing}
        decided_by = "skipped-by-user"
    elif no_input or preference == "never":
        selection = set()  # skipped-no-consent
    elif prompt is None and not sys.stdin.isatty():
        # unattended by definition: never prompt, never hang (contracts/cli.md)
        selection = set()  # skipped-no-consent
    else:
        if not_installable:
            echo("")
            echo("Not installable on this machine (skipped):")
            for tool_id in sorted(not_installable):
                echo(f"  - {tool_id} — {not_installable[tool_id]}")
        if install_plan:
            echo("")
            echo("External tools to install:")
            for line in install_plan:
                echo(f"  - {line}")
            try:
                answer = (prompt or input)(
                    "Install which? (all / none / comma-separated numbers or ids): "
                )
            except (EOFError, OSError):  # defensive: treat unreadable stdin as "none"
                answer = ""
            selection = provision.resolve_selection(answer, missing)
        decided_by = "skipped-by-user"

    if selection:
        results = {r.tool_id: r for r in provision.install_selected(missing, selection)}
    else:
        results = {}
    # present tools take the honest "use" decision, even in mixed scenarios
    for availability, record in zip(availabilities, records, strict=True):
        if availability.source != "missing" and not record["decision"]:
            record["decision"] = "use"
    for availability, record in zip(
        (a for a in availabilities if a.source == "missing"),
        (r for r in records if r["source"] == "missing"),
        strict=True,
    ):
        result = results.get(availability.tool_id)
        spec = spec_of.get(availability.tool_id)
        if result is None:
            if availability.tool_id in not_installable:
                record["decision"] = "missing-declared"
                record["detail"] = not_installable[availability.tool_id]
            elif availability.tool_id in skipped_no_key:
                record["decision"] = "skipped-no-key"
                record["credential"] = {
                    "variable": spec.env_var,
                    "state": credentials.STATE_SKIPPED_NO_KEY,
                }
                record["detail"] = "no NVD key; skipped at init"
            else:
                record["decision"] = decided_by
            continue
        if result.installed:
            record["decision"] = "installed"
            record["source"] = "system-installed"
            if result.version:
                record["version"] = result.version
            record["detail"] = result.detail
            if spec is not None and availability.tool_id in keyless_choice:
                record["credential"] = {
                    "variable": spec.env_var,
                    "state": credentials.STATE_AWAITING_KEY
                    if keyless_choice[availability.tool_id] == "provide"
                    else credentials.KEYLESS_STATE_DEGRADED,
                }
            continue
        record["decision"] = "missing-declared"
        record["detail"] = result.detail

    # every credential-declaring tool ends with exactly one honest state
    # (FR-007): any reaching here unannotated is keyless AND not installed —
    # whatever the consent reason, the key outcome is skipped-no-key
    for availability, record in zip(availabilities, records, strict=True):
        spec = spec_of.get(availability.tool_id)
        if spec is None or "credential" in record:
            continue
        record["credential"] = {
            "variable": spec.env_var,
            "state": credentials.STATE_SKIPPED_NO_KEY,
        }

    write_availability(project_root / SCAN_DIR_NAME, records)
    return records, install_plan, None


def main() -> None:  # pragma: no cover - CLI wrapper
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, default=Path.cwd())
    parser.add_argument(
        "--install",
        nargs="?",
        const="all",
        default=None,
        metavar="TOOLS",
        help="install missing applicable tools without prompting "
        "('all' or comma-separated tool ids, e.g. --install=npm-audit,osv-scanner)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="confirm the full presented install list (equivalent to --install=all)",
    )
    parser.add_argument(
        "--no-input",
        dest="no_input",
        action="store_true",
        help="never prompt; skip all installation with a declared note",
    )
    parser.add_argument(
        "--allow-keyless-nvd",
        dest="allow_keyless_nvd",
        action="store_true",
        help="explicitly permit installing NVD-backed tools (e.g. "
        "owasp-dependency-check) without an NVD_API_KEY in non-interactive "
        "contexts; without this flag such tools are skipped keyless",
    )
    args = parser.parse_args()
    report = run_init(
        args.workdir,
        install=args.install,
        yes=args.yes,
        no_input=args.no_input,
        allow_keyless_nvd=args.allow_keyless_nvd,
    )
    print(report.render())
    raise SystemExit(0 if report.ready else 1)


if __name__ == "__main__":  # pragma: no cover
    main()
