"""External-tool registry: shipped versioned data, strictly validated (FR-001).

The registry is the extensibility seam: adding a scanner or an ecosystem audit
is a data edit in ``skill_core/data/tools.json`` plus contract-test fixtures,
never a pipeline change (extensibility-as-data). Loading is strict — every
problem is reported at once, like config validation, so a malformed entry
surfaces at init rather than mid-scan.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from pipeline import resources

REGISTRY_FILE = "tools.json"
REGISTRY_VERSION = 1

VALID_KINDS = ("sast", "secrets", "iac", "dependency-audit")
VALID_NETWORK = ("none", "on-first-use", "per-run")
VALID_MECHANISMS = ("manifest-dep", "manifest-plugin", "bin-path", "wrapper")
VALID_REPORT_FORMATS = ("json", "sarif")
KNOWN_ECOSYSTEMS = ("npm", "pypi", "maven", "go", "any")

#: Lockfile markers the registry may require for an invocation to be meaningful.
KNOWN_LOCKFILES = (
    "package-lock.json", "npm-shrinkwrap.json", "poetry.lock", "Pipfile.lock", "go.sum",
)


class RegistryError(ValueError):
    """Aggregates every registry validation problem (strict, like ConfigError)."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        body = "\n".join(f"  - {p}" for p in problems)
        super().__init__(f"tool registry is invalid ({len(problems)} problem(s)):\n{body}")


@dataclass(frozen=True)
class CredentialSpec:
    """How an external tool receives its credential (feature 009, FR-002).

    Carries the environment-variable NAME and explanatory text only — the
    credential value is never represented anywhere in the scanner.
    """

    env_var: str
    obtain_url: str
    absence_impact: str


@dataclass(frozen=True)
class ToolEntry:
    """One external tool, normalized from the registry document."""

    id: str
    display_name: str
    kind: str
    ecosystems: tuple[str, ...]
    covers_ecosystems: tuple[str, ...] = ()
    project_local: tuple[dict[str, Any], ...] = ()
    system_executable: str = ""
    version_probe: tuple[str, ...] = ()
    provision_channels: tuple[dict[str, Any], ...] = ()
    invoke: dict[str, Any] = field(default_factory=dict)
    invoke_project: dict[str, Any] | None = None
    timeout_s: int = 120
    report_format: str = "json"
    network: str = "per-run"
    credential: CredentialSpec | None = None

    @property
    def requires_lockfile(self) -> str | None:
        return self.invoke.get("requires_lockfile")

    def applies_to(self, ecosystems: set[str]) -> bool:
        """Applicability join on detected ecosystems ('any' matches all)."""
        if "any" in self.ecosystems:
            return bool(ecosystems)
        return bool(set(self.ecosystems) & ecosystems)


def load_registry() -> tuple[ToolEntry, ...]:
    """Load, validate, and return registry entries in deterministic order."""
    try:
        document = json.loads(resources.data_path(REGISTRY_FILE).read_text())
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise RegistryError([f"registry file cannot be read: {exc}"]) from exc
    problems = _validate(document)
    if problems:
        raise RegistryError(problems)
    entries: list[ToolEntry] = []
    for raw in document["tools"]:
        entries.append(
            ToolEntry(
                id=str(raw["id"]),
                display_name=str(raw.get("display_name") or raw["id"]),
                kind=str(raw["kind"]),
                ecosystems=tuple(str(e) for e in raw.get("ecosystems") or ()),
                covers_ecosystems=tuple(str(e) for e in raw.get("covers_ecosystems") or ()),
                project_local=tuple(dict(rule) for rule in raw.get("project_local") or ()),
                system_executable=str(raw.get("system_executable") or ""),
                version_probe=tuple(str(a) for a in raw.get("version_probe") or ()),
                provision_channels=tuple(dict(c) for c in raw.get("provision_channels") or ()),
                invoke=dict(raw.get("invoke") or {}),
                invoke_project=(
                    dict(raw["invoke_project"]) if raw.get("invoke_project") else None
                ),
                timeout_s=int(raw.get("timeout_s") or 120),
                report_format=str(raw.get("report_format") or "json"),
                network=str(raw.get("network") or "per-run"),
                credential=_parse_credential(raw.get("credential")),
            )
        )
    return tuple(sorted(entries, key=lambda tool: tool.id))


def _parse_credential(raw: Any) -> CredentialSpec | None:
    """Normalize a validated credential block; ``None`` when absent."""
    if raw is None:
        return None
    return CredentialSpec(
        env_var=str(raw.get("env_var") or ""),
        obtain_url=str(raw.get("obtain_url") or ""),
        absence_impact=str(raw.get("absence_impact") or ""),
    )


_ENV_VAR_SHAPE = re.compile(r"[A-Z][A-Z0-9_]*")


def _validate_credential(raw: Any, label: str, problems: list[str]) -> None:
    """Strict rules for the optional credential block (feature 009)."""
    if raw is None:
        return
    if not isinstance(raw, dict):
        problems.append(f"{label}.credential must be a mapping")
        return
    env_var = raw.get("env_var")
    if not env_var or not isinstance(env_var, str):
        problems.append(f"{label}.credential.env_var is required")
    elif not _ENV_VAR_SHAPE.fullmatch(env_var):
        problems.append(
            f"{label}.credential.env_var must be an uppercase environment-variable"
            f" name (found {env_var!r})"
        )
    obtain_url = raw.get("obtain_url")
    if not obtain_url or not isinstance(obtain_url, str):
        problems.append(f"{label}.credential.obtain_url is required")
    elif not obtain_url.startswith("https://"):
        problems.append(
            f"{label}.credential.obtain_url must be an https URL (found {obtain_url!r})"
        )
    impact = raw.get("absence_impact")
    if not isinstance(impact, str) or not impact.strip():
        problems.append(f"{label}.credential.absence_impact must be non-empty")


def applicable_tools(ecosystems: set[str]) -> tuple[ToolEntry, ...]:
    """Registry entries applicable to the detected ecosystems (FR-001)."""
    return tuple(tool for tool in load_registry() if tool.applies_to(ecosystems))


def _validate(document: Any) -> list[str]:
    problems: list[str] = []
    if not isinstance(document, dict):
        return ["registry must contain a JSON object at the top level"]
    if document.get("registry_version") != REGISTRY_VERSION:
        problems.append(
            f"registry_version must be {REGISTRY_VERSION} "
            f"(found {document.get('registry_version')!r})"
        )
    tools = document.get("tools")
    if not isinstance(tools, list) or not tools:
        problems.append("registry must contain a non-empty 'tools' list")
        return problems

    seen: set[str] = set()
    for index, raw in enumerate(tools):
        label = f"tools[{index}]"
        if not isinstance(raw, dict):
            problems.append(f"{label} must be a mapping")
            continue
        tool_id = raw.get("id")
        if not tool_id:
            problems.append(f"{label}.id is required")
        elif tool_id in seen:
            problems.append(f"{label}.id duplicates '{tool_id}'")
        else:
            seen.add(str(tool_id))
            label = f"tools[{index}] ({tool_id})"

        if raw.get("kind") not in VALID_KINDS:
            problems.append(f"{label}.kind must be one of {', '.join(VALID_KINDS)}")
        if raw.get("network") not in VALID_NETWORK:
            problems.append(f"{label}.network must be one of {', '.join(VALID_NETWORK)}")
        if raw.get("report_format") not in VALID_REPORT_FORMATS:
            problems.append(
                f"{label}.report_format must be one of {', '.join(VALID_REPORT_FORMATS)}"
            )
        _validate_credential(raw.get("credential"), label, problems)
        ecosystems = raw.get("ecosystems")
        if not isinstance(ecosystems, list) or not ecosystems:
            problems.append(f"{label}.ecosystems must be a non-empty list")
        else:
            for ecosystem in ecosystems:
                if ecosystem not in KNOWN_ECOSYSTEMS:
                    problems.append(f"{label}.ecosystems: unknown ecosystem {ecosystem!r}")
        if raw.get("kind") == "dependency-audit":
            covers = raw.get("covers_ecosystems")
            if not isinstance(covers, list) or not covers:
                problems.append(
                    f"{label}.covers_ecosystems is required for dependency-audit entries"
                )
            elif isinstance(ecosystems, list):
                for ecosystem in covers:
                    if ecosystem not in ecosystems:
                        problems.append(
                            f"{label}.covers_ecosystems must be a subset of ecosystems "
                            f"(found {ecosystem!r})"
                        )
        invoke = raw.get("invoke")
        if not isinstance(invoke, dict) or not invoke.get("argv"):
            problems.append(f"{label}.invoke.argv is required")
        else:
            lockfile = invoke.get("requires_lockfile")
            if lockfile is not None and lockfile not in KNOWN_LOCKFILES:
                problems.append(
                    f"{label}.invoke.requires_lockfile names unknown lockfile {lockfile!r}"
                )
        for rule in raw.get("project_local") or []:
            mechanism = rule.get("mechanism") if isinstance(rule, dict) else None
            if mechanism not in VALID_MECHANISMS:
                problems.append(
                    f"{label}.project_local mechanism must be one of "
                    f"{', '.join(VALID_MECHANISMS)} (found {mechanism!r})"
                )
        timeout = raw.get("timeout_s", 120)
        if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
            problems.append(f"{label}.timeout_s must be a positive integer")
    return problems
