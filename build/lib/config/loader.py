"""Project configuration: loading, strict validation, env-var overrides.

Implements FR-023 (single human-editable file), FR-025 (secrets only via env
vars), and FR-026 (strict upfront validation that reports *all* problems at once
and rejects conflicting settings before any scan work begins).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from config import profiles as profiles_mod

CONFIG_RELATIVE = "config.yaml"
CONFIG_VERSION = 1
ENV_PREFIX = "SECSCAN_"

VALID_INTEGRATION_TYPES = (
    "sync-api",
    "async-messaging",
    "shared-datastore",
    "identity-propagation",
)
VALID_LLM_MODES = ("auto", "endpoint", "agent")
VALID_EXECUTION_MODES = ("interactive", "batch-offpeak")
VALID_SCANNERS = ("semgrep", "gitleaks", "osv", "trivy")
VALID_TOGGLES = ("auto", True, False)

#: Declared config surface. Anything outside this is rejected (strict schema).
_ALLOWED: dict[str, tuple[str, ...]] = {
    "": ("version", "workspace", "llm", "execution_policy", "budgets", "profiles",
         "scanners", "redaction", "tooling"),
    "workspace": ("members", "integrations"),
    "llm": ("mode", "endpoint"),
    "llm.endpoint": ("provider", "model_map", "api_key_env", "base_url"),
    "llm.endpoint.model_map": ("local", "segment", "system"),
    "execution_policy": ("mode", "offpeak_window", "batch"),
    "execution_policy.batch": ("enabled", "fallback"),
    "budgets": ("max_context_tokens", "max_output_tokens", "escalation_threshold"),
    "redaction": ("extra_patterns", "entropy_threshold"),
    "tooling": ("install", "timeout_s"),
}

DEFAULT_CONFIG: dict[str, Any] = {
    "version": CONFIG_VERSION,
    "llm": {"mode": "auto"},
    "execution_policy": {
        "mode": "interactive",
        "batch": {"enabled": False, "fallback": "interactive"},
    },
    "budgets": {
        "max_context_tokens": 12000,
        "max_output_tokens": 3000,
        "escalation_threshold": 0.75,
    },
    "scanners": {name: {"enabled": "auto"} for name in VALID_SCANNERS},
    "redaction": {"extra_patterns": []},
    "tooling": {"install": "ask", "timeout_s": 120},
}

VALID_TOOLING_INSTALL = ("never", "ask", "all")


class ConfigError(ValueError):
    """Aggregates every configuration problem found (FR-026)."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        body = "\n".join(f"  - {p}" for p in problems)
        super().__init__(
            f"Configuration is invalid ({len(problems)} problem(s)); "
            f"refusing to start the scan:\n{body}"
        )


@dataclass
class ScannerSetting:
    name: str
    enabled: Any = "auto"

    @property
    def auto(self) -> bool:
        return self.enabled == "auto"


@dataclass
class Config:
    """Validated configuration."""

    path: Path | None
    raw: dict[str, Any] = field(default_factory=dict)

    # --------------------------------------------------------------- access

    @property
    def llm_mode(self) -> str:
        return str(self._get("llm", "mode", default="auto"))

    @property
    def endpoint(self) -> dict[str, Any] | None:
        ep = (self.raw.get("llm") or {}).get("endpoint")
        return dict(ep) if ep else None

    @property
    def execution_mode(self) -> str:
        return str(self._get("execution_policy", "mode", default="interactive"))

    @property
    def offpeak_window(self) -> str | None:
        value = self._get("execution_policy", "offpeak_window", default=None)
        return str(value) if value else None

    @property
    def batch_enabled(self) -> bool:
        batch = (self.raw.get("execution_policy") or {}).get("batch") or {}
        return bool(batch.get("enabled", False))

    @property
    def budgets(self) -> dict[str, Any]:
        return dict(self.raw.get("budgets") or DEFAULT_CONFIG["budgets"])

    @property
    def custom_profiles(self) -> dict[str, Any]:
        return dict(self.raw.get("profiles") or {})

    @property
    def workspace_members(self) -> list[dict[str, str]]:
        return list((self.raw.get("workspace") or {}).get("members") or [])

    @property
    def workspace_integrations(self) -> list[dict[str, Any]]:
        return list((self.raw.get("workspace") or {}).get("integrations") or [])

    @property
    def redaction_patterns(self) -> list[str]:
        return list((self.raw.get("redaction") or {}).get("extra_patterns") or [])

    @property
    def entropy_threshold(self) -> float | None:
        value = (self.raw.get("redaction") or {}).get("entropy_threshold")
        return float(value) if value is not None else None

    @property
    def tooling_install(self) -> str:
        """Install consent default for external tools (feature 008, FR-003)."""
        return str(self._get("tooling", "install", default="ask"))

    @property
    def tooling_timeout_s(self) -> int:
        """Per-tool wall-clock ceiling for external tool runs (feature 008)."""
        return int(self._get("tooling", "timeout_s", default=120))

    def scanners(self) -> dict[str, ScannerSetting]:
        configured = self.raw.get("scanners") or {}
        out: dict[str, ScannerSetting] = {}
        for name in VALID_SCANNERS:
            entry = configured.get(name) or {}
            out[name] = ScannerSetting(name=name, enabled=entry.get("enabled", "auto"))
        return out

    def api_key(self) -> str | None:
        """Read the endpoint credential from its env var (never stored in config)."""
        ep = self.endpoint or {}
        var = ep.get("api_key_env")
        return os.environ.get(str(var)) if var else None

    def _get(self, *keys: str, default: Any = None) -> Any:
        node: Any = self.raw
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node


# ------------------------------------------------------------------ loading


def config_path_for(scan_dir: Path) -> Path:
    return Path(scan_dir) / CONFIG_RELATIVE


def default_config_yaml() -> str:
    """Commented default config written by ``init`` (FR-024)."""
    return """# secscan project configuration (see contracts/config-schema.md)
# Secrets are NEVER stored here - only the NAME of an environment variable.
version: 1

# workspace:                      # optional; auto-discovered when omitted
#   members:
#     - { name: payments, path: ../payments-service }
#   integrations:
#     - { from: orders, to: payments, type: sync-api, endpoints: ["POST /payments"] }

llm:
  mode: auto                      # auto | endpoint | agent
  # endpoint:                     # omit to use the host agent's own model
  #   provider: anthropic         # anthropic | openai-compatible
  #   api_key_env: ANTHROPIC_API_KEY
  #   model_map:
  #     local: claude-haiku-latest
  #     segment: claude-sonnet-latest
  #     system: claude-opus-latest

execution_policy:
  mode: interactive               # interactive | batch-offpeak
  # offpeak_window: "02:00-06:00" # REQUIRED when mode is batch-offpeak
  batch:
    enabled: false
    fallback: interactive

budgets:
  max_context_tokens: 12000
  max_output_tokens: 3000
  escalation_threshold: 0.75

# profiles:                       # custom profiles (built-ins: quick, full, audit)
#   ci-triage:
#     base: quick
#     report_thresholds: { min_severity_band: High, min_confidence: 0.6 }

scanners:
  semgrep: { enabled: auto }      # auto = run when the tool is detected
  gitleaks: { enabled: auto }
  osv: { enabled: auto }
  trivy: { enabled: auto }

redaction:
  extra_patterns: []

tooling:                            # external security tools (feature 008)
  install: ask                      # never | ask | all — consent default for init
  timeout_s: 120                    # per-tool wall-clock ceiling during analysis
"""


def _coerce_env_value(value: str) -> Any:
    lowered = value.strip().lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def apply_env_overrides(raw: dict[str, Any], environ: dict[str, str] | None = None) -> list[str]:
    """Apply ``SECSCAN_SECTION_KEY`` overrides in place; returns applied keys."""
    env = dict(environ if environ is not None else os.environ)
    applied: list[str] = []
    sections = {
        "BUDGETS": ("budgets",),
        "EXECUTION_POLICY": ("execution_policy",),
        "LLM": ("llm",),
        "TOOLING": ("tooling",),
    }
    for name, value in sorted(env.items()):
        if not name.startswith(ENV_PREFIX):
            continue
        remainder = name[len(ENV_PREFIX) :]
        for prefix, path in sections.items():
            if not remainder.startswith(prefix + "_"):
                continue
            key = remainder[len(prefix) + 1 :].lower()
            node = raw
            for part in path:
                node = node.setdefault(part, {})
            node[key] = _coerce_env_value(value)
            applied.append(f"{'.'.join(path)}.{key}")
            break
    return applied


def load(scan_dir: Path, environ: dict[str, str] | None = None) -> Config:
    """Load and strictly validate the project config (FR-023, FR-026)."""
    path = config_path_for(scan_dir)
    if not path.exists():
        raise ConfigNotFound(path)

    try:
        parsed = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError([f"config file is not valid YAML: {exc}"]) from exc
    if not isinstance(parsed, dict):
        raise ConfigError(["config file must contain a YAML mapping at the top level"])

    apply_env_overrides(parsed, environ)
    problems = validate_config(parsed)
    if problems:
        raise ConfigError(problems)
    return Config(path=path, raw=parsed)


class ConfigNotFound(FileNotFoundError):
    """No config present — direct the user to ``init`` rather than failing low-level."""

    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__(
            f"No scanner configuration found at {path}.\n"
            "Run the init command first: `secscan init` "
            "(generates the default config and checks your environment)."
        )


# --------------------------------------------------------------- validation


def _check_unknown_keys(node: Any, prefix: str, problems: list[str]) -> None:
    if not isinstance(node, dict):
        return
    allowed = _ALLOWED.get(prefix)
    if allowed is None:
        return
    for key in sorted(node):
        if key not in allowed:
            where = prefix or "<root>"
            problems.append(
                f"unknown setting '{key}' under {where}; expected one of: {', '.join(allowed)}"
            )
            continue
        child_prefix = f"{prefix}.{key}" if prefix else key
        _check_unknown_keys(node[key], child_prefix, problems)


def validate_config(raw: dict[str, Any]) -> list[str]:
    """Return every problem found; empty list means valid."""
    problems: list[str] = []
    _check_unknown_keys(raw, "", problems)

    version = raw.get("version", CONFIG_VERSION)
    if version != CONFIG_VERSION:
        problems.append(
            f"version must be {CONFIG_VERSION} (found {version!r}); "
            "re-run the installer to upgrade this project's configuration"
        )

    # ------------------------------------------------------------------ llm
    llm = raw.get("llm") or {}
    if not isinstance(llm, dict):
        problems.append("llm must be a mapping")
        llm = {}
    mode = llm.get("mode", "auto")
    if mode not in VALID_LLM_MODES:
        problems.append(f"llm.mode must be one of {', '.join(VALID_LLM_MODES)} (found {mode!r})")

    endpoint = llm.get("endpoint")
    if endpoint is not None:
        if not isinstance(endpoint, dict):
            problems.append("llm.endpoint must be a mapping")
        else:
            if not endpoint.get("api_key_env"):
                problems.append(
                    "llm.endpoint.api_key_env is required when an endpoint is configured "
                    "(name the environment variable holding the key; never the key itself)"
                )
            provider = endpoint.get("provider", "anthropic")
            if provider not in ("anthropic", "openai-compatible"):
                problems.append(
                    "llm.endpoint.provider must be 'anthropic' or 'openai-compatible' "
                    f"(found {provider!r})"
                )
            for key in ("api_key", "apikey", "key", "secret", "token"):
                if key in endpoint:
                    problems.append(
                        f"llm.endpoint.{key} must not hold a secret value; "
                        "use api_key_env to name an environment variable instead"
                    )
    elif mode == "endpoint":
        problems.append(
            "llm.mode is 'endpoint' but llm.endpoint is not configured; "
            "either configure an endpoint or use mode 'auto'/'agent'"
        )

    # ------------------------------------------------------- execution policy
    policy = raw.get("execution_policy") or {}
    if not isinstance(policy, dict):
        problems.append("execution_policy must be a mapping")
        policy = {}
    exec_mode = policy.get("mode", "interactive")
    if exec_mode not in VALID_EXECUTION_MODES:
        problems.append(
            f"execution_policy.mode must be one of {', '.join(VALID_EXECUTION_MODES)} "
            f"(found {exec_mode!r})"
        )
    window = policy.get("offpeak_window")
    if exec_mode == "batch-offpeak" and not window:
        problems.append(
            "execution_policy.offpeak_window is required when mode is 'batch-offpeak' "
            "(e.g. \"02:00-06:00\") - conflicting settings"
        )
    if window is not None:
        problems.extend(_validate_window(str(window)))

    batch = policy.get("batch") or {}
    if batch and not isinstance(batch, dict):
        problems.append("execution_policy.batch must be a mapping")
    elif isinstance(batch, dict):
        fallback = batch.get("fallback", "interactive")
        if fallback != "interactive":
            problems.append(
                "execution_policy.batch.fallback must be 'interactive' "
                "(batch failures are always re-executed interactively)"
            )
        if batch.get("enabled") and endpoint is None:
            problems.append(
                "execution_policy.batch.enabled requires llm.endpoint; batch APIs are "
                "unavailable in agent-mediated mode"
            )

    # -------------------------------------------------------------- budgets
    budgets = raw.get("budgets") or {}
    if not isinstance(budgets, dict):
        problems.append("budgets must be a mapping")
    else:
        for key in ("max_context_tokens", "max_output_tokens"):
            value = budgets.get(key, DEFAULT_CONFIG["budgets"][key])
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                problems.append(f"budgets.{key} must be a positive integer (found {value!r})")
        threshold = budgets.get("escalation_threshold", 0.75)
        if not isinstance(threshold, (int, float)) or isinstance(threshold, bool):
            problems.append(
                f"budgets.escalation_threshold must be a number in (0, 1] (found {threshold!r})"
            )
        elif not 0 < float(threshold) <= 1:
            problems.append(
                f"budgets.escalation_threshold must be in (0, 1] (found {threshold})"
            )

    # -------------------------------------------------------------- profiles
    custom = raw.get("profiles") or {}
    if not isinstance(custom, dict):
        problems.append("profiles must be a mapping of profile name to settings")
    else:
        for name in sorted(custom):
            try:
                profiles_mod.resolve(name, custom=custom)
            except profiles_mod.ProfileError as exc:
                problems.append(f"profiles.{name}: {exc}")

    # -------------------------------------------------------------- scanners
    scanners = raw.get("scanners") or {}
    if not isinstance(scanners, dict):
        problems.append("scanners must be a mapping")
    else:
        for name in sorted(scanners):
            if name not in VALID_SCANNERS:
                problems.append(
                    f"unknown scanner '{name}'; expected one of: {', '.join(VALID_SCANNERS)}"
                )
                continue
            entry = scanners[name] or {}
            if not isinstance(entry, dict):
                problems.append(f"scanners.{name} must be a mapping")
                continue
            enabled = entry.get("enabled", "auto")
            if enabled not in VALID_TOGGLES:
                problems.append(
                    f"scanners.{name}.enabled must be true, false, or 'auto' (found {enabled!r})"
                )

    # -------------------------------------------------------------- tooling
    tooling = raw.get("tooling") or {}
    if not isinstance(tooling, dict):
        problems.append("tooling must be a mapping")
    else:
        install = tooling.get("install", "ask")
        if install not in VALID_TOOLING_INSTALL:
            problems.append(
                f"tooling.install must be one of {', '.join(VALID_TOOLING_INSTALL)} "
                f"(found {install!r})"
            )
        timeout = tooling.get("timeout_s", 120)
        if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
            problems.append(f"tooling.timeout_s must be a positive integer (found {timeout!r})")

    # ------------------------------------------------------------- workspace
    workspace = raw.get("workspace")
    if workspace is not None:
        if not isinstance(workspace, dict):
            problems.append("workspace must be a mapping")
        else:
            problems.extend(_validate_workspace(workspace))

    # ------------------------------------------------------------- redaction
    redaction = raw.get("redaction") or {}
    if not isinstance(redaction, dict):
        problems.append("redaction must be a mapping")
    else:
        patterns = redaction.get("extra_patterns") or []
        if not isinstance(patterns, list):
            problems.append("redaction.extra_patterns must be a list of regular expressions")
        else:
            import re

            for pattern in patterns:
                try:
                    re.compile(str(pattern))
                except re.error as exc:
                    problems.append(f"redaction.extra_patterns: invalid regex {pattern!r}: {exc}")

    return problems


def _validate_window(window: str) -> list[str]:
    parts = window.split("-")
    if len(parts) != 2:
        return [
            "execution_policy.offpeak_window must look like \"HH:MM-HH:MM\" "
            f"(found {window!r})"
        ]
    for part in parts:
        bits = part.strip().split(":")
        if len(bits) != 2 or not all(b.isdigit() for b in bits):
            return [
                "execution_policy.offpeak_window must look like \"HH:MM-HH:MM\" "
                f"(found {window!r})"
            ]
        hour, minute = int(bits[0]), int(bits[1])
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            return [f"execution_policy.offpeak_window has an invalid time: {part!r}"]
    return []


def _validate_workspace(workspace: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    members = workspace.get("members") or []
    if not isinstance(members, list):
        return ["workspace.members must be a list of {name, path} entries"]

    names: set[str] = set()
    for index, member in enumerate(members):
        if not isinstance(member, dict):
            problems.append(f"workspace.members[{index}] must be a mapping with name and path")
            continue
        name, path = member.get("name"), member.get("path")
        if not name:
            problems.append(f"workspace.members[{index}].name is required")
        if not path:
            problems.append(f"workspace.members[{index}].path is required")
        if name in names:
            problems.append(f"workspace.members: duplicate member name {name!r}")
        if name:
            names.add(str(name))

    integrations = workspace.get("integrations") or []
    if not isinstance(integrations, list):
        problems.append("workspace.integrations must be a list")
        return problems

    for index, integration in enumerate(integrations):
        if not isinstance(integration, dict):
            problems.append(f"workspace.integrations[{index}] must be a mapping")
            continue
        kind = integration.get("type")
        if kind not in VALID_INTEGRATION_TYPES:
            problems.append(
                f"workspace.integrations[{index}].type must be one of "
                f"{', '.join(VALID_INTEGRATION_TYPES)} (found {kind!r})"
            )
        for side in ("from", "to"):
            value = integration.get(side)
            if not value:
                problems.append(f"workspace.integrations[{index}].{side} is required")
            elif names and value not in names:
                problems.append(
                    f"workspace.integrations[{index}].{side} references unknown member "
                    f"{value!r}; declared members: {', '.join(sorted(names))}"
                )
    return problems
