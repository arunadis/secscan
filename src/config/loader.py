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
#: ``auto`` (default) means batch whenever an endpoint is configured (feature 012, FR-023).
VALID_EXECUTION_MODES = ("auto", "interactive", "batch", "batch-offpeak")
VALID_SCANNERS = ("semgrep", "gitleaks", "osv", "trivy")
VALID_TOGGLES = ("auto", True, False)

#: Declared config surface. Anything outside this is rejected (strict schema).
_ALLOWED: dict[str, tuple[str, ...]] = {
    "": ("version", "workspace", "llm", "execution_policy", "budgets", "profiles",
         "scanners", "redaction", "tooling", "output", "triage"),
    "triage": ("enabled", "min_severity_band", "include_unverified"),
    "workspace": ("members", "integrations"),
    "llm": ("mode", "endpoint", "retry"),
    "llm.endpoint": ("provider", "model_map", "api_key_env", "base_url"),
    "llm.endpoint.model_map": ("local", "segment", "system"),
    "llm.retry": ("attempts", "max_wait_s"),
    "execution_policy": ("mode", "offpeak_window", "batch"),
    "execution_policy.batch": ("enabled", "fallback", "window_hours"),
    "budgets": ("max_context_tokens", "max_output_tokens", "escalation_threshold"),
    "redaction": ("extra_patterns", "entropy_threshold"),
    "tooling": ("install", "timeout_s"),
    "output": ("level",),
}

DEFAULT_CONFIG: dict[str, Any] = {
    "version": CONFIG_VERSION,
    "llm": {"mode": "auto"},
    "execution_policy": {
        "mode": "auto",
        "batch": {"fallback": "interactive", "window_hours": 24},
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
#: Triage round enablement (feature 013): auto follows the profile's
#: ``analysis_depth.finding_triage``; on/off override it.
VALID_TRIAGE_ENABLED = ("auto", "on", "off")
VALID_SEVERITY_BANDS = ("Low", "Medium", "High", "Critical")
#: Progress output levels for `run` (feature 011). Mirrors pipeline.progress.OutputLevel;
#: kept as data here so config validation needs no pipeline import.
VALID_OUTPUT_LEVELS = ("quiet", "default", "verbose")


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
        return str(self._get("execution_policy", "mode", default="auto"))

    @property
    def offpeak_window(self) -> str | None:
        value = self._get("execution_policy", "offpeak_window", default=None)
        return str(value) if value else None

    @property
    def batch_enabled(self) -> bool:
        return bool(self.batch_enabled_explicit)

    @property
    def batch_enabled_explicit(self) -> bool | None:
        """``execution_policy.batch.enabled`` as written, or ``None`` when absent (012)."""
        batch = (self.raw.get("execution_policy") or {}).get("batch") or {}
        value = batch.get("enabled")
        return None if value is None else bool(value)

    @property
    def batch_window_hours(self) -> float:
        """Batch expiry measured from submission (feature 012, FR-009)."""
        return float(self._get("execution_policy", "batch", "window_hours", default=24))

    @property
    def retry_attempts(self) -> int:
        return int(self._get("llm", "retry", "attempts", default=5))

    @property
    def retry_max_wait_s(self) -> int:
        return int(self._get("llm", "retry", "max_wait_s", default=60))

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

    @property
    def output_level(self) -> str:
        """Progress output level for `run`: quiet | default | verbose (feature 011)."""
        return str(self._get("output", "level", default="default"))

    @property
    def triage_enabled(self) -> str:
        """Triage round enablement: auto | on | off (feature 013)."""
        return str(self._get("triage", "enabled", default="auto"))

    @property
    def triage_min_severity_band(self) -> str | None:
        """Lowest band triaged; None resolves to the profile default (feature 013)."""
        value = self._get("triage", "min_severity_band", default=None)
        return str(value) if value is not None else None

    @property
    def triage_include_unverified(self) -> bool:
        """Whether findings with unverified status are triage candidates (feature 013)."""
        return bool(self._get("triage", "include_unverified", default=True))

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
  #   provider: anthropic         # MUST match the key: anthropic -> x-api-key to
  #                               #   api.anthropic.com/v1/messages
  #                               # openai-compatible -> Bearer to
  #                               #   {base_url}/chat/completions (default api.openai.com/v1)
  #   api_key_env: ANTHROPIC_API_KEY   # e.g. OPENAI_API_KEY for openai-compatible
  #   base_url: https://your-gateway/v1  # optional; only for gateways/proxies
  #   model_map:                  # per-level model IDs, passed to the provider verbatim
  #     local: claude-haiku-latest
  #     segment: claude-sonnet-latest
  #     system: claude-opus-latest
  # retry:                        # transient endpoint failures (429/5xx) on live requests
  #   attempts: 5                 # total attempts per request (1 initial + 4 retries)
  #   max_wait_s: 60              # ceiling for one wait; Retry-After is honoured as a minimum

execution_policy:
  mode: auto                      # auto | interactive | batch | batch-offpeak
                                  # auto = batch when an endpoint is configured; the scan
                                  # submits each analysis round as one provider batch, waits
                                  # in the foreground (Ctrl-C is resumable), and re-runs
                                  # failed items live. Set interactive for quick scans.
  # offpeak_window: "02:00-06:00" # REQUIRED when mode is batch-offpeak
  batch:
    fallback: interactive         # the only valid value
    window_hours: 24              # batch expiry, measured from submission

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

# triage:                             # finding-triage round (feature 013)
#   enabled: auto                   # auto | on | off — auto follows the profile
#                                   # (quick off; full/audit on)
#   min_severity_band: Medium       # lowest band triaged (audit defaults to Low)
#   include_unverified: true        # findings with verification gaps are
#                                   # candidates too

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
    # Nested prefixes first so ``EXECUTION_POLICY_BATCH_WINDOW_HOURS`` lands on
    # ``execution_policy.batch.window_hours`` rather than a flat key (feature 012).
    sections = {
        "EXECUTION_POLICY_BATCH": ("execution_policy", "batch"),
        "LLM_RETRY": ("llm", "retry"),
        "BUDGETS": ("budgets",),
        "EXECUTION_POLICY": ("execution_policy",),
        "LLM": ("llm",),
        "TOOLING": ("tooling",),
        "OUTPUT": ("output",),
        "TRIAGE": ("triage",),
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

    retry = llm.get("retry")
    if retry is not None:
        if not isinstance(retry, dict):
            problems.append("llm.retry must be a mapping")
        else:
            for key in ("attempts", "max_wait_s"):
                value = retry.get(key)
                if value is not None and (
                    not isinstance(value, int) or isinstance(value, bool) or value < 1
                ):
                    problems.append(f"llm.retry.{key} must be a positive integer (found {value!r})")

    # ------------------------------------------------------- execution policy
    policy = raw.get("execution_policy") or {}
    if not isinstance(policy, dict):
        problems.append("execution_policy must be a mapping")
        policy = {}
    exec_mode = policy.get("mode", "auto")
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
        enabled = batch.get("enabled")
        if enabled is False and exec_mode in ("batch", "batch-offpeak"):
            problems.append(
                f"execution_policy.mode is '{exec_mode}' but execution_policy.batch.enabled "
                "is false - conflicting settings"
            )
        if enabled is True and exec_mode == "interactive":
            problems.append(
                "execution_policy.mode is 'interactive' but execution_policy.batch.enabled "
                "is true - conflicting settings"
            )
        hours = batch.get("window_hours")
        if hours is not None and (
            not isinstance(hours, (int, float)) or isinstance(hours, bool) or hours <= 0
        ):
            problems.append(
                f"execution_policy.batch.window_hours must be a positive number (found {hours!r})"
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

    # --------------------------------------------------------------- triage
    triage = raw.get("triage")
    if triage is not None:
        if not isinstance(triage, dict):
            problems.append("triage must be a mapping")
        else:
            enabled = triage.get("enabled", "auto")
            if enabled not in VALID_TRIAGE_ENABLED:
                problems.append(
                    "triage.enabled must be one of " f"{', '.join(VALID_TRIAGE_ENABLED)} "
                    f"(found {enabled!r})"
                )
            band = triage.get("min_severity_band")
            if band is not None and band not in VALID_SEVERITY_BANDS:
                problems.append(
                    "triage.min_severity_band must be one of "
                    f"{', '.join(VALID_SEVERITY_BANDS)} (found {band!r})"
                )
            include = triage.get("include_unverified")
            if include is not None and not isinstance(include, bool):
                problems.append(
                    f"triage.include_unverified must be a boolean (found {include!r})"
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

    # --------------------------------------------------------------- output
    output = raw.get("output") or {}
    if not isinstance(output, dict):
        problems.append("output must be a mapping")
    else:
        level = output.get("level", "default")
        if level not in VALID_OUTPUT_LEVELS:
            problems.append(
                f"output.level must be one of: {', '.join(VALID_OUTPUT_LEVELS)} (got {level!r})"
            )

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
