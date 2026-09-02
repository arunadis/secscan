"""Scan profile resolution (FR-028).

Built-in profiles ship as data; users may define custom profiles in project
config (optionally inheriting from a built-in via ``base``), and any individual
setting can be overridden per scan. The resolved profile plus the overrides that
produced it are recorded in artifacts and the report.
"""

from __future__ import annotations

import copy
import functools
from dataclasses import dataclass, field
from typing import Any

import yaml

from pipeline import cwe, resources

BUILTIN_PATH = resources.profiles_path()
BUILTIN_NAMES = ("quick", "full", "audit")
DEFAULT_PROFILE = "full"


class ProfileError(ValueError):
    """Raised when a profile cannot be resolved."""


@functools.lru_cache(maxsize=1)
def builtin_profiles() -> dict[str, dict[str, Any]]:
    return yaml.safe_load(BUILTIN_PATH.read_text())


@dataclass(frozen=True)
class AnalysisDepth:
    domains: tuple[str, ...]
    max_escalation_level: int
    ingest_scanners: bool = True
    system_review: bool = True

    @property
    def all_domains(self) -> bool:
        return set(self.domains) == set(cwe.domains())

    def to_dict(self) -> dict[str, Any]:
        return {
            "domains": list(self.domains),
            "max_escalation_level": self.max_escalation_level,
            "ingest_scanners": self.ingest_scanners,
            "system_review": self.system_review,
        }


@dataclass(frozen=True)
class ReportThresholds:
    min_severity_band: str
    min_confidence: float

    def admits(self, band: str, confidence: float, verified: bool = False) -> bool:
        """Verification-aware threshold check (FR-029).

        ``verified`` findings always pass the confidence floor: a completely
        traced source-to-sink path is stronger evidence than a heuristic score.
        """
        if not cwe.band_at_least(band, self.min_severity_band):
            return False
        if verified:
            return True
        return confidence >= self.min_confidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "min_severity_band": self.min_severity_band,
            "min_confidence": self.min_confidence,
        }


@dataclass(frozen=True)
class ExcerptSettings:
    """Bounds for the redacted code excerpts attached to findings (feature 005)."""

    context_lines: int = 3
    max_lines: int = 40
    max_line_length: int = 200

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_lines": self.context_lines,
            "max_lines": self.max_lines,
            "max_line_length": self.max_line_length,
        }


@dataclass(frozen=True)
class ScanProfile:
    name: str
    description: str
    analysis_depth: AnalysisDepth
    report_thresholds: ReportThresholds
    excerpts: ExcerptSettings = field(default_factory=ExcerptSettings)
    overrides: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "analysis_depth": self.analysis_depth.to_dict(),
            "report_thresholds": self.report_thresholds.to_dict(),
            "excerpts": self.excerpts.to_dict(),
            "overrides": dict(self.overrides),
        }

    @property
    def depth_key(self) -> str:
        """Identity of the analysis depth, used to detect shallow->deep switches."""
        depth = self.analysis_depth
        domains = "all" if depth.all_domains else ",".join(sorted(depth.domains))
        return f"{domains}|L{depth.max_escalation_level}|sys={int(depth.system_review)}"


def _resolve_domains(raw: Any) -> tuple[str, ...]:
    if raw in (None, "all", ["all"]):
        return tuple(cwe.domains())
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list) or not raw:
        raise ProfileError("analysis_depth.domains must be 'all' or a non-empty list")
    known = set(cwe.domains())
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ProfileError(
            f"unknown analysis domains: {', '.join(unknown)}. Known: {', '.join(sorted(known))}"
        )
    return tuple(sorted(set(raw)))


def _merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def available_profiles(custom: dict[str, Any] | None = None) -> list[str]:
    return sorted(set(builtin_profiles()) | set(custom or {}))


def resolve(
    name: str | None = None,
    custom: dict[str, Any] | None = None,
    overrides: dict[str, Any] | None = None,
) -> ScanProfile:
    """Resolve ``name`` against built-ins and ``custom``, applying ``overrides``."""
    custom = custom or {}
    name = name or DEFAULT_PROFILE
    builtins = builtin_profiles()

    if name in custom:
        raw = copy.deepcopy(custom[name])
        base_name = raw.pop("base", None)
        if base_name:
            if base_name not in builtins and base_name not in custom:
                raise ProfileError(
                    f"profile '{name}' inherits from unknown base '{base_name}'. "
                    f"Available: {', '.join(available_profiles(custom))}"
                )
            base = builtins.get(base_name) or custom[base_name]
            raw = _merge(copy.deepcopy(base), raw)
    elif name in builtins:
        raw = copy.deepcopy(builtins[name])
    else:
        raise ProfileError(
            f"unknown profile '{name}'. Available: {', '.join(available_profiles(custom))}"
        )

    if overrides:
        raw = _merge(raw, overrides)

    depth_raw = raw.get("analysis_depth") or {}
    thresholds_raw = raw.get("report_thresholds") or {}

    level = int(depth_raw.get("max_escalation_level", 3))
    if not 1 <= level <= 4:
        raise ProfileError("analysis_depth.max_escalation_level must be between 1 and 4")

    band = str(thresholds_raw.get("min_severity_band", "Medium"))
    if band not in ("Critical", "High", "Medium", "Low", "None"):
        raise ProfileError(
            "report_thresholds.min_severity_band must be one of "
            "Critical, High, Medium, Low, None"
        )
    confidence = float(thresholds_raw.get("min_confidence", 0.0))
    if not 0.0 <= confidence <= 1.0:
        raise ProfileError("report_thresholds.min_confidence must be between 0.0 and 1.0")

    excerpts_raw = raw.get("excerpts") or {}
    excerpts = ExcerptSettings(
        context_lines=int(excerpts_raw.get("context_lines", 3)),
        max_lines=int(excerpts_raw.get("max_lines", 40)),
        max_line_length=int(excerpts_raw.get("max_line_length", 200)),
    )
    if excerpts.context_lines < 0 or excerpts.max_lines < 1 or excerpts.max_line_length < 20:
        raise ProfileError(
            "excerpts require context_lines >= 0, max_lines >= 1, max_line_length >= 20"
        )

    return ScanProfile(
        name=name,
        description=str(raw.get("description", "")).strip(),
        analysis_depth=AnalysisDepth(
            domains=_resolve_domains(depth_raw.get("domains")),
            max_escalation_level=level,
            ingest_scanners=bool(depth_raw.get("ingest_scanners", True)),
            system_review=bool(depth_raw.get("system_review", True)),
        ),
        report_thresholds=ReportThresholds(
            min_severity_band=band,
            min_confidence=confidence,
        ),
        excerpts=excerpts,
        overrides=copy.deepcopy(overrides or {}),
    )
