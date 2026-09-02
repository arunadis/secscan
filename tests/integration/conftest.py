"""Shared integration-test scaffolding.

Analysis reasoning is normally performed by the host agent (agent-mediated mode).
Tests substitute a deterministic *oracle responder* for that agent: it inspects
the context packet it is given and emits schema-conforming findings for patterns
it recognises. This exercises the whole pipeline — packet construction, budget
enforcement, schema validation, verification, correlation, reporting — without
requiring a live model, and keeps results reproducible.

The oracle is deliberately "dumb": it only reports what is present in the bounded
context it receives, so it also proves the pipeline hands over adequate context.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from config.loader import default_config_yaml
from tests.fixtures.single_repo_shop import build as build_shop

# ------------------------------------------------------------------ patterns

#: (regex, cwe, severity, confidence, description, why-it-matters)
ORACLE_RULES: tuple[tuple[str, str, float, float, str, str], ...] = (
    (
        r"cursor\.execute\(\s*f[\"']",
        "CWE-89",
        9.8,
        0.93,
        "User-controlled value is interpolated into a SQL statement via an f-string.",
        "f-string interpolation directly into cursor.execute",
    ),
    (
        r"cursor\.execute\([^)]*\+",
        "CWE-89",
        9.1,
        0.88,
        "User-controlled value is concatenated into a SQL statement.",
        "string concatenation into cursor.execute",
    ),
    (
        # Ruby-style interpolation into SQL. Present so the unmodelled-language
        # fixture has a detectable flaw: the point of that fixture is that a
        # finding in a language without a grammar still gets reported, which is
        # unobservable if the oracle cannot see anything there in the first place.
        r"(?s)execute\(\s*\"[^\"]*#\{",
        "CWE-89",
        9.4,
        0.9,
        "Ruby string interpolation places an untrusted value into a SQL statement.",
        "#{} interpolation inside a SQL string passed to connection.execute",
    ),
    (
        r"(?i)(?:DB_)?PASSWORD\s*=\s*[\"'][^\"'\n]{8,}[\"']",
        "CWE-798",
        9.1,
        0.9,
        "A credential is hard-coded in source.",
        "credential literal assigned in source",
    ),
    (
        r"methods=\[\"DELETE\"\]",
        "CWE-862",
        8.2,
        0.8,
        "A destructive endpoint is exposed without an authorization check.",
        "destructive route with no authorization guard in the handler",
    ),
)

_AUTHZ_HINTS = ("require_role", "current_user", "has_permission", "authorize", "@login_required")


#: Packets present source line-numbered as ``  7| code`` (FR-002), and narrowed
#: packets interleave ``   | ... N unrelated line(s) omitted ...`` markers. The
#: oracle strips both, exactly as a reading model would.
_LINE_PREFIX = re.compile(r"^\s*(\d+)\|\s?", re.M)
_OMISSION = re.compile(r"^\s*\|\s*\.\.\..*$", re.M)


def strip_line_numbers(text: str) -> str:
    """Packet source with the ``NN|`` prefixes and omission markers removed."""
    return _LINE_PREFIX.sub("", _OMISSION.sub("", text))


def oracle_responder(request) -> str:
    """Stand-in for agent reasoning: findings derived from the packet's own source.

    Deliberately counts lines *within the packet* rather than reading the numbers
    the packet supplies. That reproduces the real failure mode — a model reporting
    a line number relative to a document that does not exist on disk — so the
    pipeline's own location resolution has to correct it (FR-001).
    """
    payload = request.payload
    sources: dict[str, str] = payload.get("source") or {}
    segment_id = payload.get("segment_id", "unknown")
    repo = payload.get("repo", "shop")
    findings: list[dict] = []

    for path in sorted(sources):
        text = strip_line_numbers(sources[path])
        lines = text.splitlines()
        for pattern, cwe_id, severity, confidence, description, reason in ORACLE_RULES:
            for match in re.finditer(pattern, text):
                if cwe_id == "CWE-862" and any(hint in text for hint in _AUTHZ_HINTS):
                    continue
                line_no = text[: match.start()].count("\n") + 1
                symbol = _enclosing_symbol(lines, line_no)
                findings.append(
                    {
                        "cwe": cwe_id,
                        "severity_score": severity,
                        "confidence": confidence,
                        "location": {
                            "repo": repo,
                            "file": path,
                            "symbol": symbol,
                            "line_start": line_no,
                            "line_end": min(line_no + 2, max(len(lines), line_no)),
                        },
                        "description": description,
                        "evidence": [
                            {
                                "repo": repo,
                                "file": path,
                                "symbol": symbol,
                                "segment_id": segment_id,
                                "reason": reason,
                            }
                        ],
                        "attack_scenario": (
                            "An attacker supplies a crafted value to the exposed entry point "
                            "and reaches the unsafe operation."
                        ),
                        "impact": "Unauthorized data access or modification.",
                        "recommendation": (
                            "Use parameterized queries, enforce authorization, and move "
                            "credentials into environment configuration."
                        ),
                        "segment_id": segment_id,
                    }
                )
    return json.dumps({"findings": findings})


def _enclosing_symbol(lines: list[str], line_no: int) -> str:
    for index in range(min(line_no, len(lines)) - 1, -1, -1):
        stripped = lines[index].strip()
        if stripped.startswith(("def ", "class ")):
            name = stripped.split()[1]
            return name.split("(")[0].split(":")[0]
    return "<module>"


def silent_responder(_request) -> str:
    """Responder that finds nothing (clean-repo behaviour)."""
    return json.dumps({"findings": []})


# ------------------------------------------------------------------ fixtures


@pytest.fixture
def shop_repo(tmp_path: Path) -> Path:
    """Materialized single-repo fixture with seeded ground truth."""
    return build_shop(tmp_path)


def write_config(scan_root: Path, overrides: dict | None = None) -> Path:
    """Create ``.secscan/config.yaml`` for ``scan_root``."""
    scan_dir = scan_root / ".secscan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    raw = yaml.safe_load(default_config_yaml())
    if overrides:
        raw = _merge(raw, overrides)
    (scan_dir / "config.yaml").write_text(yaml.safe_dump(raw, sort_keys=False))
    return scan_dir


def _merge(base: dict, patch: dict) -> dict:
    out = dict(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


@pytest.fixture
def configured_shop(shop_repo: Path) -> Path:
    write_config(shop_repo)
    return shop_repo
