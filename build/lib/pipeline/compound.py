"""Compound cross-file findings (feature 004, FR-004..FR-006; research R2, R6).

A compound rule is a set of evidence legs over whole-repository deterministic
facts. A finding publishes only when every leg is `evidenced` or `absent-proven`
— and an absence claim always records the space that was searched (FR-005). A
leg that cannot be evaluated is `undetermined`: the finding still publishes, but
the weak leg is named and the finding can never present itself as verified
(Principle V). A leg finding its control *present* retracts the rule.

Rules ship as data (`compound_rules.json`); the leg kinds below are the stable,
reviewed evaluator vocabulary. Adding a rule over existing kinds is data-only.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from pipeline import cwe, resources
from pipeline.extract.graphql_schema import find_cycles, parse_schema
from pipeline.state import iter_source_files

DATA_FILE = "compound_rules.json"

EVIDENCED = "evidenced"
ABSENT_PROVEN = "absent-proven"
CONTROL_PRESENT = "control-present"
UNDETERMINED = "undetermined"


class InvalidRuleData(RuntimeError):
    """Rule data that fails validation fails the build, not the scan."""


@dataclass
class LegResult:
    state: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    reason: str = ""


# ------------------------------------------------------------------ leg kinds

_AUTH_HINTS = re.compile(
    r"(?i)@PreAuthorize|@Secured|@RolesAllowed|@login_required|require_auth|"
    r"IsAuthenticated|authenticated\(\)"
)


def _endpoint_unauthenticated(files: dict[str, str], repo: str, params: dict) -> LegResult:
    """A route matching ``route_contains`` is on an unauthenticated allow-list."""
    route = params["route_contains"]
    for path in sorted(files):
        for match in re.finditer(
            r"(?:antMatchers|requestMatchers)\s*\(\s*[\"'][^\"']*"
            + re.escape(route)
            + r"[^\"']*[\"']\s*\)\s*\.\s*permitAll\s*\(",
            files[path],
        ):
            line = files[path].count("\n", 0, match.start()) + 1
            return LegResult(
                EVIDENCED,
                [
                    {
                        "repo": repo,
                        "file": path,
                        "reason": (
                            f"endpoint-unauthenticated: '{route}' is permitAll at "
                            f"{path}:{line}"
                        ),
                    }
                ],
            )
    if any(route in text for text in files.values()):
        return LegResult(
            CONTROL_PRESENT,
            reason=f"'{route}' is defined but no permitAll rule covers it",
        )
    return LegResult(
        UNDETERMINED,
        reason=f"no definition of '{route}' found in the enumerated sources",
    )


def _graphql_schema_cycle(files: dict[str, str], repo: str, params: dict) -> LegResult:
    """Any cycle in the schema's type-reference graph."""
    for path in sorted(files):
        if not path.endswith((".graphql", ".graphqls")):
            continue
        cycles = find_cycles(parse_schema(files[path]))
        if cycles:
            cycle = cycles[0]
            return LegResult(
                EVIDENCED,
                [
                    {
                        "repo": repo,
                        "file": path,
                        "reason": (
                            f"graphql-schema-cycle: {' -> '.join(cycle)} in {path}"
                        ),
                    }
                ],
            )
    if any(p.endswith((".graphql", ".graphqls")) for p in files):
        return LegResult(CONTROL_PRESENT, reason="schema has no type-reference cycle")
    return LegResult(UNDETERMINED, reason="no GraphQL schema file was enumerated")


def _config_absent(files: dict[str, str], repo: str, params: dict) -> LegResult:
    """None of ``patterns`` appears in any file matching ``file_globs`` (FR-005)."""
    globs = params["file_globs"]
    patterns = [re.compile(p) for p in params["patterns"]]
    searched = [
        p for p in sorted(files) if any(fnmatch(p.lower(), g.lower()) for g in globs)
    ]
    if not searched:
        return LegResult(
            UNDETERMINED,
            reason=f"no enumerated files match the search space {globs}",
        )
    for path in searched:
        for pattern in patterns:
            match = pattern.search(files[path])
            if match:
                line = files[path].count("\n", 0, match.start()) + 1
                return LegResult(
                    CONTROL_PRESENT,
                    reason=f"control configuration found at {path}:{line}",
                )
    return LegResult(
        ABSENT_PROVEN,
        [
            {
                "repo": repo,
                "file": searched[0],
                "reason": (
                    f"config-absent: searched {len(searched)} enumerated file(s) "
                    f"matching {globs} for {params['patterns']} — none present"
                ),
            }
        ],
    )


def _seeded_credential_pattern(files: dict[str, str], repo: str, params: dict) -> LegResult:
    """A migration/seed file provisioning accounts with a documented password."""
    globs = params.get("file_globs") or ["**/*.sql", "**/seed*"]
    for path in sorted(files):
        if not any(fnmatch(path.lower(), g.lower()) for g in globs):
            continue
        text = files[path]
        documents_password = re.search(r"(?i)(?:--|#|/\*).{0,80}password", text)
        provisions = re.search(
            r"(?i)INSERT\s+INTO\s+\w*(?:user|account|member)\w*", text
        )
        if documents_password and provisions:
            line = text.count("\n", 0, provisions.start()) + 1
            return LegResult(
                EVIDENCED,
                [
                    {
                        "repo": repo,
                        "file": path,
                        "reason": (
                            "seeded-credential-pattern: migration provisions "
                            f"accounts with a documented password at {path}:{line} "
                            "(value withheld)"
                        ),
                    }
                ],
            )
    return LegResult(ABSENT_PROVEN, reason="no seed account provisioning found")


def _public_auth_entrypoint(files: dict[str, str], repo: str, params: dict) -> LegResult:
    """A login/auth route handler without an authentication annotation."""
    route = params.get("route_contains", "login")
    handler = re.compile(
        r"(?i)(?:@\w*Mapping\s*\([^)]*" + re.escape(route) + r"|def \w*"
        + re.escape(route)
        + r"\w*\s*\(|public\s+\w+\s+\w*"
        + re.escape(route)
        + r"\w*\s*\()"
    )
    saw_unparsed_hint = False
    for path in sorted(files):
        text = files[path]
        if route not in text.lower():
            continue
        if path.endswith((".java", ".py", ".ts", ".js", ".go")):
            if handler.search(text) and not _AUTH_HINTS.search(text):
                line = text.count("\n", 0, handler.search(text).start()) + 1
                return LegResult(
                    EVIDENCED,
                    [
                        {
                            "repo": repo,
                            "file": path,
                            "reason": (
                                f"public-auth-entrypoint: '{route}' handler at "
                                f"{path}:{line} carries no authentication annotation"
                            ),
                        }
                    ],
                )
        else:
            saw_unparsed_hint = True
    if saw_unparsed_hint:
        return LegResult(
            UNDETERMINED,
            reason=(
                f"a '{route}' handler exists only in a language without a grammar, "
                "so its protection state cannot be established"
            ),
        )
    return LegResult(UNDETERMINED, reason=f"no '{route}' entrypoint found")


#: The stable evaluator vocabulary. New kinds are code (reviewed); new rules
#: binding existing kinds are data.
LEG_KINDS: dict[str, Callable[[dict[str, str], str, dict], LegResult]] = {
    "endpoint-unauthenticated": _endpoint_unauthenticated,
    "graphql-schema-cycle": _graphql_schema_cycle,
    "config-absent": _config_absent,
    "seeded-credential-pattern": _seeded_credential_pattern,
    "public-auth-entrypoint": _public_auth_entrypoint,
}


# -------------------------------------------------------------------- engine


def load_rules() -> list[dict[str, Any]]:
    document = json.loads(resources.data_path(DATA_FILE).read_text())
    rules = document["rules"]
    ids: set[str] = set()
    for rule in rules:
        if rule["id"] in ids:
            raise InvalidRuleData(f"duplicate rule id: {rule['id']}")
        ids.add(rule["id"])
        cwe.validate_cwe(rule["cwe"])
        for leg in rule["legs"]:
            if leg["kind"] not in LEG_KINDS:
                raise InvalidRuleData(f"{rule['id']}: unknown leg kind {leg['kind']}")
    return rules


def evaluate_files(
    files: dict[str, str], repo: str, rules: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for rule in rules or load_rules():
        legs = [
            (leg, LEG_KINDS[leg["kind"]](files, repo, leg.get("params") or {}))
            for leg in rule["legs"]
        ]
        if any(result.state == CONTROL_PRESENT for _, result in legs):
            continue  # the control exists; the rule is retracted
        undetermined = [leg["kind"] for leg, result in legs if result.state == UNDETERMINED]
        findings.append(_finding(rule, repo, legs, undetermined))
    return findings


def run(roots: dict[str, Path]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for repo in sorted(roots):
        files = {
            str(path.relative_to(roots[repo])): path.read_text(errors="replace")
            for path in iter_source_files(roots[repo])
        }
        findings.extend(evaluate_files(files, repo))
    return findings


def _finding(
    rule: dict[str, Any],
    repo: str,
    legs: list[tuple[dict, LegResult]],
    undetermined: list[str],
) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    location = {"repo": repo, "file": "", "line_start": 1, "line_end": 1}
    for _leg, result in legs:
        evidence.extend(result.evidence)
        if result.reason:
            evidence.append({"repo": repo, "file": location["file"] or "", "reason": result.reason})
    for entry in evidence:
        if entry.get("file"):
            location["file"] = entry["file"]
            break
    description = f"{rule['title']}: {rule['summary']}"
    if undetermined:
        description += (
            " Undetermined leg(s): " + ", ".join(sorted(undetermined)) + " — the "
            "finding is published as unproven; the named leg(s) could not be "
            "evaluated deterministically (leg state: undetermined)."
        )
    return {
        "cwe": rule["cwe"],
        "severity_score": float(rule["severity_score"]),
        "confidence": 0.75 if not undetermined else 0.5,
        "location": location,
        "description": description,
        "evidence": evidence,
        "recommendation": rule["recommendation"],
        "tool_ref": f"compound:{rule['id']}",
    }
