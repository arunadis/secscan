"""Client-asserted-identity archetype rules and guard-name catalogue (feature 016).

Versioned rule pack `identity_archetype_rules.json` — the feature-004 misconfig
discipline applied to a new weakness family (research R7/R8):

- **Build-time validation** (FR-017): duplicate ids, missing fields, bad regexes, or
  unknown CWEs fail the build, never the scan.
- **Value-free findings** (Principle III): rules match code *shape*; matched text
  never enters a finding.
- **Format detections** (clarify Q2): a rule hit is demonstrated presence, so the
  reasoning triage stage may downgrade or flag — never refute.

Matching semantics: contracts/identity-archetype-rules.md §2.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from pipeline import cwe, resources

DATA_FILE = "identity_archetype_rules.json"

#: deterministic rule match, not a model judgement — same level as misconfig (004).
_CONFIDENCE = 0.9


class InvalidRuleData(RuntimeError):
    """Rule data that fails validation fails the build, not the scan."""


@dataclass(frozen=True)
class IdentityRule:
    id: str
    stacks: tuple[str, ...]
    file_globs: tuple[str, ...]
    identity_read: re.Pattern[str]
    requires_absent: tuple[re.Pattern[str], ...]
    dispatch: re.Pattern[str]
    cwe: str
    severity_score: float
    title: str
    description: str
    recommendation: str
    confidence: float = _CONFIDENCE

    def matches_file(self, path: str) -> bool:
        return any(fnmatch(path, glob) for glob in self.file_globs)

    def matches_body(self, body: str) -> bool:
        """contracts §2: identity read present, every credential-verification
        pattern absent, dispatch present."""
        if not self.identity_read.search(body):
            return False
        if not self.dispatch.search(body):
            return False
        return not any(pattern.search(body) for pattern in self.requires_absent)


def _document() -> dict[str, Any]:
    import json

    return json.loads(resources.data_path(DATA_FILE).read_text())


def validate_document(document: dict[str, Any]) -> None:
    """Fail-the-build validation. Separated from loading so tests inject
    documents directly."""
    if document.get("version") is None or not document.get("dataset_date"):
        raise InvalidRuleData("missing version or dataset_date")
    guard_names = document.get("guard_names")
    if not isinstance(guard_names, list) or not guard_names:
        raise InvalidRuleData("guard_names must be a non-empty list")
    guard_pattern_by_name = []
    for pattern in guard_names:
        try:
            guard_pattern_by_name.append(re.compile(pattern + r"$", re.IGNORECASE))
        except re.error as exc:
            raise InvalidRuleData(f"guard_names pattern is invalid: {pattern!r}: {exc}") from exc
    ids: set[str] = set()
    for rule in document.get("rules") or []:
        if not rule.get("id"):
            raise InvalidRuleData("rule missing id")
        if rule["id"] in ids:
            raise InvalidRuleData(f"duplicate rule id: {rule['id']}")
        ids.add(rule["id"])
        for field_name in (
            "stacks",
            "file_globs",
            "identity_read",
            "requires_absent",
            "dispatch",
            "cwe",
            "title",
            "description",
            "recommendation",
        ):
            if not rule.get(field_name):
                raise InvalidRuleData(f"{rule['id']}: missing {field_name}")
        if rule.get("scope", "function") != "function":
            raise InvalidRuleData(f"{rule['id']}: scope must be 'function'")
        for pattern in (rule["identity_read"], rule["dispatch"], *rule["requires_absent"]):
            try:
                re.compile(pattern)
            except re.error as exc:
                raise InvalidRuleData(f"{rule['id']}: invalid regex {pattern!r}: {exc}") from exc
        try:
            cwe.validate_cwe(rule["cwe"])
        except cwe.UnknownCWE as exc:
            raise InvalidRuleData(f"{rule['id']}: {exc}") from exc
        score = rule.get("severity_score")
        if not isinstance(score, (int, float)) or not 1.0 <= float(score) <= 10.0:
            raise InvalidRuleData(f"{rule['id']}: severity_score out of range")


def load_guard_names(document: dict[str, Any] | None = None) -> tuple[re.Pattern[str], ...]:
    """The shared guard-name catalogue (single source for FR-006 and FR-001)."""
    document = document if document is not None else _document()
    validate_document(document)
    return tuple(
        re.compile(pattern + r"$", re.IGNORECASE) for pattern in document["guard_names"]
    )


def load_identity_rules(
    document: dict[str, Any] | None = None,
) -> tuple[IdentityRule, ...]:
    document = document if document is not None else _document()
    validate_document(document)
    return tuple(
        IdentityRule(
            id=rule["id"],
            stacks=tuple(rule["stacks"]),
            file_globs=tuple(rule["file_globs"]),
            identity_read=re.compile(rule["identity_read"]),
            requires_absent=tuple(re.compile(p) for p in rule["requires_absent"]),
            dispatch=re.compile(rule["dispatch"]),
            cwe=rule["cwe"],
            severity_score=float(rule["severity_score"]),
            title=rule["title"],
            description=rule["description"],
            recommendation=rule["recommendation"],
        )
        for rule in document.get("rules") or []
    )


def no_refute_cwes(document: dict[str, Any] | None = None) -> frozenset[str]:
    """The pack's CWE set: format-detection findings that reasoning may
    downgrade/flag but never refute (clarify Q2 — shape is presence-valid)."""
    return frozenset(rule.cwe for rule in load_identity_rules(document))


def rules_version(document: dict[str, Any] | None = None) -> str:
    document = document if document is not None else _document()
    validate_document(document)
    return str(document["version"])


def rules_path() -> Path:
    return resources.data_path(DATA_FILE)


# ------------------------------------------------------------------ detection


def evaluate_segment(
    roots: dict[str, Path],
    graph: dict[str, Any],
    segment: dict[str, Any],
    rules: tuple[IdentityRule, ...],
    pack_version: str,
    segment_id: str | None = None,
) -> list[dict[str, Any]]:
    """Deterministic findings for one segment (FR-014, contracts §2/§4).

    Function bodies are sliced from the file on disk using the code model's own
    line ranges, so the reported location is always model-resolvable. Rule matches
    are ``format`` detections; rule ids travel as ``tool_ref`` with the pack
    version. Test code is out of scope — identity checks in tests/fixtures are
    scaffolding, and reporting them would be precision noise.
    """
    from pipeline.stacks import is_test_code

    out: list[dict[str, Any]] = []
    repo = segment["repos"][0]
    root = roots.get(repo)
    if root is None:
        return out
    nodes_by_file: dict[str, list[dict[str, Any]]] = {}
    for node in graph.get("nodes") or []:
        if node.get("repo") == repo and node.get("path") in segment["files"]:
            nodes_by_file.setdefault(node["path"], []).append(node)

    for relative in sorted(segment["files"]):
        if is_test_code(relative):
            continue
        path = root / relative
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        symbols = sorted(
            (
                node
                for node in nodes_by_file.get(relative, [])
                if node.get("type") == "function" and node.get("line_start")
            ),
            key=lambda n: (int(n["line_start"]), str(n.get("symbol"))),
        )
        for node in symbols:
            body = "\n".join(
                lines[int(node["line_start"]) - 1 : int(node.get("line_end", node["line_start"]))]
            )
            for rule in rules:
                if not rule.matches_file(relative) or not rule.matches_body(body):
                    continue
                # name the actual channel read (feature 017): family grouping in
                # the report keys on the channel token, so the evidence must
                # carry it — e.g. `req.headers['x-user-email']` → 'x-user-email'.
                channel = _channel_token(rule.identity_read.search(body) or _EMPTY_MATCH)
                out.append(
                    _finding(rule, repo, relative, node, segment_id, pack_version,
                             channel_token=channel)
                )
    return out


class _EmptyMatch:
    def group(self, _index: int) -> str:
        return ""


_EMPTY_MATCH = _EmptyMatch()
_READ_NAME = re.compile(r"['\"]([A-Za-z0-9_-]+)['\"]|\.(\w+)\s*[,)\]}]")


def _channel_token(match: Any) -> str:
    """Header/cookie/field name out of the identity-read expression, or ''."""
    text = match.group(0) if match else ""
    found = _READ_NAME.search(str(text))
    if not found:
        return ""
    return next(g for g in found.groups() if g)


def _finding(
    rule: IdentityRule,
    repo: str,
    relative: str,
    node: dict[str, Any],
    segment_id: str | None,
    pack_version: str,
    channel_token: str = "",
) -> dict[str, Any]:
    symbol = str(node.get("symbol") or "")
    return {
        "cwe": rule.cwe,
        "severity_score": rule.severity_score,
        "confidence": rule.confidence,
        "detection": "format",
        "code_context": "production",
        "location": {
            "repo": repo,
            "file": relative,
            "symbol": symbol,
            "line_start": int(node["line_start"]),
            "line_end": int(node.get("line_end", node["line_start"])),
        },
        "description": rule.description,
        "evidence": [
            {
                "repo": repo,
                "file": relative,
                "symbol": symbol,
                "segment_id": segment_id,
                "reason": (
                    "deterministic rule matched the identity-read/no-credential/"
                    f"dispatch shape in {symbol}"
                    + (
                        f" (client-controlled channel: {channel_token})"
                        if channel_token
                        else ""
                    )
                ),
            }
        ],
        "attack_scenario": (
            "An attacker supplies the asserted identity value directly (it is a "
            "client-controlled request channel), selecting any account the "
            "handler trusts."
        ),
        "impact": "Account/tenant impersonation without any credential.",
        "recommendation": rule.recommendation,
        "tool_ref": f"identity-archetype@{pack_version}:{rule.id}",
        "segment_id": segment_id,
    }

