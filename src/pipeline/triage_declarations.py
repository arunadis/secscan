"""User-declared answers to flagged findings (feature 013, FR-018/019/020).

The operator answers a triage flag's question in ``.secscan/triage/declarations.json``;
the next scan applies it as user-declared evidence. Declarations are bound to a
finding's identity (repo + file + weakness + optional symbol) AND the question
they answer — drift in either lapses the declaration and the finding is
re-flagged. A declaration is always reversible (delete it, re-run, flag returns),
carries explicit ``user-declared`` provenance, and can never refute a
credential-class finding (same bar as reasoning, FR-008).
"""

from __future__ import annotations

from typing import Any

from pipeline.redact import Redactor
from pipeline.triage import is_credential_finding
from pipeline.triage_apply import _record_suppression, apply_downgrade

DECLARATIONS_PATH = "triage/declarations.json"
SCHEMA_VERSION = 1
MAX_ANSWER_CHARS = 2000

_ALLOWED_KEYS = {"finding_ref", "question", "answer", "resolution"}
_REF_KEYS = {"repo", "file", "cwe", "symbol"}


class DeclarationError(ValueError):
    """The declarations file is malformed; the scan refuses to guess (strict)."""


def load_declarations(store: Any) -> list[dict[str, Any]]:
    """Read and strictly validate the declarations file; absent ⇒ []."""
    raw = store.read_optional(DECLARATIONS_PATH)
    if raw is None:
        return []
    problems: list[str] = []
    if not isinstance(raw, dict):
        problems.append("declarations file must be a JSON object")
    else:
        if raw.get("schema_version") != SCHEMA_VERSION:
            problems.append(
                f"declarations schema_version must be {SCHEMA_VERSION} "
                f"(found {raw.get('schema_version')!r})"
            )
        declarations = raw.get("declarations")
        if not isinstance(declarations, list):
            problems.append("'declarations' must be a list")
            declarations = []
        for index, entry in enumerate(declarations):
            if not isinstance(entry, dict):
                problems.append(f"declarations[{index}] must be an object")
                continue
            unknown = sorted(set(entry) - _ALLOWED_KEYS)
            if unknown:
                problems.append(
                    f"declarations[{index}]: unknown keys: {', '.join(unknown)}"
                )
            ref = entry.get("finding_ref")
            if not isinstance(ref, dict) or sorted(set(ref) - _REF_KEYS):
                problems.append(
                    f"declarations[{index}].finding_ref must be an object with keys "
                    "repo, file, cwe (optional symbol)"
                )
            else:
                for key in ("repo", "file", "cwe"):
                    if not isinstance(ref.get(key), str) or not ref[key]:
                        problems.append(
                            f"declarations[{index}].finding_ref.{key} is required"
                        )
            if not isinstance(entry.get("question"), str) or not entry["question"]:
                problems.append(f"declarations[{index}].question is required")
            if not isinstance(entry.get("answer"), str) or not entry["answer"]:
                problems.append(f"declarations[{index}].answer is required")
            elif len(entry["answer"]) > MAX_ANSWER_CHARS:
                problems.append(
                    f"declarations[{index}].answer exceeds {MAX_ANSWER_CHARS} characters"
                )
            if entry.get("resolution") not in ("downgrade", "refute"):
                problems.append(
                    f"declarations[{index}].resolution must be 'downgrade' or 'refute'"
                )
    if problems:
        raise DeclarationError("Invalid triage declarations:\n" + "\n".join(problems))
    return list(raw.get("declarations") or [])


def declarations_key(declarations: list[dict[str, Any]]) -> str:
    """Content identity for the stage resume key — a changed answer re-runs triage."""
    import json

    from pipeline.state import hash_text

    return hash_text(json.dumps(declarations, sort_keys=True))


def _identity_matches(ref: dict[str, Any], finding: dict[str, Any]) -> bool:
    location = finding.get("location") or {}
    if ref.get("repo") != location.get("repo"):
        return False
    if ref.get("file") != location.get("file"):
        return False
    if str(ref.get("cwe", "")).upper() != str(finding.get("cwe", "")).upper():
        return False
    if ref.get("symbol") and ref["symbol"] != location.get("symbol"):
        return False
    return True


def apply_declarations(
    declarations: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    suppressions: list[dict[str, Any]],
    *,
    redactor: Redactor,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Match declarations against open flags and apply their resolution.

    Returns (findings, suppressions, decision entries). Unmatched declarations
    lapse: recorded in the decision log with no effect (FR-020).
    """
    kept = list(findings)
    decisions: list[dict[str, Any]] = []
    redactor = redactor or Redactor()

    for declaration in declarations:
        ref = declaration["finding_ref"]
        target_label = f"declaration:{ref['repo']}:{ref['file']}:{ref['cwe']}"
        flagmatch = [
            f
            for f in kept
            if f.get("awaiting_verification")
            and _identity_matches(ref, f)
            and f["awaiting_verification"]["question"] == declaration["question"]
        ]
        if not flagmatch:
            decisions.append(
                {
                    "finding_id": target_label,
                    "verdict_attempted": "user-declared",
                    "outcome": "declared-lapsed",
                    "applied_effect": "none",
                    "reason": "no open flag matches the declaration identity and question",
                    "citations": [],
                }
            )
            continue

        result = redactor.redact(str(declaration["answer"]))
        if result.blocked or not result.clean:
            decisions.append(
                {
                    "finding_id": target_label,
                    "verdict_attempted": "user-declared",
                    "outcome": "rejected-declaration",
                    "applied_effect": "none",
                    "reason": "answer content failed the credential sweep",
                    "citations": [],
                }
            )
            continue

        for finding in flagmatch:
            fid = str(finding.get("id", target_label))
            if declaration["resolution"] == "refute" and is_credential_finding(finding):
                decisions.append(
                    {
                        "finding_id": fid,
                        "verdict_attempted": "user-declared-refute",
                        "outcome": "rejected-credential-refute",
                        "applied_effect": "none",
                        "reason": "credential-class findings cannot be refuted, "
                        "even by user declaration (FR-008 parity)",
                        "citations": [],
                    }
                )
                continue

            finding.pop("awaiting_verification", None)
            provenance = {
                "answer": str(declaration["answer"]),
                "resolution": declaration["resolution"],
            }
            if declaration["resolution"] == "downgrade":
                apply_downgrade(
                    finding,
                    {
                        "verdict": "downgraded",
                        "rationale": f"user-declared: {declaration['answer']}",
                        "citations": [],
                    },
                )
                finding["triage"]["user_declaration"] = provenance
                decisions.append(
                    {
                        "finding_id": fid,
                        "verdict_attempted": "user-declared-downgrade",
                        "outcome": "applied",
                        "applied_effect": "grading-adjusted",
                        "reason": None,
                        "citations": [],
                    }
                )
            else:
                record = _record_suppression(
                    finding,
                    {"rationale": f"user-declared: {declaration['answer']}"},
                    [],
                )
                record["provenance"] = "user-declared"
                suppressions.append(record)
                kept.remove(finding)
                decisions.append(
                    {
                        "finding_id": fid,
                        "verdict_attempted": "user-declared-refute",
                        "outcome": "applied",
                        "applied_effect": "suppression-added",
                        "reason": None,
                        "citations": [],
                    }
                )

    return kept, suppressions, decisions
