"""Agent-answer validation and handoff response I/O (feature 018, FR-006, FR-022).

The plugin tool provider accepts an answer for a pending reasoning request and
writes it exactly where the skill path tells an agent to write it:
``.secscan/handoff/responses/<request-id>.json``. Validation is *the same
acceptance test the resume path applies* (research R12) — segment answers must
parse as structured findings JSON (``FindingNormalizer.parse``), flow and triage
answers must conform to their shipped schema — so the plugin form can never
accept less or more than the skill form does.

Request ids are matched against the directory *listing*, never path-joined, so an
id can never address a file outside ``handoff/requests/`` (research R10).
Rejection reasons carry the schema path and message only — never the offending
instance, which could echo content the host must not see.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pipeline import schemas
from pipeline.normalize_findings import FindingNormalizer, MalformedAnalysisOutput
from pipeline.state import canonical_json

REQUESTS_DIR = "requests"
RESPONSES_DIR = "responses"

#: request ``stage`` -> answer kind (which validator applies).
_KIND_BY_STAGE = {
    "segment_analysis": "finding",
    "business_flow_analysis": "flow_answer",
    "finding_triage": "triage_answer",
}
_GUIDANCE = {
    "finding": "prompts/segment_scan.md",
    "flow_answer": "prompts/business_flow.md",
    "triage_answer": "prompts/triage_finding.md",
}


class UnknownRequest(KeyError):
    """No pending request with that id exists in ``handoff/requests/``."""


class AlreadyAnswered(FileExistsError):
    """A response for that request already exists (pass ``overwrite=True``)."""


def answer_kind(request_doc: dict[str, Any]) -> str:
    stage = str(request_doc.get("stage") or "")
    return _KIND_BY_STAGE.get(stage, "finding")


def guidance_for(kind: str) -> str:
    return _GUIDANCE[kind]


# ------------------------------------------------------------------- listing


def _requests_dir(handoff_dir: Path) -> Path:
    return Path(handoff_dir) / REQUESTS_DIR


def _responses_dir(handoff_dir: Path) -> Path:
    return Path(handoff_dir) / RESPONSES_DIR


def _request_paths(handoff_dir: Path) -> dict[str, Path]:
    directory = _requests_dir(handoff_dir)
    if not directory.is_dir():
        return {}
    return {p.stem: p for p in sorted(directory.glob("*.json")) if p.is_file()}


def is_answered(handoff_dir: Path, request_id: str) -> bool:
    path = _responses_dir(handoff_dir) / f"{request_id}.json"
    try:
        return path.is_file() and bool(path.read_text().strip())
    except OSError:
        return False


def resolve_request(handoff_dir: Path, request_id: str) -> dict[str, Any]:
    """The request document for ``request_id`` — matched against the listing only."""
    paths = _request_paths(handoff_dir)
    if request_id not in paths:
        raise UnknownRequest(request_id)
    return json.loads(paths[request_id].read_text())


def list_requests(handoff_dir: Path) -> list[dict[str, Any]]:
    """Summary rows for every pending request, sorted by id; never the packet."""
    rows: list[dict[str, Any]] = []
    for request_id, path in _request_paths(handoff_dir).items():
        try:
            doc = json.loads(path.read_text())
        except (OSError, ValueError):
            doc = {}
        rows.append(
            {
                "request_id": request_id,
                "stage": doc.get("stage"),
                "escalation_level": doc.get("escalation_level"),
                "estimated_tokens": doc.get("estimated_tokens"),
                "answered": is_answered(handoff_dir, request_id),
            }
        )
    return rows


# ---------------------------------------------------------------- validation


def _as_text(content: Any) -> str:
    return content if isinstance(content, str) else canonical_json(content)


def _schema_errors(name: str, document: Any) -> list[dict[str, str]]:
    validator = schemas.validator_for(name)
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.path))
    return [
        {"path": "/".join(str(part) for part in error.path), "message": error.message}
        for error in errors
    ]


def validate_answer(request_doc: dict[str, Any], content: Any) -> list[dict[str, str]]:
    """Errors (empty when accepted) using the resume path's own acceptance test."""
    kind = answer_kind(request_doc)
    if kind == "finding":
        try:
            FindingNormalizer.parse(_as_text(content))
        except MalformedAnalysisOutput as exc:
            return [{"path": "", "message": str(exc)}]
        return []

    if isinstance(content, str):
        try:
            document = json.loads(content)
        except ValueError as exc:
            return [{"path": "", "message": f"answer is not valid JSON: {exc.msg}"}]
    else:
        document = content
    return _schema_errors(kind, document)


# ------------------------------------------------------------------- writing


def write_response(
    handoff_dir: Path, request_id: str, content: Any, *, overwrite: bool = False
) -> Path:
    """Write the answer as the skill path would: a string verbatim, an object canonical."""
    if request_id not in _request_paths(handoff_dir):
        raise UnknownRequest(request_id)
    directory = _responses_dir(handoff_dir)
    path = directory / f"{request_id}.json"
    if path.exists() and not overwrite:
        raise AlreadyAnswered(str(path))
    directory.mkdir(parents=True, exist_ok=True)
    path.write_text(_as_text(content))
    return path


@dataclass
class SubmitOutcome:
    request_id: str
    kind: str
    errors: list[dict[str, str]] = field(default_factory=list)
    path: Path | None = None


def submit(
    handoff_dir: Path, request_id: str, content: Any, *, overwrite: bool = False
) -> SubmitOutcome:
    """Validate, then write; a rejection leaves the responses directory untouched."""
    request_doc = resolve_request(handoff_dir, request_id)
    kind = answer_kind(request_doc)
    errors = validate_answer(request_doc, content)
    if errors:
        return SubmitOutcome(request_id, kind, errors=errors)
    path = write_response(handoff_dir, request_id, content, overwrite=overwrite)
    return SubmitOutcome(request_id, kind, path=path)
