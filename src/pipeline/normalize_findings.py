"""Stage: findings normalization and schema enforcement (FR-012, FR-013).

Analysis output is parsed, completed (CWE-derived OWASP label, severity band,
compliance refs), assigned stable ids, and validated against the finding schema.
Anything that does not conform is rejected — free-form prose never enters the
findings pipeline.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pipeline import cwe
from pipeline.schemas import SchemaError, validate

_JSON_BLOCK = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)
#: request ids are `<segment-id>-l<escalation-level>`
_REQUEST_SUFFIX = re.compile(r"-l\d+$")


class MalformedAnalysisOutput(ValueError):
    """Raised when analysis output cannot be parsed as structured findings."""


@dataclass
class NormalizationResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[dict[str, str]] = field(default_factory=list)

    def extend(self, other: NormalizationResult) -> None:
        self.findings.extend(other.findings)
        self.rejected.extend(other.rejected)


class FindingNormalizer:
    """Assigns ids and enforces the schema across a whole scan."""

    def __init__(self, start: int = 1) -> None:
        self._next = start

    def allocate_id(self) -> str:
        identifier = f"SEC-{self._next:04d}"
        self._next += 1
        return identifier

    # ------------------------------------------------------------- parsing

    @staticmethod
    def parse(content: str) -> list[dict[str, Any]]:
        """Extract the findings list from analysis output.

        Tolerates a fenced code block around the JSON (a very common model
        behaviour) but nothing looser — prose-only output raises.
        """
        text = (content or "").strip()
        if not text:
            return []
        candidates = [text]
        block = _JSON_BLOCK.search(text)
        if block:
            candidates.insert(0, block.group(1).strip())

        for candidate in candidates:
            try:
                document = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(document, dict):
                findings = document.get("findings")
                if findings is None:
                    findings = [document] if "cwe" in document else []
            elif isinstance(document, list):
                findings = document
            else:
                continue
            if not isinstance(findings, list):
                raise MalformedAnalysisOutput("'findings' must be a list")
            return [f for f in findings if isinstance(f, dict)]

        raise MalformedAnalysisOutput(
            "analysis output was not structured findings JSON (free-form output is rejected)"
        )

    # --------------------------------------------------------- normalizing

    def normalize(
        self,
        raw_findings: list[dict[str, Any]],
        *,
        source: str = "analysis",
        status: str = "local",
        default_repo: str = "",
        segment_id: str | None = None,
    ) -> NormalizationResult:
        result = NormalizationResult()
        for raw in raw_findings:
            try:
                result.findings.append(
                    self._normalize_one(
                        raw,
                        source=source,
                        status=status,
                        default_repo=default_repo,
                        segment_id=segment_id,
                    )
                )
            except (SchemaError, cwe.UnknownCWE, KeyError, TypeError, ValueError) as exc:
                result.rejected.append(
                    {
                        "reason": str(exc),
                        "cwe": str(raw.get("cwe", "?")),
                        "file": str((raw.get("location") or {}).get("file", "?")),
                    }
                )
        return result

    def _normalize_one(
        self,
        raw: dict[str, Any],
        *,
        source: str,
        status: str,
        default_repo: str,
        segment_id: str | None,
    ) -> dict[str, Any]:
        identifier = str(raw.get("cwe", "")).upper().strip()
        if identifier and not identifier.startswith("CWE-"):
            identifier = f"CWE-{identifier}"
        cwe.validate_cwe(identifier)  # rejects hallucinated ids

        score = raw.get("severity_score")
        score = float(score) if score is not None else cwe.default_severity(identifier)
        score = max(0.0, min(10.0, round(score, 1)))

        location = dict(raw.get("location") or {})
        location.setdefault("repo", default_repo)
        location["line_start"] = int(location.get("line_start") or 1)
        location["line_end"] = int(location.get("line_end") or location["line_start"])
        if location["line_end"] < location["line_start"]:
            location["line_end"] = location["line_start"]
        location = {k: v for k, v in location.items() if v not in (None, "")}

        evidence = []
        for item in raw.get("evidence") or []:
            entry = {
                "repo": str(item.get("repo") or location.get("repo") or default_repo),
                "file": str(item.get("file") or location.get("file", "")),
                "reason": str(item.get("reason") or "").strip(),
            }
            if item.get("symbol"):
                entry["symbol"] = str(item["symbol"])
            if item.get("segment_id") or segment_id:
                entry["segment_id"] = str(item.get("segment_id") or segment_id)
            if entry["file"] and entry["reason"]:
                evidence.append(entry)
        if not evidence:
            raise ValueError("finding has no usable evidence (FR-012 requires evidence)")

        finding: dict[str, Any] = {
            "id": str(raw.get("id") or self.allocate_id()),
            "cwe": identifier,
            "severity_score": score,
            "severity_band": cwe.band_for(score),
            "confidence": max(0.0, min(1.0, float(raw.get("confidence", 0.5)))),
            "location": location,
            "description": str(raw.get("description") or cwe.name_for(identifier)),
            "evidence": evidence,
            "attack_scenario": str(raw.get("attack_scenario") or "").strip()
            or f"An attacker exploits {cwe.name_for(identifier)} via the exposed entry point.",
            "impact": str(raw.get("impact") or "").strip() or "Security impact on the application.",
            "recommendation": str(raw.get("recommendation") or "").strip()
            or f"Remediate {cwe.name_for(identifier)} at the reported location.",
            "source": source,
            "status": status,
        }

        owasp = cwe.owasp_for(identifier)
        if owasp:
            finding["owasp_top10"] = owasp
        refs = cwe.compliance_refs(identifier)
        if refs:
            finding["compliance_refs"] = refs
        if raw.get("related_symbols"):
            finding["related_symbols"] = [str(s) for s in raw["related_symbols"]]
        # Detection provenance (feature 003, FR-008/FR-010): additive, emitted
        # only by the deterministic secret stage.
        if raw.get("detection") in ("format", "heuristic"):
            finding["detection"] = raw["detection"]
        if raw.get("code_context") in ("production", "test"):
            finding["code_context"] = raw["code_context"]
        if raw.get("tool_ref"):
            finding["tool_ref"] = str(raw["tool_ref"])
        if segment_id or raw.get("segment_id"):
            finding["segment_id"] = str(raw.get("segment_id") or segment_id)
        for optional in (
            "verification",
            "reproduction",
            "relationships",
            "canonical_id",
            "mitigation",
        ):
            if raw.get(optional):
                finding[optional] = raw[optional]

        validate("finding", finding)
        return finding


def segment_id_for(request_id: str) -> str:
    """Strip the escalation-level suffix from a handoff request id."""
    return _REQUEST_SUFFIX.sub("", request_id)


def normalize_responses(store: Any, segments: list[dict[str, Any]]) -> dict[str, Any]:
    """Normalize agent-written handoff responses into `findings/local/*.json`.

    This is the standalone counterpart to what the driver does in-process, so an
    agent that answered requests out of band can normalize without a full run.
    """
    repo_for = {segment["id"]: segment["repos"][0] for segment in segments}
    responses = sorted((store.dir / "handoff" / "responses").glob("*.json"))
    normalizer = FindingNormalizer()

    per_segment: dict[str, list[dict[str, Any]]] = {}
    warnings: list[str] = []

    for path in responses:
        segment_id = segment_id_for(path.stem)
        try:
            parsed = normalizer.parse(path.read_text())
        except MalformedAnalysisOutput as exc:
            warnings.append(f"{path.name}: {exc}")
            continue
        result = normalizer.normalize(
            parsed,
            source="analysis",
            status="local",
            default_repo=repo_for.get(segment_id, ""),
            segment_id=segment_id,
        )
        warnings.extend(
            f"{segment_id}: rejected non-conforming finding "
            f"({r['cwe']} in {r['file']}): {r['reason']}"
            for r in result.rejected
        )
        per_segment.setdefault(segment_id, []).extend(result.findings)

    for segment_id, findings in sorted(per_segment.items()):
        store.write(
            f"findings/local/{segment_id}.json",
            "normalize_findings",
            {"segment_id": segment_id, "findings": findings},
        )

    return {
        "segments": len(per_segment),
        "findings": sum(len(v) for v in per_segment.values()),
        "warnings": warnings,
    }


def resolve_and_dedupe(
    findings: list[dict[str, Any]],
    graph: dict[str, Any],
    roots: dict[str, Any] | None = None,
    analyzed_files: set[tuple[str, str]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve locations against the code model, then dedupe. Order matters.

    Resolution MUST precede deduplication (FR-007): two findings that differ only
    in the line numbers a model guessed are the same finding, and only become
    recognizably identical once both have been snapped to the authoritative range.
    Deduping first would keep both.

    Returns ``(kept, rejected)`` — rejected findings had unresolvable locations
    and never reach a report (FR-003).
    """
    from pipeline.locate import apply_resolution

    kept, rejected = apply_resolution(findings, graph, roots, analyzed_files)
    return dedupe_by_location(kept), rejected


def dedupe_by_location(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse findings that are literally the same CWE at the same line."""
    out: dict[tuple, dict[str, Any]] = {}
    for finding in findings:
        location = finding["location"]
        key = (
            finding["cwe"],
            location.get("repo"),
            location.get("file"),
            location.get("line_start"),
            # Feature 004 (D3): distinct packages sharing a manifest line are
            # distinct findings; findings without symbols dedupe as before.
            location.get("symbol"),
            # Spec 007: rule-driven findings are distinct per rule even when
            # they share CWE and line (doc) (e.g. separate excessive-agency
            # grants in one agent-configuration artifact).
            finding.get("tool_ref"),
        )
        existing = out.get(key)
        if existing is None:
            out[key] = finding
            continue
        # keep the higher-confidence record, merging evidence
        winner, loser = (
            (finding, existing)
            if finding["confidence"] > existing["confidence"]
            else (existing, finding)
        )
        merged = list(winner["evidence"])
        seen = {(e["file"], e["reason"]) for e in merged}
        for item in loser["evidence"]:
            if (item["file"], item["reason"]) not in seen:
                merged.append(item)
        winner["evidence"] = merged
        out[key] = winner
    return sorted(out.values(), key=lambda f: f["id"])


def main() -> None:  # pragma: no cover - CLI wrapper
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    args = parser.parse_args()

    from pipeline.state import ArtifactStore

    store = ArtifactStore(args.workdir)
    segments = [store.read(f"segments/{p.name}") for p in store.glob("segments/*.json")]
    summary = normalize_responses(store, segments)
    print(
        f"normalized {summary['findings']} finding(s) across "
        f"{summary['segments']} segment(s)"
    )
    for warning in summary["warnings"]:
        print(f"  ! {warning}")


if __name__ == "__main__":  # pragma: no cover
    main()
