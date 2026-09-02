"""Artifact store, checkpoints, resume, and change detection.

Implements the durable-artifact contract (FR-016), automatic resume (FR-016a),
and the per-file hashing that drives incremental scans (FR-017).

Determinism: artifacts are written with sorted keys and a trailing newline so
identical inputs yield byte-identical files (artifact-schemas.md invariant 1).
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pipeline.schemas import SCHEMA_VERSION, validate

TOOL_VERSION = "0.1.0"
SCAN_DIR_NAME = ".secscan"

#: Ordered pipeline stages. Resume walks this list and skips stages whose
#: recorded resume key still matches.
#: The accuracy stages added in feature 002 sit between analysis and reporting,
#: and their order is forced by the requirements rather than chosen (research.md
#: A8): location resolution runs inside `normalize_findings` so it precedes
#: deduplication (FR-007); `applicability` precedes `correlate_findings` so a
#: remap that creates a duplicate is deduplicated (FR-018); `calibrate` follows
#: `verify_findings` because the severity cap is keyed on the verdict (FR-020);
#:
#: One deviation from research.md A8, recorded deliberately: A8 sketched
#: correlation *before* verification. Nothing requires that ordering — FR-018 only
#: pins correlation after remapping — and doing it would let a finding that
#: verification later disproves be chosen as a duplicate group's canonical entry,
#: taking the whole group down with it. Verification therefore stays ahead of
#: correlation, as it was before this feature.
#: `reproduce` follows `calibrate` because the hypothesis-versus-observation
#: choice is keyed on the verdict too (FR-008); and `consistency` is last because
#: it validates the assembled result before it is written (FR-042).
STAGES: tuple[str, ...] = (
    "discover_repo",
    "build_code_graph",
    "partition_repo",
    "build_context",
    "ingest_findings",
    "segment_analysis",
    "normalize_findings",
    "applicability",
    "verify_findings",
    "correlate_findings",
    "calibrate",
    "reproduce",
    "consistency",
    "system_review",
    "generate_report",
)

#: Non-hidden directories that never contain reviewable application source.
#: Hidden directories (any component starting with ".") are skipped wholesale —
#: that covers VCS metadata, virtualenvs, tool caches, `.secscan/` itself,
#: and critically the installed agent skill directories (`.claude/`, `.devin/`,
#: ...), so the scanner never wastes budget analysing its own payload.
_SKIP_DIRS = {
    "node_modules",
    "__pycache__",
    "venv",
    "dist",
    "build",
    "target",
    "vendor",
    "site-packages",
    "bower_components",
}

#: Suffixes ``iter_source_files`` will even look at.
#:
#: Broadened in feature 002 (FR-003c): languages with no grammar are enumerated so
#: they can be represented at file granularity. A file the enumerator never sees
#: cannot be represented at all, and a finding in it would then be rejected for an
#: unresolvable location — turning a parser gap into silent under-reporting.
_SOURCE_SUFFIXES = {
    # grammar-backed
    ".py",
    ".java",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".go",
    # markup and view templates (FR-025)
    ".html",
    ".htm",
    ".vue",
    ".jsp",
    ".jspx",
    ".djhtml",
    ".j2",
    ".jinja",
    ".jinja2",
    ".njk",
    ".tmpl",
    ".gohtml",
    ".gotmpl",
    ".hbs",
    ".mustache",
    ".erb",
    # enumerated, no grammar
    ".yaml",
    ".yml",
    ".json",
    ".tf",
    ".sql",
    ".graphql",
    ".graphqls",
    ".properties",
    ".env",
    ".xml",
    ".toml",
    # unmodelled programming languages (file-tier representation only)
    ".rb",
    ".php",
    ".cs",
    ".rs",
    ".kt",
    ".kts",
    ".swift",
    ".scala",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".hpp",
    ".m",
    ".pl",
    ".sh",
    ".bash",
    ".ps1",
    ".lua",
    ".dart",
    ".ex",
    ".exs",
    ".erl",
    ".groovy",
    ".r",
}


def canonical_json(document: Any) -> str:
    """Deterministic JSON rendering used for both artifacts and hashing."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def hash_document(document: Any) -> str:
    return hash_text(canonical_json(document))


def is_skipped_dir(name: str) -> bool:
    return name.startswith(".") or name in _SKIP_DIRS


def iter_source_files(root: Path) -> list[Path]:
    """Deterministically enumerate candidate source files under ``root``.

    AI configuration artifacts (spec 007) are enumerated by shipped file class
    even when their suffix or dotfile name would otherwise skip them — these
    files govern model behavior and must be visible to coverage and review
    (FR-005/FR-009/FR-011); otherwise the class would be silently invisible.
    """
    from pipeline import stacks

    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        ai_class = stacks.file_class_for(path.name) in (
            "ai-agent-config",
            "ai-mcp-config",
            "prompt-artifact",
        )
        directories = path.relative_to(root).parts[:-1]
        if any(is_skipped_dir(part) for part in directories) and not ai_class:
            continue
        if path.name.startswith(".") and not ai_class:
            continue
        if path.suffix.lower() in _SOURCE_SUFFIXES or ai_class:
            found.append(path)
    return found


@dataclass
class StageRecord:
    status: str = "pending"  # pending | running | done | failed
    resume_key: str | None = None
    artifacts: list[str] = field(default_factory=list)
    error: str | None = None
    updated_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "resume_key": self.resume_key,
            "artifacts": sorted(self.artifacts),
            "error": self.error,
            "updated_at": round(self.updated_at, 3),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> StageRecord:
        return cls(
            status=raw.get("status", "pending"),
            resume_key=raw.get("resume_key"),
            artifacts=list(raw.get("artifacts") or []),
            error=raw.get("error"),
            updated_at=float(raw.get("updated_at") or 0.0),
        )


class ArtifactStore:
    """Filesystem-backed artifact store rooted at ``<scan_root>/.secscan``."""

    def __init__(self, scan_root: Path, scan_id: str | None = None) -> None:
        self.scan_root = Path(scan_root).resolve()
        self.dir = self.scan_root / SCAN_DIR_NAME
        self.state_path = self.dir / "state.json"
        self._state: dict[str, Any] = {}
        self._load_state()
        if scan_id:
            self._state["scan_id"] = scan_id
        elif not self._state.get("scan_id"):
            self._state["scan_id"] = self._new_scan_id()

    # ---------------------------------------------------------------- state

    @staticmethod
    def _new_scan_id() -> str:
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        return f"{stamp}-{hash_text(str(time.time_ns()))[:6]}"

    @property
    def scan_id(self) -> str:
        return self._state["scan_id"]

    def _load_state(self) -> None:
        if self.state_path.exists():
            self._state = json.loads(self.state_path.read_text())
        else:
            self._state = {"schema_version": SCHEMA_VERSION, "stages": {}, "file_hashes": {}}
        self._state.setdefault("stages", {})
        self._state.setdefault("file_hashes", {})

    def save_state(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(canonical_json(self._state))

    # --------------------------------------------------------------- stages

    def stage(self, name: str) -> StageRecord:
        raw = self._state["stages"].get(name)
        return StageRecord.from_dict(raw) if raw else StageRecord()

    def set_stage(self, name: str, record: StageRecord) -> None:
        record.updated_at = time.time()
        self._state["stages"][name] = record.to_dict()
        self.save_state()

    def should_skip(self, name: str, resume_key: str) -> bool:
        """True when the stage already completed for this exact input (FR-016a)."""
        rec = self.stage(name)
        return rec.status == "done" and rec.resume_key == resume_key

    def mark_running(self, name: str) -> None:
        rec = self.stage(name)
        rec.status = "running"
        rec.error = None
        self.set_stage(name, rec)

    def mark_done(self, name: str, resume_key: str, artifacts: list[str] | None = None) -> None:
        rec = self.stage(name)
        rec.status = "done"
        rec.resume_key = resume_key
        rec.error = None
        if artifacts:
            rec.artifacts = artifacts
        self.set_stage(name, rec)

    def mark_failed(self, name: str, error: str) -> None:
        rec = self.stage(name)
        rec.status = "failed"
        rec.error = error
        self.set_stage(name, rec)

    def invalidate(self, *names: str) -> None:
        """Reset stages so they re-run (used by incremental/profile-depth changes)."""
        for name in names:
            if name in self._state["stages"]:
                self._state["stages"][name] = StageRecord().to_dict()
        self.save_state()

    def stage_summary(self) -> dict[str, str]:
        return {name: self.stage(name).status for name in STAGES}

    # ------------------------------------------------------------ artifacts

    def path_for(self, relative: str) -> Path:
        return self.dir / relative

    def write(self, relative: str, stage: str, payload: Any, schema: str | None = None) -> Path:
        """Write an enveloped artifact; validates ``payload`` when ``schema`` given."""
        if schema:
            validate(schema, payload)
        envelope = {
            "schema_version": SCHEMA_VERSION,
            "produced_by": {"stage": stage, "tool_version": TOOL_VERSION},
            "scan_id": self.scan_id,
            "payload": payload,
        }
        path = self.path_for(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(canonical_json(envelope))
        return path

    def read(self, relative: str) -> Any:
        """Read an artifact payload, tolerating raw (envelope-less) documents."""
        path = self.path_for(relative)
        if not path.exists():
            raise FileNotFoundError(f"missing artifact: {path}")
        doc = json.loads(path.read_text())
        if isinstance(doc, dict) and "payload" in doc and "produced_by" in doc:
            self._check_schema_version(relative, doc)
            return doc["payload"]
        return doc

    def read_optional(self, relative: str, default: Any = None) -> Any:
        try:
            return self.read(relative)
        except FileNotFoundError:
            return default

    def exists(self, relative: str) -> bool:
        return self.path_for(relative).exists()

    def glob(self, pattern: str) -> list[Path]:
        return sorted(self.dir.glob(pattern))

    @staticmethod
    def _check_schema_version(relative: str, envelope: dict[str, Any]) -> None:
        found = str(envelope.get("schema_version"))
        if found != SCHEMA_VERSION:
            raise SchemaVersionMismatch(relative, found, SCHEMA_VERSION)

    def write_text(self, relative: str, text: str) -> Path:
        path = self.path_for(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    # -------------------------------------------------- change detection

    def snapshot_files(self, roots: dict[str, Path]) -> dict[str, str]:
        """Hash every source file across workspace members (``name -> path``)."""
        hashes: dict[str, str] = {}
        for repo, root in sorted(roots.items()):
            root = Path(root).resolve()
            if not root.exists():
                continue
            for path in iter_source_files(root):
                key = f"{repo}:{path.relative_to(root).as_posix()}"
                try:
                    hashes[key] = hash_text(path.read_text(errors="replace"))
                except OSError:
                    continue
        return hashes

    def changed_files(self, current: dict[str, str]) -> dict[str, list[str]]:
        """Compare ``current`` against the recorded snapshot."""
        previous: dict[str, str] = self._state.get("file_hashes") or {}
        added = sorted(k for k in current if k not in previous)
        removed = sorted(k for k in previous if k not in current)
        modified = sorted(k for k in current if k in previous and current[k] != previous[k])
        return {"added": added, "removed": removed, "modified": modified}

    def record_files(self, current: dict[str, str]) -> None:
        self._state["file_hashes"] = dict(sorted(current.items()))
        self.save_state()

    def has_snapshot(self) -> bool:
        return bool(self._state.get("file_hashes"))

    # ------------------------------------------------------------ metadata

    def get_meta(self, key: str, default: Any = None) -> Any:
        return (self._state.get("meta") or {}).get(key, default)

    def set_meta(self, key: str, value: Any) -> None:
        self._state.setdefault("meta", {})[key] = value
        self.save_state()


class SchemaVersionMismatch(RuntimeError):
    """Artifact written by an incompatible tool version (FR-020 upgrade path)."""

    def __init__(self, artifact: str, found: str, expected: str) -> None:
        self.artifact = artifact
        super().__init__(
            f"artifact '{artifact}' has schema_version {found}, expected {expected}. "
            "Re-run the affected stages (or a full scan) after the upgrade."
        )
