"""Persisted model answers (feature 012, data-model.md "Segment Answer").

One file per analysis request under ``.secscan/analysis/answers/``. An answer is reused
only when its key — derived from the serialized request and the model tier that
answered it — matches the request being made now (FR-008). The file holds exactly
``{request_id, answer_key, content}``: nothing policy-dependent, so a batch run and an
interactive run of the same input persist byte-identical files (SC-003).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.state import canonical_json, hash_text

if TYPE_CHECKING:  # pragma: no cover
    from pipeline.llm_client import AnalysisRequest


def answer_key(request: AnalysisRequest, model_tier: str) -> str:
    """Identity of an answer: the exact serialized request plus who answered it."""
    return hash_text(request.context_text + "\n" + model_tier)


class AnswerStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def path_for(self, request_id: str) -> Path:
        return self.root / f"{request_id}.json"

    def get(self, request: AnalysisRequest, model_tier: str) -> str | None:
        path = self.path_for(request.id)
        try:
            doc = json.loads(path.read_text())
        except (OSError, ValueError):
            return None
        if not isinstance(doc, dict) or doc.get("answer_key") != answer_key(request, model_tier):
            return None
        content = doc.get("content")
        return content if isinstance(content, str) else None

    def put(self, request: AnalysisRequest, model_tier: str, content: str) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.path_for(request.id)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(
            canonical_json(
                {
                    "answer_key": answer_key(request, model_tier),
                    "content": content,
                    "request_id": request.id,
                }
            )
        )
        os.replace(tmp, path)
        return path

    def clear(self) -> None:
        if not self.root.is_dir():
            return
        for path in sorted(self.root.iterdir()):
            if path.is_file():
                path.unlink()
