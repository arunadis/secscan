"""Feature 013 fixture targets: repositories and scripted triage answers.

Ground truth is declared here, next to the code that produces it:

- ``src/api/admin.py``  — a destructive-looking endpoint the segment oracle
  flags (CWE-862); a filter in ``security.py`` neutralizes it, so a correct
  triage round refutes it with a verified citation.
- ``src/security.py``   — the control (``RoleAuthorizationFilter`` covering
  ``/api/admin/**``); also where fabricated citations fail re-verification.
- ``src/dev/auth.py``   — a localhost-only dev token (deterministic CWE-798);
  a correct triage round may flag or downgrade it, never refute it.
"""

from __future__ import annotations

import json
from pathlib import Path

SECRET_LINE = 'DEV_ONLY_TOKEN = "local-dev-token-only"'
DECLARATION_QUESTION = (
    "Is local-dev-token-only ever presented to a non-localhost listener?"
)


def build_repo(root: Path) -> Path:
    """Write the mini-repo; returns the member directory (``root/'shop'``)."""
    member = root / "shop"
    (member / "src" / "api").mkdir(parents=True)
    (member / "src" / "api" / "admin.py").write_text(
        "def delete_all_users(request):\n"
        "    # destructive endpoint; authorization enforced upstream\n"
        "    return wipe_database()\n"
        "\n"
        "def wipe_database():\n"
        "    return None\n"
    )
    (member / "src" / "security.py").write_text(
        "class RoleAuthorizationFilter:\n"
        "    ROUTES = {'/api/admin/**': 'MANAGE_USERS'}\n"
        "\n"
        "    def applies(self, path):\n"
        "        return path.startswith('/api/admin')\n"
    )
    (member / "src" / "dev").mkdir(exist_ok=True)
    (member / "src" / "dev" / "auth.py").write_text(f"{SECRET_LINE}\n")
    return member


def segment_findings(repo: str = "shop") -> str:
    """The segment-analysis answer seeding the CWE-862 finding."""
    return json.dumps(
        {
            "findings": [
                {
                    "cwe": "CWE-862",
                    "severity_score": 8.2,
                    "confidence": 0.8,
                    "location": {
                        "repo": repo,
                        "file": "src/api/admin.py",
                        "symbol": "delete_all_users",
                        "line_start": 1,
                        "line_end": 3,
                    },
                    "description": "A destructive endpoint lacks an authorization check.",
                    "evidence": [
                        {
                            "repo": repo,
                            "file": "src/api/admin.py",
                            "reason": "no guard visible in the handler",
                        }
                    ],
                    "attack_scenario": "An unauthenticated caller wipes user data.",
                    "impact": "Total data loss.",
                    "recommendation": "Require an authorization check.",
                }
            ]
        }
    )


def confirmed(fid: str) -> str:
    return json.dumps({"finding_id": fid, "verdict": "confirmed"})


def scripted_responder(triage_answer=None):
    """Responder covering segment analysis and the triage round.

    ``triage_answer``: dict (answered for findings whose CWE matches ``only_cwe``,
    others get ``confirmed``), callable (raw content), or None (confirm all).
    """

    def respond(request) -> str:
        if request.stage == "finding_triage":
            finding = request.payload["finding"]
            fid = str(finding["id"])
            if triage_answer is None:
                return confirmed(fid)
            if callable(triage_answer):
                return triage_answer(request)
            if isinstance(triage_answer, dict):
                only_cwe = triage_answer.get("only_cwe")
                if only_cwe and finding["cwe"] != only_cwe:
                    return confirmed(fid)
                payload = {k: v for k, v in triage_answer.items() if k != "only_cwe"}
                payload["finding_id"] = fid
                return json.dumps(payload)
            return confirmed(fid)

        payload = request.payload
        sources = payload.get("source") or {}
        if any("admin.py" in path for path in sources):
            return segment_findings(str(payload.get("repo") or "shop"))
        return json.dumps({"findings": []})

    return respond


REFUTING_ANSWER = {
    "only_cwe": "CWE-862",
    "verdict": "refuted",
    "rationale": (
        "RoleAuthorizationFilter maps /api/admin/** to MANAGE_USERS, so the "
        "endpoint is authorized upstream of the handler."
    ),
    "citations": [
        {
            "repo": "shop",
            "file": "src/security.py",
            "line_start": 1,
            "line_end": 5,
            "pattern": "RoleAuthorizationFilter",
        }
    ],
}

FABRICATED_REFUTAL = {
    "only_cwe": "CWE-862",
    "verdict": "refuted",
    "rationale": "claims a control that does not exist",
    "citations": [
        {
            "repo": "shop",
            "file": "src/security.py",
            "line_start": 1,
            "line_end": 5,
            "pattern": "NoSuchFilter",
        }
    ],
}

DEV_TOKEN_FLAG = {
    "only_cwe": "CWE-798",
    "verdict": "flagged",
    "user_question": DECLARATION_QUESTION,
    "settling_evidence_hint": "deployment manifests, gateway rules",
}
