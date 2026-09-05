"""Feature 015: a seeded single-repo business-flow fixture.

Layout: a single Flask shop application with one deliberately broken business flow
and two deliberately safe flows:

    flow-app/
      requirements.txt
      src/app.py

Seeded gap (must be reported): the order flow lets any caller reach the staff-discount
mutation directly — no role check at that step — even though the flow's preceding steps
never establish staff identity. A regular shopper grants themselves staff pricing.

Safe flows (must NOT be flagged): the profile flow carries authentication at the entry
step, and the admin-user flow carries both authentication and an explicit admin
authorization check at the privileged step.
"""

from __future__ import annotations

import shutil
from pathlib import Path

APP_FILES: dict[str, str] = {
    "requirements.txt": "flask==3.0.0\n",
    "src/app.py": '''"""Shop app: one broken order flow, two safe flows."""

import sqlite3

from flask import Flask, g, request

app = Flask(__name__)


def current_user():
    return g.get("user")


def require_admin():
    user = current_user()
    if not user or user.get("role") != "admin":
        return False
    return True


# --- seeded broken flow: order checkout -------------------------------

@app.route("/order/start", methods=["POST"])
def order_start():
    """Entry step: creates a pending order. Anonymous is allowed by design."""
    order_id = request.form["item"]
    return {"order_id": order_id, "status": "pending"}


@app.route("/order/apply-staff-discount", methods=["POST"])
def order_apply_staff_discount():
    """Seeded gap: staff-only pricing mutation with NO authorization check here."""
    order_id = request.form["order_id"]
    db = sqlite3.connect("shop.db")
    db.execute("UPDATE orders SET price = price * 0.5 WHERE id = ?", (order_id,))
    return {"order_id": order_id, "discount": "staff"}


@app.route("/order/confirm", methods=["POST"])
def order_confirm():
    """Terminal step: captures payment for the (possibly discounted) order."""
    order_id = request.form["order_id"]
    return {"order_id": order_id, "status": "confirmed"}


# --- seeded regulatory case: signup collects personal data, no consent step ---

@app.route("/signup", methods=["POST"])
def signup():
    """Seeded regulatory gap: personal data stored with no consent step."""
    email = request.form["email"]
    db = sqlite3.connect("shop.db")
    db.execute("INSERT INTO users (email) VALUES (?)", (email,))
    return {"created": email}


@app.route("/account/delete", methods=["POST"])
@login_required
def account_delete():
    """Safe: a reachable, authenticated data-subject deletion path."""
    db = sqlite3.connect("shop.db")
    db.execute("DELETE FROM users WHERE email = ?", (current_user()["email"],))
    return {"deleted": True}


# --- deliberately safe flows ------------------------------------------

@app.route("/profile", methods=["GET"])
@login_required
def profile_view():
    """Safe step: entry carries authentication."""
    return current_user()


@app.route("/admin/users", methods=["POST"])
@login_required
def admin_create_user():
    """Safe step: privileged mutation is behind an explicit admin check."""
    if not require_admin():
        return {"error": "forbidden"}, 403
    return {"created": request.form["name"]}
''',
}


def build(root: Path) -> Path:
    """Materialize the fixture and return its root."""
    app_root = root / "flow-app"
    if app_root.exists():
        shutil.rmtree(app_root)
    for relative, content in APP_FILES.items():
        path = app_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return app_root


def flow_oracle_answer(request) -> str | None:
    """Flow-aware stand-in for agent reasoning (feature 015).

    Returns a JSON answer for ``business_flow_analysis`` requests — the seeded
    staff-discount gap for that flow, clean otherwise — or ``None`` for packets of
    other stages, so callers can fall back to the shared oracle responder.
    """
    import json

    payload = request.payload
    if "flow" not in payload:
        return None
    flow = payload["flow"]
    regimes = payload.get("regimes") or []
    if "/signup" in str(flow.get("name", "")) and regimes:
        repo = flow["steps"][0]["node_id"].split(":", 1)[0]
        refs = [
            {
                "regime": regime["regime"],
                "obligation": next(
                    (
                        o["id"]
                        for o in regime["obligations"]
                        if "consent-before-collection" in o.get("flow_patterns", [])
                    ),
                    regime["obligations"][0]["id"],
                ),
            }
            for regime in regimes
        ]
        return json.dumps(
            {
                "flow_id": flow["id"],
                "assessment": "violation",
                "findings": [
                    {
                        "cwe": "CWE-359",  # exposure of personal information
                        "severity_score": 6.5,
                        "confidence": 0.8,
                        "location": {
                            "repo": repo,
                            "file": "src/app.py",
                            "symbol": "signup",
                        },
                        "description": (
                            "The signup flow stores personal data (email) without a "
                            "consent step before collection — a potential compliance risk."
                        ),
                        "evidence": [
                            {
                                "repo": repo,
                                "file": "src/app.py",
                                "reason": "collection step has no preceding consent step",
                            }
                        ],
                        "missing_check": "consent before collection",
                        "compromise": "users' personal data is collected without consent",
                        "regulatory_refs": refs,
                    }
                ],
            }
        )
    if GROUND_TRUTH["flow_gaps"][0]["flow_contains"] in json.dumps(flow):
        repo = flow["steps"][0]["node_id"].split(":", 1)[0]
        return json.dumps(
            {
                "flow_id": flow["id"],
                "assessment": "gap",
                "findings": [
                    {
                        "cwe": "CWE-862",
                        "severity_score": 8.5,
                        "confidence": 0.85,
                        "location": {
                            "repo": repo,
                            "file": GROUND_TRUTH["flow_gaps"][0]["file"],
                            "symbol": "order_apply_staff_discount",
                        },
                        "description": (
                            "The staff-discount step performs a pricing mutation without "
                            "re-checking that the caller holds a staff role."
                        ),
                        "evidence": [
                            {
                                "repo": repo,
                                "file": GROUND_TRUTH["flow_gaps"][0]["file"],
                                "reason": "privileged step lacks staff authorization",
                            }
                        ],
                        "missing_check": GROUND_TRUTH["flow_gaps"][0]["missing_check"],
                        "compromise": "a regular shopper grants themselves staff pricing",
                        "attack_scenario": "Call the discount endpoint directly mid-flow.",
                        "impact": "Unauthorized price manipulation.",
                        "recommendation": "Enforce a staff role check at the discount step.",
                    }
                ],
            }
        )
    return json.dumps(
        {"flow_id": flow["id"], "assessment": "clean", "findings": []}
    )


#: Declared ground truth, asserted by tests rather than restated inline.
GROUND_TRUTH = {
    # The staff-discount step is reachable without the shopper ever establishing
    # staff identity — the one flow gap in the fixture.
    "flow_gaps": [
        {
            "flow_contains": "apply-staff-discount",
            "missing_check": "staff",
            "file": "src/app.py",
        }
    ],
    # Deliberately safe flows that MUST NOT be reported as flow gaps.
    "safe_flows_at": ["/profile", "/admin/users"],
    # Nothing a code-level scan would attribute to the staff-discount handler.
    "code_level_findings_for_gap": 0,
    # Seeded regulatory case: the signup flow collects personal data (email) with
    # no consent step; /account/delete is the safe deletion path.
    "regulatory_case": {
        "violation_flow": "/signup",
        "expected_regime": "gdpr",
        "expected_obligation": "gdpr-consent-before-collection",
        "safe_deletion_flow": "/account/delete",
    },
}
