"""T018: `single-repo-shop` fixture — a multi-module Flask app with seeded flaws.

Ground truth (SC-009):
  * SQL injection in the orders repository            (CWE-89,  true positive)
  * Missing authorization on the admin endpoint       (CWE-862, true positive)
  * Hard-coded credential in config                   (CWE-798, true positive)
  * Cross-component flow: controller validates, service assumes, repo executes
                                                      (CWE-89,  true positive)
  * Parameterized query already safe upstream         (false positive for triage)
"""

from __future__ import annotations

from pathlib import Path

from tests.fixtures.build_fixture import Fixture, SeededVuln

FIXTURE = Fixture(
    name="single-repo-shop",
    seeded=[
        SeededVuln(
            key="sqli-order-lookup",
            cwe="CWE-89",
            file="src/orders/repository.py",
            symbol="find_by_id",
            note="order id interpolated into SQL via f-string",
        ),
        SeededVuln(
            key="missing-authz-admin",
            cwe="CWE-862",
            file="src/admin/api.py",
            symbol="delete_user",
            note="destructive admin endpoint with no authorization check",
        ),
        SeededVuln(
            key="hardcoded-credential",
            cwe="CWE-798",
            file="src/config/settings.py",
            symbol="DB_PASSWORD",
            note="database password committed in source",
        ),
        SeededVuln(
            key="cross-component-sqli",
            cwe="CWE-89",
            file="src/reports/repository.py",
            symbol="run_report",
            note="controller validates shape only; service trusts it; repo concatenates",
        ),
        SeededVuln(
            key="safe-parameterized-query",
            cwe="CWE-89",
            file="src/users/repository.py",
            symbol="find_by_email",
            note="scanner may flag this, but the query is parameterized (false positive)",
            expect_reported=False,
        ),
    ],
    files={
        "requirements.txt": "flask==3.0.0\npsycopg2-binary==2.9.9\n",
        "src/__init__.py": "",
        # ----------------------------------------------------------- config
        "src/config/__init__.py": "",
        "src/config/settings.py": '''"""Application settings."""

DB_HOST = "db.internal"
DB_USER = "shop_app"
# Seeded flaw: hard-coded credential (CWE-798)
DB_PASSWORD = "Pr0d-Sh0p-DB-2024!"
SESSION_TIMEOUT_MINUTES = 30
''',
        # ----------------------------------------------------------- orders
        "src/orders/__init__.py": "",
        "src/orders/api.py": '''"""Order HTTP endpoints."""

from flask import Blueprint, jsonify, request

from src.orders.service import OrderService

bp = Blueprint("orders", __name__)
service = OrderService()


@bp.route("/orders/<order_id>", methods=["GET"])
def get_order(order_id):
    """Return a single order."""
    return jsonify(service.get_order(order_id))


@bp.route("/orders", methods=["GET"])
def list_orders():
    customer = request.args.get("customer")
    return jsonify(service.list_for_customer(customer))
''',
        "src/orders/service.py": '''"""Order business logic."""

from src.orders.repository import OrderRepository


class OrderService:
    def __init__(self):
        self.repository = OrderRepository()

    def get_order(self, order_id):
        return self.repository.find_by_id(order_id)

    def list_for_customer(self, customer):
        return self.repository.find_by_customer(customer)
''',
        "src/orders/repository.py": '''"""Order persistence."""

import psycopg2

from src.config import settings


def _connect():
    return psycopg2.connect(
        host=settings.DB_HOST,
        user=settings.DB_USER,
        password=settings.DB_PASSWORD,
    )


class OrderRepository:
    def find_by_id(self, order_id):
        """Seeded flaw: SQL injection (CWE-89) - order_id is user controlled."""
        conn = _connect()
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM orders WHERE id = '{order_id}'")
        return cursor.fetchall()

    def find_by_customer(self, customer):
        conn = _connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM orders WHERE customer = %s", (customer,))
        return cursor.fetchall()
''',
        # ------------------------------------------------------------ admin
        "src/admin/__init__.py": "",
        "src/admin/api.py": '''"""Administrative endpoints."""

from flask import Blueprint, jsonify

from src.admin.service import AdminService

bp = Blueprint("admin", __name__)
service = AdminService()


@bp.route("/admin/users/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    """Seeded flaw: missing authorization (CWE-862).

    No role check, no session validation - any caller may delete any user.
    """
    service.delete_user(user_id)
    return jsonify({"deleted": user_id})


@bp.route("/admin/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})
''',
        "src/admin/service.py": '''"""Administrative operations."""

from src.users.repository import UserRepository


class AdminService:
    def __init__(self):
        self.repository = UserRepository()

    def delete_user(self, user_id):
        return self.repository.delete(user_id)
''',
        # ------------------------------------------------------------ users
        "src/users/__init__.py": "",
        "src/users/repository.py": '''"""User persistence - safe (false-positive bait)."""

import psycopg2

from src.config import settings


class UserRepository:
    def _connect(self):
        return psycopg2.connect(
            host=settings.DB_HOST, user=settings.DB_USER, password=settings.DB_PASSWORD
        )

    def find_by_email(self, email):
        """Parameterized - NOT injectable despite touching user input."""
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        return cursor.fetchone()

    def delete(self, user_id):
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
''',
        # ---------------------------------------------------------- reports
        "src/reports/__init__.py": "",
        "src/reports/api.py": '''"""Reporting endpoints."""

from flask import Blueprint, jsonify, request

from src.reports.service import ReportService

bp = Blueprint("reports", __name__)
service = ReportService()


@bp.route("/reports/run", methods=["POST"])
def run_report():
    """Validates only that the field is a non-empty string."""
    body = request.get_json() or {}
    group_by = body.get("group_by")
    if not isinstance(group_by, str) or not group_by:
        return jsonify({"error": "group_by required"}), 400
    return jsonify(service.run(group_by))
''',
        "src/reports/service.py": '''"""Reporting logic - trusts controller validation."""

from src.reports.repository import ReportRepository


class ReportService:
    def __init__(self):
        self.repository = ReportRepository()

    def run(self, group_by):
        # Assumes group_by was validated as a safe column name upstream.
        return self.repository.run_report(group_by)
''',
        "src/reports/repository.py": '''"""Report persistence."""

import psycopg2

from src.config import settings


class ReportRepository:
    def run_report(self, group_by):
        """Seeded flaw: cross-component SQL injection (CWE-89).

        Each layer looks defensible alone: the controller checks the type, the
        service trusts the controller, and this method concatenates.
        """
        conn = psycopg2.connect(
            host=settings.DB_HOST, user=settings.DB_USER, password=settings.DB_PASSWORD
        )
        cursor = conn.cursor()
        cursor.execute("SELECT " + group_by + ", COUNT(*) FROM orders GROUP BY " + group_by)
        return cursor.fetchall()
''',
        # -------------------------------------------------------------- app
        "src/app.py": '''"""Application entrypoint."""

from flask import Flask

from src.admin import api as admin_api
from src.orders import api as orders_api
from src.reports import api as reports_api


def create_app():
    app = Flask(__name__)
    app.register_blueprint(orders_api.bp)
    app.register_blueprint(admin_api.bp)
    app.register_blueprint(reports_api.bp)
    return app
''',
    },
)


def build(root: Path) -> Path:
    """Materialize the fixture under ``root`` and return its path."""
    return FIXTURE.write(root)
