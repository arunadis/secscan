"""T018: synthetic scale generator for SC-001.

SC-001 requires a repository at least 10x larger than a single analysis context
window, with no invocation exceeding its budget. Committing such a repo would be
absurd, so we generate one deterministically: many modules of realistic-looking
service code, plus a small number of seeded flaws so the scan has something to
find at scale.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from tests.fixtures.build_fixture import Fixture, SeededVuln

MODULE_TEMPLATE = '''"""Auto-generated service module {index}."""

import psycopg2

from src.config import settings


class Service{index}:
    """Handles domain operations for partition {index}."""

    def __init__(self):
        self.table = "entity_{index}"

    def fetch(self, entity_id):
        conn = psycopg2.connect(
            host=settings.DB_HOST, user=settings.DB_USER, password=settings.DB_PASSWORD
        )
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM " + self.table + " WHERE id = %s", (entity_id,))
        return cursor.fetchall()

    def summarize(self, rows):
        total = 0
        for row in rows:
            if row and len(row) > 1:
                total += 1
        return {{"table": self.table, "count": total}}

    def validate(self, payload):
        if not isinstance(payload, dict):
            raise ValueError("payload must be a mapping")
        missing = [k for k in ("id", "name") if k not in payload]
        if missing:
            raise ValueError("missing fields: " + ", ".join(missing))
        return payload
'''

API_TEMPLATE = '''"""Auto-generated endpoints for partition {index}."""

from flask import Blueprint, jsonify, request

from src.generated.service_{index} import Service{index}

bp = Blueprint("generated_{index}", __name__)
service = Service{index}()


@bp.route("/api/v1/entity{index}/<entity_id>", methods=["GET"])
def get_entity_{index}(entity_id):
    return jsonify(service.summarize(service.fetch(entity_id)))


@bp.route("/api/v1/entity{index}", methods=["POST"])
def create_entity_{index}():
    payload = request.get_json() or {{}}
    return jsonify(service.validate(payload))
'''

#: A flawed module planted every N modules so findings exist at scale.
FLAWED_TEMPLATE = '''"""Auto-generated service module {index} (contains a seeded flaw)."""

import psycopg2

from src.config import settings


class Service{index}:
    def search(self, term):
        """Seeded flaw: SQL injection (CWE-89) at scale."""
        conn = psycopg2.connect(
            host=settings.DB_HOST, user=settings.DB_USER, password=settings.DB_PASSWORD
        )
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM entity_{index} WHERE name LIKE '%{{term}}%'")
        return cursor.fetchall()
'''

FLAW_EVERY = 40


def build_fixture(modules: int) -> Fixture:
    files: dict[str, str] = {
        "src/__init__.py": "",
        "src/generated/__init__.py": "",
        "src/config/__init__.py": "",
        "src/config/settings.py": (
            '"""Settings."""\n\n'
            'DB_HOST = "db.internal"\n'
            'DB_USER = "app"\n'
            'DB_PASSWORD = "generated-fixture-password"\n'
        ),
    }
    seeded: list[SeededVuln] = []

    for index in range(modules):
        if index % FLAW_EVERY == 0:
            files[f"src/generated/service_{index}.py"] = FLAWED_TEMPLATE.format(index=index)
            seeded.append(
                SeededVuln(
                    key=f"scale-sqli-{index}",
                    cwe="CWE-89",
                    file=f"src/generated/service_{index}.py",
                    symbol="search",
                    note="seeded injection in generated module",
                )
            )
        else:
            files[f"src/generated/service_{index}.py"] = MODULE_TEMPLATE.format(index=index)
            files[f"src/generated/api_{index}.py"] = API_TEMPLATE.format(index=index)

    return Fixture(name="generated-scale-repo", files=files, seeded=seeded)


def estimate_tokens(fixture: Fixture) -> int:
    from pipeline.budget import estimate_tokens as est

    return sum(est(content) for content in fixture.files.values())


def build_for_budget(root: Path, context_window_tokens: int, factor: int = 10) -> Path:
    """Generate a repo whose source is at least ``factor``x ``context_window_tokens``."""
    target = context_window_tokens * factor
    modules = 64
    fixture = build_fixture(modules)
    while estimate_tokens(fixture) < target and modules < 20000:
        modules = int(modules * 1.8) + 1
        fixture = build_fixture(modules)
    return fixture.write(root)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--context-window", type=int, default=12000)
    parser.add_argument("--factor", type=int, default=10)
    args = parser.parse_args()
    path = build_for_budget(args.root, args.context_window, args.factor)
    fixture = build_fixture(len(list((path / "src" / "generated").glob("service_*.py"))))
    print(f"generated {path} (~{estimate_tokens(fixture):,} estimated tokens)")


if __name__ == "__main__":
    main()
