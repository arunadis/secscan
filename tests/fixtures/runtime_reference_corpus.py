"""Feature 010: runtime-reference corpus — must-NOT-find (FR-012, contract R1/R2).

Every entry assigns a credential-named key from a runtime indirection expression:
the value is supplied by the environment when the program runs, and no credential
material exists in the source. Each MUST produce zero hits, zero blocked spans,
and exactly one recorded ``exempt-reference`` decision.

The first three entries are the exact lines behind SEC-0080, SEC-0082 and
SEC-0084 in the ``skh`` baseline scan.
"""

from __future__ import annotations

#: (origin path, line of source, why this is a runtime reference)
REFERENCES: tuple[tuple[str, str, str], ...] = (
    # ---- skh baseline (SEC-0080, SEC-0082, SEC-0084) ----
    (
        "skillhunt-portal-backend/migration/p0/verify-account.sh",
        '  export AWS_SECRET_ACCESS_KEY="$AWS_DEVIN_PROD_SECRET_ACCESS_KEY"',
        "SEC-0080: shell-bare reference to another environment variable",
    ),
    (
        "skillhunt-portal-backend/migration/p8/preflight-check.sh",
        '  AWS_ACCESS_KEY_ID="$OLD_AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY='
        '"$OLD_AWS_SECRET_ACCESS_KEY" \\',
        "SEC-0082: shell-bare references as an inline command environment prefix",
    ),
    (
        "skillhunt-portal-backend/migration/p9/cost-compare.sh",
        'AWS_ACCESS_KEY_ID="$NEW_AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY='
        '"$NEW_AWS_SECRET_ACCESS_KEY" \\',
        "SEC-0084: shell-bare references; referenced names embed 'SECRET' (FR-004)",
    ),
    # ---- one per family (research R1) ----
    (
        "config/settings.py",
        'secret = "${ENV_SECRET}"',
        "shell-braced reference",
    ),
    (
        "deploy/run.bat",
        'password: "%DB_PASSWORD%"',
        "batch reference",
    ),
    (
        "deploy/playbook.yml",
        'secret: "{{ vault_secret }}"',
        "template placeholder (Jinja/Ansible)",
    ),
    (
        "deploy/chart/values.yaml",
        'password: "{{ .Values.db.password }}"',
        "template placeholder (Helm/Go) with dotted expression",
    ),
    (
        ".github/workflows/deploy.yml",
        'token: "${{ secrets.GH_TOKEN }}"',
        "ci-expr reference (GitHub Actions)",
    ),
    (
        "deploy/entrypoint.sh",
        'api_key = "$(cat /run/secrets/key)"',
        "shell-subst command substitution",
    ),
    # ---- compositions joined by punctuation (clarification Q2) ----
    (
        "deploy/entrypoint.sh",
        'AUTH_TOKEN="$DB_USER:$DB_PASSWORD"',
        "two shell-bare references joined by ':'",
    ),
    (
        "deploy/entrypoint.sh",
        'password: "${HOST}/${TOKEN}"',
        "two shell-braced references joined by '/'",
    ),
    # ---- expansion operands (clarification Q3) ----
    (
        "deploy/docker-compose.yml",
        'password: "${DB_PASSWORD:-}"',
        "empty :- operand",
    ),
    (
        "deploy/docker-compose.yml",
        'password: "${DB_PASSWORD:-$FALLBACK_PASSWORD}"',
        ":- operand that is itself a reference",
    ),
    (
        "deploy/docker-compose.yml",
        'password: "${DB_PASSWORD:-changeme}"',
        ":- operand that is a placeholder",
    ),
    (
        "deploy/docker-compose.yml",
        'password: "${DB_PASSWORD:?DB_PASSWORD is required}"',
        ":? operand is a diagnostic message, never the value",
    ),
    # ---- entropy path (research R4): the long NAME trips the entropy heuristic ----
    (
        "deploy/entrypoint.sh",
        'export DB_PASSWORD="${SKILLHUNT_PORTAL_BACKEND_PROD_DB_PASSWORD_2024_v3}"',
        "shell-braced reference whose 43-char name has entropy > 4.0",
    ),
)


def corpus_text() -> str:
    """The reference corpus as one source file (origins dropped)."""
    return "\n".join(line for _origin, line, _why in REFERENCES) + "\n"
