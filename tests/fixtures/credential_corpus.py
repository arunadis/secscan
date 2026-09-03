"""T003: seeded credential corpus — the recall floor (FR-005, FR-006, contract C3).

Every entry MUST be detected (redacted or blocked). Entries carry their origin
path so the test-code grading rules (FR-010) are exercised against realistic
locations. Values are synthetic; none is a real credential.
"""

from __future__ import annotations

#: (origin path, line of source, why this is a credential)
CREDENTIALS: tuple[tuple[str, str, str], ...] = (
    # ---- production code ----
    (
        "src/main/java/com/example/AuthConfig.java",
        'private static final String GOOGLE_KEY = "AIzaSyD-1234567890abcdefghijklmnopqrstu";',
        "Google API key format match in production code",
    ),
    (
        "config/settings.py",
        'password = "correct horse battery staple"',
        "readable passphrase assigned to a credential-named key (FR-006)",
    ),
    (
        "src/main/resources/application.properties",
        'jwt.secret="nRvyYC4soFxBdZ-F-5Nnzz5USXstR1YylsTd-mA0aKtI9HUlriGrtkf-TiuDapkLiUCogO3JOK7kwZisrHp6wA"',
        "high-entropy value on a credential-keyed properties line",
    ),
    (
        "src/lib/api.ts",
        'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";',
        "GitHub token format match",
    ),
    (
        "src/main/java/com/example/DbConfig.java",
        'dbPassword = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY";',
        "camelCase credential-named key — last segment names the credential",
    ),
    (
        "src/main/java/com/example/ErrorHandler.java",
        'throw new Error("Invalid token: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");',
        "real key embedded in a prose message that names a credential — must not be exempted",
    ),
    # ---- feature 010: reference look-alikes (FR-007, FR-013, contract R3) ----
    # A `$`, `%` or `${…}` wrapper never exempts literal material it contains.
    # The first three are the recall GAIN: before 010 the blanket `${…}`
    # placeholder silently exempted a literal default (research R3).
    (
        "deploy/docker-compose.yml",
        'password: "${DB_PASSWORD:-hunter2hunter2}"',
        "literal default operand of :- inside a braced reference",
    ),
    (
        "deploy/entrypoint.sh",
        'password: "${DB_PASSWORD:=hunter2hunter2}"',
        "literal operand of := inside a braced reference",
    ),
    (
        "deploy/entrypoint.sh",
        'password: "${DB_PASSWORD:+hunter2hunter2}"',
        "literal operand of :+ inside a braced reference",
    ),
    (
        "config/settings.sh",
        'password = "$PREFIX-hunter2hunter2"',
        "reference concatenated with a literal — letters outside the reference",
    ),
    (
        "config/settings.sh",
        'password = "hunter2hunter2$SUFFIX"',
        "literal concatenated with a reference",
    ),
    (
        "config/settings.py",
        'password = "pa$$w0rd-really-long"',
        "literal that merely contains a `$` marker",
    ),
    (
        "config/settings.sh",
        'password = "${DB_PASSWORD"',
        "unbalanced braced reference is a literal (FR-003)",
    ),
    (
        "config/settings.bat",
        'password = "%DB_PASSWORD"',
        "unterminated batch reference is a literal (FR-003)",
    ),
    (
        "deploy/docker-compose.yml",
        'key: "${AKIAIOSFODNN7EXAMPLE}"',
        "known credential format inside a reference-like wrapper (FR-008)",
    ),
    # ---- test code: still reported, graded lower (FR-010) ----
    (
        "src/test/java/com/example/DefaultJwtServiceTest.java",
        'private static final String SECRET = "testSigningKeyForUnitTestsOnly1234567890abcd'
        'efghij";',
        "credential literal in test code",
    ),
    (
        "tests/test_api.py",
        'API_TOKEN = "xoxb-1234567890-abcdefghijklmnop"',
        "Slack token format match in test code",
    ),
)

#: Entries expected to be graded as test code (FR-010).
TEST_CODE_ORIGINS: frozenset[str] = frozenset(
    {
        "src/test/java/com/example/DefaultJwtServiceTest.java",
        "tests/test_api.py",
    }
)


def corpus_text() -> str:
    """The credential corpus as one source file (origins dropped)."""
    return "\n".join(line for _origin, line, _why in CREDENTIALS) + "\n"
