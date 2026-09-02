"""T084: identifier corpus for redaction precision (SC-009).

Values drawn from real front-end and JVM projects, including the four the
independent reviewer confirmed as false positives in the benchmark scan. Each is
paired with the line context it actually appeared in, because the exemption gate
is shape *and* context — an identifier-shaped value on a credential-shaped line
must still be redacted.
"""

from __future__ import annotations

#: (line of source, the high-entropy token in it, why it is not a credential)
IDENTIFIERS: tuple[tuple[str, str, str], ...] = (
    (
        "import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';",
        "platform-browser-dynamic",
        "import specifier, entropy 4.054 (benchmark false positive)",
    ),
    (
        "import { BrowserDynamicTestingModule } from '@angular/platform-browser-dynamic/testing';",
        "BrowserDynamicTestingModule",
        "PascalCase class name, entropy 4.208 (benchmark false positive)",
    ),
    (
        "import { platformBrowserDynamicTesting } from '@angular/core/testing';",
        "platformBrowserDynamicTesting",
        "camelCase function name, entropy 4.142 (benchmark false positive)",
    ),
    (
        "  public unSubscribeToSystemPrefferedColorScheme(): void {",
        "unSubscribeToSystemPrefferedColorScheme",
        "camelCase method name, entropy 4.025 (benchmark false positive)",
    ),
    (
        "from django.contrib.contenttypes.fields import GenericForeignKey",
        "GenericForeignKey",
        "dotted module path plus PascalCase symbol",
    ),
    (
        "public class AbstractAnnotationConfigDispatcherServletInitializer {",
        "AbstractAnnotationConfigDispatcherServletInitializer",
        "long PascalCase Java class name",
    ),
    (
        "export const DEFAULT_RETRY_BACKOFF_MULTIPLIER = 2;",
        "DEFAULT_RETRY_BACKOFF_MULTIPLIER",
        "SCREAMING_SNAKE constant name",
    ),
    (
        "import 'reflect-metadata-polyfill-shim';",
        "reflect-metadata-polyfill-shim",
        "kebab-case package name",
    ),
    # ---- feature 003: credential-word identifiers (SEC-0085/0091/0092/0093 class)
    # The credential word appears only *inside* the identifier or inside prose on
    # the line — never in a structural credential position (FR-001, FR-002, C1).
    (
        "  private Double openaiModelInputTokenCostGpt51ChatLatest;",
        "openaiModelInputTokenCostGpt51ChatLatest",
        "SEC-0085: camelCase pricing identifier containing 'Token', entropy 4.08",
    ),
    (
        "  private Double openaiModelOutputTokenCostGpt51ChatLatest;",
        "openaiModelOutputTokenCostGpt51ChatLatest",
        "SEC-0085 sibling: same class, 'Output' variant",
    ),
    (
        '  @Value("${openai.model.input-token-cost-gpt51-chat-latest}")',
        "input-token-cost-gpt51-chat-latest",
        "SEC-0085 sibling: kebab-case config key inside an annotation",
    ),
    (
        'const [authTokenError, setAuthTokenErrorMessage] = useState("");',
        "setAuthTokenErrorMessage",
        "SEC-0091/0092: login-page identifier; 'auth'/'Token' appear only inside identifiers",
    ),
    (
        'export const INVALID_PASSWORD_RESET_TOKEN_ERROR_MESSAGE = '
        '"The password reset token is invalid";',
        "INVALID_PASSWORD_RESET_TOKEN_ERROR_MESSAGE",
        "SEC-0093: UI message constant; credential words are in the name (masked) and in prose",
    ),
    (
        "                openaiModelInputTokenCostGpt41,",
        "openaiModelInputTokenCostGpt41",
        "SEC-0085 sibling: bare identifier reference as a call argument",
    ),
)

#: Credentials that MUST still be detected — the recall guard (FR-037).
#: The last entry is deliberately identifier-shaped: shape alone must never
#: exempt a value whose line says "credential".
CREDENTIALS: tuple[tuple[str, str], ...] = (
    ('DB_PASSWORD = "Pr0d-Sh0p-DB-2024!"', "assigned password literal"),
    (
        'aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        "AWS secret access key",
    ),
    ('const googleApiKey = "AIzaSyD-1234567890abcdefghijklmnopqrstu";', "Google API key"),
    ('token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"', "GitHub token"),
    ('SESSION_SECRET = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldA=="', "base64 session secret"),
    (
        'apiSecret = "ThisLooksLikeAnIdentifierButIsASecretValue"',
        "identifier-shaped value on a credential line",
    ),
)


def corpus_text() -> str:
    """The identifier corpus as one source file."""
    return "\n".join(line for line, _token, _why in IDENTIFIERS) + "\n"
