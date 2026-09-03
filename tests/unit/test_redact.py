"""T017: unit tests for the deterministic redaction engine (FR-006a)."""

from __future__ import annotations

import pytest

from pipeline.redact import BLOCKED, Redactor, shannon_entropy


@pytest.fixture
def redactor() -> Redactor:
    return Redactor()


@pytest.mark.parametrize(
    ("text", "label"),
    [
        ("key = 'AKIAIOSFODNN7EXAMPLE'", "aws-access-key"),
        ("token: ghp_abcdefghijklmnopqrstuvwxyz0123456789", "github-token"),
        ("GOOGLE=AIzaSyA1234567890abcdefghijklmnopqrstuv", "google-api-key"),
        ("stripe = sk_live_abcdefghij1234567890", "stripe-key"),
        ("auth = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz'", "anthropic-key"),
        ("slack_hook = xoxb-123456789012-abcdefghijkl", "slack-token"),
    ],
)
def test_known_credential_formats_are_redacted(redactor: Redactor, text: str, label: str) -> None:
    result = redactor.redact(text)
    assert label in result.labels
    assert result.redacted >= 1
    assert not result.clean


def test_private_key_block_is_redacted(redactor: Redactor) -> None:
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAx7Vv2mQ8kFq3Z9pLm4nO5rS6tU7vW8xY9zA0bC1dE2fG3hI4\n"
        "-----END RSA PRIVATE KEY-----"
    )
    result = redactor.redact(text)
    assert "private-key-block" in result.labels
    assert "MIIEowIBAAKCAQEA" not in result.text


def test_assigned_secret_and_connection_string(redactor: Redactor) -> None:
    result = redactor.redact('password = "s3cret-pa55word"')
    assert "assigned-secret" in result.labels
    assert "s3cret-pa55word" not in result.text

    conn = redactor.redact("DB=postgres://admin:hunter2xyz@db.internal:5432/app")
    assert "connection-string" in conn.labels
    assert "hunter2xyz" not in conn.text


def test_placeholders_are_not_redacted(redactor: Redactor) -> None:
    for benign in [
        'password = "changeme"',
        'api_key = "<YOUR_API_KEY>"',
        'secret = "${ENV_SECRET}"',
        'token = "xxxxxxxxxx"',
        'password = "example"',
    ]:
        assert redactor.redact(benign).clean, benign


def test_high_entropy_in_secret_context_is_redacted(redactor: Redactor) -> None:
    text = "SESSION_SIGNING_SECRET = 'Xh8Kq2Lm9Rt4Wv7Zy1Bc3Df6Gj0Np5Sa'"
    result = redactor.redact(text)
    assert not result.clean
    assert "Xh8Kq2Lm9Rt4Wv7Zy1Bc3Df6Gj0Np5Sa" not in result.text


def test_high_entropy_without_context_is_blocked_not_leaked(redactor: Redactor) -> None:
    """Uncertain content must be blocked, never passed through (edge case)."""
    value = "Zk3Qp9Xr7Lm2Vn8Bt4Wy6Cd0Hj5Gs1F"
    result = redactor.redact(f"const blob = '{value}';", origin="app.js")
    assert result.blocked == 1
    assert BLOCKED in result.text
    assert value not in result.text
    assert result.warnings and "app.js" in result.warnings[0]


def test_ordinary_code_is_untouched(redactor: Redactor) -> None:
    code = "def add(a, b):\n    return a + b\n"
    result = redactor.redact(code)
    assert result.clean
    assert result.text == code


def test_custom_patterns_are_applied() -> None:
    redactor = Redactor(extra_patterns=[r"INTERNAL-[0-9]{6}"])
    result = redactor.redact("ref INTERNAL-123456 here")
    assert result.redacted == 1
    assert "INTERNAL-123456" not in result.text


def test_redaction_is_deterministic(redactor: Redactor) -> None:
    text = "key = 'AKIAIOSFODNN7EXAMPLE'\npassword = \"s3cret-pa55word\"\n"
    first = redactor.redact(text)
    second = Redactor().redact(text)
    assert first.text == second.text
    assert first.labels == second.labels


def test_redact_mapping_aggregates_counts(redactor: Redactor) -> None:
    mapping = {
        "b.py": 'password = "s3cret-pa55word"',
        "a.py": "key = 'AKIAIOSFODNN7EXAMPLE'",
        "c.py": "print('hello')",
    }
    out, total = redactor.redact_mapping(mapping)
    assert set(out) == set(mapping)
    assert total.redacted == 2
    assert "AKIAIOSFODNN7EXAMPLE" not in out["a.py"]
    assert out["c.py"] == mapping["c.py"]


def test_scan_detects_residual_secrets(redactor: Redactor) -> None:
    assert redactor.scan("key = 'AKIAIOSFODNN7EXAMPLE'")
    assert not redactor.scan("clean = 1")


def test_entropy_helper() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") < 1.0
    assert shannon_entropy("Xh8Kq2Lm9Rt4Wv7Zy1Bc3Df6Gj0Np5Sa") > 4.0


# ----------------------------------------------- identifier precision (US5)
#
# T085. The reviewed benchmark reported four coverage gaps for "unclassifiable
# high-entropy values" and all four were ordinary identifiers. Each gap claimed
# uncertainty the scan did not have, and buried any genuine hit in noise.


def test_identifier_shape_is_recognized() -> None:
    from pipeline.redact import identifier_shape

    assert identifier_shape("platformBrowserDynamicTesting") == "camelCase"
    assert identifier_shape("BrowserDynamicTestingModule") == "PascalCase"
    assert identifier_shape("platform-browser-dynamic") == "kebab-case"
    assert identifier_shape("DEFAULT_RETRY_BACKOFF_MULTIPLIER") == "snake_case"
    assert identifier_shape("@angular/platform-browser-dynamic") == "module-path"
    # A real credential does not decompose into readable segments.
    assert identifier_shape("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY") is None
    assert identifier_shape("aGVsbG8gd29ybGQ") is None


def test_benchmark_identifier_false_positives_produce_no_gap() -> None:
    """SC-009: zero coverage gaps caused by an identifier."""
    from tests.fixtures.identifier_corpus import IDENTIFIERS

    redactor = Redactor()
    for line, token, why in IDENTIFIERS:
        result = redactor.redact(line, origin="src/app.ts")
        assert result.blocked == 0, f"{token} blocked ({why}): {result.warnings}"
        assert result.redacted == 0, f"{token} redacted ({why})"


def test_identifier_corpus_as_a_whole_produces_no_gap() -> None:
    from tests.fixtures.identifier_corpus import corpus_text

    result = Redactor().redact(corpus_text(), origin="src/app.ts")
    assert result.blocked == 0, result.warnings
    assert result.clean


def test_credential_recall_is_not_reduced() -> None:
    """FR-037: recall takes absolute precedence over precision."""
    from tests.fixtures.identifier_corpus import CREDENTIALS

    redactor = Redactor()
    for line, why in CREDENTIALS:
        result = redactor.redact(line, origin="src/config.py")
        assert result.redacted + result.blocked >= 1, f"missed credential ({why}): {line}"
        assert "ThisLooksLikeAnIdentifier" not in result.text or result.redacted >= 1


def test_identifier_shaped_credential_is_still_removed() -> None:
    """Shape alone never exempts: the line context decides first."""
    result = Redactor().redact(
        'apiSecret = "ThisLooksLikeAnIdentifierButIsASecretValue"', origin="c.py"
    )
    assert result.redacted >= 1
    assert "ThisLooksLikeAnIdentifierButIsASecretValue" not in result.text


def test_entropy_threshold_was_not_raised() -> None:
    """Precision came from shape, not from loosening detection.

    Raising the threshold above the benchmark's 4.208 false positive would start
    discarding genuine base64 secrets (research.md A4).
    """
    from pipeline.redact import _ENTROPY_THRESHOLD

    assert _ENTROPY_THRESHOLD == 4.0


def test_blocked_value_gap_names_file_line_and_reason() -> None:
    """FR-038: a gap a reader can locate and dismiss in seconds."""
    text = 'x = 1\ny = "Zk3Lq9Xv2Bn7Rt4Wy8Pc1Md6Hj5Gf0Ds"\n'
    result = Redactor().redact(text, origin="src/blob.py")
    assert result.blocked == 1
    warning = result.warnings[0]
    assert "src/blob.py:2" in warning
    assert "could not be confirmed" in warning


def test_exemptions_are_recorded_for_inspection() -> None:
    """The decision is explainable, not an opaque 'trust me'."""
    result = Redactor().redact(
        "import { platformBrowserDynamicTesting } from '@angular/core/testing';",
        origin="src/test.ts",
    )
    assert result.exempted
    assert all(e.origin == "src/test.ts" for e in result.exempted)
    assert all(
        e.classification in ("camelCase", "PascalCase", "kebab-case", "snake_case", "module-path")
        for e in result.exempted
    )
    assert all(e.decision == "exempt-identifier" for e in result.exempted)
    assert all(e.rule == "entropy-candidate" for e in result.exempted)
    assert all(e.reason and e.value for e in result.exempted)


# ------------------------- structured-data precision (found by the E1 sweep)
#
# Feature 002 brought dependency manifests and platform configuration into scope
# (FR-026). Those files are almost entirely `key: value` pairs whose values are
# package names and paths, so the identifier gate has to recognise that context or
# it reintroduces the very defect FR-036 removes — in the files 002 just added.


@pytest.mark.parametrize(
    "line",
    [
        '    "platform-browser-dynamic": "^9.0.0",',
        '  "@angular-devkit/build-angular": "~0.900.1",',
        '  "outputPath": "dist/angular2-hn-production-build",',
        '      "rule": "plausible-unconfirmed-reachability"',
        '  "root": "/private/var/folders/p5/hjtlvdnj35b8q81384v7l5xw0000gn/T/x/shop",',
    ],
)
def test_config_value_identifiers_produce_no_gap(line: str) -> None:
    """SC-009 holds for configuration files, not only for source."""
    result = Redactor().redact(line, origin="package.json")
    assert result.blocked == 0, result.warnings
    assert result.redacted == 0


def test_filesystem_paths_are_recognized_by_shape() -> None:
    from pipeline.redact import identifier_shape

    assert identifier_shape("dist/angular2-hn-production-build") == "filesystem-path"
    assert identifier_shape("src/app/comment.component.html") == "filesystem-path"


def test_key_material_containing_slashes_is_not_mistaken_for_a_path() -> None:
    """The recall trap: base64 and AWS keys also contain `/`.

    Segments are checked individually for exactly this reason — a whole-string
    test would read an AWS secret as a two-level path and exempt it.
    """
    from pipeline.redact import identifier_shape

    assert identifier_shape("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") is None
    assert identifier_shape("aGVsbG8vd29ybGQvdGhpcy9pcy9hL3NlY3JldA==") is None


@pytest.mark.parametrize(
    "line",
    [
        '  "x": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",',
        '  "value": "AIzaSyD-1234567890abcdefghijklmnopqrstu",',
        '  "innocuous": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",',
    ],
)
def test_credential_under_an_innocuous_key_is_still_removed(line: str) -> None:
    """Structured-data context must not become a blanket exemption."""
    result = Redactor().redact(line, origin="config.json")
    assert result.redacted + result.blocked >= 1, line


# ------------------------- feature 003: credential-context precision (C1, C2, C3)
#
# SEC-0085 class: the credential word appears only inside the matched identifier
# (or inside prose), never in a structural credential position. Context must be
# evaluated with the candidate span masked (R1), and credential words count only
# as standalone code words or as the final segment of an assignment key (FR-003).


def test_credential_word_inside_matched_identifier_is_not_context(redactor: Redactor) -> None:
    """C1/FR-001: 'Token' inside openaiModelInputTokenCost... creates no context."""
    result = redactor.redact(
        "  private Double openaiModelInputTokenCostGpt51ChatLatest;",
        origin="TokenCostBreakdownBuilderUtil.java",
    )
    assert result.clean
    assert [e.decision for e in result.exempted] == ["exempt-identifier"]
    exemption = result.exempted[0]
    assert exemption.rule == "entropy-candidate"
    assert exemption.classification == "camelCase"
    assert exemption.reason


def test_credential_word_inside_sibling_identifier_is_not_context(redactor: Redactor) -> None:
    """C1: 'auth' inside a neighbouring identifier is not context either."""
    result = redactor.redact(
        'const [authTokenError, setAuthTokenErrorMessage] = useState("");',
        origin="LoginPage.tsx",
    )
    assert result.clean, result.warnings


def test_credential_word_in_prose_does_not_condemn_identifier(redactor: Redactor) -> None:
    """C1/FR-002: a message literal's 'token' is not credential context for a name."""
    result = redactor.redact(
        'export const INVALID_PASSWORD_RESET_TOKEN_ERROR_MESSAGE = '
        '"The password reset token is invalid";',
        origin="alert-const.ts",
    )
    assert result.clean, result.warnings


def test_assignment_to_credential_named_key_still_redacts(redactor: Redactor) -> None:
    """C1/C3: the key survives masking, so structural context still fires (FR-003)."""
    result = redactor.redact(
        'String apiKey = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY";',
        origin="Config.java",
    )
    assert result.redacted == 1
    # The rule pack may claim it first — either way it is detected and removed.
    assert result.labels in (["assigned-secret"], ["high-entropy-secret"])


def test_camelcase_credential_key_is_structural_context(redactor: Redactor) -> None:
    """FR-003/FR-006: dbPassword's final segment names a credential."""
    result = redactor.redact(
        'dbPassword = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY";',
        origin="DbConfig.java",
    )
    assert result.redacted == 1


def test_real_key_in_credential_naming_prose_is_redacted(redactor: Redactor) -> None:
    """C3 recall: a message that names a credential and contains a key is a finding."""
    result = redactor.redact(
        'throw new Error("Invalid token: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");',
        origin="ErrorHandler.java",
    )
    assert result.redacted == 1
    assert "wJalrXUtnFEMI" not in result.text


def test_prose_literal_without_credential_words_is_exempt_message(redactor: Redactor) -> None:
    """C2 message arm: an unclassifiable run inside plain prose is exempt, not blocked."""
    result = redactor.redact(
        'log.warn("Upstream request Zk3Lq9Xv2Bn7Rt4Wy8Pc1Md6Hj5Gf0 rejected by peer");',
        origin="http-client.ts",
    )
    assert result.clean, result.warnings
    assert [e.decision for e in result.exempted] == ["exempt-message"]
    assert result.exempted[0].classification == "message-string"


def test_credential_corpus_recall_is_100_percent(redactor: Redactor) -> None:
    """C3/FR-005: every seeded credential is detected, at any origin."""
    from tests.fixtures.credential_corpus import CREDENTIALS

    for origin, line, why in CREDENTIALS:
        result = redactor.redact(line, origin=origin)
        assert result.redacted >= 1, f"missed credential ({why}): {line}"


# ------------------------- feature 010: runtime references (contracts R1, R2, R3)
#
# SEC-0080 class: a credential-named key assigned from `"$VAR"` (or any other
# indirection expression) is runtime wiring, not a hard-coded credential. The
# classifier is a pure function of the quoted value: every letter and digit must
# lie inside a well-formed reference (FR-002); anything else is a literal.


@pytest.mark.parametrize(
    "value",
    [
        "$AWS_DEVIN_PROD_SECRET_ACCESS_KEY",
        "${DB_PASSWORD}",
        "%DB_PASSWORD%",
        "{{ vault_secret }}",
        "${{ secrets.GH_TOKEN }}",
        "$(cat /run/secrets/key)",
        "$DB_USER:$DB_PASSWORD",
        "${HOST}/${TOKEN}",
        "${X:-}",
        "${X:-$Y}",
        "${X:-changeme}",
        "${DB_PASSWORD:?DB_PASSWORD is required}",
    ],
)
def test_runtime_reference_is_classified(value: str) -> None:
    """R1 MUST-classify list (FR-001, FR-002, FR-003, FR-004)."""
    from pipeline.redact import classify_runtime_reference

    assert classify_runtime_reference(value) is not None, value


@pytest.mark.parametrize(
    "value",
    [
        "hunter2hunter2",
        "$PREFIX-hunter2hunter2",
        "hunter2hunter2$SUFFIX",
        "pa$$w0rd-really-long",
        "${NAME",
        "%NAME",
        "{{ name",
        "${X:-hunter2hunter2}",
        "${X:=hunter2hunter2}",
        "${X:+hunter2hunter2}",
        "abc%20def%20secret",
        "",
        "-:/",
    ],
)
def test_literal_is_not_classified_as_reference(value: str) -> None:
    """R1 MUST-NOT-classify list (FR-002, FR-003): recall wins every tie."""
    from pipeline.redact import classify_runtime_reference

    assert classify_runtime_reference(value) is None, value


def test_runtime_reference_records_families_names_and_operators() -> None:
    from pipeline.redact import classify_runtime_reference

    joined = classify_runtime_reference("$DB_USER:$DB_PASSWORD")
    assert joined is not None
    assert joined.families == ("shell-bare", "shell-bare")
    assert joined.names == ("DB_USER", "DB_PASSWORD")
    assert joined.operators == ()

    guarded = classify_runtime_reference("${DB_PASSWORD:?DB_PASSWORD is required}")
    assert guarded is not None
    assert guarded.families == ("shell-braced",)
    assert guarded.names == ("DB_PASSWORD",)
    assert guarded.operators == (":?",)

    # Determinism: a pure function of the value.
    assert classify_runtime_reference("$A:$B") == classify_runtime_reference("$A:$B")


def test_runtime_references_are_exempt_at_the_redaction_layer() -> None:
    """R2 / FR-005a: visible in context, recorded, never a hit."""
    from tests.fixtures.runtime_reference_corpus import REFERENCES

    redactor = Redactor()
    for origin, line, why in REFERENCES:
        result = redactor.redact(line, origin=origin)
        assert result.text == line, f"redacted a reference ({why}): {result.text}"
        assert result.hits == [], f"hit on a reference ({why})"
        assert result.blocked == 0, f"blocked a reference ({why}): {result.warnings}"
        decisions = [e for e in result.exempted if e.decision == "exempt-reference"]
        assert len(decisions) >= 1, f"no exempt-reference decision ({why})"
        for decision in decisions:
            assert decision.origin == origin
            assert decision.line == 1
            assert decision.classification.startswith("runtime-reference:")
            assert decision.reason


def test_reference_exemption_names_the_rule_and_the_referenced_variable() -> None:
    redactor = Redactor()
    result = redactor.redact(
        '  export AWS_SECRET_ACCESS_KEY="$AWS_DEVIN_PROD_SECRET_ACCESS_KEY"',
        origin="migration/p0/verify-account.sh",
    )
    (decision,) = result.exempted
    assert decision.rule == "assigned-secret"
    assert decision.classification == "runtime-reference:shell-bare"
    assert "AWS_DEVIN_PROD_SECRET_ACCESS_KEY" in decision.reason

    entropy = redactor.redact(
        'export DB_PASSWORD="${SKILLHUNT_PORTAL_BACKEND_PROD_DB_PASSWORD_2024_v3}"',
        origin="deploy/entrypoint.sh",
    )
    assert entropy.clean, entropy.warnings
    # Both paths record their decision: the assignment rule and the entropy
    # candidate on the 43-char name (research R4).
    assert {e.rule for e in entropy.exempted} == {"assigned-secret", "entropy-candidate"}
    assert all(e.decision == "exempt-reference" for e in entropy.exempted)


def test_runtime_reference_corpus_as_a_whole_is_clean() -> None:
    from tests.fixtures.runtime_reference_corpus import corpus_text

    result = Redactor().redact(corpus_text(), origin="deploy/all.sh")
    assert result.clean, result.warnings
    assert result.text == corpus_text()


# ------------------------- feature 010: known-safe location tokens (contract R4)
#
# The reproduction builder redacts its own prose after composing it, and a long
# slash-joined repository path on a line that also names a credential symbol is
# eaten by the entropy heuristic — "Inspect [REDACTED:high-entropy-secret].sh".
# Tokens the scanner itself placed (file, symbol) are already published in the
# structured location, so protecting them in prose adds no exposure.

_PATH = "skillhunt-portal-backend/migration/p0/verify-account.sh"
_TRIGGER = (
    f"Inspect {_PATH}#AWS_SECRET_ACCESS_KEY in a local checkout and grep for the "
    "assignment (marker SECSCAN-CANARY-1 denotes the redacted literal in this report)."
)


def test_known_safe_tokens_survive_heuristic_redaction(redactor: Redactor) -> None:
    result = redactor.redact(_TRIGGER, origin="reproduction.trigger",
                             known_safe=(_PATH, "AWS_SECRET_ACCESS_KEY"))
    assert result.text == _TRIGGER
    assert result.clean, result.warnings
    assert [e.decision for e in result.exempted] == ["exempt-location"]
    assert result.exempted[0].classification == "location-token"
    assert result.exempted[0].rule == "entropy-candidate"


def test_known_safe_tokens_do_not_protect_a_value_elsewhere(redactor: Redactor) -> None:
    """FR-010: locations are protected, values are not."""
    value = "Xh8Kq2Lm9Rt4Wv7Zy1Bc3Df6Gj0Np5Sa"
    result = redactor.redact(f"{_TRIGGER} secret={value}", origin="reproduction.trigger",
                             known_safe=(_PATH, "AWS_SECRET_ACCESS_KEY"))
    assert _PATH in result.text
    assert value not in result.text
    assert result.redacted == 1


def test_known_safe_never_overrides_a_format_rule(redactor: Redactor) -> None:
    """A path that literally contains a credential format is still redacted."""
    token = "AKIAIOSFODNN7EXAMPLE"
    result = redactor.redact(f"Inspect build/{token}/out.sh in a local checkout",
                             origin="reproduction.trigger", known_safe=(token,))
    assert token not in result.text
    assert "aws-access-key" in result.labels


def test_empty_known_safe_is_byte_identical_to_the_default(redactor: Redactor) -> None:
    text = f"{_TRIGGER}\nconst blob = 'Zk3Qp9Xr7Lm2Vn8Bt4Wy6Cd0Hj5Gs1F';\n"
    default = redactor.redact(text, origin="x")
    explicit = redactor.redact(text, origin="x", known_safe=())
    assert default.text == explicit.text
    assert default.redacted == explicit.redacted and default.blocked == explicit.blocked


def test_known_safe_token_that_would_be_blocked_is_preserved(redactor: Redactor) -> None:
    """Case (e): the token has no identifier shape and would otherwise be BLOCKED."""
    path = "build/ABCDEFGHJKLMNPQRSTUVWXYZ2345/out.sh"
    text = f"Inspect {path}#run in a local checkout and grep for the assignment."
    before = redactor.redact(text, origin="reproduction.trigger")
    assert before.blocked == 1, "precondition: this path is blocked without protection"
    after = redactor.redact(text, origin="reproduction.trigger", known_safe=(path,))
    assert after.text == text
    assert after.clean, after.warnings
    (decision,) = after.exempted
    assert decision.decision == "exempt-location"
    assert "already published" in decision.reason


def test_identifier_gate_sees_through_packet_line_numbers(redactor: Redactor) -> None:
    """Packet source is line-numbered (FR-002); the prefix must not defeat the gate."""
    result = redactor.redact(
        "5|   private Double openaiModelInputTokenCostGpt51ChatLatest;",
        origin="TokenCostBreakdownBuilderUtil.java",
    )
    assert result.clean, result.warnings
    assert result.exempted[0].decision == "exempt-identifier"
