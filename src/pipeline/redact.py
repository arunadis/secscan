"""Deterministic secret redaction (FR-006a).

Layered, per research.md R5:
  1. rule packs for known credential formats
  2. entropy detection for unknown high-entropy strings
  3. operator-defined custom patterns

Uncertain content is *blocked* rather than passed through: the caller receives a
warning and the offending span is replaced with a BLOCKED marker so it never
reaches a model (spec edge case "redaction uncertainty").

No ML, no network: identical input always yields identical output (FR-039). The
identifier-shape gate added in feature 002 keeps that property — it is pure
pattern matching over the value and its line, with no dictionary and no lookup.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

RULES_VERSION = "1"

REDACTED = "[REDACTED:{label}]"
BLOCKED = "[BLOCKED:unclassified-secret]"

# --------------------------------------------------------------------- rules


@dataclass(frozen=True)
class Rule:
    label: str
    pattern: re.Pattern[str]
    #: group holding the secret itself (0 = whole match)
    group: int = 0


def _c(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


BUILTIN_RULES: tuple[Rule, ...] = (
    Rule("aws-access-key", _c(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b")),
    Rule(
        "aws-secret-key",
        _c(r"(?i)aws.{0,20}?(?:secret|key).{0,5}['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"),
        1,
    ),
    Rule("github-token", _c(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    Rule("slack-token", _c(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    Rule("google-api-key", _c(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Rule("stripe-key", _c(r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    Rule("openai-key", _c(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    Rule("anthropic-key", _c(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    Rule("jwt", _c(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    Rule(
        "private-key-block",
        _c(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
            r".*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    Rule(
        "connection-string",
        _c(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s:@/]+:([^\s:@/]{3,})@[^\s/]+"),
        1,
    ),
    Rule(
        # Letter-only lookaround (not \b) so underscore-joined names such as
        # DB_PASSWORD / APP_SECRET are matched: `\b` fails there because `_` is a
        # word character.
        "assigned-secret",
        _c(
            r"(?i)(?<![A-Za-z])(?:pass(?:word|wd)?|secret|token|api[_\-]?key|"
            r"access[_\-]?key|client[_\-]?secret|credential|auth[_\-]?token)"
            r"(?![A-Za-z])\s*[:=]\s*['\"]([^'\"\n]{6,})['\"]"
        ),
        1,
    ),
)

#: Values that look like secrets by shape but are obviously placeholders —
#: including this redactor's own markers, so redaction is idempotent.
#:
#: Braced shell references (`${NAME}`) are deliberately NOT listed here any more.
#: Feature 010 found the blanket `\$\{[^}]*\}` alternative was a recall hole: it
#: exempted `${DB_PASSWORD:-hunter2hunter2}` wholesale, literal default and all.
#: References are now classified structurally by `classify_runtime_reference`.
_PLACEHOLDER = _c(
    r"(?i)^(?:x{3,}|\*{3,}|\.{3,}|<[^>]*>|changeme|placeholder|example|"
    r"your[_\-]?[a-z]*|dummy|redacted|todo|none|null|test|sample|foo|bar|"
    r"\[REDACTED:[^\]]*\]|\[BLOCKED:[^\]]*\])$"
)

#: High-entropy candidates: long unbroken base64/hex-ish runs.
_ENTROPY_CANDIDATE = _c(r"\b[A-Za-z0-9+/=_\-]{24,}\b")
_ENTROPY_THRESHOLD = 4.0

#: Contexts that make a high-entropy string much more likely to be a real secret.
#: Letter-bounded (not \b, which fails at camelCase humps only by accident): the
#: word must stand alone in *code* — `Token` inside `openaiModelInputTokenCost`
#: is not context, but `secret` in `jwt.secret=...` is (`.` is not a letter).
#: Evaluated against the line with the candidate span masked out (research R1),
#: so the matched value can never supply its own context (FR-003, contract C1).
_SECRET_CONTEXT = _c(
    r"(?i)(?<![A-Za-z])(?:secret|token|key|password|passwd|credential|auth|bearer|"
    r"signature|salt|cert)(?![A-Za-z])"
)

#: Credential words as identifier segments: `dbPassword`'s final segment names a
#: credential even though no standalone word appears on the line (FR-003).
_CRED_WORDS = frozenset(
    {"secret", "token", "key", "password", "passwd", "credential", "auth",
     "bearer", "signature", "salt", "cert"}
)

#: Quoted literals on a line. A quoted span whose content contains a space is
#: prose (a message), not code: credential words inside prose do not condemn a
#: candidate elsewhere on the line (SEC-0093), while a candidate *inside* prose
#: that names a credential is still reported (recall, contract C3).
_QUOTED = _c(r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'")

#: Identifier shapes that decompose into readable segments. Real credentials
#: essentially never do, which is what makes shape a usable discriminator where
#: entropy alone is not (research.md A4).
#:
#: Measured against the four false positives from the reviewed benchmark:
#:
#:   unSubscribeToSystemPrefferedColorScheme   entropy 4.025   camelCase, 6 parts
#:   platform-browser-dynamic                  entropy 4.054   kebab-case, 3 parts
#:   BrowserDynamicTestingModule                entropy 4.208   PascalCase, 4 parts
#:   platformBrowserDynamicTesting              entropy 4.142   camelCase, 4 parts
#:
#: Raising the entropy threshold instead would have to clear 4.21, and that starts
#: discarding genuine base64 secrets — so precision here must come from shape.
#: Every segment must carry at least one lowercase character. That single
#: requirement is what separates an identifier from a key: real camel-case
#: segments are pronounceable words, whereas a base64 or AWS-style secret has runs
#: of consecutive capitals. Without it, `wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY`
#: reads as camelCase and a genuine credential would be exempted — a recall
#: failure, which FR-037 forbids outright.
_CAMEL_OR_PASCAL = _c(r"^[A-Za-z][a-z0-9]+(?:[A-Z][a-z0-9]+){2,}$")
_DELIMITED = _c(r"^[A-Za-z][A-Za-z0-9]*(?:[_\-][A-Za-z][A-Za-z0-9]*){2,}$")
_MODULE_PATH = _c(r"^[@A-Za-z][\w.\-]*(?:[./][\w.\-]+){1,}$")

#: A run of four or more capitals is characteristic of encoded key material and
#: rare in identifiers outside short acronyms. Belt-and-braces alongside the rule
#: above, because the cost of a wrong exemption is a leaked credential.
_CAPITAL_RUN = _c(r"[A-Z]{4,}")

#: Packet source is line-numbered (`NN| code`, FR-002); the gate must see
#: through the prefix or every declaration in a packet reads as unclassifiable.
_LINE_NUMBER = _c(r"^\s*\d+\|\s*")

#: Lines where a high-entropy token is structurally an identifier, not a value.
#:
#: The structured-data clause is required, not a convenience. Feature 002 brought
#: dependency manifests and platform configuration into scope (FR-026), and those
#: files are almost entirely `key: value` pairs whose values are package names and
#: paths. Without it, `"platform-browser-dynamic": "^9.0.0"` in a package.json
#: raises a coverage gap — reintroducing the exact defect FR-036 removes, just
#: relocated from source into the newly-scanned files. Feature 003 adds the
#: scripting-language declaration keywords and annotation lines for the same
#: reason: `const [authTokenError, ...] = ...` and `@Value("${...}")` are
#: declarations too.
#:
#: Recall is unaffected because `_SECRET_CONTEXT` is checked *first*: a line whose
#: key names a credential (`"apiKey"`, `"token"`, `"secret"`) is redacted before
#: shape is ever consulted.
_IDENTIFIER_CONTEXT = _c(
    r"(?i)^\s*(?:\d+\|\s*)?(?:import\b|from\b|export\b|require\s*\(|#include\b|using\b|package\b)"
    r"|^\s*(?:\d+\|\s*)?(?:public|private|protected|static|final|def|class|interface|func|fn|"
    r"const|let|var|val|function|async)\b"
    r"|^\s*(?:\d+\|\s*)?@"  # annotation/decorator lines: @Value("${...}") names config
    r"|^\s*(?:\d+\|\s*)?(?://|#|\*|/\*)"  # comment lines: a flag name is not a credential
    r"|^\s*(?:\d+\|\s*)?-?\s*[\"']?[\w.\-/@]+[\"']?\s*:\s*"  # JSON/YAML key-value line
)

#: A path segment carrying no key material: has a lowercase character (or is too
#: short to carry entropy) and no run of capitals.
_PATH_SEGMENT = _c(r"^[A-Za-z0-9][A-Za-z0-9._\-]*$")


def _is_path_like(value: str) -> bool:
    """True when ``value`` decomposes into ordinary filesystem/path segments.

    Checked **per segment** rather than on the whole string, because base64 key
    material also contains `/` — `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` would
    otherwise read as a path. Requiring every segment to look like a word is what
    separates `dist/angular2-hn-production-build` from an AWS secret.
    """
    if "/" not in value:
        return False
    segments = [s for s in value.split("/") if s]
    if not segments:
        return False
    for segment in segments:
        if not _PATH_SEGMENT.match(segment) or _CAPITAL_RUN.search(segment):
            return False
        # Short segments (`T`, `p5`, `v4`) carry no entropy, so the lowercase
        # requirement would only reject legitimate paths.
        if len(segment) >= 4 and not any(c.islower() for c in segment):
            return False
    return True


def identifier_shape(value: str) -> str | None:
    """The identifier form ``value`` decomposes into, or ``None``.

    Returns the shape name so the decision is explainable in the artifact rather
    than being an opaque "trust me".
    """
    if _is_path_like(value):
        return "filesystem-path"
    if _CAPITAL_RUN.search(value) and not _DELIMITED.match(value):
        return None
    if _CAMEL_OR_PASCAL.match(value):
        return "PascalCase" if value[0].isupper() else "camelCase"
    if _DELIMITED.match(value):
        return "kebab-case" if "-" in value else "snake_case"
    if _MODULE_PATH.match(value):
        return "module-path"
    return None


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def line_no_for(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.match(value.strip()))


# ------------------------------------------------------ runtime references
#
# Feature 010 (SEC-0080 class). `export AWS_SECRET_ACCESS_KEY="$AWS_PROD_SECRET"`
# is the *recommended* way to wire a credential — the value is supplied by the
# environment when the script runs and nothing secret exists in the source. The
# `assigned-secret` rule cannot tell that from a literal, and the entropy path
# fires on long reference NAMES (`${SKILLHUNT_…_PROD_DB_PASSWORD_2024_v3}` has
# entropy 4.26), so both paths consult one classifier (research R4).
#
# The classifier is a pure function of the quoted value with a single invariant
# (research R2): every letter and digit must lie inside a well-formed indirection
# expression. That one rule accepts `"$A:$B"` and `"${HOST}/${TOKEN}"`, and
# rejects `"$PREFIX-hunter2hunter2"`, `"pa$$w0rd"`, `"${NAME"` and
# `"${X:-hunter2hunter2}"` — so no literal alphanumeric material can ever be
# exempted, which is what makes it safe under Principle III.


@dataclass(frozen=True)
class RuntimeReference:
    """A quoted value that resolves to a credential only when the program runs."""

    #: expression families in order of appearance
    families: tuple[str, ...]
    #: referenced identifiers where extractable ("" for opaque expression bodies)
    names: tuple[str, ...]
    #: shell parameter-expansion operators seen (":-", ":=", ":+", ":?", …)
    operators: tuple[str, ...]


_REF_BARE = _c(r"\$([A-Za-z_]\w*)")
_REF_BATCH = _c(r"%([A-Za-z_]\w*)%")
_REF_IDENT = _c(r"^[A-Za-z_]\w*$")
#: `${NAME<op>operand}` — `:-` `-` `:=` `=` `:+` `+` `:?` `?`
_REF_EXPANSION = _c(r"^([A-Za-z_]\w*)(:?[-=+?])(.*)$", re.DOTALL)
#: operators whose operand is a diagnostic message, never the value
_DIAGNOSTIC_OPERATORS = frozenset({":?", "?"})


def _match_bracket(value: str, start: int, open_ch: str, close_ch: str) -> int:
    """Index just past the bracket matching ``value[start]``, or -1 if unbalanced."""
    depth = 0
    for index in range(start, len(value)):
        char = value[index]
        if char == open_ch:
            depth += 1
        elif char == close_ch:
            depth -= 1
            if depth == 0:
                return index + 1
    return -1


def _find_close(value: str, start: int, close: str) -> int:
    """Index just past the first ``close`` at or after ``start``, or -1."""
    index = value.find(close, start)
    return -1 if index < 0 else index + len(close)


def _operand_is_safe(operand: str) -> bool:
    """A `:-`/`:=`/`:+` operand can become the value: it must itself be harmless."""
    return (
        not operand
        or _is_placeholder(operand)
        or classify_runtime_reference(operand) is not None
    )


def classify_runtime_reference(value: str) -> RuntimeReference | None:
    """Classify ``value`` as runtime indirection, or ``None`` if it may hold a literal.

    Returns a reference **iff** every letter and digit lies inside one well-formed
    expression of a supported family (FR-002). Unbalanced delimiters, literal
    characters outside an expression, and credential-like `:-`/`:=`/`:+` operands
    all fail classification (FR-003, FR-007): the caller then treats the value
    exactly as before. Pure, deterministic, origin-independent (FR-000).
    """
    families: list[str] = []
    names: list[str] = []
    operators: list[str] = []
    index, length = 0, len(value)
    while index < length:
        char = value[index]
        if value.startswith("${{", index):  # ci-expr, before shell-braced
            end = _find_close(value, index + 3, "}}")
            if end < 0:
                return None
            families.append("ci-expr")
            names.append(value[index + 3 : end - 2].strip())
            index = end
        elif value.startswith("${", index):
            end = _match_bracket(value, index + 1, "{", "}")
            if end < 0:
                return None
            body = value[index + 2 : end - 1]
            expansion = _REF_EXPANSION.match(body)
            if expansion:
                name, operator, operand = expansion.groups()
                if operator not in _DIAGNOSTIC_OPERATORS and not _operand_is_safe(operand):
                    return None
                operators.append(operator)
            elif _REF_IDENT.match(body):
                name = body
            else:
                return None
            families.append("shell-braced")
            names.append(name)
            index = end
        elif value.startswith("$(", index):
            end = _match_bracket(value, index + 1, "(", ")")
            if end < 0:
                return None
            families.append("shell-subst")
            names.append("")
            index = end
        elif char == "$":
            bare = _REF_BARE.match(value, index)
            if bare:
                families.append("shell-bare")
                names.append(bare.group(1))
                index = bare.end()
            else:
                index += 1  # a lone `$` is punctuation
        elif char == "`":
            end = value.find("`", index + 1)
            if end < 0:
                return None
            families.append("shell-subst")
            names.append("")
            index = end + 1
        elif value.startswith("{{", index):
            end = _find_close(value, index + 2, "}}")
            if end < 0:
                return None
            families.append("template")
            names.append(value[index + 2 : end - 2].strip())
            index = end
        elif char == "%":
            batch = _REF_BATCH.match(value, index)
            if batch:
                families.append("batch")
                names.append(batch.group(1))
                index = batch.end()
            else:
                index += 1  # a lone `%` is punctuation
        elif char.isalnum():
            return None  # literal material outside any reference
        else:
            index += 1  # punctuation / whitespace between references
    if not families:
        return None
    return RuntimeReference(tuple(families), tuple(names), tuple(operators))


def _reference_reason(reference: RuntimeReference) -> str:
    named = ", ".join(sorted({n for n in reference.names if n})) or "an opaque expression"
    kinds = ", ".join(sorted(set(reference.families)))
    return (
        f"every letter and digit lies inside a well-formed {kinds} reference to {named}; "
        "a reference exposes an environment-variable name, not a value"
    )


def _reference_classification(reference: RuntimeReference) -> str:
    return "runtime-reference:" + ",".join(sorted(set(reference.families)))


def _protected_spans(text: str, tokens: Sequence[str]) -> list[tuple[int, int, str]]:
    """Every occurrence of every non-empty known-safe token, in deterministic order."""
    spans: list[tuple[int, int, str]] = []
    for token in sorted({t for t in tokens if t}):
        position = text.find(token)
        while position >= 0:
            spans.append((position, position + len(token), token))
            position = text.find(token, position + len(token))
    return sorted(spans)


def _protecting_token(
    protected: list[tuple[int, int, str]], start: int, end: int
) -> str | None:
    for span_start, span_end, token in protected:
        if start < span_end and end > span_start:
            return token
    return None


def _enclosing_value(line: str, start: int, end: int) -> str:
    """The assigned value that contains ``line[start:end]`` — a quoted literal if one
    encloses the span, otherwise the whitespace-delimited token (right of any `=`/`:`)."""
    for match in _QUOTED.finditer(line):
        if match.start() < start and end <= match.end() - 1:
            return match.group()[1:-1]
    left = start
    while left > 0 and not line[left - 1].isspace():
        left -= 1
    right = end
    while right < len(line) and not line[right].isspace():
        right += 1
    token = line[left:right].rstrip(";,")
    for separator in ("=", ":"):
        head, sep, tail = token.partition(separator)
        if sep and len(head) < start - left:
            token = tail
            left += len(head) + 1
    return token


_ASSIGNMENT = re.compile(r"([A-Za-z_$][\w.$\-]*)\s*[:=]\s*$")


def _assigned_identifier(text: str, position: int) -> str | None:
    """The identifier a secret at ``position`` is assigned to, if any."""
    line_start = text.rfind("\n", 0, position) + 1
    prefix = text[line_start:position]
    # Strip an opening quote so `KEY = "<secret>` still exposes `KEY`.
    match = _ASSIGNMENT.search(prefix.rstrip("\"' \t"))
    return match.group(1) if match else None


def _key_names_credential(key: str) -> bool:
    """True when an assignment key's final segment names a credential (FR-003).

    `dbPassword` and `SESSION_SECRET` name credentials; `authTokenError` names
    an error message about one. Only the final segment counts — anything broader
    reintroduces the substring-inside-identifier false positive (contract C1).
    """
    segments = [
        segment.lower()
        for segment in re.split(r"[_.$\-]+|(?<=[a-z0-9])(?=[A-Z])", key)
        if segment
    ]
    return bool(segments) and segments[-1] in _CRED_WORDS


def _prose_spans(line: str) -> list[tuple[int, int]]:
    """Quoted spans whose content reads as prose (contains a space)."""
    return [m.span() for m in _QUOTED.finditer(line) if " " in m.group()]


def _within(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    return any(s <= span[0] and span[1] <= e for s, e in spans)


def _has_credential_context(text: str, start: int, end: int, line: str, line_start: int) -> bool:
    """Structural credential context for a candidate at ``[start, end)`` (C1).

    Three tiers, all deterministic and recall-first:
      1. a standalone credential word in *code* — the candidate's own span is
         masked first, and words inside prose literals do not count;
      2. an assignment/key whose final segment names a credential (FR-006);
      3. a credential word inside a prose literal *that contains the candidate*
         — a message naming a credential while embedding a key is a real finding.
    """
    masked = (
        line[: start - line_start] + " " * (end - start) + line[end - line_start :]
    )
    prose = _prose_spans(masked)
    for match in _SECRET_CONTEXT.finditer(masked):
        if not _within(match.span(), prose):
            return True
    key = _assigned_identifier(text, start)
    if key and _key_names_credential(key):
        return True
    candidate_span = (start - line_start, end - line_start)
    for span in prose:
        if _within(candidate_span, [span]) and _SECRET_CONTEXT.search(line[span[0] : span[1]]):
            return True
    return False


# -------------------------------------------------------------------- result


@dataclass(frozen=True)
class SecretHit:
    """A secret the redactor removed — evidence for a hard-coded-credential finding.

    The redactor is the deterministic secret scanner: because it must locate every
    credential before analysis can see the code, it already knows precisely what
    was found and where. Reporting hits means secrets are still *findings* even
    though their values never reach a model.
    """

    origin: str
    label: str
    line: int
    blocked: bool = False
    #: identifier the secret was assigned to, when the line reveals one
    symbol: str | None = None


@dataclass(frozen=True)
class ExemptionDecision:
    """A value the redactor deliberately left in place, with the reason (FR-004).

    Precision gains must be auditable rather than silent: every exemption records
    what rule fired, how the value was classified, and the structural basis for
    leaving it visible. ``value`` lives here for in-process inspection and tests
    only; artifact surfaces (context packets) omit it.
    """

    origin: str
    line: int
    #: rule/label that matched ("assigned-secret" for reference exemptions on the
    #: assignment path), or "entropy-candidate" for exempted entropy hits
    rule: str
    value: str
    #: "identifier" shape name | "message-string" | "runtime-reference:<families>"
    #: | "location-token" | "credential-format" | "ambiguous-literal"
    classification: str
    reason: str
    #: "exempt-identifier" | "exempt-message" | "exempt-reference" | "exempt-location"
    decision: str


@dataclass
class RedactionResult:
    text: str
    redacted: int = 0
    blocked: int = 0
    labels: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    hits: list[SecretHit] = field(default_factory=list)
    #: values exempted as code identifiers or message strings (FR-036, FR-004)
    exempted: list[ExemptionDecision] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return self.redacted == 0 and self.blocked == 0


class Redactor:
    """Applies the layered redaction rules to text before it reaches a model."""

    def __init__(
        self,
        extra_patterns: list[str] | None = None,
        entropy_threshold: float = _ENTROPY_THRESHOLD,
    ) -> None:
        self.rules: list[Rule] = list(BUILTIN_RULES)
        for index, raw in enumerate(extra_patterns or []):
            self.rules.append(Rule(f"custom-{index}", _c(raw)))
        self.entropy_threshold = entropy_threshold
        self.rules_version = RULES_VERSION
        #: values exempted as identifiers or message strings.
        #: Kept so the decision is inspectable rather than invisible (FR-038).
        self._exemptions: list[ExemptionDecision] = []

    # ------------------------------------------------------------------ api

    def redact(
        self, text: str, origin: str = "", known_safe: Sequence[str] = ()
    ) -> RedactionResult:
        """Return ``text`` with secrets replaced by deterministic markers.

        ``known_safe`` names tokens the *caller* composed into ``text`` from
        information already published elsewhere in the report — a finding's file
        path or symbol (feature 010, FR-009). Heuristic (entropy) candidates inside
        such a token are left alone and recorded as ``exempt-location``; rule-pack
        format matches are never protected (FR-010).
        """
        if not text:
            return RedactionResult(text="")

        self._exemptions = []
        spans: list[tuple[int, int, str, bool]] = []  # start, end, label, blocked
        protected = _protected_spans(text, known_safe)

        for rule in self.rules:
            for match in rule.pattern.finditer(text):
                start, end = match.span(rule.group) if rule.group else match.span()
                if start < 0 or end <= start:
                    continue
                value = text[start:end]
                if _is_placeholder(value):
                    continue
                # Feature 010 (FR-001, FR-005a, FR-008): only the variable-assignment
                # rule consults the reference classifier. Format rules never do — a
                # known credential format is reported wherever it appears.
                if rule.label == "assigned-secret":
                    reference = classify_runtime_reference(value)
                    if reference is not None:
                        self._exempt_reference(origin, text, start, rule.label, value, reference)
                        continue
                spans.append((start, end, rule.label, False))

        for match in _ENTROPY_CANDIDATE.finditer(text):
            value = match.group()
            if _is_placeholder(value):
                continue
            if shannon_entropy(value) < self.entropy_threshold:
                continue
            start, end = match.span()
            if self._overlaps(spans, start, end):
                continue
            line_start = text.rfind("\n", 0, start) + 1
            line_end = text.find("\n", end)
            line = text[line_start : line_end if line_end != -1 else len(text)]
            # Feature 010 (research R4): a long reference NAME can clear the entropy
            # threshold on its own. If the value enclosing the candidate is entirely
            # runtime indirection, the candidate is a name, not key material.
            enclosing = _enclosing_value(line, start - line_start, end - line_start)
            reference = classify_runtime_reference(enclosing)
            if reference is not None:
                self._exempt_reference(origin, text, start, "entropy-candidate", value, reference)
                continue
            token = _protecting_token(protected, start, end)
            if token is not None:
                self._exemptions.append(
                    ExemptionDecision(
                        origin=origin,
                        line=line_no_for(text, start),
                        rule="entropy-candidate",
                        value=value,
                        classification="location-token",
                        reason=(
                            f"inside scanner-composed location token {token!r}, already "
                            "published unredacted in the finding's structured location"
                        ),
                        decision="exempt-location",
                    )
                )
                continue
            if _has_credential_context(text, start, end, line, line_start):
                spans.append((start, end, "high-entropy-secret", False))
                continue

            # Shape-and-context gate before blocking (FR-036). An identifier that
            # decomposes into readable segments, on a line that is structurally a
            # declaration or an import, is not a credential — and blocking it
            # published a coverage gap claiming uncertainty the scan did not have.
            # Recall still wins: the credential context check above runs first, so
            # an identifier-shaped value on a credential-shaped line is redacted.
            shape = identifier_shape(value)
            bare = _LINE_NUMBER.sub("", line).strip().rstrip(",;")
            if shape and (_IDENTIFIER_CONTEXT.search(line) or bare == value):
                # `bare == value`: the line is nothing but this identifier — a
                # reference passed as a call argument, as in the multi-line
                # `Pair.of(...)` usages of the SEC-0085 fields.
                self._exemptions.append(
                    ExemptionDecision(
                        origin=origin,
                        line=line_no_for(text, start),
                        rule="entropy-candidate",
                        value=value,
                        classification=shape,
                        reason=(
                            f"identifier shape {shape} on a declaration, import, "
                            "comment, or key line with no credential context"
                        ),
                        decision="exempt-identifier",
                    )
                )
                continue

            # Message arm (FR-002): an unclassifiable run inside a prose literal
            # that names no credential is a message string, not a secret. The
            # context check above has already fired for prose that *does* name a
            # credential, so this arm only sees credential-free prose.
            prose = _prose_spans(line)
            if _within((start - line_start, end - line_start), prose):
                self._exemptions.append(
                    ExemptionDecision(
                        origin=origin,
                        line=line_no_for(text, start),
                        rule="entropy-candidate",
                        value=value,
                        classification="message-string",
                        reason=(
                            "inside a quoted prose literal with no credential "
                            "context — a message string, not credential material"
                        ),
                        decision="exempt-message",
                    )
                )
                continue

            # Shape says secret, context does not confirm it: block rather
            # than risk leaking an unclassified credential.
            spans.append((start, end, "unclassified", True))

        if not spans:
            return RedactionResult(text=text, exempted=list(self._exemptions))

        result = self._apply(text, spans, origin)
        result.exempted = list(self._exemptions)
        return result

    def redact_mapping(self, mapping: dict[str, str]) -> tuple[dict[str, str], RedactionResult]:
        """Redact every value in ``mapping`` (e.g. a context packet's sources)."""
        out: dict[str, str] = {}
        total = RedactionResult(text="")
        for key in sorted(mapping):
            result = self.redact(mapping[key], origin=key)
            out[key] = result.text
            total.redacted += result.redacted
            total.blocked += result.blocked
            total.labels.extend(result.labels)
            total.warnings.extend(result.warnings)
            total.hits.extend(result.hits)
            total.exempted.extend(result.exempted)
        total.labels = sorted(set(total.labels))
        return out, total

    def scan(self, text: str) -> bool:
        """True when ``text`` still contains anything the redactor would act on."""
        return not self.redact(text).clean

    # ------------------------------------------------------------- internals

    def _exempt_reference(
        self,
        origin: str,
        text: str,
        position: int,
        rule: str,
        value: str,
        reference: RuntimeReference,
    ) -> None:
        self._exemptions.append(
            ExemptionDecision(
                origin=origin,
                line=line_no_for(text, position),
                rule=rule,
                value=value,
                classification=_reference_classification(reference),
                reason=_reference_reason(reference),
                decision="exempt-reference",
            )
        )

    @staticmethod
    def _overlaps(spans: list[tuple[int, int, str, bool]], start: int, end: int) -> bool:
        return any(not (end <= s or start >= e) for s, e, _, _ in spans)

    def _apply(
        self, text: str, spans: list[tuple[int, int, str, bool]], origin: str
    ) -> RedactionResult:
        # Resolve overlaps deterministically: earliest start wins, then longest.
        spans.sort(key=lambda s: (s[0], -(s[1] - s[0]), s[2]))
        merged: list[tuple[int, int, str, bool]] = []
        for span in spans:
            if merged and span[0] < merged[-1][1]:
                continue
            merged.append(span)

        result = RedactionResult(text="")
        pieces: list[str] = []
        cursor = 0
        for start, end, label, blocked in merged:
            pieces.append(text[cursor:start])
            line = text.count("\n", 0, start) + 1
            result.hits.append(
                SecretHit(
                    origin=origin,
                    label=label,
                    line=line,
                    blocked=blocked,
                    symbol=_assigned_identifier(text, start),
                )
            )
            if blocked:
                pieces.append(BLOCKED)
                result.blocked += 1
                where = f"{origin}:{line}" if origin else f"line {line}"
                # FR-038: name the file, the line, and why. A gap a reader cannot
                # locate is a gap they cannot dismiss, which is how four
                # identifier false positives came to look like four real unknowns.
                result.warnings.append(
                    f"blocked a high-entropy value at {where}: it does not decompose "
                    "into identifier segments and its line carries no credential "
                    "context, so it could not be confirmed as a non-credential"
                )
            else:
                pieces.append(REDACTED.format(label=label))
                result.redacted += 1
                result.labels.append(label)
            cursor = end
        pieces.append(text[cursor:])

        result.text = "".join(pieces)
        result.labels = sorted(set(result.labels))
        return result
