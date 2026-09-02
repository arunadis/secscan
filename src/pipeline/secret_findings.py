"""Deterministic hard-coded-credential findings from redaction hits.

Secrets are removed from context packets before any model sees them (FR-006a),
which means an LLM can never report them. The redactor, however, must locate every
credential to do its job — so it is the authoritative, deterministic detector.
This module turns its hits into schema-shaped findings.

Values are never included: only the label (what kind of credential), the file, and
the line.
"""

from __future__ import annotations

from typing import Any

from pipeline.redact import SecretHit
from pipeline.stacks import is_test_code

#: redactor label -> (CWE, severity, human description)
_LABEL_TO_CWE: dict[str, tuple[str, float, str]] = {
    "aws-access-key": ("CWE-798", 9.8, "AWS access key id"),
    "aws-secret-key": ("CWE-798", 9.8, "AWS secret access key"),
    "github-token": ("CWE-798", 9.1, "GitHub token"),
    "slack-token": ("CWE-798", 7.5, "Slack token"),
    "google-api-key": ("CWE-798", 8.6, "Google API key"),
    "stripe-key": ("CWE-798", 9.1, "Stripe API key"),
    "openai-key": ("CWE-798", 8.6, "OpenAI API key"),
    "anthropic-key": ("CWE-798", 8.6, "Anthropic API key"),
    "jwt": ("CWE-522", 6.5, "JSON Web Token"),
    "private-key-block": ("CWE-798", 9.8, "private key block"),
    "connection-string": ("CWE-798", 9.1, "credential inside a connection string"),
    "assigned-secret": ("CWE-798", 8.2, "credential assigned to a variable"),
    "high-entropy-secret": ("CWE-798", 7.5, "high-entropy secret in a credential context"),
}

_DEFAULT = ("CWE-798", 7.5, "hard-coded credential")

#: Only the entropy-heuristic label is unproven; every rule-pack label is a
#: known credential format (contract C4). Heuristic matches are graded lower
#: (FR-008) and described as needing review rather than as confirmed exposures
#: (FR-009).
_HEURISTIC_LABEL = "high-entropy-secret"

#: Confidence and severity grading per (detection, code context), ordered
#: format-prod > heuristic-prod > format-test > heuristic-test (C4). Test-code
#: findings are reported, never suppressed (FR-010): a committed credential is a
#: real exposure if it is ever a live value — but it is usually a fixture, so
#: both confidence and severity step down.
_CONFIDENCE = {
    ("format", "production"): 0.95,
    ("heuristic", "production"): 0.6,
    ("format", "test"): 0.55,
    ("heuristic", "test"): 0.2,
}
_TEST_SEVERITY_FACTOR = 0.6


def findings_from_hits(
    hits: list[SecretHit], repo: str, segment_id: str | None = None
) -> list[dict[str, Any]]:
    """Build raw (pre-normalization) findings from redaction hits.

    One finding per (file, label): repeated occurrences of the same credential
    kind in one file are a single issue, not several.
    """
    grouped: dict[tuple[str, str], list[SecretHit]] = {}
    for hit in hits:
        if hit.blocked:
            # Unclassifiable content: reported as a coverage warning, not a finding.
            continue
        if hit.label.startswith("custom-"):
            continue
        grouped.setdefault((hit.origin, hit.label), []).append(hit)

    out: list[dict[str, Any]] = []
    for (origin, label), group in sorted(grouped.items()):
        identifier, severity, description = _LABEL_TO_CWE.get(label, _DEFAULT)
        first = min(group, key=lambda h: h.line)
        occurrences = len(group)
        suffix = f" ({occurrences} occurrences)" if occurrences > 1 else ""
        detection = "heuristic" if label == _HEURISTIC_LABEL else "format"
        code_context = "test" if is_test_code(origin) else "production"
        confidence = _CONFIDENCE[(detection, code_context)]
        if code_context == "test":
            severity = round(severity * _TEST_SEVERITY_FACTOR, 1)
        location: dict[str, Any] = {
            "repo": repo,
            "file": origin,
            "line_start": first.line,
            "line_end": max(h.line for h in group),
        }
        if first.symbol:
            location["symbol"] = first.symbol
        if detection == "heuristic":
            finding_description = (
                f"A high-entropy string in a credential-like context may be a "
                f"hard-coded credential{suffix}. This is a heuristic match — "
                "review required. The value was redacted from analysis context "
                "and from this report."
            )
        else:
            finding_description = (
                f"A {description} is hard-coded in source{suffix}. The value was "
                "redacted from analysis context and from this report."
            )
        if code_context == "test":
            finding_description += (
                " The location is test code: the value is likely a fixture, but "
                "it is committed to the repository and must be treated as exposed."
            )
        out.append(
            {
                "cwe": identifier,
                "severity_score": severity,
                "confidence": confidence,
                "detection": detection,
                "code_context": code_context,
                "location": location,
                "description": finding_description,
                "evidence": [
                    {
                        "repo": repo,
                        "file": origin,
                        **({"symbol": first.symbol} if first.symbol else {}),
                        "segment_id": segment_id,
                        "reason": (
                            f"deterministic redaction matched rule '{label}' at line "
                            f"{first.line}"
                        ),
                    }
                ],
                "attack_scenario": (
                    "Anyone with read access to the repository — including its history, "
                    "forks, CI logs, and build artifacts — obtains a working credential "
                    "and authenticates as the application."
                ),
                "impact": (
                    "Direct authenticated access to the protected resource; rotation is "
                    "required because the value must be assumed compromised."
                ),
                "recommendation": (
                    "Remove the literal, load the value from environment configuration or "
                    "a secret manager at runtime, and rotate the exposed credential. "
                    "Purge it from version-control history."
                ),
                "segment_id": segment_id,
            }
        )
    return out
