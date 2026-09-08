"""Feature 016 T006/T028: rule-pack validation and archetype matching."""

from __future__ import annotations

import pytest

from pipeline.identity_rules import (
    InvalidRuleData,
    load_guard_names,
    load_identity_rules,
    rules_version,
)

_VALID_DOC = {
    "version": "0",
    "dataset_date": "2026-09-07",
    "guard_names": ["authenticat\\w+"],
    "rules": [],
}

_RULE = {
    "id": "node-header-identity-no-credential",
    "stacks": ["node"],
    "file_globs": ["**/*.js", "**/*.ts"],
    "scope": "function",
    "identity_read": "req\\.(?:headers|cookies)[\\[.]",
    "requires_absent": ["jwt\\.verify", "bcrypt\\.(?:compare|checkpw)"],
    "dispatch": "\\bnext\\s*\\(",
    "cwe": "CWE-290",
    "severity_score": 9.1,
    "title": "Identity asserted from client-controlled header without any credential",
    "description": "d",
    "recommendation": "r",
}

_WEAK_BODY = """
function authenticateUser(req, res, next) {
  const userEmail = req.headers['x-user-email'];
  if (!userEmail) return res.status(401).end();
  req.userEmail = userEmail;
  next();
}
"""

_SAFE_BODY = """
function verifyJwt(req, res, next) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '');
  const payload = jwt.verify(token, process.env.JWT_SECRET);
  req.userId = payload.sub;
  next();
}
"""

_NO_DISPATCH_BODY = """
function readIdentity(req) {
  return req.headers['x-user-email'];
}
"""


def _doc(**overrides):
    doc = dict(_VALID_DOC)
    doc.update(overrides)
    return doc


def test_shipped_pack_validates() -> None:
    """The pack that ships with the payload must always load."""
    load_guard_names()
    load_identity_rules()
    assert rules_version() >= "1"


def test_duplicate_rule_id_fails_the_build() -> None:
    doc = _doc(rules=[_RULE, dict(_RULE)])
    with pytest.raises(InvalidRuleData, match="duplicate rule id"):
        load_identity_rules(doc)


def test_missing_required_field_fails() -> None:
    broken = {k: v for k, v in _RULE.items() if k != "requires_absent"}
    with pytest.raises(InvalidRuleData, match="missing requires_absent"):
        load_identity_rules(_doc(rules=[broken]))


def test_invalid_regex_fails_with_rule_id() -> None:
    broken = dict(_RULE, identity_read="[unclosed")
    with pytest.raises(InvalidRuleData, match="node-header-identity"):
        load_identity_rules(_doc(rules=[broken]))


def test_unknown_cwe_fails() -> None:
    broken = dict(_RULE, cwe="CWE-9999")
    with pytest.raises(InvalidRuleData):
        load_identity_rules(_doc(rules=[broken]))


def test_missing_guard_names_fails() -> None:
    with pytest.raises(InvalidRuleData, match="guard_names"):
        load_guard_names(_doc(guard_names=[]))


def test_archetype_fires_on_weak_guard() -> None:
    (rule,) = load_identity_rules(_doc(rules=[_RULE]))
    assert rule.matches_file("backend/src/middleware/auth.js")
    assert rule.matches_body(_WEAK_BODY)


def test_archetype_suppressed_by_any_credential_verification() -> None:
    (rule,) = load_identity_rules(_doc(rules=[_RULE]))
    # the deliberate safe pattern: identity channel read, but jwt.verify present
    assert not rule.matches_body(_SAFE_BODY)


def test_archetype_requires_dispatch() -> None:
    (rule,) = load_identity_rules(_doc(rules=[_RULE]))
    assert not rule.matches_body(_NO_DISPATCH_BODY)


def test_file_glob_scope() -> None:
    (rule,) = load_identity_rules(_doc(rules=[_RULE]))
    assert rule.matches_file("a/b/auth.ts")
    assert not rule.matches_file("a/b/auth.py")


def test_guard_name_catalogue_matches_prefix_families() -> None:
    catalogue = load_guard_names()
    names = ("authenticate", "authenticateAdmin", "authorizeUser", "verifyToken",
             "isAuthenticated", "requireRole", "guardAccess", "checkPermission")
    for name in names:
        assert any(pattern.match(name) for pattern in catalogue), name
    # non-guard vocabulary must not match (auth-prefix families only)
    for name in ("handlerFunc", "sendEmail", "listOrders", "makeToken"):
        assert not any(pattern.match(name) for pattern in catalogue), name


def test_guard_names_are_prefix_matched_not_substring() -> None:
    """`unauthenticated` starts with `un` + auth… — a plain substring match would
    accept it; the catalogue anchors at the identifier head."""
    catalogue = load_guard_names()
    assert not any(pattern.match("unauthenticatedHandler") for pattern in catalogue)
    assert not any(pattern.match("postAuthenticateHook") for pattern in catalogue)
