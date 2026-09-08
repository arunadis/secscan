"""Feature 016 T008/T009: source channels, driver conventions, auth prefixes,
and wiring-fact extraction (research R1/R2, graph-wiring contract §1)."""

from __future__ import annotations

from pipeline.extract import extract_file


def _js(source: str):
    return extract_file("src/routes/x.js", source, "javascript")


def _py(source: str):
    return extract_file("src/views.py", source, "python")


# ------------------------------------------------------------------ channels


def test_request_headers_mark_user_controlled_js() -> None:
    facts = _js("const email = req.headers['x-user-email'];\n")
    assert "user_controlled_input" in facts.annotations


def test_request_cookies_mark_user_controlled_js() -> None:
    facts = _js("const session = req.cookies.session_id;\n")
    assert "user_controlled_input" in facts.annotations


def test_flask_request_headers_mark_user_controlled() -> None:
    facts = _py("email = request.headers.get('X-User-Email')\n")
    assert "user_controlled_input" in facts.annotations


def test_go_header_read_marks_user_controlled() -> None:
    facts = extract_file(
        "src/handler.go", 'email := c.GetHeader("X-User-Email")\n', "go"
    )
    assert "user_controlled_input" in facts.annotations


def test_java_request_header_annotation_counts() -> None:
    facts = extract_file(
        "src/OrderApi.java",
        "public void me(@RequestHeader(\"X-User\") String email) {\n}\n",
        "java",
    )
    assert "user_controlled_input" in facts.annotations


def test_unrelated_identifiers_do_not_count_as_sources() -> None:
    facts = _js("const value = store.headers;\n")
    assert "user_controlled_input" not in facts.annotations


# ------------------------------------------------------- driver conventions


def test_sqlite_style_convenience_calls_are_data_access() -> None:
    facts = _js(
        "function f() {\n"
        "  const db = getDatabase();\n"
        "  db.get('SELECT 1', [], () => {});\n"
        "  db.run('INSERT INTO t VALUES (?)', [], () => {});\n"
        "  db.all('SELECT 2', [], () => {});\n"
        "}\n"
    )
    ops = {(d.detail, d.symbol) for d in facts.data_access if d.operation == "execute"}
    assert ("get", "f") in ops
    assert ("run", "f") in ops
    assert ("all", "f") in ops


def test_flask_session_dict_read_is_not_a_db_call() -> None:
    facts = _py("value = session.get('cart')\n")
    assert not facts.data_access


def test_generic_object_get_is_not_a_db_call() -> None:
    facts = _js("function f() { config.get('timeout'); }\n")
    assert not facts.data_access


# ------------------------------------------------------------ auth prefixes


def test_camelcase_authenticator_matches_auth_hint() -> None:
    r"""The original miss: `authenticateUser(` never matched the exact
    `authenticate\(` literal."""
    facts = _js(
        "function authenticateUser(req, res, next) {\n"
        "  const e = req.headers['x-user-email'];\n"
        "  next();\n"
        "}\n"
    )
    symbol = next(s for s in facts.symbols if s.name == "authenticateUser")
    assert "authentication_required" in symbol.annotations


def test_token_verifier_families_match_auth_hint() -> None:
    facts = _js("const payload = verifyJwtToken(raw);\n")
    assert "authentication_required" in facts.annotations


def test_passport_authenticate_matches() -> None:
    facts = _js("passport.authenticate('local');\n")
    assert "authentication_required" in facts.annotations


def test_plain_handler_names_do_not_match_auth_hint() -> None:
    facts = _js("function sendEmail(to) { return mailer.send(to); }\n")
    assert "authentication_required" not in facts.annotations


# ------------------------------------------------------------- wiring facts


def test_router_use_produces_wiring_fact() -> None:
    facts = _js("router.use(authenticateUser);\n")
    assert [(w.target, w.route) for w in facts.wiring] == [("authenticateUser", None)]


def test_route_argument_middleware_produces_route_scoped_fact() -> None:
    facts = _js(
        "router.get('/me', authenticateUser, (req, res) => { res.json({}); });\n"
    )
    by_target = {w.target: w.route for w in facts.wiring}
    assert by_target.get("authenticateUser") == "GET /me"


def test_app_use_with_prefix_records_identifier_only() -> None:
    facts = _js("app.use('/api/clients', clientRoutes);\n")
    assert [(w.target, w.route) for w in facts.wiring] == [("clientRoutes", None)]


def test_flask_before_request_produces_wiring_fact() -> None:
    facts = _py("@app.before_request\ndef load_user():\n    pass\napp.before_request(load_user)\n")
    assert any(w.target == "load_user" and w.route is None for w in facts.wiring)


def test_inline_handler_is_not_a_wiring_target() -> None:
    facts = _js("router.get('/x', (req, res) => res.end());\n")
    assert facts.wiring == []


def test_invoked_or_member_arguments_are_not_wiring() -> None:
    facts = _js("app.use(helmet());\nrouter.get('/y', authlib.guard, handler);\n")
    # helmet() is invoked; authlib.guard is member access — neither is a bare
    # identifier. The final named handler is a legitimate handler-position edge.
    assert [(w.target, w.route) for w in facts.wiring] == [("handler", "GET /y")]
