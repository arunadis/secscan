"""Framework and security enrichment (FR-003, research.md R2).

Detects HTTP entry points, database access, and security annotations for the
frameworks the manifest is likely to encounter (Flask, FastAPI, Django, Express,
Spring, Gin/Echo). These are deliberately pattern-based heuristics layered on the
tree-sitter facts — deterministic, fast, and honest about being heuristics.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from tree_sitter import Node

    from pipeline.extract import FileFacts

# ----------------------------------------------------------------- decorators

_PY_DECORATOR = re.compile(r"^\s*@([\w.]+)")


def decorators_for(node: Node, source: bytes, language: str) -> tuple[str, ...]:
    """Decorators/annotations attached to a definition node."""
    found: list[str] = []
    parent = node.parent
    if parent is None:
        return ()

    if language == "python":
        if parent.type == "decorated_definition":
            for child in parent.named_children:
                if child.type == "decorator":
                    text = source[child.start_byte : child.end_byte].decode(
                        "utf-8", errors="replace"
                    )
                    found.append(text.strip())
    elif language in ("java", "typescript", "javascript"):
        for child in node.named_children:
            if child.type in ("modifiers", "decorator"):
                text = source[child.start_byte : child.end_byte].decode("utf-8", errors="replace")
                found.extend(
                    part.strip() for part in text.split("\n") if part.strip().startswith("@")
                )
    return tuple(sorted(set(found)))


# --------------------------------------------------------------- entry points

#: (regex, kind, route-group, method-group)
_ROUTE_PATTERNS: tuple[tuple[re.Pattern[str], str, int | None, int | None], ...] = (
    # Flask / Blueprint: @bp.route("/x", methods=["GET"])
    (
        re.compile(
            r"@[\w.]*\.?route\(\s*[\"']([^\"']+)[\"'](?:.*?methods\s*=\s*\[([^\]]*)\])?",
            re.DOTALL,
        ),
        "http",
        1,
        2,
    ),
    # FastAPI / Django-ninja / Express router: @app.get("/x") | router.post("/x")
    # The route must be path-like, so `request.args.get("customer")` is not a route.
    (
        re.compile(r"@?[\w.]*\.(get|post|put|patch|delete|head|options)\(\s*[\"'](/[^\"']*)[\"']"),
        "http",
        2,
        1,
    ),
    # Spring: @GetMapping("/x") | @RequestMapping(value = "/x", method = RequestMethod.POST)
    (
        re.compile(
            r"@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"']"
        ),
        "http",
        2,
        1,
    ),
    # Go net/http: http.HandleFunc("/x", handler)
    (re.compile(r"http\.HandleFunc\(\s*[\"']([^\"']+)[\"']"), "http", 1, None),
    # Django urls.py: path("x/", view)
    (re.compile(r"\bpath\(\s*[\"']([^\"']*)[\"']"), "http", 1, None),
)

_CONSUMER_PATTERNS = (
    re.compile(r"@KafkaListener|@RabbitListener|@SqsListener|@StreamListener"),
    re.compile(r"\.(?:subscribe|consume)\(\s*[\"']([^\"']+)[\"']"),
)

_RPC_PATTERNS = (re.compile(r"@GrpcService|grpc\.Server|ServicerToServer"),)

_CLI_PATTERNS = (
    re.compile(r"@click\.command|argparse\.ArgumentParser|cobra\.Command"),
)


def _normalize_methods(raw: str | None) -> str:
    if not raw:
        return "GET"
    methods = re.findall(r"[A-Za-z]+", raw)
    if not methods:
        return "GET"
    return "|".join(sorted({m.upper() for m in methods}))


# ------------------------------------------------------------- data access

_SQL_EXECUTE = re.compile(
    r"(?:cursor|conn|connection|db|session|stmt|statement)\s*\.\s*"
    r"(execute|executemany|query|raw|exec|Query|Exec|prepareStatement|createQuery)\s*\("
)
_ORM_READ = re.compile(
    r"\.(?:objects\.(?:get|filter|all)|find_one|find_by|findAll|findById|"
    r"createQuery|from\(|select\()"
)
_ORM_WRITE = re.compile(r"\.(?:save|insert|update|delete|create|commit|persist|merge)\s*\(")
_UNSAFE_INTERP = re.compile(
    r"""(?x)
    (?:execute|query|raw|exec|Query|Exec)\s*\(\s*
    (?:
        f["']            # python f-string
      | ["'][^"']*["']\s*(?:\+|%|\.format\(|\.concat\()   # concatenation / format
      | [A-Za-z_][\w.]*\s*\+                              # variable + string
      | `[^`]*\$\{                                        # JS template literal
      | ["'][^"']*["']\s*\+
    )
    """
)
_SQL_STRING_CONCAT = re.compile(
    r"""(?ix)
    (?:execute|query|exec)\s*\(\s*["'][^"']*(?:select|insert|update|delete)\b[^"']*["']\s*\+
    """
)

# Boundaries use letter-only lookaround so `DB_PASSWORD` and `apiKey` match while
# `tokenizer` does not (`\b` fails on underscore-joined names).
_SENSITIVE_FIELDS = re.compile(
    r"(?i)(?<![A-Za-z])(?:password|passwd|secret|token|ssn|social_security|credit_card|"
    r"card_number|cvv|api_key|apikey|private_key|email|phone|address|dob|"
    r"date_of_birth|salary)(?![A-Za-z])"
)

_AUTH_HINTS = re.compile(
    r"(?i)@login_required|@requires_auth|@authenticated|IsAuthenticated|"
    r"@PreAuthorize|@Secured|@RolesAllowed|verify_token|check_session|current_user|"
    r"require_auth|authenticate\("
)
_AUTHZ_HINTS = re.compile(
    r"(?i)@PreAuthorize|@Secured|@RolesAllowed|require_role|has_permission|"
    r"can_access|authorize\(|is_admin|check_permission|@permission_required"
)

_USER_INPUT_HINTS = re.compile(
    r"(?i)request\.(?:args|form|json|data|body|params|query|GET|POST|get_json)|"
    r"req\.(?:body|query|params)|@RequestParam|@RequestBody|@PathVariable|"
    r"c\.Query\(|c\.Param\(|r\.URL\.Query\(|os\.Args"
)

#: Value construction where the untrusted part is interpolated AFTER a prefix the
#: attacker does not control (FR-009). Two shapes matter:
#:
#:   1. a literal absolute URL base — `"https://api.example.com/" + id`
#:   2. a template literal whose first interpolation is followed by more literal
#:      path text and then another interpolation — `${this.baseUrl}/user/${id}`
#:
#: Detecting this is what makes probe feasibility decidable. A probe that only
#: succeeds by controlling the scheme or host cannot succeed against either shape,
#: which is exactly why the benchmark's `http://127.0.0.1:9/...` reproduction step
#: could never have worked.
_FIXED_PREFIX_SINK = re.compile(
    r"""['"`][a-zA-Z][a-zA-Z0-9+.\-]*://[^'"`\n]*['"`]?\s*(?:\+|,|\}\})"""
    r"""|\$\{[^}\n]*(?:base[Uu]rl|BASE_URL|baseURL|host|endpoint|apiUrl)[^}\n]*\}"""
    r"""|`[^`\n]*\$\{[^}\n]+\}[^`\n$]*/[^`\n$]*\$\{[^}\n]+\}"""
)

_SINK_HINTS = re.compile(
    # `system` requires a call shape: the bare word matches the LLM message-role
    # key `"role": "system"` and would sink-mark every chat payload (spec 007).
    r"(?i)\b(?:eval|exec|popen|subprocess\.(?:run|call|Popen)|os\.system|"
    r"system\s*\(|"
    r"Runtime\.getRuntime|ProcessBuilder|pickle\.loads|yaml\.load|"
    r"innerHTML|dangerouslySetInnerHTML|child_process)\b"
)


def enrich(facts: FileFacts, text: str) -> None:
    """Attach endpoints, data access, and security annotations to ``facts``."""
    from pipeline.extract import DataAccess, Endpoint

    lines = text.splitlines()

    # ---- entry points -------------------------------------------------
    seen: set[tuple[str, str]] = set()
    for pattern, kind, route_group, method_group in _ROUTE_PATTERNS:
        for match in pattern.finditer(text):
            route = match.group(route_group) if route_group else ""
            if not route:
                continue
            method = (
                _normalize_methods(match.group(method_group))
                if method_group and match.lastindex and match.lastindex >= method_group
                else "GET"
            )
            line = text[: match.start()].count("\n") + 1
            symbol = _following_symbol(facts, line)
            key = (symbol, f"{method} {route}")
            if key in seen:
                continue
            seen.add(key)
            facts.endpoints.append(
                Endpoint(symbol=symbol, kind=kind, route=f"{method} {route}", line=line)
            )

    for group, kind in ((_CONSUMER_PATTERNS, "consumer"), (_RPC_PATTERNS, "rpc"),
                        (_CLI_PATTERNS, "cli")):
        for pattern in group:
            for match in pattern.finditer(text):
                line = text[: match.start()].count("\n") + 1
                symbol = _following_symbol(facts, line)
                route = match.group(1) if match.lastindex else match.group(0)[:40]
                key = (symbol, route)
                if key in seen:
                    continue
                seen.add(key)
                facts.endpoints.append(
                    Endpoint(symbol=symbol, kind=kind, route=route, line=line)
                )

    facts.endpoints.sort(key=lambda e: (e.line, e.route))

    # ---- data access ---------------------------------------------------
    for match in _SQL_EXECUTE.finditer(text):
        line = text[: match.start()].count("\n") + 1
        statement = _statement_at(text, match.start())
        unsafe = bool(_UNSAFE_INTERP.search(statement) or _SQL_STRING_CONCAT.search(statement))
        facts.data_access.append(
            DataAccess(
                symbol=facts.symbol_at(line),
                operation="execute",
                detail=match.group(1),
                line=line,
                unsafe_interpolation=unsafe,
            )
        )
    for pattern, operation in ((_ORM_READ, "read"), (_ORM_WRITE, "write")):
        for match in pattern.finditer(text):
            line = text[: match.start()].count("\n") + 1
            facts.data_access.append(
                DataAccess(
                    symbol=facts.symbol_at(line),
                    operation=operation,
                    detail=match.group(0).strip("."),
                    line=line,
                )
            )
    facts.data_access.sort(key=lambda d: (d.line, d.operation, d.detail))

    # ---- file-level security annotations --------------------------------
    annotations: set[str] = set()
    if _USER_INPUT_HINTS.search(text) or facts.endpoints:
        annotations.add("user_controlled_input")
    if facts.endpoints:
        annotations.add("trust_boundary")
    if _AUTH_HINTS.search(text):
        annotations.add("authentication_required")
    if _AUTHZ_HINTS.search(text):
        annotations.add("authorization_required")
    if _SENSITIVE_FIELDS.search(text):
        annotations.add("sensitive_data")
    if any(d.operation == "execute" for d in facts.data_access) or _SINK_HINTS.search(text):
        annotations.add("security_sink")
    if re.search(r"(?i)https?://(?!localhost|127\.0\.0\.1)", text):
        annotations.add("external_system")
    facts.annotations = sorted(annotations)

    # ---- per-symbol annotations ----------------------------------------
    annotated: list[Any] = []
    for symbol in facts.symbols:
        body = "\n".join(lines[symbol.line_start - 1 : symbol.line_end])
        decorator_text = " ".join(symbol.decorators)
        combined = decorator_text + "\n" + body
        marks: set[str] = set()
        if _AUTH_HINTS.search(combined):
            marks.add("authentication_required")
        if _AUTHZ_HINTS.search(combined):
            marks.add("authorization_required")
        if _USER_INPUT_HINTS.search(combined):
            marks.add("user_controlled_input")
        if _SENSITIVE_FIELDS.search(combined):
            marks.add("sensitive_data")
        if _SINK_HINTS.search(combined) or any(
            d.line >= symbol.line_start and d.line <= symbol.line_end and d.operation == "execute"
            for d in facts.data_access
        ):
            marks.add("security_sink")
        if any(e.symbol == symbol.name for e in facts.endpoints):
            marks.add("trust_boundary")
            marks.add("user_controlled_input")
        if _FIXED_PREFIX_SINK.search(combined):
            marks.add("fixed_prefix_sink")
        symbol.annotations = tuple(sorted(marks))
        annotated.append(symbol)
    facts.symbols = annotated


def _following_symbol(facts: FileFacts, line: int) -> str:
    """The symbol a decorator/route registration applies to (next definition)."""
    candidates = [s for s in facts.symbols if s.line_start >= line and s.kind == "function"]
    if candidates:
        return min(candidates, key=lambda s: s.line_start).name
    containing = facts.symbol_at(line)
    return containing


def _statement_at(text: str, position: int) -> str:
    """The balanced call expression starting at ``position`` (bounded lookahead)."""
    end = position
    depth = 0
    limit = min(len(text), position + 2000)
    while end < limit:
        char = text[end]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[position : end + 1]
        end += 1
    return text[position:limit]
