# Segment Analysis Prompt

You are performing a security analysis of **one segment** of a codebase. You have
been given a bounded context packet — not the repository. Reason only from it.

## Input

The context packet contains:

- `purpose` — what this segment does
- `domains` — the vulnerability domains relevant here (analyze only these)
- `entrypoints` — externally reachable routes/handlers
- `call_graph_summary` — who calls what inside the segment
- `data_flows` — traced source → transforms → validations → sink paths
- `security_relevant_symbols` — annotated symbols worth attention
- `source` — redacted source excerpts, keyed by path

### Reading `source`

Every line is prefixed with its **real line number in the file on disk**:

```
 41| def find_by_id(self, order_id):
 42|     cursor.execute(f"SELECT * FROM orders WHERE id = '{order_id}'")
```

A narrowed packet omits code you do not need, and says so explicitly:

```
   | ... 12 unrelated line(s) omitted ...
```

So **never count lines yourself** — the excerpt is not the file. Copy the number
from the prefix. If you cannot see a prefix for the line you mean, report the
enclosing symbol and your best line; the pipeline resolves every location against
its own code model before publishing, and a symbol name it can confirm is worth
more than a line number it cannot.

## Two levels of reasoning

**Level 1 — local.** For each symbol in `source`, is there a flaw in that code
alone? Check the domains listed in the packet.

**Level 2 — segment.** Does the *combination* create a vulnerability invisible in
any single component? The classic shape:

```
Controller validates the shape of X
        ↓
Service assumes X was validated for safety
        ↓
Repository uses X in a dangerous operation
```

Each layer looks defensible; the flow is not. Use `data_flows` to spot these.

## Domain guidance

Only the domains relevant to this segment are included below (FR-011).

<!-- DOMAIN-GUIDANCE:START -->
- **injection** — Untrusted value reaching an interpreter: SQL (string building
  vs parameter binding), OS commands, LDAP, XPath, template engines, `eval`.
  A parameterized query with bound arguments is NOT injectable — do not report it.
- **authorization** — Missing/incorrect access control: destructive or
  cross-tenant operations with no role/ownership check; object identifiers taken
  from user input and used without scoping (IDOR).
- **authentication** — Unauthenticated access to protected functionality, weak
  credential handling, token verification that does not check signature/issuer/
  expiry.
- **session-management** — Fixation, missing rotation on privilege change, cookie
  flags (HttpOnly/Secure/SameSite), unbounded lifetime.
- **secrets** — Credentials, keys, or tokens embedded in source or logged.
- **data-protection** — Sensitive data stored or transmitted without protection.
- **pii** — Personal data exposed, over-collected, or leaked into logs/analytics.
- **encryption** — Weak or homegrown cryptography, weak randomness for security
  purposes, missing encryption of sensitive data in transit or at rest.
- **api-security** — Missing input validation at the boundary, mass assignment,
  verbose errors leaking internals, CSRF on state-changing routes.
- **ssrf** — User-controlled URL or host reaching an outbound request.
- **path-traversal** — User-controlled path segments reaching filesystem APIs.
- **file-handling** — Unrestricted upload types, archive extraction without
  containment, unsafe temporary files.
- **deserialization** — Untrusted data reaching a deserializer that can construct
  arbitrary types.
- **rate-limiting** — Unbounded expensive operations on unauthenticated routes.
- **infrastructure** — Insecure defaults, over-permissive permissions, exposed
  management surfaces.
- **logging** — Security-relevant events not recorded, or secrets written to logs.
- **error-handling** — Error paths leaking internals or failing open.
- **dependencies** — Known-vulnerable or unmaintained components in use.
- **llm-security** — Prompt injection and model-context exposure: untrusted or
  third-party content interpolated into instruction-bearing model context
  (direct when the user controls it; indirect when it arrives via fetched
  documents, messages, or tool results), sensitive data demonstrated to enter
  model context (CWE-200), and model output flowing into execution, query, or
  rendering without demonstrated validation (CWE-116/CWE-20). A claim needs a
  listed flow as evidence — cite the source, the assembly point, and the model
  call. Read the model's reachable capabilities (tool/function declarations)
  from the code facts. If you cannot tell whether an isolation boundary,
  validation, or human-approval control exists, state the mitigation as
  undetermined with its reason — never assume one either way.
<!-- DOMAIN-GUIDANCE:END -->

If a domain you would normally check is absent above, it is out of scope for this
segment — do not report findings for it.

## Confidence and honesty

- Set `confidence` to reflect the evidence you actually have (0.0–1.0).
- If the packet does not contain enough context to decide, do **not** guess.
  Return `"needs_escalation": true` and explain what is missing in
  `escalation_reason`. A larger packet will be provided.
- Do not report a flaw you cannot point at with a file, symbol, and reason.

## Output — JSON only

```json
{
  "needs_escalation": false,
  "escalation_reason": "",
  "findings": [
    {
      "cwe": "CWE-89",
      "severity_score": 9.8,
      "confidence": 0.9,
      "location": {
        "repo": "<repo>",
        "file": "<path from the packet>",
        "symbol": "<enclosing function/class - name it whenever you can>",
        "line_start": 1,
        "line_end": 1
      },
      "description": "What is wrong, in one or two sentences.",
      "evidence": [
        {
          "repo": "<repo>",
          "file": "<path>",
          "symbol": "<symbol>",
          "reason": "The specific code fact that proves this."
        }
      ],
      "attack_scenario": "How an attacker exploits it, concretely.",
      "impact": "What they gain.",
      "recommendation": "The fix.",
      "related_symbols": ["<file#symbol>"]
    }
  ]
}
```

Rules: emit JSON and nothing else. Use CWE ids only from the shipped dataset.
Omit `severity_score` to accept the dataset default. Report each distinct issue
once.
