# Data Model: Runtime Credential References

**Feature**: 010-runtime-credential-refs | **Date**: 2026-09-02

All entities are in-process values inside the deterministic redactor; only `ExemptionDecision`
reaches an artifact (via `context_packet.redaction.exempted_items`, values omitted).

## RuntimeReference (new, in-process)

The result of classifying a quoted assignment value.

| Field | Type | Notes |
|-------|------|-------|
| `families` | `tuple[str, ...]` | ordered families encountered, from {`shell-bare`, `shell-braced`, `shell-subst`, `batch`, `template`, `ci-expr`}; length ≥ 1 |
| `names` | `tuple[str, ...]` | referenced identifiers where extractable (`AWS_DEVIN_PROD_SECRET_ACCESS_KEY`); empty string for opaque expressions such as `$(…)` or `{{ … }}` bodies |
| `operators` | `tuple[str, ...]` | shell expansion operators seen (`:-`, `:=`, `:+`, `:?`, …); empty when none |

**Validation rules** (research R2/R3):
- Every alphanumeric character of the source value lies inside one of the consumed expressions.
- Every expression's delimiters balance; an unterminated `${`, `%`, `{{`, `$(` fails classification.
- For `:-`/`-`/`:=`/`=`/`:+`/`+` the operand is empty, a placeholder, or itself a `RuntimeReference`; otherwise classification fails.
- For `:?`/`?` the operand is ignored.
- Classification is a pure function of the value string (no line context, no origin).

**Lifecycle**: created and consumed within one `Redactor.redact` call; never stored.

## ExemptionDecision (existing, extended)

Defined in `src/pipeline/redact.py`; serialised without `value` in `exempted_items`.

| Field | Type | Existing / New |
|-------|------|----------------|
| `origin` | `str` | existing |
| `line` | `int` | existing |
| `rule` | `str` | existing — now also `"assigned-secret"` (assignment path) alongside `"entropy-candidate"` |
| `value` | `str` | existing, in-process only |
| `classification` | `str` | existing — new values `"runtime-reference:<family>"` (comma-joined when several) and `"location-token"` |
| `reason` | `str` | existing — e.g. `"every letter and digit lies inside a well-formed shell-bare reference to AWS_DEVIN_PROD_SECRET_ACCESS_KEY; a reference exposes an environment-variable name, not a value"` |
| `decision` | `str` | existing enum — **new members** `"exempt-reference"`, `"exempt-location"` |

**Constraints**:
- `reason` may name environment variables (names are permitted in artifacts); it MUST never contain a literal that failed classification — by construction, exemptions are only created for values that passed.
- `exempt-location` decisions are created only from `build_reproduction`, whose result's `exempted` list is not serialised; the `context_packet.json` enum therefore gains only `exempt-reference`.

## SecretHit (existing, unchanged)

No new fields. Behavioural change only: a value classified as a `RuntimeReference` never becomes a `SecretHit`, so `secret_findings.findings_from_hits` needs no change.

## Protected span (new, in-process)

Used by the `known_safe` mechanism (research R5).

| Field | Type | Notes |
|-------|------|-------|
| `start`, `end` | `int` | offsets of one occurrence of a known-safe token in the text being redacted |
| `token` | `str` | the token (file path or symbol) as supplied by the caller |

**Rules**: a heuristic span (`high-entropy-secret` / `unclassified`) that overlaps a protected span is dropped and recorded as `exempt-location`; a format-rule span is never affected.

## Corpus entries (test data)

**RuntimeReferenceCorpusEntry** — `tests/fixtures/runtime_reference_corpus.py`

| Field | Type | Notes |
|-------|------|-------|
| `origin` | `str` | realistic path, e.g. `skillhunt-portal-backend/migration/p0/verify-account.sh` |
| `line` | `str` | the source line |
| `why` | `str` | rationale; MUST name the family |

Expectation per entry: `result.hits == []`, `result.blocked == 0`, exactly one `exempted` decision with `decision == "exempt-reference"`.

**CredentialCorpusEntry** — `tests/fixtures/credential_corpus.py` (existing tuple shape `(origin, line, why)`), extended with reference-look-alike literals. Expectation per entry: `result.redacted >= 1`.

**AuditedBaselineEntry** — `tests/benchmark/cases/audited_credential_baseline.json` (existing shape). The three feature-010 findings are recorded in a new top-level `follow_up_scans[]` block (`scan_id`, `audited`, `feature`, `entries`) rather than appended to `entries`, because their labels SEC-0080/0082/0084 collide with the 2026-08-31 scan's own labels for unrelated findings. `entries` remains 23; the follow-up block holds 3, all `verdict: "false-positive"`.

## State transitions

Classification outcome for a value `v` that matched `assigned-secret` (or is an entropy candidate inside a reference):

```text
v ──_is_placeholder──▶ skip (unchanged behaviour)
v ──classify_runtime_reference ok──▶ ExemptionDecision(exempt-reference), no SecretHit, text unchanged
v ──classification fails──▶ existing path: SecretHit + [REDACTED:assigned-secret] (or entropy gate)
```

There is no partial state: a value is exempted whole or handled exactly as before.
