# Contract: Runtime Credential References

Contracts asserted by tests. Each maps to spec requirements; a failure of any is a build failure.
Contracts C1–C6 of feature 003 remain in force unchanged.

## R1 — Reference exemption is structural and exhaustive (FR-000, FR-001, FR-002)

`classify_runtime_reference(value)` returns a `RuntimeReference` **iff** every letter and digit of
`value` lies inside a well-formed indirection expression of a supported family.

- MUST classify: `$AWS_DEVIN_PROD_SECRET_ACCESS_KEY`, `${DB_PASSWORD}`, `%DB_PASSWORD%`,
  `{{ vault_secret }}`, `${{ secrets.GH_TOKEN }}`, `$(cat /run/secrets/key)`,
  `$DB_USER:$DB_PASSWORD`, `${HOST}/${TOKEN}`, `${X:-}`, `${X:-$Y}`, `${X:-changeme}`,
  `${DB_PASSWORD:?DB_PASSWORD is required}`.
- MUST NOT classify: `hunter2hunter2`, `$PREFIX-hunter2hunter2`, `hunter2hunter2$SUFFIX`,
  `pa$$w0rd-really-long`, `${NAME`, `%NAME`, `{{ name`, `${X:-hunter2hunter2}`,
  `${X:=hunter2hunter2}`, `${X:+hunter2hunter2}`, `abc%20def%20secret`.
- MUST be a pure function of the value string — identical output across runs and independent of
  origin, line context, or file type (FR-000).

## R2 — Exemption is at the redaction layer and recorded (FR-005, FR-005a)

For a line whose `assigned-secret` match classifies as a reference:

- `RedactionResult.text == input` (nothing replaced), `hits == []`, `blocked == 0`.
- Exactly one `ExemptionDecision` with `rule == "assigned-secret"`,
  `classification.startswith("runtime-reference:")`, `decision == "exempt-reference"`,
  `origin`/`line` set, non-empty `reason`.
- The same holds on the entropy path when the candidate is the name inside a well-formed
  reference (e.g. `"${SKILLHUNT_PORTAL_BACKEND_PROD_DB_PASSWORD_2024_v3}"`), with
  `rule == "entropy-candidate"`.
- `findings_from_hits(result.hits, repo) == []` for every runtime-reference corpus entry.

## R3 — Recall floor is raised, never lowered (FR-006, FR-007, FR-008)

- Every existing entry of `credential_corpus.py` is still detected (`redacted >= 1`).
- New must-find entries are detected: `password: "${DB_PASSWORD:-hunter2hunter2}"` (today
  silently clean — this contract asserts the recall **gain**), `${X:=…}`, `${X:+…}`,
  `"$PREFIX-hunter2hunter2"`, `"hunter2hunter2$SUFFIX"`, `"pa$$w0rd-really-long"`, `"${NAME"`,
  `"%NAME"` when assigned to a credential-named key.
- A format-rule match is redacted regardless of wrapper:
  `key: "${AKIAIOSFODNN7EXAMPLE}"` still yields `aws-access-key`.
- Every pre-existing redaction test remains green with unmodified expectations, except the
  single placeholder case `secret = "${ENV_SECRET}"`, which now passes via `exempt-reference`
  rather than via the removed blanket `${…}` placeholder (its observable outcome — clean text —
  is unchanged).

## R4 — Known-safe location tokens (FR-009, FR-010, FR-011)

`Redactor.redact(text, origin, known_safe=(...))`:

- A heuristic span (`high-entropy-secret`, `unclassified`) overlapping an occurrence of a
  known-safe token is not redacted and is recorded as `decision == "exempt-location"`,
  `classification == "location-token"`.
- A format-rule span is redacted even inside a known-safe token.
- With `known_safe=()` behaviour is byte-identical to today.

`build_reproduction(finding, …)` for a CWE-798 finding at
`skillhunt-portal-backend/migration/p0/verify-account.sh#AWS_SECRET_ACCESS_KEY`:

- `block["trigger"]` contains `skillhunt-portal-backend/migration/p0/verify-account.sh` verbatim.
- A seeded credential value placed in the same field is still replaced by a marker.
- For every published finding, `location.file` occurs verbatim in `reproduction.trigger` (or
  `trigger_omitted_reason`) — asserted in the integration report-consistency check.

## R5 — Schema additivity (constitution gate)

- `context_packet.json`: `redaction.exempted_items[].decision` enum is extended with
  `"exempt-reference"` only; no field changes type or meaning; `schema_version` unchanged.
- Existing packets validate unchanged; a packet containing an `exempt-reference` item validates.
- The artifact redaction sweep passes over every artifact: no credential value appears anywhere,
  including in `reason` strings (which may name environment variables).

## R6 — Benchmark gate (FR-012, FR-013, FR-014)

- `runtime_reference_corpus.py` produces zero hits, zero blocked, zero findings — asserted per
  entry, including the three `skh` lines behind SEC-0080, SEC-0082, SEC-0084.
- `audited_credential_baseline.json` keeps its 23 sorted `entries` and gains one `follow_up_scans` block for feature 010 whose entries are SEC-0080/0082/0084 with `verdict == "false-positive"` and a rationale naming the runtime-reference class.
- `test_defect_class_credential_precision` iterates both the identifier corpus and the
  runtime-reference corpus on the FP side and the extended credential corpus on the TP side;
  a regression in either fails the build regardless of other classes.
