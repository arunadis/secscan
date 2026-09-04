# Quickstart: Validating Report Accuracy Hardening (014)

Runnable validation scenarios proving each user story end-to-end. See
`contracts/` for field-level guarantees and `data-model.md` for shapes.

## Prerequisites

```bash
uv venv --python 3.11 && uv pip install -e ".[dev]"
source .venv/bin/activate
```

Baseline (must stay green before and after):

```bash
pytest -q                 # full suite
pytest -q -m slow         # scale scan
ruff check src tests
```

## Scenario 1 — Dependency usage evidence (US1, P1)

Fixture: a member whose `package.json` pins a vulnerable package with **zero**
imports; the code uses a different HTTP client. (New fixture +
`tests/benchmark/cases/usage_none_found.json`.)

```bash
pytest -q tests/unit -k usage_evidence
pytest -q tests/benchmark -k usage_none_found
```

Expected:
- Finding retained (not suppressed) with `usage.state == "none-found"`.
- Rendered impact uses conditional framing; no exploitation chain stated as fact.
- Confidence ≤ 0.5; severity unchanged from the CWE default.
- Control variant: same fixture WITH an import site ⇒ `usage.state == "found"`,
  locations listed.
- Unsupported-language variant ⇒ `usage.state == "undetermined"` with reason.

## Scenario 2 — Misconfig integration evidence (US1, FR-004)

Fixture: permissive `database.rules.json` + `firebase.json`, no Firebase SDK
anywhere.

```bash
pytest -q tests/integration -k integration_evidence
```

Expected: finding present with `integration.state == "no-integration-found"`;
remediation leads with removing the stale config. Variant with SDK declared ⇒
`integrated` with evidence.

## Scenario 3 — Template-aware controls (US2, P2)

Fixture: templates using escaped bindings (`[innerHTML]`) and **no** bypass call.

```bash
pytest -q tests/unit -k "controls and template"
pytest -q tests/benchmark -k template_sink_escaping
```

Expected:
- No-bypass variant: control credited (severity reduced, narrative reframed to
  residual impact) OR refuted/downgraded via scripted triage answer with
  citations that pass re-verification.
- Bypass variant (one `bypassSecurityTrustHtml` call): deterministic credit
  withheld; finding retains standing; bypass site recorded as evidence.
- Sink-not-in-list variant: control `absent`/not applicable — no silent
  assumption either way.

## Scenario 4 — Currency merge (US3, P3)

Fixture: one package attracting two currency signals; two packages attracting one
each (including an EOL framework family).

```bash
pytest -q tests/unit -k currency_merge
pytest -q tests/benchmark -k currency_merge
```

Expected: one finding per `(member, product, cycle)`; a member pinning both
`@angular/core` and `@angular/platform-browser` (same product, same cycle) yields
a single merged finding listing both packages as evidence; distinct products stay
distinct; no merge with CVE findings.

## Scenario 5 — Report reference quarantine (US4, P3)

Fixture: report input whose system review names a nonexistent `SEC-0006`.

```bash
pytest -q tests/integration -k dangling_reference
```

Expected:
- Report files (json/md/html) written without the offending section; omission
  declared inline; `quarantined_sections` records `(section, SEC-0006)`.
- Scan exit code is **4**; stdout summary lines are the existing three, unaltered.
- Clean control report: exit code 0, byte-identical output vs. pre-014.

## Determinism gate (all scenarios)

```bash
pytest -q tests/benchmark -k two_run  # byte-identical artifacts incl. new fields
```

## Manual re-validation against the original report

Re-run the scan profile that produced `20260904T085653Z-7ab7bd.md` on the same
target repository and verify the cross-check outcomes: the unused-package CVE
advisory no longer narrates exploitation as established fact; the escaped-template
XSS claim is downgraded/refuted with verified citations; the EOL pair appears as
one finding per product-cycle; no dangling `SEC-0006` reference survives.
