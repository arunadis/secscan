# Quickstart: Validating Scan Accuracy

Runnable validation scenarios proving the accuracy work holds. Each maps to a user story and to the
success criteria it discharges.

**Prerequisites**: Python 3.11+, the scanner installed for development
(`uv pip install -e ".[dev]"`), and the new grammar (`tree-sitter-html`). Fixtures are generated on
demand from `tests/fixtures/`. Native audits exercise whichever ecosystem toolchains are present; the
"toolchain absent" cases are validated by fixtures that hide the tool from `PATH`, so no scenario
requires installing anything.

**The benchmark**: scan `20260830T113443Z-00250b` against `codev-workshops/angular2-hn` @ `b4677f3`,
plus the independent review of it, are the ground truth for the reviewed-real case (FR-043). Expected
outcomes per defect class live in `tests/benchmark/cases/`.

```bash
pytest -q                            # full suite
pytest -q tests/benchmark            # accuracy benchmark only, asserts per defect class
```

## Scenario 1 — Locations are exact, or the finding does not ship (US1)

```bash
cd tests/fixtures/single-repo-shop
security-scan run --full
python -m pipeline.scan_cli report --format json \
  | jq '[.findings_by_band[][] | {id, tier: .location.tier, line: .location.line_start}]'
```

**Expected**: every reported location resolves to the correct symbol with an exactly correct line
range, and each finding declares `location.tier`. A finding whose file cannot be verified is absent
from the report and present in the rejected set with a reason. No finding anywhere says its location
could not be matched to the code model.

**Validates**: FR-001–FR-004, FR-007, SC-001, SC-002. Contract:
[accuracy-contracts.md](contracts/accuracy-contracts.md) §1.

## Scenario 2 — An unparsed language still gets reported (US1)

```bash
cd tests/fixtures/unparsed-language     # seeded findings in a language the code model does not parse
security-scan run --full
python -m pipeline.scan_cli report --format json | jq '.coverage.resolution_tiers'
```

**Expected**: seeded findings are reported, not rejected; all carry `tier: "file"` with
`symbol_confirmed: false`; `resolution_tiers.file` is non-zero and `rejected` is zero. This is the
regression guard for the defect where tiering did not exist and language coverage silently became a
precondition for reporting anything.

**Validates**: FR-003, FR-003a–FR-003c, SC-001a.

## Scenario 3 — Reproduction steps are achievable or plainly hypothetical (US1)

```bash
cd tests/fixtures/single-repo-shop
security-scan run --full
python -m pipeline.scan_cli report --format json \
  | jq '[.findings_by_band[][] | {id, verdict: .verification.status,
          mode: .reproduction.mode, has_trigger: (.reproduction.trigger != null)}]'
```

**Expected**: `mode: "observed"` appears only where `verification.status == "verified"`. Everywhere
else `mode: "hypothesis"` with `outcome_to_check`, stating that the scanner did not observe it. Where
the sink interpolates after a fixed prefix, no infeasible trigger is emitted and
`trigger_omitted_reason` explains why. `traced_trail` contains only nodes from `verification.path`, and
is absent when no path was traced.

**Validates**: FR-005, FR-006, FR-008–FR-012, SC-003, SC-004. Contract:
[accuracy-contracts.md](contracts/accuracy-contracts.md) §5.

## Scenario 4 — Weakness classes are possible for the architecture (US2)

```bash
cd tests/fixtures/architectures          # browser-client | server | cli | library, same seeded smell
security-scan run --full
python -m pipeline.scan_cli report --format json \
  | jq '[.findings_by_band[][] | {id, cwe, shape: .applicability.reachable_shapes,
          remap: .reclassification.original_cwe}]'
```

**Expected**: no finding carries a weakness class structurally impossible for its reachable
architectures. On the browser-only member the request-forgery smell is remapped to improper
validation/encoding, with `reclassification` recording the original class, the new class, and the
reason. Remaps below the reporting threshold still appear in the artifacts.

**Validates**: FR-013–FR-019, SC-005. Contract:
[accuracy-contracts.md](contracts/accuracy-contracts.md) §2.

## Scenario 5 — Cross-member reachability does not create false negatives (US2)

```bash
cd tests/fixtures/multi-member-workspace   # browser client + sibling server, mixed ecosystems
security-scan run --full
python -m pipeline.scan_cli report --format json \
  | jq '[.findings_by_band[][] | {id, cwe, enabling: .applicability.enabling_member}]'
```

**Expected**: the class suppressed in Scenario 4's single browser-only member is **retained** here,
because a sibling member issues server-side requests, and `enabling_member` names that sibling. A
member whose architecture is `undetermined`, or an integration point whose far side cannot be
resolved, suppresses nothing. This is the guard against the applicability rule introducing a
false-negative class that does not exist today.

Also assert host ownership on the same fixture:

```bash
python -m pipeline.scan_cli report --format json \
  | jq '[.findings_by_band[][] | select(.cwe=="CWE-1104" or (.description|test("third-party|trust")))
         | {id, description}]'
```

**Expected**: the client's hard-coded host pointing at its sibling member raises **no** third-party
trust finding, because it resolves to a workspace member. A genuinely unowned host still does. A host
whose ownership cannot be determined is reported as external with ownership stated as undetermined —
never silently exempted.

**Validates**: FR-013a–FR-013c, FR-015a–FR-015c, FR-024–FR-024b, SC-005a. Contract:
[accuracy-contracts.md](contracts/accuracy-contracts.md) §2, §7.

## Scenario 6 — Framework controls are credited only when established (US2)

```bash
cd tests/fixtures/architectures
security-scan run --full
python -m pipeline.scan_cli report --format json \
  | jq '[.findings_by_band[][] | {id, control: .framework_control.state,
          severity: .severity_score, caps: .calibration.caps_applied}]'
```

**Expected**: a recognized escape-by-default framework with no bypass on the path yields
`credited`, a reduced severity, and a narrative reframed to what the control still permits. A bypass on
the path yields `bypassed` with the site named; a bypass off the path leaves severity untouched and
becomes its own finding. An unrecognized framework, or any unparsed file on the path, yields
`unassessed` — confidence capped, severity **not** inflated, coverage gap named. A framework with no
such control yields `absent` and no gap. No `plausible` finding with unconfirmed reachability outranks
any `verified` finding.

**Validates**: FR-020–FR-024b, SC-006. Contract:
[accuracy-contracts.md](contracts/accuracy-contracts.md) §3–§4.

## Scenario 7 — Templates and configuration are in the model (US3)

```bash
cd tests/fixtures/per-language-stacks     # one member per parsed language, each with templates
security-scan run --full
python -m pipeline.scan_cli report --format json | jq '.coverage.file_classes'
jq '[.payload.nodes[] | select(.type=="template" or .type=="config") | .path]' \
  .security-scan/code-graph.json
```

**Expected**: all five security-relevant file classes are represented and segment-assigned. Template
bindings appear as `template_sink` nodes linked by `renders` edges to the code supplying the value —
with **zero manual steps**, which is the specific gap that changed a conclusion in the benchmark. A
template dialect that cannot be parsed appears under `unparsed` with its format named, never silently
skipped. `.tsx` files parse without error (the mis-mapped-grammar defect from research.md A1).

**Validates**: FR-025–FR-029, SC-007, SC-007a.

## Scenario 8 — Dependency exposure is reported, or loudly unassessed (US4)

```bash
cd tests/fixtures/multi-member-workspace   # known-vulnerable manifests, one hoisted lockfile
security-scan run --full
python -m pipeline.scan_cli report --format json \
  | jq '{gaps: .coverage.blocking_gaps, audits: .coverage.audit_outcomes,
         deps: [.findings_by_band[][] | select(.source=="dependency-audit")
                | {pkg: .dependency.package, exposure: .dependency.exposure,
                   members: .dependency.affected_members,
                   attribution: .dependency.attribution}]}'
```

**Expected**: each member is audited against its own ecosystem. Runtime advisories rank above
development-only ones. A package shared across members produces one finding attributing every affected
member. Under the hoisted lockfile, attribution is per-member where derivable and
`workspace-not-derivable` — stated, not guessed — where not. A member with no toolchain gets its own
named gap and the workspace is not presented as fully audited. With the network unavailable the
outcome is `could-not-check`, never `clean`, and a blocking gap appears at the top of the report with a
runnable command. Manifest and lockfile hashes are unchanged after the run.

**Validates**: FR-030–FR-035, SC-008, SC-008a. Contract:
[audit-adapter-contract.md](contracts/audit-adapter-contract.md).

## Scenario 9 — Redaction stops inventing coverage gaps (US5)

```bash
pytest -q tests/unit/test_redact.py -k "identifier or recall"
cd tests/fixtures/identifier-corpus
security-scan run --full
python -m pipeline.scan_cli report --format json | jq '.coverage.gaps'
```

**Expected**: zero coverage gaps caused by a long camel-case, Pascal-case, kebab-case or snake-case
identifier, an import specifier, or a module path — including the four benchmark false positives
(`unSubscribeToSystemPrefferedColorScheme`, `platform-browser-dynamic`,
`BrowserDynamicTestingModule`, `platformBrowserDynamicTesting`). Every seeded credential is still
detected: recall stays at 100%. Any value that is still blocked names file, line, and reason.

**Validates**: FR-036–FR-039, SC-009.

## Scenario 10 — The report does not contradict itself (US6)

```bash
cd tests/fixtures/all-bands
security-scan report --format json > /tmp/r.json
pytest -q tests/unit/test_consistency.py
```

**Expected**: every internal cross-reference names a section that exists, and every severity pointer
comes from the finding's own published band — the benchmark's "see the High section" pointer at a
Medium finding is impossible by construction. No narrative contradicts its own verification verdict or
reproduction block. When nothing was verified end to end, the executive summary says how to read the
report. A contradiction **blocks** the write rather than warning. Verdict badges, verification gaps,
the verified count, and declared coverage gaps are all still present — precision was not bought by
deleting the honesty markers.

**Validates**: FR-040–FR-042, FR-044, SC-010. Contract:
[accuracy-contracts.md](contracts/accuracy-contracts.md) §6.

## Scenario 11 — The benchmark, end to end (US1–US6)

```bash
pytest -q tests/benchmark                       # both cases, per defect class
pytest -q tests/benchmark -k reviewed_real      # the reviewed angular2-hn scan
pytest -q tests/benchmark -k seeded_workspace   # the multi-member fixture
```

**Expected**, on a fresh scan of the benchmark target: no request-forgery finding; the injection
finding at Low/informational with the framework sanitizer credited; at least one dependency finding or
a blocking gap with a runnable command; zero coverage gaps caused by identifiers; no dangling section
reference; and the ranked recommendations reproducing the reviewer's remediation order — dependencies
first. A regression in any single defect class fails the run without being masked by another class
improving.

**Validates**: FR-043–FR-044, SC-011, SC-012.

## Scenario 12 — No regression in the properties feature 001 established

```bash
pytest -q -m slow                               # large-repository scale scan
python -m pipeline.scan_cli report --format json | jq '.usage'
```

**Expected**: no attack executed; no credential in any artifact (the redaction sweep still passes); no
token budget exceeded; byte-identical artifacts across two runs on identical input, including the new
normalized audit output; and the measured savings ratio versus the maximal-context baseline no more
than 15% below the previously reported figure, with line-numbered context accounted for.

**Validates**: SC-013. Baseline for comparison: the benchmark scan's reported 7.58x savings across 25
invocations and 39,575 input tokens.
