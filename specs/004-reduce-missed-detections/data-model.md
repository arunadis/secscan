# Phase 1 Data Model: Reduce Missed Detections

All data files follow the established convention: top-level `version`, `dataset_date`, `_doc`,
and a domain key; loaded via `resources.data_path(...)` and validated at first load
(`controls.py:36-51` precedent). Schema changes to artifacts are additive only.

## Control Check (`src/skill_core/data/misconfig_rules.json`)

A data-driven rule describing a dangerous configuration state (US1, FR-001–FR-003).

| Field | Type | Notes |
|-------|------|-------|
| id | string, unique | e.g. `spring-csrf-disabled` |
| stacks | list of string | e.g. `["jvm"]`; evaluated only where the stack is present |
| file_globs | list of string | which files the rule scans (e.g. `**/*SecurityConfig*.java`, `**/settings.py`) |
| pattern | string (regex) | anchored structural pattern (e.g. `csrf\s*\([^)]*\)\s*\.\s*disable\s*\(`) |
| cwe | string | validated against the CWE catalogue at load (controls.py precedent) |
| severity_score | number 0–10 | fixed per rule — deterministic grading |
| title / description / recommendation | string | finding text; never interpolates matched values |

**Validation rules**: duplicate ids rejected; every pattern must compile; every rule must carry
a must-find fixture and a must-not-find fixture (spec clarification 2026-08-31); matched text
is never copied into findings or artifacts.

**Initial rule set** (four evidenced + top OWASP misconfigurations per supported stack):
- JVM/Spring: `csrf().disable()` (CWE-352); `allowedOrigins("*")` / `allowedOriginPatterns("*")` (CWE-942); `permitAll()` on actuator or schema-exposing endpoints (CWE-306); dev console exposed — GraphiQL/console route permitAll (CWE-489)
- Node: wildcard CORS origin (`cors()` with `origin: true`/`"*"`), especially with credentials enabled (CWE-942); session cookie configured without `secure`/`httpOnly` (CWE-1004)
- Python/Django/Flask: `DEBUG = True` (CWE-489); `ALLOWED_HOSTS = ["*"]` (CWE-1188); `CORS_ALLOW_ALL_ORIGINS = True` (CWE-942); `@csrf_exempt` (CWE-352)
- Go: `InsecureSkipVerify: true` (CWE-295); CORS `AllowedOrigins: ["*"]` with credentials (CWE-942)

## Compound Finding Rule (`src/skill_core/data/compound_rules.json`)

A named weakness pattern over deterministic whole-repo evidence legs (US2, FR-004–FR-006).

| Field | Type | Notes |
|-------|------|-------|
| id | string, unique | e.g. `graphql-depth-dos` |
| cwe / severity_score / title | | as for Control Check |
| legs | list of Leg | every leg must be evidenced for a finding to publish |
| summary / recommendation | string | |

**Leg**: `{kind, params, state}` where `kind` names a deterministic evaluator in
`compound.py`, `params` are rule data (route substrings, config patterns, file classes), and
`state` is the evaluation outcome: `evidenced` (with locations) | `absent-proven` (with the
searched space recorded) | `undetermined` (with reason — FR-005; downgrades the finding to
plausible and names the weak leg, never suppresses).

**Initial leg kinds**: `endpoint-unauthenticated`, `graphql-schema-cycle`, `config-absent`,
`seeded-credential-pattern`, `public-auth-entrypoint`. Scope: single repository per workspace
member (clarified 2026-08-31); cross-repo legs are a future extension.

**Initial rules**:
- `graphql-depth-dos` (CWE-400): endpoint-unauthenticated(route contains `/graphql`) AND
  graphql-schema-cycle(any) AND config-absent(depth/complexity/cost-limit patterns over
  enumerated config + source files).
- `seeded-shared-password` (CWE-798 variant → CWE-1391): seeded-credential-pattern(`.sql`
  migrations / seed fixtures) AND public-auth-entrypoint(login route/mutation without auth
  annotation).

## Dependency Advisory snapshot (`src/skill_core/data/advisories/<ecosystem>.json`)

Per ecosystem `npm | maven | pypi | go` (FR-007, FR-008; clarified 2026-08-31 — all four).

| Field | Type | Notes |
|-------|------|-------|
| version / dataset_date / source / staleness_threshold_days | | eol.json convention; stale beyond threshold ⇒ could-not-check with reason, never clean (FR-008) |
| packages | map: package/coordinate → list of advisory entries | entries: `introduced`, `fixed`, `affected_range?`, `ids` (CVE/GHSA), `severity`, `summary` — the shape `audits/java.py` already consumes |

**Component Instance**: a pinned dependency — `{package, version, ecosystem, manifest path,
lockfile path?, exposure: runtime|development}` — extracted deterministically from manifests
and lockfiles (no native tool required for the baseline match).

**Finding linkage fix**: dependency findings set `location.symbol = <package>` so distinct
vulnerable packages in one manifest no longer collapse under location dedupe.

## Coverage Gap Detail (additive `coverage.gap_details` in report artifact)

| Field | Type | Notes |
|-------|------|-------|
| cause | `blocked-value` \| `budget-dropped` \| `unparsed-format` | from the producing stage |
| file | string | repo-relative path |
| segment_id | string | |
| security_critical | boolean | file carries security annotations, is a config/datastore-rules file class, or matches security-config path conventions |
| impact | string | what could not be assessed, named concretely (FR-010) |

The legacy `coverage.gaps` string array is retained unchanged (additive schema). The Markdown
report renders critical gaps first and additionally renders `audit_outcomes`/`blocking_gaps`
(previously JSON-only).

## Must-Find Corpus Entry (`tests/benchmark/cases/must_find.json`)

| Field | Type | Notes |
|-------|------|-------|
| reference | string | reference scan + issue class (e.g. "20260831T071644Z-c3b48b / graphql-depth-dos") |
| rule_id | string | the misconfig/compound/advisory rule expected to fire |
| expected | string | the finding that must be produced |
| rationale | string | link to the evidenced miss |

FR-011 gate: every corpus entry must be produced by the fixture-driven benchmark; a miss fails
the build, per defect class.
