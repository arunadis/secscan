# Research: Scan Result Accuracy Hardening

Phase 0 output. All Technical Context unknowns resolved. A1–A3 required external research; A4–A8
were resolved from the existing codebase, the reviewed benchmark scan, and the spec's clarified
decisions. Numbering continues from feature 001's R1–R6 in a separate `A` (accuracy) series.

## A1 — Template and view parsing

**Decision**: Add **`tree-sitter-html`** (0.23.2, MIT, pre-built wheel) as the single new grammar
dependency, and fix the existing **TSX misconfiguration** rather than adding per-dialect grammars.
Template dialects with no maintained PyPI wheel (Angular, Vue SFC, JSP, Thymeleaf, Go
`html/template`, Jinja/Django) are handled as HTML structure plus a deterministic delimiter/attribute
pass over the parsed tree — not as new grammars.

**Rationale**: the decisive observation is that the benchmark's four missed sinks were Angular
`[innerHTML]` bindings in plain `.html` files. `[innerHTML]` is simply an *attribute name* in HTML, so
`tree-sitter-html` locates all four with no Angular grammar involved. The same holds for Vue
`v-html`, Thymeleaf `th:utext`, and JSP `escapeXml="false"` — every one is an attribute in
otherwise-valid markup. Only Jinja/Django `|safe` and Go `template.HTML` need delimiter awareness,
and those are a bounded lexical pass. This keeps one new dependency instead of six, all of it
wheel-installed and offline.

**Rejected**: `tree-sitter-language-pack` — it downloads parser binaries on demand, which breaks both
the offline guarantee and byte-identical determinism. `tree-sitter-jinja-dialects` 0.1.1 — sdist-only
(no wheel), 0.1.x, and would need a compiler at install time; the delimiter pass covers the same
sinks without the supply-chain and build risk. GitHub-only grammars for Angular/Vue/JSP/Go templates —
not installable as pinned wheels.

**Defect found while verifying (must be fixed as part of this work)**: `extract/__init__.py` maps
`typescript` to `language_typescript()`, and `discover_repo.py` maps **both** `.ts` and `.tsx` to
`typescript`. `tree-sitter-typescript` ships a separate `language_tsx()` entry point; parsing a `.tsx`
file with the non-JSX grammar produces parse errors, so **React `dangerouslySetInnerHTML` in `.tsx`
files is currently invisible to the pipeline**. `.jsx` is unaffected because
`tree-sitter-javascript` includes JSX. This is the same class of silent coverage hole as the missing
`.html`, and it is why FR-029's per-file-class coverage reporting matters.

**Sink and control catalogue** (feeds `skill_core/data/framework_controls.json`, FR-022d):

| Stack | Default escaping | Unsafe sink | Documented bypass |
|---|---|---|---|
| Angular | escapes + sanitizes | `[innerHTML]`, `ng-bind-html` | `DomSanitizer.bypassSecurityTrust*` |
| React | JSX escapes | `dangerouslySetInnerHTML` | direct `.innerHTML` on a ref |
| Vue 2/3 | `{{ }}`, `v-bind`, `v-text` escape | `v-html` | `v-html` is itself the bypass |
| Jinja2 | **off by default** | `\|safe`, `Markup(...)` | `{% autoescape false %}` |
| Django | on by default | `\|safe` | `mark_safe`, `{% autoescape off %}` |
| Thymeleaf | `th:text` escapes | `th:utext` | `th:utext` is itself the bypass |
| JSP | `<%= %>` is **raw**; `<c:out>` escapes | `<%= %>`, `escapeXml="false"` | `escapeXml="false"`, bare EL |
| Go `html/template` | contextual auto-escaping | `template.HTML(...)` | `HTML`/`HTMLAttr`/`JS`/`URL`/`CSS` conversions |

Note that Jinja2 and JSP are **not** escape-by-default. FR-021 credits framework controls; crediting
must therefore be per-framework-and-configuration, never "a framework is present, so output is safe".

Refs: pypi.org/project/tree-sitter-html; tree-sitter.github.io/py-tree-sitter (ABI 13–15 for
py-tree-sitter 0.26); angular.dev security guide; react.dev DOM-elements docs; jinja.palletsprojects.com
autoescaping; docs.djangoproject.com automatic-html-escaping; thymeleaf.org standard-dialect;
pkg.go.dev/html/template.

## A2 — Native ecosystem dependency audits

**Decision**: one adapter per ecosystem behind a common contract
(`contracts/audit-adapter-contract.md`), with **two capability classes** because not every ecosystem
has a read-only native audit:

| Ecosystem | Capability | Command | Notes |
|---|---|---|---|
| npm | native advisory audit | `npm audit --json --omit=dev --package-lock-only` | needs `package-lock.json`; `--package-lock-only` avoids depending on installed `node_modules` |
| pnpm | native advisory audit | `pnpm audit --json --prod` | needs `pnpm-lock.yaml` |
| yarn Berry | native advisory audit | `yarn npm audit --json --environment production --all --recursive` | **NDJSON** since 4.0.1, not one object |
| yarn Classic | native advisory audit | `yarn audit --json --groups dependencies` | JSON-lines |
| Python | native advisory audit | `pip-audit --format json` (`--locked` for PEP-751; `poetry export`/`uv export` upstream of it) | |
| Go | native advisory audit, reachability-aware | `govulncheck -json ./...` | DB cached after first run; `-db file://…` for air-gapped |
| Maven / Gradle | **coordinate enumeration + offline advisory match** | `mvn -o -q dependency:list` / `gradle -q dependencies` matched against a bundled OSV Maven export | see rationale |

**Rationale for the Java split**: Java has no read-only native audit. The commonly cited option —
OWASP `dependency-check-maven` / `dependencyCheckAnalyze` — would have Maven or Gradle *resolve and
download a plugin artifact*, which FR-031 forbids ("no install"). Rather than violate FR-031 or
leave a language the code model parses uncovered (FR-030d), Java is covered by enumerating resolved
coordinates in Maven's offline mode and matching them against a bundled, refreshable OSV export.
That keeps FR-031 intact, keeps the scan offline-capable, and produces the same finding shape as the
native adapters.

**Runtime vs development discrimination** (FR-032) is available natively everywhere except the Java
path: `--omit=dev` (npm), `--prod` (pnpm), `--environment production` (yarn Berry), `--groups
dependencies` (yarn Classic), `--no-dev`/export scope (Python), and Go modules having no dev/prod
split at all. For Maven/Gradle it comes from the dependency *scope* (`test`, `provided` → development).

**Monorepo attribution** (FR-030e/FR-030f) has a native answer for npm: `npm audit
--workspace=<name> --json` produces per-workspace output even with one hoisted lockfile. The adapter
therefore tries, in order: (1) per-workspace native invocation; (2) mapping the advisory's package
back to members whose own manifests declare it; (3) workspace-level attribution with
"not derivable" stated, per FR-030f. Guessing and broadening are both prohibited.

**Network is required** by npm, pnpm, yarn, and pip-audit (registry/advisory endpoints), and by
`govulncheck` on first run. FR-033 depends on distinguishing failure from cleanliness, so the adapter
contract requires a tri-state result — `advisories` / `clean` / `could-not-check` — and a non-zero
exit or a network error MUST map to `could-not-check`, never to `clean`.

**Determinism hazard (important)**: `npm audit --json` output is known to vary between runs in its
`via`, `effects`, and `fixAvailable` fields (npm/cli#4366). Since SC-013 requires byte-identical
artifacts for identical input, the adapter MUST normalize onto the stable subset — package `name`,
`severity`, `range`, `nodes`, and the advisory id — sort all collections, and discard the volatile
fields. The same rule is applied to every adapter: the normalized artifact is a projection, not a
verbatim capture of tool output.

**Rejected**: shelling out to `osv-scanner`/`trivy` as the fallback (they are exactly the tools
FR-030 assumes are *absent*); vendoring a full advisory database for every ecosystem (size and
staleness, and the native tools already do it better where they exist); `npm audit fix` or any
mutating command (FR-031).

Refs: docs.npmjs.com/cli/v10/commands/npm-audit; github.com/npm/cli/issues/4366;
pnpm.io/cli/audit; yarnpkg.com/cli/npm/audit; pypi.org/project/pip-audit;
go.dev/security/vuln (govulncheck, vuln.go.dev); jeremylong.github.io/DependencyCheck (rejected);
osv.dev data exports.

## A3 — Offline end-of-support data

**Decision**: vendor a **pinned snapshot of `endoflife-date/release-data` (MIT)** as
`skill_core/data/eol.json`, carrying an explicit `dataset_version` and `dataset_date`. Report a
staleness warning when the snapshot is older than a configurable threshold (default 90 days), and
provide an explicit opt-in refresh command rather than any implicit network fetch.

**Rationale**: MIT licensing permits redistribution inside the skill payload; the data is a simple
version → date mapping, so matching is deterministic and offline; and it sits naturally beside the
existing versioned `cwe_map.json`, matching the precedent set in feature 001 R6 (ship standards data,
do not look it up live).

**Correction to a spec assumption**: spec 002's Assumptions section says end-of-support data is
"sourced from the shipped dataset that already carries the weakness taxonomy". Research shows the
taxonomy dataset (`cwe_map.json`) and the end-of-support dataset have unrelated shapes and refresh
cadences — daily for end-of-support versus effectively static for CWE. They ship as **sibling files in
`skill_core/data/`**, not one merged file. The assumption's intent (offline, shipped, versioned,
staleness reportable) is preserved exactly.

**Also required**: a small product-name mapping from package-manager and manifest identifiers to
dataset product ids (`nodejs`, `python`, `django`, `angular`, `react`, …), since the two namespaces do
not coincide. It lives in the same file so adding a stack stays a data change (FR-025b).

**Rejected**: live API calls to `endoflife.date` (network dependency, non-deterministic, defeats
offline scanning); `norwegianblue`/`endoflifedate`/`endoflife-lib` PyPI packages (all online clients —
none vendors the dataset); commercial datasets (licensing).

Refs: github.com/endoflife-date/release-data (MIT); github.com/endoflife-date/endoflife.date (MIT);
endoflife.date/docs/api/v1.

## A4 — Redaction identifier discrimination

**Decision**: insert a **shape-and-context gate before blocking**, not a threshold change. A
high-entropy candidate is exempt when it decomposes into a recognizable identifier form —
`camelCase`, `PascalCase`, `snake_case`, `kebab-case`, a dotted/slashed module path, or a
`filesystem-path` — and the enclosing line has no credential context. Blocking remains the default
for anything that does not decompose.

**Amended during implementation.** Two additions were forced by evidence the original analysis
missed, both found by the artifact redaction sweep rather than by the source-file tests:

1. **Structured-data context.** The gate originally recognised only declaration and comment lines.
   FR-026 brings dependency manifests and platform configuration into scope, and those files are
   almost entirely `key: value` pairs of package names and paths — `"platform-browser-dynamic":
   "^9.0.0"` in a `package.json` was blocked, reintroducing this exact defect in the files FR-026
   added. A JSON/YAML key-value line is now an identifier context.

2. **`filesystem-path` shape, matched per segment.** Whole-string path matching is unsafe because
   base64 and AWS keys also contain `/`: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` reads as a
   two-level path. Every `/`-separated segment must therefore look like a word — no run of four or
   more capitals, and a lowercase character in any segment of four characters or more. That is what
   separates `dist/angular2-hn-production-build` from key material.

Recall is unaffected in both cases because credential context is evaluated *first*: a value under a
key naming a credential is redacted whatever its shape.

**Rationale**: measured against the four benchmark false positives, entropy alone cannot separate them
from real secrets — `platform-browser-dynamic` scores 4.054 and `BrowserDynamicTestingModule` 4.208
against a threshold of 4.0, so raising the threshold to 4.3 would start dropping genuine
base64 secrets. Identifier *shape* separates them cleanly: real credentials essentially never
decompose into dictionary-shaped camel-case segments. Word-boundary decomposition is deterministic,
needs no dictionary, and is cheap.

Verified locally with the shipped redactor:

| Blocked value from the benchmark | Entropy | Decomposes as |
|---|---|---|
| `unSubscribeToSystemPrefferedColorScheme` | 4.025 | camelCase, 6 segments |
| `platform-browser-dynamic` | 4.054 | kebab-case, 3 segments |
| `BrowserDynamicTestingModule` | 4.208 | PascalCase, 4 segments |
| `platformBrowserDynamicTesting` | 4.142 | camelCase, 4 segments |

**Rejected**: raising the entropy threshold (loses real secrets — FR-037 forbids any recall
regression); allow-listing specific strings (does not generalize); a bundled English dictionary
(size, locale assumptions, and unnecessary — segmentation alone suffices).

## A5 — Encoding the applicability relation

**Decision**: encode applicability as **data keyed by weakness class**, with each entry naming the
architectures on which the class is structurally possible plus the defensible alternative class when
it is not — `skill_core/data/applicability.json`, versioned like `cwe_map.json`. Only classes whose
impossibility is *structural* are listed; the file is intentionally small and grows on evidence.

**Rationale**: keeping it as data satisfies FR-013c/FR-022d/FR-025b's extensibility requirement and
keeps the relation reviewable by a security engineer without reading Python. Starting small is
deliberate: a wrong suppression is a false negative, which the reviewed benchmark shows is the more
damaging error direction, so the relation must only encode claims that are true by construction —
"no server-side request issuer ⇒ CWE-918 impossible" — and never stylistic judgements.

The benchmark's case gives the first entry: CWE-918 requires a server-side request-issuing
architecture; on a browser-only architecture the defensible classes are CWE-20 (improper input
validation) and CWE-116 (improper encoding), which is precisely what the reviewer concluded
independently.

**Rejected**: hard-coding the relation in Python (not reviewable, not extensible); asking the model to
decide applicability (FR-015b forbids it, and the model is what produced the misclassification);
deriving applicability from the OWASP category rather than the CWE (too coarse — A10 covers more than
request forgery).

## A6 — Line-numbered context and its budget cost

**Decision**: prefix every source line in a context packet with `<line>|`, applied at all escalation
levels, and keep the token budget authoritative — if numbering pushes a packet over budget, files are
shed and reported exactly as today.

**Rationale**: this removes the root cause rather than compensating for it. The current narrowest
level reassembles source with unrelated lines deleted and an `# ... unrelated code omitted ...`
marker, so the model is counting lines in a document that does not exist on disk; a 1–2 line error is
the expected outcome, not a surprise. Numbering plus FR-001's authoritative override makes the
reported line correct by construction, and the numbers also make the omission markers unambiguous.

Estimated cost: 3–5 characters per line, roughly 1–2 tokens on a typical source line, against SC-013's
allowance of a 15% reduction in the savings ratio. Comfortable, but it must be measured rather than
assumed — the benchmark scan's usage figures give the before number (7.58x savings, 39,575 input
tokens across 25 invocations).

**Rejected**: numbering only at the narrowest level (inconsistent, and the model would have to infer
which convention is in play); returning symbol names only and dropping line reporting (loses precision
the graph can supply); post-hoc fuzzy matching of the model's guessed line against nearby source (
non-deterministic, and unnecessary once the graph is authoritative).

## A7 — Cross-member reachability without escalation level 4

**Decision**: derive cross-member reachability for FR-015a/FR-015b from the **existing code graph's
`cross_repo` edges plus the workspace model's typed integration points**, traversed deterministically.
Direction is respected; all four integration classes (sync API, async messaging, shared datastore,
identity propagation) count as reachability.

**Rationale**: this resolves the apparent conflict with the out-of-scope exclusion of escalation level
4. Level 4 is about *supplying cross-segment source to an analysis step* — an LLM context concern.
Reachability is a graph traversal that costs no context and involves no model. Feature 001 already
builds `cross_repo` edges and typed integrations, so the input exists.

The known fidelity limit: v1 call edges are name-based (001 R2), so cross-member call reachability is
best-effort. FR-015c is what makes this safe — undetermined reachability never suppresses a finding —
so imperfect edges degrade toward *retaining* findings, which is the correct failure direction.

**Rejected**: waiting for Phase 6 (leaves the false-negative class open in the interim); using
declared integration points only and ignoring graph edges (misses undeclared coupling, which is the
common case in auto-discovered workspaces).

## A8 — Where the new stages belong in the pipeline

**Decision**: five new deterministic stages between analysis and reporting, in this order —
resolution (inside normalize, before dedupe), applicability, correlation, verification, calibration,
reproduction, then a consistency gate before the report is written.

**Rationale**: the ordering is forced by the requirements rather than chosen. FR-007 puts resolution
before deduplication so findings differing only in guessed lines collapse. FR-018 puts correlation
after remapping so a remap that creates a duplicate is deduplicated. Calibration must follow
verification because FR-020's cap is keyed on the verdict. Reproduction must follow calibration
because FR-008's hypothesis-versus-observation choice is keyed on the verdict too. The consistency
gate is last because it validates the assembled result (FR-042).

**Rejected**: folding the logic into `normalize_findings.py` and `verify.py` (fewer modules, but each
concern has a distinct failure mode the benchmark harness must assert separately — see plan.md
Complexity Tracking); running applicability at analysis time as a prompt constraint (the model already
demonstrated it cannot be trusted with this, and FR-015b requires determinism).

## Resolved Technical Context summary

| Item | Resolution |
|------|-----------|
| Template parsing | `tree-sitter-html` 0.23.2 + deterministic attribute/delimiter pass (A1) |
| TSX parsing | Fix: use `language_tsx()` for `.tsx` — currently mis-mapped (A1) |
| Framework controls data | Catalogue in A1 → `skill_core/data/framework_controls.json` |
| Native audits | Per-ecosystem adapters; Java via offline coordinates + OSV export (A2) |
| Audit determinism | Normalize onto stable fields; npm output is not stable (A2) |
| Monorepo attribution | `npm audit --workspace=`, then manifest mapping, then "not derivable" (A2) |
| End-of-support data | Pinned MIT `release-data` snapshot in `skill_core/data/eol.json` (A3) |
| Redaction precision | Identifier-shape gate before blocking; threshold unchanged (A4) |
| Applicability relation | Small versioned data file, structural claims only (A5) |
| Context line numbers | `<line>|` prefix at every level; budget stays authoritative (A6) |
| Cross-member reachability | Graph `cross_repo` edges + typed integrations; no level 4 (A7) |
| Stage ordering | Forced by FR-007, FR-018, FR-020, FR-008, FR-042 (A8) |
