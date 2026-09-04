# Research: Report Accuracy Hardening (014)

All open design questions resolved against the codebase before writing this file.
No web research was required; every answer is internal to the repository.

## R1. How to attach usage evidence to dependency findings (FR-001)

**Decision**: Persist per-file imports in the code graph by adding an optional
`sorted imports: [string]` field to `type:"file"` graph nodes, populated from the
already-extracted `FileFacts.imports` (`src/pipeline/extract/__init__.py:146-151`).
A new deterministic pass computes usage evidence per `(member, package)` by exact
module-name matching over those imports, plus config-file references per shipped
rules (R2), plus dynamic forms per shipped patterns (R3). The result is written
onto the finding as a `usage` block (see data-model.md).

**Rationale**: The extractor already captures imports per file per language
(`_IMPORT_NODES` covers python/java/javascript/typescript/tsx/go,
`extract/__init__.py:77-84`) and dedupes/sorts them, but `build_code_graph.py`
drops them — only `annotations` reach persisted nodes
(`build_code_graph.py:162-171`). The graph schema (`code_graph.json`) already
permits an `"imports"` edge type that is never emitted; an edge cannot carry the
raw import string without a target node, so an optional node field is the
additive, deterministic choice.

**Alternatives considered**:
- *Emit `"imports"` edges*: schema permits it but edges require a target node id;
  import strings have none. Creating stub nodes per package pollutes the graph.
- *Re-scan source at finding time*: duplicates extractor work, breaks the rule
  that all discovery happens in deterministic tooling once.
- *Leave imports in in-memory `FileFacts` only*: usage pass would need extractor
  internals; persisting in the graph makes evidence auditable and reproducible.

## R2. Config-file references that count as usage (FR-001 FR-004)

**Decision**: Ship a new versioned data file `usage_patterns.json` in
`src/skill_core/data/` mapping config file classes to package-name extraction
rules (JSON paths / regex over known config formats: bundler aliases and
plugin/loader lists for npm; equivalent markers for other ecosystems as they are
added). Only rules present in shipped data participate; a config class with no
rule yields `undetermined`, never `none-found`.

**Rationale**: Constitution gate "Extensibility as data" — adding a config class
or rule MUST NOT require changing a pipeline stage. `type:"config"` nodes already
exist in the graph (`build_code_graph.py:97-113`), so the pass consumes graph
nodes plus shipped data only.

**Alternatives considered**: hard-coding webpack/plugin parsing in the pipeline
(rejected: violates the extensibility gate); treating config refs as full usage
without rules (rejected: false none-found risk).

## R3. Dynamic-import detection (FR-001)

**Decision**: Extend the same `usage_patterns.json` with per-language, fully
deterministic dynamic forms (e.g. literal-argument `require("pkg")`,
`import("pkg")` with a string literal). Any dynamic expression whose argument is
not a string literal attributable to the package yields `undetermined`.

**Rationale**: FR-001 as clarified (Session 2026-09-04 Q4) requires covering
dynamic forms, but only deterministically — the no-guess rule of Principle V
applies within usage detection itself.

**Alternatives considered**: static imports only (rejected by the user in
clarification); speculative pattern matching over arbitrary expressions
(rejected: non-deterministic attribution risk).

## R4. Where the usage pass lives in the pipeline

**Decision**: New module `src/pipeline/usage_evidence.py`, invoked inside
`correlate_findings.finalize()` after `resolve_and_dedupe` and before
`calibrate.apply_calibration`, so calibration can apply the confidence ceiling
and narrative reframing.

**Rationale**: `finalize()` (`correlate_findings.py:107`) is the single
pre-calibration choke point all findings flow through; running before calibration
is required because FR-003 changes confidence via the existing
`UNCONFIRMED_CONFIDENCE_CEILING` mechanism (`calibrate.py:23`).

**Alternatives considered**: inside `ingest_findings` (too early — dedupe not yet
run); inside `generate_report` (too late — calibration already applied; report
stage must not compute evidence).

## R5. Integration evidence for all misconfiguration findings (FR-004)

**Decision**: Add an `integration_markers` field to each entry of
`src/skill_core/data/misconfig_rules.json` (package names, import markers, or
config-presence markers for the technology the rule configures). The misconfig
pass attaches one of three states to each finding: `integrated` (markers found,
locations listed as evidence), `no-integration-found`, or `undetermined` (rule
class carries no markers or a referenced manifest could not be read).

**Rationale**: Clarification Session 2026-09-04 Q3 broadened scope from a curated
list to all misconfig rules, governed by the extensibility-as-data gate. The
three-state model mirrors Principle V (`unassessed` precedent in controls.py).

**Alternatives considered**: curated Firebase-only list (rejected by user);
gating only deploy-config rules (rejected by user).

## R6. Hybrid control path for template sinks (FR-005/006/007)

**Decision**: Extend `controls.evaluate()` with template awareness:

1. Sink matching: if the finding's location or traced path touches a
   `type:"template"` node, check the control's `sinks` list against extracted
   template bindings (extended template extraction records binding names as
   node annotations).
2. Member-wide bypass scan: deterministic credit for a template sink requires
   **no** `control_bypass`-annotated node anywhere in the member AND full parse
   coverage of the member's source files; otherwise the control is not credited
   deterministically and the finding flows to the triage round with the control
   as a candidate (existing `collect_candidate_controls` mechanism in
   `triage.py:97+`), where verified citations can still refute/downgrade.
3. `bypassed`/`absent`/`unassessed` semantics unchanged for code-path findings.

**Rationale**: Clarification Q2 chose hybrid. `evaluate()` today is strictly
path-scoped (`controls.py:142-220`), which is why a sanitizer never engaged for a
sink living in a template. The member-wide bypass scan follows the same
"conservative unless provable" pattern as the existing unparsed-file check.

**Alternatives considered**: always-deterministic credit (rejected: no nuance for
hedged cases); always-triage (rejected: spends a model call when provable — and
violates Determinism Before Intelligence where a deterministic answer exists).

## R7. Currency-finding merge (FR-008/009)

**Decision**: Currency findings gain a `dependency` block
(`{ecosystem, package, packages[], product, cycle, signals[]}`) from
`stack_currency.status_for` data. **Rollup key: `(member, product, cycle)`** —
packages of the same product-cycle pair (e.g. `@angular/core` +
`@angular/platform-browser` at 9.0.1) become one finding with per-package
evidence; single-package entries render unchanged. Merge happens before IDs are
assigned, inside the currency builder (`audits/__init__.py`), so no cross-source
renumbering occurs. Advisory (CVE) findings never merge with currency findings.

**Rationale**: SC-001 requires the observed duplicate EOL pair to appear as one
finding; the pair shared product and cycle but not package, so a per-package key
(as initially drafted) would NOT have merged it. Product/cycle rollup is the
correct discharge and subsumes same-package multi-signal merging.

**Alternatives considered**: merging in `merge_external_findings` by extending
`_advisory_key` (rejected: that seam is for external advisories and currency
findings carry no advisory ids; a dedicated pass keeps the contracts separate);
per-package-only merge key (superseded: fails SC-001, as shown by the original
duplicate pair).

**Implementation note (recorded post-merge)**: the shipper code follows this
product/cycle key; an intermediate draft of this section described a per-package
key with rollup deferred — that draft is superseded by the SC-001-driven
decision above.

## R8. Identifier-reference validation and quarantine (FR-010)

**Decision**: Two layers, both in `generate_report.write()`:

1. A pre-gate `resolve_narrative_references(report, system_review)` that scans
   narrative sections (system review, cross-system findings, attack paths,
   recommendations) for `SEC-\d+` references and removes any section containing
   an unresolvable id, recording each removal in a new
   `report["quarantined_sections"]` list (name + dangling id + reason).
2. `consistency.enforce()` gains a ninth rule family: any *remaining* dangling
   reference raises `ReportInconsistent` as today — a dangling reference that
   survives quarantine is a pipeline bug, not user data.

Exit signaling: new `EXIT_REPORT_DEFECT = 4` in `scan_cli.py`; `cmd_run` returns
it when `quarantined_sections` is non-empty. The three stdout summary lines stay
frozen (AGENTS.md frozen interface) — no fourth line; the defect is visible in
the report itself, `scan.log` via the progress reporter, and the exit code.

**Rationale**: Clarification Q5 chose quarantine+publish over block-publication.
`enforce()` currently raises and writes nothing (`generate_report.py:775-796`),
so the quarantine must happen *before* the strict gate, and the residual-check
layer preserves the "references must resolve" invariant for what ships.

**Alternatives considered**: quarantine inside `consistency.enforce` (rejected:
the gate today is check-only/no-mutation; mutating the report inside the checker
breaks that contract); warn-only (rejected by user); block publication (rejected
by user).

## R9. Benchmark extension (FR-012, SC-002/003)

**Decision**: Extend `tests/benchmark/cases/` with four new ground-truth cases
and fixture builders in `tests/fixtures/`:
- `usage_none_found.json` — manifest pins a vulnerable package, zero imports;
  asserts finding retained, `usage.state="none-found"`, confidence ≤ ceiling,
  no exploitation narrative asserted as fact.
- `template_sink_escaping.json` — escaped bindings, no bypass → control credited
  (or refuted via scripted triage answer with verified citations); with bypass →
  finding stands.
- `currency_merge.json` — one package, two currency signals → single finding.
- `dangling_reference.json` — narrative names a nonexistent id → section
  quarantined, exit code 4, defect declared in report.

**Rationale**: The constitution makes accuracy regressions release-blocking and
requires deliberate-false-positive fixtures ("must NOT be reported"); these
cases encode the exact cross-check failures as regression tests.

## Open risks

- *Member-wide bypass scan cost*: bypass annotations are already extracted per
  file, so the scan is O(member files) over graph nodes — negligible.
- *Import-name → package mapping* (scoped npm packages, python module≠dist name):
  resolved per ecosystem by shipped mapping rules in `usage_patterns.json`
  (e.g. `@angular/core` ↔ `@angular/core`, `python-dateutil` ↔ `dateutil`);
  unmapped names yield `undetermined`, never `none-found`.
