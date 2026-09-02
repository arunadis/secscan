# Specification Quality Checklist: Scan Result Accuracy Hardening

**Purpose**: Validate specification completeness and quality before proceeding to planning
**Created**: 2026-08-30
**Feature**: [spec.md](../spec.md)

## Content Quality

- [x] No implementation details (languages, frameworks, APIs)
- [x] Focused on user value and business needs
- [x] Written for non-technical stakeholders
- [x] All mandatory sections completed

## Requirement Completeness

- [x] No [NEEDS CLARIFICATION] markers remain
- [x] Requirements are testable and unambiguous
- [x] Success criteria are measurable
- [x] Success criteria are technology-agnostic (no implementation details)
- [x] All acceptance scenarios are defined
- [x] Edge cases are identified
- [x] Scope is clearly bounded
- [x] Dependencies and assumptions identified

## Feature Readiness

- [x] All functional requirements have clear acceptance criteria
- [x] User scenarios cover primary flows
- [x] Feature meets measurable outcomes defined in Success Criteria
- [x] No implementation details leak into specification

## Notes

Validation performed 2026-08-30 (initial) and re-validated after each of two clarification passes on
the same date — the first on multi-repository behaviour, the second on technology and repository
agnosticism. Result: all 16 items pass in all three passes; no item has ever regressed.

**Post-implementation analysis remediation (2026-08-31)**

`/speckit-analyze` raised 11 findings (0 CRITICAL, 4 HIGH). All are now resolved:

| ID | Finding | Resolution |
|----|---------|------------|
| I1 | HIGH — `FR-020` in `schema-deltas.md` meant feature 001's requirement, which reads as nonsense against 002's numbering | Qualified as `001:FR-020` and a reference convention added to the contract preamble |
| U1 | HIGH — `evidence_trail` orphaned: superseded in prose but never given a disposition | Explicit disposition recorded (deprecated, retained, unpopulated) in both `schema-deltas.md` and `data-model.md`, with the reason removal was rejected; the `if`/`then` mechanism for the conditional requirements is now specified |
| A1 | HIGH — "every language the code model already parses" was ambiguous against the code (8 suffix names vs 5 grammars) | "Grammar-backed language" defined once in Assumptions and used in FR-025a, FR-030d and SC-007a; `pipeline/stacks.py` is the single runtime answer |
| U2 | HIGH — SC-006 and SC-011 required human judgement, so no test could discharge them | Both restated as machine-checkable encodings, plus a new "Manual validation gate" section making the human re-review an explicit non-blocking gate with the reviewer authoritative over the fixture |
| A2 | MEDIUM — "the currently reported figure" for token savings was ambiguous between 7.3x and 7.58x | SC-013 now requires a same-target, same-profile baseline recorded as a triple, with a documented fallback floor |
| I2 | MEDIUM — spec assumption said end-of-support data shares the taxonomy dataset; research A3 corrected this | Assumption rewritten to sibling datasets, with the reason (different refresh cadences) |
| D1 | MEDIUM — the "never guess" invariant restated in four requirements | Now Principle V of the ratified constitution; the duplication is a recorded cost rather than an open question |
| C1 | MEDIUM — constitution was an unfilled template | Ratified at v1.0.0, amended to v1.0.1 once this feature closed its three non-compliance entries |
| F1 | MEDIUM — T016 marked `[P]` while depending on same-phase T013 | Marker removed; the parallel-execution note corrected |
| G1 | LOW — four requirements covered only via range notation | Left as-is: the work is covered and ranges are legible; expanding them adds noise without adding traceability |
| G2 | LOW — 29 tasks cite no requirement | Left as-is: all are setup, fixture or polish tasks where that is expected |

Both `plan.md` Constitution Check sections (001 and 002) were also stale after ratification and have
been re-evaluated against the six principles.

**Second clarification pass re-validation (2026-08-30) — technology and repository agnosticism**

Five further clarifications integrated. The specification grew from 56 to 69 functional requirements
and 15 to 17 success criteria. Checklist impact — all 16 items still pass, no regressions:

- *Requirements are testable and unambiguous* — strengthened. Three requirements assumed technology
  knowledge would always be available and did not say what happens when it is not: location
  resolution (FR-003), framework controls (FR-021/FR-022), and architecture classification (FR-013).
  Each now has an explicit degraded state. A fourth, SC-007, measured "the **declared** file classes"
  without saying who declares them, which made it vacuously satisfiable; the minimum is now tied to
  the languages the code model already parses.
- *Edge cases are identified* — strengthened with unmodelled-language resolution, mixed-tier
  workspaces, partial path knowledge, no-framework targets, undetermined sibling architecture, and
  hoisted monorepo lockfiles.
- *Feature meets measurable outcomes* — strengthened. SC-001a and SC-007a added; neither behaviour was
  observable under the previous criteria.

The most consequential correction in this pass was a defect introduced by the first draft: FR-003 as
originally written rejected any finding whose location could not be resolved to the code model. The
code model parses eight languages, and files outside those produce no node at all — not even a file
node — so a Ruby, PHP, C#, Rust or Swift repository would have had every finding rejected and would
have reported nothing, silently. FR-003 is now tiered and FR-003c requires file-granularity
representation for unparsed languages.

**First clarification session re-validation (2026-08-30) — multi-repository**

Five clarifications were integrated, all prioritized by multi-repo impact. The specification grew
from 44 to 56 functional requirements and from 13 to 15 success criteria. Checklist impact:

- *Requirements are testable and unambiguous* — strengthened, not changed in state. Four requirements
  previously used the unscoped word "target" in a workspace context (applicability, host ownership,
  dependency audit, bypass search). Each now names its scope explicitly, removing an ambiguity that
  would have surfaced as rework during planning.
- *Edge cases are identified* — strengthened. Added indirect reachability through shared datastores
  and message queues, and reachability direction, both of which could silently invert the
  applicability relation.
- *Scope is clearly bounded* — strengthened. The out-of-scope exclusion of escalation level 4 was
  genuinely ambiguous: it could be read as excluding the deterministic cross-member reachability that
  FR-015a now requires. The exclusion is now stated as applying to analysis context only.
- *Feature meets measurable outcomes* — strengthened. SC-005a and SC-008a were added because four of
  the five clarified behaviours cannot be observed on a single-member target, so the original
  criteria could not have detected a regression in them.
- All other items: unchanged, still passing.

**Iteration 1 findings and resolutions**

1. *All functional requirements have clear acceptance criteria* — initially **failed**. FR-043
   (regression benchmark) and FR-044 (preserve the honesty properties the review credited) were
   cross-cutting and had no acceptance scenario in any user story; they were covered only indirectly
   by SC-011 and SC-013. Resolved by adding User Story 1 scenario 6 (benchmark asserted per defect
   class) and User Story 6 scenario 4 (no honesty marker removed while reducing over-claiming).

2. *No implementation details* — reviewed and passed. The specification deliberately names no
   module, function, language, or third-party framework. Terms such as *code model*, *context
   packet*, *segment*, *escalation level*, *profile*, and *verification verdict* are product domain
   entities already defined in `001-hierarchical-security-scan`, not implementation choices. Where
   the reviewed scan's target framework mattered (its default output sanitizer), the specification
   states the capability generically as a **Framework Control** so the requirement applies to any
   framework with an equivalent default.

3. *Success criteria are technology-agnostic* — reviewed and passed. Every criterion is a percentage,
   count, or ratio measured against a stated baseline drawn from the reviewed scan. SC-013 references
   token budgets and reproducibility, which are product-level guarantees from the parent
   specification rather than implementation details.

**Scope decisions recorded during specification** (confirmed with the requester, so no
[NEEDS CLARIFICATION] markers were needed):

| Decision | Choice |
|----------|--------|
| Breadth of the feature | All five accuracy defect classes in one feature |
| Dependency coverage with no third-party scanner installed | Invoke the ecosystem's own native audit capability |
| Weakness class structurally impossible for the target architecture | Reclassify to the defensible class and rescore, recording the remap |
| Location trust | Number the source presented for analysis, resolve against the code model, and reject unresolvable locations |
| Applicability scope (multi-repo) | Decide per traced workspace path; a class is ruled out only when no reachable component in any member can exhibit it |
| Workspace-internal hosts | Exempt a hard-coded host that resolves to a member or declared integration point; only unowned hosts are flagged |
| Advisory grouping | Audit per member against its own ecosystem; group by package and version into one finding attributing every affected member |
| Bypass search scope | The traced path to the sink; a bypass off that path is its own hygiene finding, not a severity change |
| Benchmark scope | Keep the reviewed single-repo target and add a seeded multi-member workspace fixture with declared ground truth |
| Unmodelled languages | Tiered location resolution — symbol tier where parsed, file tier where not, rejection only when the file itself is unverifiable; tier recorded per finding |
| Unknown framework controls | Never credit, never inflate on the assumption of absence, cap confidence, declare "framework controls unassessed" |
| Undetermined architecture | Record as `undetermined`, disable applicability remapping for that scope, never substitute an assumed architecture |
| Minimum stack support | One template form and the primary package ecosystem per language the code model already parses |
| Hoisted monorepo lockfiles | Attribute by declaring manifests; where not derivable, attribute to the workspace and say so rather than guessing or broadening |

**Open risks carried into planning** (not specification defects):

1. FR-015 and FR-016 require an applicability relation between weakness classes and architectures.
   The size of that relation, and whether it ships as data alongside the existing weakness taxonomy,
   is a planning decision. The specification deliberately states the required behaviour and leaves
   the encoding open.
2. FR-015b requires cross-member reachability derived from the code model's own cross-member edges
   and declared integration points. Whether the existing graph already carries enough cross-member
   edge fidelity to answer this — or whether reachability must fall back to declared integration
   points alone for some integration classes — needs to be settled in planning. FR-015c makes the
   safe direction explicit (undetermined reachability never suppresses a finding), so the
   specification is correct either way, but the implementation cost differs materially.
3. ~~FR-030a assumes each member's ecosystem is detectable and its toolchain independently
   invocable. Monorepos with a single hoisted lockfile across members may not partition cleanly.~~
   **Resolved** in the second clarification pass by FR-030e/FR-030f, with the FR-035 interaction
   stated explicitly in FR-035 itself.
4. FR-025a and FR-030d define the minimum stack support as "one template form and the primary package
   ecosystem per parsed language". Which specific template form and which package manager per
   language is a planning decision; the requirement is deliberately stated as a floor, not a list, so
   it does not go stale as ecosystems change.
5. FR-003's file tier verifies that a file exists and that the reported line is within its bounds.
   Whether that check reads the file at scan time or relies on the recorded file hashes in the scan
   state is a planning decision with determinism implications.
