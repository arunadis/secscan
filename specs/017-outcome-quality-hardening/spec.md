# Feature Specification: Outcome-Quality Hardening

**Feature Branch**: `017-outcome-quality-hardening`

**Created**: 2026-09-07

**Status**: Draft

**Input**: Post-implementation re-scan of the timesheet reference app (report
`20260907T100050Z-271d82`) with feature 016 shipped. The Critical auth bypass was
found but graded like a guess. This feature hardens grading, resume integrity,
presentation, and triage ergonomics.

## Background & Problem Statement

The post-016 scan found the seeded issue — SEC-0002, CWE-290 at the middleware
trust point — but the report read `[plausible]`, 7.4/High, confidence 0.5, with an
"Awaiting Verification" flag. Engine analysis found concrete causes:

Post-implementation anchor: this feature's own scan at `20260907T113546Z-3ce775`
(`/private/tmp/timesheet-app-main/.secscan/reports/20260907T113546Z-3ce775.md`)
shows the corrected shape: SEC-0003 CWE-290 at the trust function,
`[verified]` 9.1 Critical, `Detection: format` with the pack's rule id, presence
basis, and the presence caveat sentence only when relevant.

1. The weakness's class (CWE-290) never joined the presence-verified catalogue, so
   shape-proven findings cannot verify when no flow is traced.
2. Stage resume keys hash file contents only; a graph built by an older extractor
   can be reused after the tool is upgraded.
3. The deterministic archetype finding never surfaced: only the model-derived one
   survived, with no audit trail showing why.
4. One root cause — client-asserted identity — renders as three parallel entries
   that each restate the scheme (backend middleware, frontend client, login page).
5. Identical or semantically-identical declarations (budget-dropped coverage notes
   per escalation level, three near-identical deployment questions) repeat.
6. A presence-proven finding graded plausible reads as "maybe not real", masking
   its exposure-only uncertainty.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Proven weaknesses carry the grade they earned (Priority: P1)

An engineer scans a codebase whose critical weakness is shape-proven but not
flow-traced. The weakness grades on what is proven (presence) instead of degrading
into the same bucket as a guess. After upgrading secscan, no scan silently reuses
structures the new extractor would build differently. Deterministic (rule-driven)
findings are always visible with their provenance.

**Why this priority**: Grading is the report's core contract with the reader — an
overstated or understated grade is the product's defining failure mode (Constitution
Principles IV/V).

**Independent Test**: unit tests over the updated verify class set show the
CWE-290 format finding verifies on presence; an upgrade-simulation test shows stale
artifacts invalidate; a correlation test shows deterministic + model findings at the
same site both survive with distinct provenance.

**Acceptance Scenarios**:

1. **Given** a format-detected CWE-290 finding with no traced flow and no active
   reachability gap, **When** verification runs, **Then** the finding is `verified`
   with `basis: "presence"`.
2. **Given** the same finding while the FR-007/016 reachability gap is active,
   **When** verification runs, **Then** it demotes to `plausible` with the gap named.
3. **Given** a `.secscan` directory produced by a scanner whose recognizer rules
   differ from the current build, **When** a new scan starts, **Then** the graph and
   downstream stages rebuild instead of resuming stale artifacts.
4. **Given** a deterministic pack finding and a model finding at the same trust
   point, **When** deduplication runs, **Then** both contributing sources remain
   provenance-visible — the surviving record identifies the deterministic rule.

---

### User Story 2 - The report presents one issue once, graded by what is proven (Priority: P2)

An engineer reads the report for code where one root cause shows in several files.
The report treats the finding at the trust decision as the anchor and folds the
client-side counterparts into it, instead of parallel re-statements. A presence-
proven finding is labeled as proven-weakness/exposure-unconfirmed — language that
says exactly what is unknown, not generic uncertainty.

**Why this priority**: Reader trust: three parallel near-identical entries bury the
decision (fix the trust point); ambient uncertainty language mutes real severity.

**Independent Test**: report-build unit tests over a crafted finding set sharing an
assertion channel show the anchor/dependent grouping; the graded 'plausible +
presence' block renders the provenness sentence.

**Acceptance Scenarios**:

1. **Given** findings whose evidence shares one attacker-controlled channel,
   **When** the report is written, **Then** the trust-point finding is the anchor
   and the client-side findings reference it as dependents with their distinct
   evidence only.
2. **Given** a presence-proven finding without a traced path, **When** rendered,
   **Then** its block states the weakness is proven at its location while exposure
   is unconfirmed — in place of vague plausibility framing.
3. **Given** a file budget-dropped at several escalation levels, **When** coverage
   renders, **Then** one entry per (file, segment) appears.

---

### User Story 3 - One question, one answer (Priority: P2)

An operator answers a duplicated deployment question once. All findings asking it
resolve. Re-running re-ranks the affected findings together.

**Why this priority**: operator fatigue is the recall enemy; today the same
question is asked three times over and must be answered three times.

**Independent Test**: unit + integration: three findings carrying identical
question text render once; a single declaration resolves all of them; unrelated
questions remain independent.

**Acceptance Scenarios**:

1. **Given** three findings flagged with identical question text, **When** the
   report renders Awaiting Verification, **Then** they appear under one entry
   naming all three.
2. **Given** that entry answered once in declarations, **When** triage re-runs,
   **Then** every bound finding applies the declared resolution.
3. **Given** a declaration whose bound question no longer appears, **When** the
   next scan runs, **Then** it lapses (existing drift behaviour preserved).

---

### User Story 4 - The exact failure chain cannot regress (Priority: P3)

A maintainer touching correlation, grading, resume keys, or the pack sees failures
immediately if the anchored weakness is re-hidden or mis-graded.

**Independent Test**: the benchmark reproduces the observed report's structure
(attachment wiring, deterministic pack visibility, presence grading) and an
upgrade-simulation case (pre-016 artifacts present, current recognizers) cannot
reuse stale graphs.

**Acceptance Scenarios**:

1. **Given** artifacts stamped with an older recognizer version, **When** the
   scan runs, **Then** build stages rebuild (the wiring edges reappear) and the
   report marks the deterministic finding by its rule.
2. **Given** the fixture pack + model findings at one location, **When** the
   report renders, **Then** deterministic provenance is visible.

### Edge Cases

- Multiple unrelated findings share a channel name by coincidence (`"query"`):
  family grouping MUST NOT merge by generic names; the channel token must be
  identity-bearing (guard annotation or archetype provenance), never a plain
  string-match free-for-all.
- An answer resolving one finding but not admitted for another (band thresholds):
  batch resolution MUST respect per-finding admission, not force-uniform outcomes.
- A recognizer-version bump legitimately reused by replay tooling: invalidation
  is by stage resume identity only — artifacts on disk remain inspectable.
- Presence-proven finding during reachability gap: the proven at-block statement
  stays, the demotion rule from 016 applies, no double-language.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The set of weakness classes allowed to verify by presence MUST be a
  versioned catalogue (static constant mapped from the class definitions), include
  CWE-290, and demote presence-verified outcome under an active reachability gap
  for reachability-sensitive members (CWE-306, CWE-290).
- **FR-002**: The `build_code_graph` stage resume key MUST incorporate the tool
  version and the deterministic recognizer rule-pack versions, so a scanner
  upgrade invalidates stale extraction artifacts. `partition_repo`'s graph-hash
  key follows automatically.
- **FR-003**: Deterministic rule-driven findings MUST reach the report carrying
  `Detection: format` and their rule identity; when a model finding at the same
  weakness and location survives too, correlation MUST NOT erase either
  provenance (related as same weakness, never silently dropped).
- **FR-004**: Findings whose evidence shares one attacker-controlled, identity-
  bearing channel form a family: the trust-decision finding anchors, dependents
  link (`dependent`), and the report renders the anchor with dependents folded.
- **FR-005**: Presence-proven findings without a traced path MUST render as
  "weakness proven at location; exposure unconfirmed" instead of generic
  plausibility phrasing.
- **FR-006**: Coverage notes for one (file, cause) MUST appear once in the report,
  regardless of how many escalation levels dropped it.
- **FR-007**: Tool-limitation messages MUST reflect the artifact state (a budget-
  dropped lockfile is "present but outside analysis scope", never "the project
  does not have it").
- **FR-008**: Awaiting-verification entries MUST be deduplicated by question text
  (one entry listing every bound finding); a single declaration resolves all
  members of one question group.
- **FR-009**: Deliberate-family edge cases MUST be guarded: generic channel names
  NEVER merge families; batch resolution honours per-finding admission; stale
  invalidation leaves artifacts for inspection.
- **FR-010**: The accuracy benchmark MUST assert upgrade-simulation invalidation
  and deterministic-provenance visibility; determinism holds.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On the timesheet reference scan: the CWE-290 anchor renders
  `[verified]`, `basis: presence`, Critical band, `Detection: format`, with
  frontend/login-page findings folded as dependents. 100% of runs.
- **SC-002**: One scan with identical deployment-posture questions shows exactly
  one Awaiting-Verification entry per distinct question.
- **SC-003**: Zero stale-graph reuse under a recognizer-version bump (test-asserted).
- **SC-004**: `pytest -q` full suite + `-m slow` + `ruff check src tests` green; two-run byte identity holds.
- **SC-005**: Zero duplicate lines in the coverage sections of a scan that escalates a
  budget-dropped file.

## Assumptions

- The pack-rule-vs-model merge failure will be reproduced during Phase B before
  any fix is written; whichever seam proves responsible carries the fix.
- Family detection is deterministic and conservative: identity-bearing channel
  only when the channel surfaces in the graph's annotated sources or the pack's
  provenance.
- Resume-key additions are a one-time re-analysis cost; operators accept it.

## Out of Scope

- Semgrep-style generative rule authoring; LLM-proposed graph changes (deferred
  by feature 016's constitution call).
- Power-user regrade workflows (they belong to triage declarations UI).
