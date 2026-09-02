# Architecture

secscan is built on one observation: scanning a large repository with an LLM fails
because the codebase does not fit in the context window. The design answer is to
treat **context as a managed resource**:

> Don't make the LLM the repository analyzer. Make the LLM the reasoning engine
> sitting on top of a deterministic repository model.

Deterministic tooling does all discovery, splitting, and evidence collection. The
model only ever sees small, semantically meaningful, budgeted packets — and it is
never trusted with a structural claim the pipeline did not establish.

## The pipeline

A scan runs a fixed, ordered set of stages. Stages 1–4 and the post-analysis
stages are deterministic Python; only segment analysis and system review involve
model reasoning.

```
repository/workspace
        │  deterministic (no LLM)
        ▼
1. discover_repo      manifest: languages, frameworks, modules, entry points, data stores
2. build_code_graph   tree-sitter → symbols, calls, routes, DB access, trust annotations
3. partition_repo     segments along security boundaries — never by line count
4. build_context      bounded packets, secrets redacted, token budget enforced
5. ingest_findings    external scanner output, when tools are present (spec 008)
        │  bounded LLM reasoning
        ▼
6. segment_analysis   per segment, only the relevant vulnerability domains
        │  deterministic again
        ▼
7. normalize_findings schema enforcement + tiered location resolution + CWE/OWASP mapping
8. applicability      architecture-aware remapping of structurally impossible classes
9. verify_findings    static source→sink trace: verified / plausible / disproven
10. correlate_findings dedupe, relate, group systemic issues
11. calibrate          verification-aware severity calibration
12. reproduce          benign-canary reproduction steps, local/test scope
13. consistency        pre-write gate: a self-contradicting report is withheld
14. system_review      cross-boundary review (deterministic narrative today;
                       LLM cross-boundary reasoning lands with multi-repo work)
15. generate_report    unified report (Markdown + JSON + HTML) + usage/cost summary
```

The canonical definition is `STAGES` in [`src/pipeline/state.py`](../src/pipeline/state.py);
accuracy-stage ordering is *forced by requirements* (documented in that module's
docstring) — e.g. location resolution precedes deduplication, applicability precedes
correlation so a remap creating a duplicate is deduplicated, and calibration follows
verification because the severity cap is keyed on the verdict.

Every stage writes a durable artifact under `.secscan/` (see
[Artifacts](artifacts.md)), so any stage can be re-run in isolation and an
interrupted scan resumes where it stopped.

## Design principles

The constitution ([`.specify/memory/constitution.md`](../.specify/memory/constitution.md))
fixes six principles; the architecture follows from them:

1. **Determinism before intelligence.** Identical input + identical tool version ⇒
   byte-identical artifacts (sorted, canonical JSON with trailing newline). Third-party
   tool output is normalized into a stable projection before it touches an artifact.
2. **Context is a managed resource.** Budgets are enforced against the *actual
   serialized request*. Oversized units are subdivided along security boundaries;
   files that cannot fit are dropped whole and reported as coverage gaps — source is
   never silently truncated.
3. **Secrets never reach a model.** The layered redactor runs before any context
   packet exists; unclassifiable content is blocked, not passed through. See
   [Security model](security-model.md).
4. **Evidence over assertion.** Findings must conform to the shipped schema; locations
   resolve against the code model (the sole authority for line ranges), not against
   model output. A trail rendered with dataflow arrows contains only traced edges.
5. **Honest uncertainty.** Undetermined states (`undetermined` architecture,
   `unassessed` control, `could-not-check` audit) are recorded explicitly and can
   neither suppress a finding nor read as clean.
6. **Observe, never attack.** Verification is static; reproduction steps use benign
   canary values targeting local/test deployments; tooling run against a scanned
   project is read-only (asserted by manifest hashing).

## Evidence escalation

Analysis starts at the smallest useful context and grows only when the evidence is
genuinely insufficient:

| Level | Context |
|-------|---------|
| 1 | security-relevant symbols only |
| 2 | + calling/called code in the segment |
| 3 | + the full segment and its data flows |
| 4 | + cross-segment context |

The scan profile caps the ceiling (see [Scan profiles](scan-profiles.md)). Keeping
most invocations at level 1 is where the token savings come from — 7.3x fewer tokens
than a maximal-context baseline on the reference fixture (`audit` profile).

## The two halves of the system

### Installer (what you install)

The `secscan` CLI (a click group, `src/installer/`) scaffolds the skill into a
coding agent, generates config, and checks the environment. Each of the seven
supported agents (`claude`, `copilot`, `cursor`, `windsurf`, `devin`, `agents`,
`gemini`) is a thin adapter over one agent-agnostic core — adding an agent means
adding an adapter, never touching the core.

The payload copied into the project (`skill_core/` + `pipeline/` + `config/` +
`profiles/`) makes each project pin its own scanner version, and the copied
`scripts/` tree means the deterministic stages run with `python -m pipeline.scan_cli`
— no global install needed at scan time. Re-running `init` on a project performs an
in-place upgrade, preserving config and artifacts and flagging schema changes.

### Pipeline (what scans)

`src/pipeline/` holds the deterministic stages plus support modules:

- **Repository model** — `discover_repo`, `build_code_graph`, `extract/` (tree-sitter
  grammars), `partition_repo`, `architecture`, `integrations`
- **Context construction** — `build_context`, `redact`, `budget`, `escalate`
- **Reasoning exchange** — `llm_findings`, `prompts`, `llm_client` (endpoint mode),
  handoff under `.secscan/handoff/` (agent mode)
- **Accuracy stages** — `normalize_findings`, `locate`, `applicability`, `controls`,
  `verify`, `dataflow`, `calibrate`, `correlate_findings`, `compound`, `reproduce`,
  `consistency`, `excerpts`, `misconfig`, `secret_findings`, `supply_chain`, `hosts`
- **External tooling** — `tooling/` (provision, run, cross-check), `audits/`
  (per-ecosystem native audit adapters), `stack_currency`, `crosscheck`
- **Reporting** — `generate_report`, `render_html`, `report_view`, `usage`
- **Infrastructure** — `state` (artifact store, checkpoints, resume), `schemas`,
  `run`, `scan_cli`, `init_cmd`, `resources`, `agent_config`

`src/config/` loads and strictly validates configuration; `src/profiles/` is pure
data (`builtin.yaml`). `src/skill_core/` is the installable payload: `SKILL.md`,
`prompts/`, `schemas/`, `cwe_map.json`, and the four versioned knowledge bases in
`data/` (see [Extending the knowledge bases](extending-data.md)).

## Decision authority

A recurring rule: the model may *propose*, but the pipeline decides.

| Decision | Authority |
|----------|-----------|
| What the repository contains | the manifest and code graph (deterministic) |
| Where a finding is | the code model, via tiered location resolution |
| Whether a weakness class is possible | `applicability.json` + architecture |
| Whether a framework control applies | `framework_controls.json` + detected config |
| Whether a finding verifies | the static source→sink trace |
| What a report may claim | the consistency gate |

Model output that fails schema or location verification is rejected outright — it is
never published with a caveat.

## Related pages

- [Security model](security-model.md) — the safety guarantees in depth
- [Artifacts](artifacts.md) — what each stage writes
- [Agent integration](agent-integration.md) — how model reasoning is delivered
- [Extending the knowledge bases](extending-data.md) — adding rules/stacks as data
