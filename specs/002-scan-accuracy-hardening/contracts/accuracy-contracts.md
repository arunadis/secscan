# Contract: Accuracy Stages

Behavioural contracts for the five new deterministic stages. Each is a pure function of artifacts
already on disk plus shipped data — no model call, no network, no clock dependence — so identical
input yields byte-identical output.

Stage order is forced by the requirements (research.md A8):

```text
normalize_findings [+ locate]  →  applicability  →  correlate_findings
   →  verify_findings  →  calibrate [+ controls]  →  reproduce  →  consistency  →  generate_report
```

## 1. Tiered location resolution — `pipeline/locate.py`

**Input**: normalized findings, `code-graph.json`, member roots.
**Output**: each finding gains a Resolved Location, or is rejected.

```text
resolve(finding, graph) -> Resolved | Rejected
```

| Case | Result |
|---|---|
| language parsed, symbol named and found | `tier=symbol`; line range overwritten from the node; model's guess discarded |
| language parsed, symbol named, several definitions | `tier=symbol`; deterministic tie-break; `alternatives_existed=true`, `chosen_by` recorded |
| language parsed, no symbol named, file in graph | `tier=file`; line verified within bounds |
| language not parsed, file node present | `tier=file`; `symbol_confirmed=false` even if a symbol was reported |
| file not verifiable at the scanned revision | `Rejected` with reason |
| file was shed to satisfy the token budget | `Rejected` — the location could not be confirmed |

**Tie-break (FR-004)**: prefer a definition in the finding's own repository; then the same file as the
finding's reported path; then the lexicographically smallest node id. Deterministic and recorded.

**Guarantees**
- Runs **before** deduplication, so line-number-only differences collapse (FR-007).
- Never emits a finding stating that its location could not be matched (FR-003b) — `file` tier is a
  positive result.
- Language coverage is never a precondition for reporting (FR-003, SC-001a).

## 2. Applicability — `pipeline/architecture.py` + `pipeline/applicability.py`

**Input**: findings, architecture profiles, `code-graph.json` (`cross_repo` edges), `workspace.json`
(typed integration points), `skill_core/data/applicability.json`.
**Output**: an Applicability Conclusion per finding; a Reclassification Record where remapped.

```text
classify(member|segment) -> ArchitectureProfile      # deterministic, offline (FR-013)
reachable_shapes(finding, graph, workspace) -> set   # graph traversal, no LLM (FR-015b)
evaluate(finding, shapes, relation) -> Conclusion
remap(finding, conclusion, relation) -> Reclassification | None
```

**Reachability**: directed traversal from the finding's location across `cross_repo` edges and all
four declared integration classes — sync API, async messaging, shared datastore, identity
propagation. Direction is respected: a sibling that calls *in* does not lend its architecture to this
location (Edge Cases).

**Remap gate — the only path to suppression**

| Conclusion | Action |
|---|---|
| `applicable: true` | retain as classified; record `enabling_member` |
| `applicable: undetermined` | retain; record reason (FR-015c) |
| architecture `undetermined` | retain; applicability disabled for that scope (FR-013a) |
| `applicable: false` | remap to the relation's defensible class, recompute severity, record everything (FR-016) |
| operator explicitly requested the class | retain; record the applicability doubt (FR-019) |

**Guarantees**
- Never suppresses on an unknown of any kind — unknown architecture, unknown reachability, or an
  unresolved far side all retain the finding. Suppression requires positive structural disproof.
- Records the remap even when the result falls below the profile threshold (FR-017).
- Runs **before** correlation, so a remap that creates a duplicate is deduplicated (FR-018).

## 3. Framework controls — `pipeline/controls.py`

**Input**: finding, `verification.path`, `code-graph.json` (`parsed`, `framework_control`,
`control_bypass` annotations), `skill_core/data/framework_controls.json`.
**Output**: a Framework Control Evaluation.

```text
evaluate(finding, path, graph, catalogue) -> Evaluation
```

| Condition | `state` |
|---|---|
| control covers this weakness class, on the path, no bypass on the path, every path file parsed | `credited` |
| a bypass sits on the traced path to this sink | `bypassed` (+ `bypass_site`) |
| framework recognized, no such default control exists | `absent` |
| framework unrecognized, **or** any file on the path unparsed | `unassessed` (+ reason) |

**Guarantees**
- `credited` ⇒ full parse coverage of the path (FR-022a). Partial knowledge is never full knowledge.
- `unassessed` neither credits nor inflates; it caps confidence and emits a named coverage gap
  (FR-022c).
- A bypass off the path leaves this finding's state untouched and becomes its own hygiene finding
  (FR-022b).
- `absent` is a determined state — no coverage gap (Edge Cases).
- Escape-by-default is **per framework and configuration**: Jinja2 and JSP are not
  escape-by-default (research.md A1), so presence of a framework never implies a control.

## 4. Calibration — `pipeline/calibrate.py`

**Input**: finding, `verification`, Framework Control Evaluation.
**Output**: a Calibration Record; published severity and confidence.

```text
calibrate(finding, verdict, control) -> (severity, confidence, Record)
```

Caps, each recorded with its rule and reason:

| Trigger | Cap |
|---|---|
| `plausible` with reachability unconfirmed | severity and confidence capped so it cannot outrank any `verified` finding (FR-020) |
| control `credited` | severity reduced to the residual impact the control still permits; narrative reframed (FR-023) |
| control `unassessed` | confidence capped; severity **not** inflated (FR-022c) |
| reclassified | severity recomputed from the new class before any cap applies (FR-016) |

**Guarantees**
- Ordering: reclassification → verification → control evaluation → caps. Each stage reads only
  already-settled state.
- Post-condition asserted in tests: `max(severity of plausible-unconfirmed) < min(severity of
  verified)` within a scan, or the cap failed.
- `severity_band` is recomputed from the published score (rule 9 in `schema-deltas.md`).

## 5. Reproduction — `pipeline/reproduce.py` (modified)

**Input**: finding, `verification`, sink value-construction shape.
**Output**: a reproduction block in `observed` or `hypothesis` mode.

```text
probe_feasible(cwe, sink_shape) -> Probe | None
build(finding, verdict, probe) -> Block
```

**Sink shape** describes how the untrusted value enters the dangerous operation — in particular
whether it is interpolated **after a fixed prefix** the attacker does not control. A probe whose
success criterion requires controlling that prefix is infeasible.

The benchmark's failing case, now handled: a probe of `http://127.0.0.1:9/<canary>` for a
request-forgery finding whose URL is `${baseUrl}/user/${id}` is rejected, because scheme and host are
fixed by the prefix and no request to a local port can result.

| Verdict | `mode` | Contents |
|---|---|---|
| `verified` | `observed` | full block; `observed_behavior` permitted |
| anything else | `hypothesis` | `outcome_to_check`; states plainly that the scanner did not observe it |
| no feasible probe | either | `trigger` omitted; `trigger_omitted_reason` present |

**Guarantees**
- Never asserts an observation the pipeline did not make (FR-008).
- `traced_trail` contains only nodes from `verification.path`; omitted when no path was traced.
  Supporting evidence stays under `evidence` and is never rendered with dataflow arrows (FR-005/FR-006).
- Existing safety constraints unchanged: benign canaries, no real credentials, `local/test` scope, no
  attack execution (FR-012).

## 6. Consistency gate — `pipeline/consistency.py`

**Input**: the assembled report document, pre-write.
**Output**: pass, or a list of contradictions with the offending part withheld or regenerated.

```text
check(report) -> [Contradiction]
```

Checks:
1. Every internal cross-reference names a section present in this report; every severity pointer is
   derived from the finding's own published band (FR-040).
2. No finding narrative asserts an impact its Framework Control Evaluation says is prevented (FR-023).
3. No reproduction block depends on a precondition the finding's own impact text says is absent — the
   benchmark's self-contradiction (FR-011).
4. `mode = observed` only alongside `verified` (FR-008).
5. When no finding was verified end to end, the executive summary states how to read the report
   (FR-041).

**Guarantee**: a contradiction blocks the write (FR-042). This is a gate, not a warning — the whole
point is that a self-inconsistent report never reaches a reader.

## 7. Host ownership — `pipeline/hosts.py`

**Input**: hard-coded hosts extracted from the code model, `workspace.json` (members and declared
integration points).
**Output**: an ownership verdict per host, consumed when minting the third-party trust finding.

```text
classify(host, workspace) -> "internal" | "external" | "undetermined"
```

| Condition | Verdict |
|---|---|
| host matches a workspace member, or a declared integration point's far side | `internal` |
| host matches none of them and the workspace model is complete | `external` |
| ownership cannot be determined from the workspace model | `undetermined` |

**Guarantees**
- `internal` raises **no** third-party trust finding (FR-024a) — this is what stops every microservice
  that calls its sibling from being flagged.
- Ownership is derived from the workspace model alone. No new operator configuration is introduced
  (FR-024a).
- `undetermined` is reported as **external** with ownership stated as undetermined, so an unowned host
  is never silently exempted (FR-024b). Note the asymmetry with the applicability relation: there,
  an unknown retains the finding by *not suppressing*; here, an unknown retains the finding by
  *defaulting to external*. Both directions preserve the same rule — an unknown never buys silence.
- Where a target's only data source is an `external` host, the trust boundary is minted as a finding
  in its own right rather than as a note on another weakness class (FR-024).

## Shipped data contracts

All four files live in `skill_core/data/`, carry `version` and `dataset_date`, are sorted for
determinism, and are loaded read-only. Adding a stack, control, or rule is a **data** change and must
require no pipeline change (FR-013c, FR-022d, FR-025b).

| File | Keyed by | Contents |
|---|---|---|
| `applicability.json` | weakness class | architectures where structurally possible; defensible alternative class; rationale |
| `framework_controls.json` | framework | default controls, weakness classes mitigated, sink syntaxes, bypass syntaxes, whether escape-by-default |
| `stacks.json` | language | template forms, file suffixes, primary package ecosystem, audit adapter id |
| `eol.json` | product | version → support dates, plus manifest-identifier → product-id mapping |

**Staleness**: `eol.json` reports a warning when `dataset_date` exceeds the configured threshold
(default 90 days). Staleness is itself reportable — the report never presents stale support data as
current (spec Assumptions).
