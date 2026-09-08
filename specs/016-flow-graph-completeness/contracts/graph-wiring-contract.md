# Contract: Graph wiring & guard visibility (feature 016)

Consumers: partition_repo, build_context, verify, triage, business_flow.
Authority: `src/skill_core/schemas/code_graph.json`,
`src/pipeline/extract/enrichers.py`, `src/pipeline/build_code_graph.py`.

## 1. Wiring facts (extraction → graph)

`FileFacts.wiring[]` (additive) items: `target` (registered identifier), `route`
(null = module/application scope), `line`.

Recognizer scope (documented; anything outside is *undetermined*, never guessed —
FR-010):

- `router.use(x)` / `app.use(x)` / `app.use("/prefix", x)` — JS/TS (Express-like)
- middleware arguments in route registrations `router.METHOD("/p", mw…, handler)`
- `app.before_request(fn)` / `bp.before_app_request(fn)` — Python (Flask)
- `app.middlewares.append(fn)` — Python (aiohttp)
- `r.Use(mw)` / `e.Use(mw)` — Go (Gin/Echo)

Only whole-argument bare identifiers produce facts.

## 2. Resolutions (graph)

Second pass after all files are parsed (template-binding precedent):

- the wiring file gains a `calls` edge to each in-repo symbol named `target`
- each scoped endpoint node gains a `handler` edge to the same targets:
  file-scoped `use(…)` → every endpoint registered in that file; route-scoped → the
  matching route only
- unresolved names produce **no edge** and, when the name matches the guard
  catalogue (identity_archetype_rules.json `guard_names`), feed the
  `unattached_security_guard` annotation check on the defining symbol — **and in
  every case they are recorded** (see §6).

## 6. Unresolved wiring record (FR-010)

Wiring facts whose `target` resolves to no in-repo symbol MUST NOT silently
vanish. The graph document gains an additive top-level array:

```json
"unresolved_wiring": [
  {"file": "backend/src/routes/clients.js", "line": 9, "name": "mw_var",
   "reason": "no in-repo symbol with this name"}
]
```

- Sorted by (file, line, name); empty array MUST be present when none (the absence
  of the key would be ambiguous between "old artifact" and "nothing unresolved").
- Present in the artifact even when zero so resume and single-stage replays
  recompute consensus-free.
- Every entry carries an explicit reason; consumers must not infer that attached
  wiring existed from an entry's silence.
- Code-graph schema: additive `unresolved_wiring` property (array of objects with
  required file/line/name/reason); no schema_version bump.

## 3. Annotation enum (additive)

`annotations` gains `"unattached_security_guard"`. Attached for function symbols
matching the guard-name catalogue with no inbound edge from production code; test
paths (`__tests__`, `/tests?/`, `.test.`, `.spec.`, `_test.`) and self-containment
are excluded as referrers.

Consumers: `partition_repo.DOMAIN_BY_ANNOTATION` maps it to `authentication`,
`authorization`; `triage.CONTROL_ANNOTATIONS` admits it as candidate-control seed;
role digest lines name it.

## 4. Source channels

`user_controlled_input` recognition additionally covers header/cookie idioms
(research R2 list). The annotation value is unchanged.

## 5. Guard inconsistency (FR-016)

Digests in the packet's `call_graph_summary`: per route-bearing file in the segment,
`guards: [names]` or `guards: none recorded`. No finding is emitted for absence
(clarify Q4).

The same matrix is derived a second time, deterministically from the graph, at
system-review time and appended to `_system_review_narrative` as a "Guard
attachment" section (per route-bearing module: attached guard names, or `none`),
so the inconsistency reaches the review directly — segment packets are never the
review's input. Precedent: feature 015's `flow_coverage` feeds the report the same
way (structured evidence, never prose).
