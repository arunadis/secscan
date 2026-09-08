# Contract: Traceability & verification grades (feature 016)

Consumers: report builders, accuracy benchmark, `/speckit-implement` verifier.
Authority: `src/skill_core/schemas/finding.json`, `src/pipeline/verify.py`,
`src/pipeline/generate_report.py`.

## 1. Verification record (`finding.json`)

```json
"verification": {
  "status": "verified" | "plausible" | "disproven",
  "basis": "traced" | "presence",
  "gap": "string (optional)",
  "path": ["node ids (optional)"]
}
```

Rules:

1. `basis` is present whenever `status == "verified"`; `"traced"` asserts a complete
   source-to-sink path was walked, `"presence"` asserts the weakness's code is
   present at the location (secret/config/no-mechanism classes). Older artifacts
   without `basis` remain valid (the field is not added to `required`).
2. `status` vocabulary is unchanged. Nothing downstream keys on `basis` except the
   report summary and benchmark assertions.
3. Demotion (FR-009): while the run's reachability gap is declared, a CWE-306
   finding that would be `verified`/`presence` becomes `plausible` with
   `gap` set to the reachability-gap message; all other presence classes hold.

## 2. Executive summary wording

The summary lead states counts as (shipped wording — note the traced clause keeps
the FR-044 honesty-marker phrase verbatim):

```text
<N> finding(s): <band counts>. <V> verified (<T> statically verified with a complete source-to-sink path; <P> presence-confirmed).
```

(with the traced clause omitted when T == 0 and the presence clause omitted when
P == 0; when V == 0 the FR-041 leads-not-confirmed wording follows instead)

- A sentence claiming a *complete source-to-sink path* may quantify only
  `basis == "traced"` findings.
- When P > 0, the following sentence MUST accompany the count: presence-confirmed
  findings assert the weakness's code is present; reachability from an entry point
  was not traced for them.

## 3. Reachability gap (coverage entry)

Exact trigger: endpoints > 0, security-relevant operations > 0 (annotated
files/symbols or datastore nodes — counted by annotation so a *sink*-recognition
failure still fires), traced flows == 0.
Emission channel: the run's warning collector (stage `segment_analysis`), which
writes the report Coverage section, the scan log, and terminal progress. One entry
per scan, counts interpolated; the message names the unrecognized-convention causes
and tells the reader how to read presence verdicts (see data-model.md template).

Polling rules:

- The gap is computed identically on resume (from the persisted graph and flow
  artifacts), so restored runs declare the same state.
- It appears in `findings/local/*` datasets never; it is a run-level declaration.
