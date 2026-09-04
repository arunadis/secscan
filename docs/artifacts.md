# Artifacts

Every pipeline stage writes a durable artifact under `.secscan/` in the scanned
project. This is what makes scans resumable, reports re-renderable, and findings
auditable: identical input plus identical tool version yields byte-identical files
(canonical JSON — sorted keys, trailing newline).

`.secscan/` is gitignored by default on `secscan init`; opt in to sharing scan
history with `--commit-artifacts`.

## Layout

```
.secscan/
├── config.yaml                 project configuration (human-editable; see Configuration)
├── workspace.json              members + typed integration points
├── repository/<repo>.manifest.json   languages, frameworks, modules, entry points
├── code-graph.json             nodes/edges, stable ids, security annotations
├── segments/<id>.json          security-boundary segments
├── context-packets/<id>-l<level>.json   post-redaction, budgeted packets
├── handoff/
│   ├── requests/<request-id>.json      prompt + bounded packet (agent mode)
│   └── responses/<request-id>.json     agent's schema-conforming answers
├── analysis/answers/<request-id>.json  persisted model answers (endpoint mode) — resumption
│                                       state, not an artifact: safe to delete, forces re-analysis
├── findings/
│   ├── local/                  per-stage raw findings
│   ├── correlated/             deduplicated, related, grouped
│   └── triaged.json            post-triage finding set + triage suppressions + summary
├── triage/
│   ├── packets/<id>.json       per-finding triage packets (redacted, budgeted)
│   ├── decisions.json          every attempted verdict: applied/rejected/degraded/…
│   └── declarations.json       YOUR file: recorded answers to flagged findings
│                               (input, not artifact — see Configuration)
├── system-review.md            cross-boundary review narrative
├── reports/<scan-id>.{md,json,html}    one data set, three renderings
├── state.json                  checkpoints, file hashes (resume + change detection),
│                               and meta.analysis_batches — the provider batch ledger
├── usage.json                  tokens per stage/tier, savings vs baseline
└── scan.log                    progress trace of the latest run (diagnostic, NOT an artifact)
```

## How artifacts are used

- **Resume.** `state.json` records checkpoints keyed per stage; `secscan run`
  walks the stage order and skips stages whose resume key still matches. File
  hashes drive change detection. `--full` ignores checkpoints.
- **Re-rendering.** `secscan report [--format markdown|json|html] [--repo name]`
  re-rendered from artifacts costs nothing — no LLM calls, no rescanning. Raising a
  report threshold later never requires a new scan.
- **Auditability.** A finding in the report traces back through
  `findings/correlated/` to its local evidence and the context packets the model
  actually saw. A trail rendered with dataflow arrows contains only traced edges.
- **Cost accounting.** `usage.json` records tokens per stage and model tier, the
  batch/interactive split with an estimated saving (50% × batch token share,
  labelled as assuming the provider's published batch discount), and the measured
  savings against a maximal-context baseline.
- **Finding triage.** On `full`/`audit` profiles the correlated findings go through
  one more reasoning round (`finding_triage`): the reasoner confirms, downgrades,
  refutes-with-citations, or flags each candidate. Verdicts that refute or regrade
  apply only after the pipeline mechanically re-verifies every citation against
  the repository; triage-verified suppressions appear in the report's suppression
  list (ground `triage-control-present`) and flagged findings render in the
  report's Awaiting Verification section. Persisted triage answers follow the same
  content-addressed reuse rule as analysis answers, so a re-run replays outcomes
  byte-identically.
- **Answers and the batch ledger (endpoint mode).** `analysis/answers/<request-id>.json`
  holds exactly `{request_id, answer_key, content}` for every model answer, whether it
  arrived by batch, by fallback, or live. The key is derived from the serialized
  request and the model tier, so an answer is reused only for a byte-identical request
  — and the file is identical whichever policy produced it (it is *inside* the
  determinism comparison and the redaction sweep). `state.json → meta.analysis_batches`
  records each submitted batch (provider handle, items with their keys, submission and
  expiry times, status); it is what lets an interrupted wait resume the same batch. Both
  are cleared by `--full`.

## Schema versioning

Artifact and finding schemas are **additive by default**: new optional fields may
be added within a version. A breaking change requires a `schema_version` bump in
`src/pipeline/schemas.py` and a documented upgrade path. `secscan version` prints
the tool version alongside the artifact and config schema versions, and
`secscan init` reports when an upgrade changes the config schema.

Contract tests (`tests/contract/`) validate every artifact against its shipped JSON
schema, so conformance is enforced in CI rather than assumed.

## Honest gaps on disk

Where the pipeline could not decide or could not cover, the artifact says so
instead of going quiet: blocked values and budget-dropped files are recorded with
cause, criticality, and impact; unaudited dependency domains are recorded as
`could-not-check`, never clean. See
[Security model — honest uncertainty](security-model.md#honest-uncertainty).

## The scan log

`scan.log` is the plain-text progress trace of the most recent `secscan run`:
every stage, segment, tool, warning, heartbeat and terminal event at verbose
detail, one line each with wall-clock and elapsed time, regardless of the
terminal output level. It is written incrementally and overwritten by each run,
so after a failed, interrupted or paused scan its last line names the stage (and
segment or tool) that was in progress.

It is a **diagnostic side file, not a scan artifact**: it has no JSON envelope or
schema, carries timing that legitimately differs between runs, and is excluded
from the byte-identical determinism comparison. It obeys the same content rule as
everything else under `.secscan/` — identifiers, paths, counts, durations and
report wording only — and is included in the credential redaction sweep.

## What never lands in an artifact

Credential values. The redactor runs before context packets are built, an
artifact-wide redaction sweep catches the rest, and config validation rejects key
values under `llm.endpoint` before scanning begins. Only environment-variable
*names* are ever stored.

Every value the redactor deliberately left visible is recorded under
`context-packets/*.json → redaction.exempted_items` with `origin`, `line`, `rule`,
`classification`, `reason`, and a `decision` of `exempt-identifier` (a declared
name), `exempt-message` (a prose literal) or `exempt-reference` (a runtime
reference such as `"$VAR"`, classified `runtime-reference:<family>`). Values are
omitted from the record. Location tokens protected in reproduction prose
(`exempt-location`) are an in-process decision and are not serialised.
