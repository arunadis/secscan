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
├── findings/
│   ├── local/                  per-stage raw findings
│   └── correlated/             deduplicated, related, grouped
├── system-review.md            cross-boundary review narrative
├── reports/<scan-id>.{md,json,html}    one data set, three renderings
├── state.json                  checkpoints, file hashes (resume + change detection)
└── usage.json                  tokens per stage/tier, savings vs baseline
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
- **Cost accounting.** `usage.json` records tokens per stage and model tier, and
  the measured savings against a maximal-context baseline.

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

## What never lands in an artifact

Credential values. The redactor runs before context packets are built, an
artifact-wide redaction sweep catches the rest, and config validation rejects key
values under `llm.endpoint` before scanning begins. Only environment-variable
*names* are ever stored.
