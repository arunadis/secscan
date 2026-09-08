# Contract: Resume key composition (feature 017)

## Rule

A stage resume key MAY cover file-content identity only when the stage's output
depends ONLY on file contents. Extraction-affecting inputs are part of the key.

| Stage | Inputs in the key |
|---|---|
| `discover_repo` | members, root (unchanged) |
| `build_code_graph` | file hashes + `TOOL_VERSION` + recognizer versions (`EXTRACTOR_VERSION`, identity pack, redactor rules, CWE dataset) |
| `partition_repo` | graph content hash + budget (unchanged — inherits rebuild) |
| downstream analysis stages | existing resume identities; re-key automatically when graph content hash changes |

## Policy

- An upgrade that changes no recognition rule is a no-op (no re-keying storm).
- An upgrade that changes any recognizer version must intend invalidation; the
  version bump is a deliberate, visible change (`EXTRACTOR_VERSION` constant in
  `src/pipeline/state.py` next to `TOOL_VERSION`, with a comment tying it to
  "release notes: invalidates graphs").
- In-place artifacts remain on disk for inspection after invalidation (never
  deleted).
