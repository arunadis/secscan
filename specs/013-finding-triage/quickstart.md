# Quickstart: Finding Triage Reasoning Round

**Feature**: `013-finding-triage` | validation guide (no implementation here —
that lives in `tasks.md`)

## Prerequisites

```bash
uv venv --python 3.11
uv pip install -e ".[dev]"
source .venv/bin/activate
```

## Validation scenarios

### 1. Unit fast path — verdict parsing, evidence re-verification, application

```bash
pytest -q tests/unit/test_triage.py tests/unit/test_triage_evidence.py \
         tests/unit/test_triage_apply.py
```

Expected: green. Covers the evidence gates directly: a citation with a pattern not
present at the cited lines rejects the verdict and degrades to flagged; a
credential-class `refuted` verdict is rejected before evidence checking; malformed
answer JSON leaves the finding untriaged.

### 2. Contract — answer schema and declarations file

```bash
pytest -q tests/contract -k triage
```

Expected: `schemas/triage_answer.json` conformance passes for all four verdicts;
the declarations fixture matrix (applied / lapsed / rejected-credential-refute /
reversibility) matches `contracts/report-and-decisions.md` §4.

### 3. Integration — full scan with triage in each execution mode

Scan the triage fixture workspace — materialized as
`tests/fixtures/triage_targets.build_repo(root)` (a segment-protected endpoint
refuted by a security-config control, a fixture credential in test code, a
dev-local token) — in all three modes. From a scratch copy of the fixture:

```bash
# agent-mediated: scan exits 3 mid-triage; answer requests, re-run
python - <<'EOF'
from pathlib import Path
from tests.fixtures.triage_targets import build_repo
member = build_repo(Path("/tmp/triage-ws"))
from tests.integration.conftest import write_config  # test helper
write_config(member)
EOF
secscan run --workdir /tmp/triage-ws/shop --profile full
# → "N analysis request(s) await agent reasoning" including triage-SEC-* ids
# write responses per handoff instructions, then re-run the same command

# endpoint (interactive) and batch: point llm.endpoint at the fixture server
secscan run --workdir /tmp/triage-ws/shop --profile full --policy interactive  # endpoint-configured: provider does the reasoning
secscan run --workdir /tmp/triage-ws/shop  # batch default in endpoint mode
```

Expected outcomes (assert in `tests/integration/test_finding_triage.py`):

- The control-elsewhere finding appears in the report's **suppressions** section
  with ground `triage-control-present` and verified-citation evidence — and NOT in
  the findings bands or headline counts.
- The credential finding is never refuted: it is graded normally or flagged.
- The dev-local-token finding appears in **awaiting verification** with a question,
  and its grading is unchanged in the findings stream.
- A second run over identical input reuses answer files: byte-identical report
  (diff against the first run's artifacts).

### 4. User declaration loop

1. Take the flagged finding from scenario 3; add a matching entry to
   `.secscan/triage/declarations.json` (copy `question` verbatim, set
   `resolution: downgrade`).
2. Re-run the scan.
3. Expected: the flag resolves; the finding carries provenance `user-declared`;
   the declaration text appears nowhere as pipeline-derived evidence.
4. Delete the declaration; re-run. Expected: the flag returns.

### 5. Benchmark gate

```bash
pytest -q tests/benchmark -k triage
```

Expected: the `triage_correctness` class passes — every `expect-refuted` case
refuted with verified citations, every `expect-flagged` case flagged with a
question, every `must-survive` case graded intact (zero true-positive loss,
SC-002). A regression in this class fails the build.

### 6. Baseline spot-check (SC-001 sanity)

Re-scan the baseline repository and compare against the labelled audit
(21 FPs / 16 context-dependent from `20260903T042832Z-c63749`): at least 80% of
the context-disprovable FPs are refuted or flagged automatically; none of the 8
confirmed-real findings is suppressed or downgraded.

## Troubleshooting

- **Scan exits 3 during triage**: answer the `triage-SEC-*` request files in
  `.secscan/handoff/requests/` (see `prompts/triage_finding.md` and
  `contracts/triage-round.md` §4), write responses, re-run.
- **Verdict unexpectedly rejected**: inspect `triage/decisions.json` — the
  `reason` field names the failed gate (malformed, unverified citation, credential
  sweep).
- **Flag did not resolve from a declaration**: `finding_ref` must match on
  repo/file/cwe/symbol AND the question text; a changed question lapses the
  declaration by design.
