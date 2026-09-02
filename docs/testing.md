# Testing

secscan's detection quality is *asserted*, not eyeballed: fixtures carry declared
ground truth, contract tests pin every schema, and accuracy benchmarks are
release-blocking. This page is the map.

## Running the suite

```bash
uv venv --python 3.11
uv pip install -e ".[dev]"       # editable install into ./.venv
source .venv/bin/activate        # ...or prefix commands with `uv run`

pytest -q                        # full suite (~800 tests); must be green
pytest -q -m slow                # + the large-repository scale scan
ruff check src tests             # line-length 100, py311, rules E/F/I/UP/B
```

Integration tests exercise the install matrix and the full scan lifecycle end to
end, so most behavioral changes are covered there. If the project has one
verification gate before finishing any change, it is the three commands above.

## Suite layout

```
tests/
├── contract/      JSON-schema conformance — every artifact validates against its
│                  shipped schema, every audit adapter against its guarantees
├── integration/   end-to-end scans, the seven-agent install matrix, and
│                  installed-payload subprocess tests (python -m pipeline.scan_cli)
├── benchmark/     accuracy benchmarks asserting per defect class:
│                  core detection, llm-detection, supply-chain-detection,
│                  and external-tooling cross-check behavior
├── fixtures/      seeded-vulnerability repos + a synthetic scale generator
├── helpers/       shared assertions/utilities
└── unit/          per-module unit tests
```

## Ground-truth fixtures

Fixtures under `tests/fixtures/` are **generated with declared ground truth** —
each seeded repository states the vulnerabilities it contains, including a
deliberate false positive (a parameterized query plumbing the same names as the
seeded SQLi) that must *not* be reported. This is what turns "feels accurate" into
"asserts per defect class".

The credential corpus (`credential_corpus.py`) pins the redactor's recall — under
the constitution, no change may reduce detection of a known credential in order to
reduce false positives.

`generate_large_repo.py` builds the synthetic scale fixture used by the `slow`
marker run, which also asserts token budgets against the actual serialized requests
and two-run byte-identical determinism.

## Accuracy benchmarks are release-blocking

The benchmark in `tests/benchmark/test_accuracy_benchmark.py` asserts detection
**per defect class** — a regression in any single class fails the build even if
other classes improve. The same holds for the modern-exploit classes:
`test_llm_detection.py` (prompt injection CWE-1427, sensitive data into model
context, unvalidated model output, over-privileged agent/MCP config) and
`test_supply_chain_detection.py` (dependency confusion CWE-829, mutable references
CWE-494).

`tests/benchmark/MANUAL_REVIEW.md` documents cases that need human judgment rather
than automated assertion.

## What the safety invariants map to

Each constitution-level guarantee has living test coverage:

| Invariant | Where enforced |
|---|---|
| Secrets never reach a model | redaction sweep over every artifact, using the redactor's own rules; credential-corpus recall assertions |
| No attack executed | verification is trace-only; reproduction blocks asserted benign |
| Budgets never exceeded | asserted against serialized requests in the scale scan |
| Byte-identical for identical input | two-run comparison across all artifacts |
| Scanner ignores itself | payload/tool directories excluded from enumeration |
| Read-only against scanned projects | manifest and lockfile hashes compared before and after audit runs |

## Writing tests for a change

The constitution requires test-first: write the failing test, then implement.
Practical pointers:

- Fixture repos declare ground truth — extend the declaration when you seed a new
  vulnerability case.
- Schema changes are additive; contract tests will reject a breaking change without
  a `schema_version` bump.
- A new stack, rule, or control is a **data change** — extend the versioned data
  files (see [Extending the knowledge bases](extending-data.md)); a pipeline-stage
  change for that is the smell, not the solution. `tests/unit/test_data_files.py`
  fails the build if descriptor data drifts from loaded grammars.
