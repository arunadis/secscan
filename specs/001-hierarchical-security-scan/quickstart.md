# Quickstart: Validating the Security Scanner End-to-End

Runnable validation scenarios proving the feature works.

**Prerequisites**: Python 3.11+, the scanner installed (`uv pip install -e ".[dev]"`,
which provides the `secscan` and `security-scan` commands), and at least one
supported coding agent (or a terminal for standalone mode). Fixture repositories
with seeded ground truth are generated on demand from `tests/fixtures/`.

**Two command surfaces**

| Command | Purpose |
|---------|---------|
| `secscan` | Distribution-level installer: scaffolds the skill into an agent |
| `security-scan` | Per-project scan command the agent invokes (`init`/`run`/`status`/`report`) |

From an installed skill payload (no global install) the same commands are
available as `python -m pipeline.scan_cli <subcommand>` with
`<skill>/scripts` on `PYTHONPATH`.

## Scenario 0 — Install and initialize (US2)

```bash
secscan agents                        # list supported agents and their paths
secscan init ./demo --ai devin        # or claude | copilot | cursor | windsurf | agents | gemini
cd demo && security-scan status .
```

**Expected**: skill scaffolded into the agent's skills directory with a registered
scan command; `.security-scan/config.yaml` generated and an environment readiness
table printed (`secscan init` runs `init` automatically; pass `--no-init` to skip).
`.security-scan/` is added to `.gitignore`. Re-running the installer performs an
in-place upgrade preserving config and artifacts.

**Validates**: FR-020, FR-021, FR-022, FR-023, FR-024, FR-025. Contract: [cli-contracts.md](contracts/cli-contracts.md).

## Scenario 1 — Single-repo full scan, agent-mediated (US1, zero-config)

```bash
cd tests/fixtures/single-repo-shop   # generated: SQLi, missing authz, hardcoded secret
security-scan run --full --profile full
```

**Expected**: completes without any API key (agent-mediated mode). Every report
finding has a CWE id, CVSS-style severity + band, confidence, file/symbol/line
evidence, attack scenario, and recommendation; the seeded true positives are
identified; a usage/cost summary is included; no analysis invocation exceeded its
context budget.

**Note**: run from a terminal (no host agent), the scanner writes handoff requests
and exits 3 — see Scenario 8. Inside an agent, the agent answers them.

**Validates**: FR-001–FR-008, FR-012–FR-016, FR-018, FR-019, FR-027; SC-001, SC-002, SC-004, SC-009.

## Scenario 2 — Scanner-finding triage (US3)

```bash
cd tests/fixtures/single-repo-shop   # with semgrep + gitleaks on PATH
security-scan run --full --profile full
```

**Expected**: scanner findings ingested with `tool_ref` preserved; each triaged
for exploitability with code evidence; the seeded false positive (a parameterized
query) is marked not-exploitable with the mitigating code cited.

**Validates**: FR-009, FR-012 (tool_ref); [finding-schema.md](contracts/finding-schema.md) rule 6.

## Scenario 3 — Cross-segment + cross-repo correlation (US4, multi-repo)

```bash
cd tests/fixtures/workspace-orders-payments   # manifest declares 2 repos + sync-api
security-scan run --full --profile audit
security-scan report --repo orders            # derived per-repository view
```

**Expected**: unified workspace report; the seeded systemic weakness reported once
with evidence from all affected segments; the seeded cross-repo vulnerability
(identity trusted across a service boundary under mismatched authorization
assumptions) identified with evidence from both repos. Removing the manifest
exercises the auto-discovery path.

**Validates**: FR-001a/b/c, FR-010, FR-014, FR-015, FR-018; SC-003, SC-010.

## Scenario 4 — Resume and incremental rescan (US5)

```bash
security-scan run --full & kill %1            # interrupt mid-scan
security-scan run                              # auto-resumes; completed stages skipped
echo "# change" >> src/orders/repository.py
security-scan run                              # incremental
security-scan run --segment seg-single-repo-shop-orders   # one segment only
```

**Expected**: resume re-executes no completed stage; incremental rescan
re-analyzes only affected segments (plus integration-dependent segments in other
repos) at under 20% of full-scan cost; a single segment can be re-run alone.

**Validates**: FR-016a, FR-017; SC-005, SC-007, SC-008.

## Scenario 5 — Redaction and config validation (safety)

```bash
# fixture contains a live-looking credential; set a conflicting policy:
security-scan run --policy batch-offpeak      # no offpeak_window configured
```

**Expected**: the scan refuses to start, reporting the
`execution_policy.offpeak_window` conflict with expected values. After fixing the
config, the hard-coded credential is reported as a finding (detected
deterministically by the redactor) while its **value** appears nowhere — not in
any context packet, artifact, or report.

**Validates**: FR-006a, FR-026; edge case "redaction uncertainty". Contract: [config-schema.md](contracts/config-schema.md).

## Scenario 6 — Batch/off-peak with fallback (external-endpoint mode)

```bash
export ANTHROPIC_API_KEY=...                  # plus llm.endpoint in config.yaml
security-scan run --full --policy batch-offpeak
```

**Expected**: analysis items submitted as batch jobs within the configured window;
failed or expired items re-executed interactively and recorded; the report states
the execution mode plus batch/interactive share and estimated savings.

**Validates**: FR-007a, FR-016b, FR-019; SC-006. Research: R4.

## Scenario 7 — Verification and reproduction blocks

```bash
security-scan run --full --profile audit
security-scan report --format json | jq '.findings_by_band'
```

**Expected**: every Critical/High finding carries `verified` status (complete
source-to-sink path) or `plausible` with the untraced gap documented; each
reportable finding has an inline Reproduction subsection (preconditions,
benign-canary trigger, expected vs. observed) in **both** the Markdown and JSON
renderings; no `disproven` finding appears anywhere; reproduction triggers contain
no real secrets and are scoped to a local/test deployment.

**Validates**: FR-029, FR-030; SC-011; [finding-schema.md](contracts/finding-schema.md) rules 7–8.

## Scenario 8 — Agent handoff across sessions (FR-027)

```bash
security-scan run --full                       # exits 3: requests written
ls .security-scan/handoff/requests/            # one per pending analysis unit
# the agent writes .security-scan/handoff/responses/<request-id>.json for each
security-scan run                              # consumes answers, continues
security-scan status .                         # shows answered/pending counts
```

**Expected**: the scanner itself calls nothing; each request carries the prompt
(filtered to the segment's domains) plus its bounded context packet within budget.
Answering only some requests still makes progress — the rest are re-requested.

**Validates**: FR-011, FR-027; artifact contract "Agent handoff protocol".

## Scenario 9 — Profiles (quick/full/audit + custom)

```bash
security-scan run --profile quick     # High/Critical only, reduced depth
security-scan run --profile audit     # everything, max depth (re-analyzes deeper)
security-scan run --profile full --set report_thresholds.min_confidence=0.8
```

**Expected**: `quick` completes materially cheaper/faster than `audit` (the usage
summary proves it, and sends less domain guidance per call); switching
shallow→deep re-analyzes at the new depth while reusing valid artifacts; the
report records the active profile and any overrides.

**Validates**: FR-011, FR-028; edge case "switching to a deeper profile".

---

## Automated equivalents

Every scenario above has executable coverage:

| Scenario | Test |
|----------|------|
| 0 | `tests/integration/test_install_matrix.py`, `test_installed_payload.py` |
| 1, 5 | `tests/integration/test_full_scan.py` |
| 7 | `tests/integration/test_verification.py` |
| 8 | `tests/integration/test_agent_handoff.py` |
| 0, 3 (views), 4 (`--segment`), 9 (flags) | `tests/integration/test_scan_cli.py` |
| 9 (prompt filtering) | `tests/unit/test_prompts.py` |

Run everything with `pytest -q` (add `-m slow` for the SC-001 scale scan).
