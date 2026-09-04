# secscan

Hierarchical, context-bounded security scanning for large codebases — installable
as a skill into your coding agent.

Scanning a big repository with an LLM fails for a simple reason: the codebase does
not fit in the context window. secscan treats **context as a managed resource**.
Deterministic tooling builds a model of the repository and collects evidence; the
LLM reasons over small, semantically meaningful slices; findings are correlated and
aggregated from structured evidence rather than by re-reading the source.

> Don't make the LLM the repository analyzer. Make the LLM the reasoning engine
> sitting on top of a deterministic repository model.

**Status: in development.** The core pipeline and installer work end to end, the
accuracy-hardening work is complete through its polish phase, external-scanner
tooling (provision, run, cross-check) is built per spec 008, endpoint
scheduling (provider batch, off-peak windows) is built per feature 012, the
post-correlation finding-triage round is built per feature 013, and report
accuracy hardening (dependency usage evidence, template-control credit,
currency merge, dangling-reference quarantine) is built per feature 014 — see
[Roadmap](#roadmap). Multi-repo workspaces scan end to end today: cross-repo
graph edges, cross-member applicability, and a workspace-wide cross-boundary
review are built and tested; the still-open cross-repo items are
undeclared-integration inference, the richer correlation relationships, and
selective incremental rescan (see [Roadmap](#roadmap)).

---

## Why it's different

| | Typical LLM scanner | secscan |
|---|---|---|
| Splitting | Chunks by token count | Segments by **security/business boundary** |
| Context | As much code as fits | Smallest useful slice, expanded only on demand |
| Secrets | Sent to the model | **Redacted before any model call**, deterministically |
| Output | Prose report | Schema-validated findings; free-form output is rejected |
| Evidence | "The model said so" | Traced source→sink path per finding |
| Repeatability | Varies per run | Durable artifacts, resumable, byte-identical for identical input |
| Cost | Every call maximal | Evidence escalation — **7.3x fewer tokens** than a maximal-context baseline (measured, reference fixture, `audit` profile) |

Every finding carries a CWE id, a CVSS-style score, a confidence value, file/symbol/line
evidence, a verification verdict, and **reproduction steps** a developer can follow.

## Quick start

Requires Python 3.11+.

```bash
# install `secscan` onto your PATH
uv tool install .                    # or: pipx install .

# scaffold the skill into your agent, generate config, check the environment
secscan agents                       # see what's supported
secscan init /path/to/your/project --ai claude

# scan
cd /path/to/your/project
secscan run --full             # progress on stderr; add -q for summary only
secscan report                 # re-render from artifacts
```

> **`command not found: secscan`?** `uv pip install -e .` installs into the
> project's `.venv` **without** putting it on your PATH. Either use
> `uv tool install .` as above, or activate the venv first
> (`source .venv/bin/activate`), or prefix commands with `uv run`.

> **Upgrading from a source checkout?** `uv tool install . --force` reuses the
> cached wheel because the version number has not changed, so you keep running the
> old code. Use `uv tool install . --force --reinstall --no-cache`, or
> `uv tool install --editable . --force` for development. See
> [Getting started → Upgrading](docs/getting-started.md#upgrading-a-source-install).

**No API key is required.** By default the coding agent running the skill does the
reasoning with its own model. Configuring an external endpoint is optional and
switches analysis to the provider's batch API (rate-limit-proof, provider batch
pricing), with off-peak scheduling and per-level model tiers available on top.

### Supported agents

`claude` · `copilot` · `cursor` · `windsurf` · `devin` · `agents` (cross-vendor) · `gemini`

Each gets a thin adapter over one agent-agnostic core skill; Gemini's flat TOML
command format is translated automatically. Adding an agent means adding an
adapter — the core never changes.

## Documentation

The docs live in [`docs/`](docs/); start at the [documentation hub](docs/index.md).

| Page | Contents |
|------|----------|
| [Getting started](docs/getting-started.md) | Install, scaffold, first scan |
| [Architecture](docs/architecture.md) | Pipeline stages, design principles, module map |
| [Configuration](docs/configuration.md) | `config.yaml` reference, LLM modes, endpoint setup, budgets |
| [CLI reference](docs/cli-reference.md) | Every command, flag, and exit code |
| [Scan profiles](docs/scan-profiles.md) | `quick` / `full` / `audit`, custom profiles, per-scan overrides |
| [Agent integration](docs/agent-integration.md) | Handoff protocol, cross-session resume, adding an agent |
| [Security model](docs/security-model.md) | Redaction, offline/read-only guarantees, honest uncertainty |
| [Artifacts](docs/artifacts.md) | `.secscan/` layout, schema versioning, resume |
| [Testing](docs/testing.md) | Suite layout, ground-truth fixtures, accuracy benchmarks |
| [Extending the knowledge bases](docs/extending-data.md) | Adding stacks, rules, and controls as data |

## How it works

```
repository/workspace
        │  deterministic (no LLM)
        ▼
1. discover      manifest: languages, frameworks, modules, entry points, data stores
2. code graph    tree-sitter → symbols, calls, routes, DB access, trust annotations
3. partition     segments along security boundaries — never by line count
4. context       bounded packets, secrets redacted, token budget enforced
        │  bounded LLM reasoning
        ▼
5. analyze       per segment, only the relevant vulnerability domains
        │  deterministic again
        ▼
6. normalize     schema enforcement + CWE/OWASP mapping
7. verify        static source→sink trace: verified / plausible / disproven
8. reproduce     benign-canary reproduction steps, local/test scope
9. correlate     dedupe, relate, group systemic issues
10. report       unified report (Markdown + JSON + navigable HTML with redacted
                 code excerpts per finding) + usage/cost summary
```

Each stage writes a durable artifact under `.secscan/`, so any stage can be
re-run in isolation and an interrupted scan resumes where it stopped.

### Evidence escalation

Analysis starts with the smallest useful context and grows only when the evidence
is genuinely insufficient:

| Level | Context |
|-------|---------|
| 1 | security-relevant symbols only |
| 2 | + calling/called code in the segment |
| 3 | + the full segment and its data flows |
| 4 | + cross-segment context |

Keeping most invocations at level 1 is where the token savings come from. The
scan profile caps the ceiling.

### Agent-mediated execution

The scanner never calls a model itself in the default mode. When reasoning is
needed it writes requests and stops with exit code 3:

```bash
secscan run --full
# → 6 analysis request(s) await agent reasoning
#   .secscan/handoff/requests/<request-id>.json   (prompt + bounded packet)
#   answer into .secscan/handoff/responses/<request-id>.json, then re-run
```

Because the exchange is files, one scan can span **multiple agent sessions** —
answer what you can, re-run, repeat. Partial answers keep prior work.

### Report integrity (exit code 4)

If a report's narrative sections (system review, attack paths, …) reference a
finding identifier that is not part of the report, the offending section is
quarantined: the report still publishes — all findings intact — with the omission
declared in a *Report Integrity* section, and the scan exits with code 4.
Dependency findings also carry a **usage** state (found / none-found /
undetermined) so an advisory never narrates exploitation for a package nothing
imports, and misconfiguration findings carry an **integration** state so stale
rules-config (e.g. backend access rules for a service nothing integrates) reads
as removal work, not as a live attack surface.

## Configuration

One human-editable file, `.secscan/config.yaml`, strictly validated before
any scan work begins (all problems reported at once, conflicting settings rejected).

```yaml
version: 1

llm:
  mode: auto                      # auto | endpoint | agent
  # endpoint:                     # omit to use the host agent's own model
  #   provider: anthropic
  #   api_key_env: ANTHROPIC_API_KEY   # variable NAME only — never the secret

execution_policy:
  mode: auto                      # auto | interactive | batch | batch-offpeak
  # offpeak_window: "02:00-06:00"

budgets:
  max_context_tokens: 12000
  max_output_tokens: 3000
  escalation_threshold: 0.75

scanners:
  semgrep: { enabled: auto }      # auto = run when detected

tooling:                          # external security tools (spec 008)
  install: ask                    # never | ask | all — consent default for init
  timeout_s: 120                  # per-tool wall-clock ceiling during analysis
```

### Execution modes

`llm.mode` chooses **who does the reasoning** — every scan runs in exactly one of
three modes:

| Mode | Who analyzes | Needs a key | Endpoint-only cost features |
|------|--------------|-------------|------------------------------|
| `agent` | The coding agent running the skill, with its own model | No | Unavailable (declared at init) |
| `endpoint` | A provider endpoint you configure | Yes (`api_key_env`) | Provider batch API (the default; providers publish a 50% discount for it), off-peak window scheduling, per-level model tiers |
| `auto` (default) | Endpoint when one is configured, otherwise the agent | Only with an endpoint | As above when an endpoint is configured |

Explicit configuration always wins: setting `llm.endpoint` switches analysis to it even
in `auto`, and `llm.mode: agent` forces agent-mediated reasoning even with an endpoint
present. Agent-mediated mode makes no analysis call leave your machine — prompts and
bounded context packets become handoff files the agent answers (see
[Agent-mediated execution](#agent-mediated-execution)).

#### Configuring an endpoint

`provider` selects the wire protocol and **must match the key you supply**:

| `provider` | Sends to | Auth header | Use for |
|------------|----------|-------------|---------|
| `anthropic` (default) | `{base_url}/v1/messages` (default `https://api.anthropic.com`) | `x-api-key` | Anthropic keys |
| `openai-compatible` | `{base_url}/chat/completions` (default `https://api.openai.com/v1`) | `Authorization: Bearer` | OpenAI keys and any Chat-Completions gateway (Azure OpenAI, OpenRouter, LiteLLM, vLLM, internal proxies) |

```yaml
# Anthropic
llm:
  mode: endpoint
  endpoint:
    provider: anthropic
    api_key_env: ANTHROPIC_API_KEY  # variable NAME — the key itself is never in this file
    model_map:                      # optional per-analysis-level model tiers
      local: claude-haiku-latest    # cheap tier: per-symbol/secret checks
      segment: claude-sonnet-latest # segment analysis (fallback tier for the others)
      system: claude-opus-latest    # cross-boundary system review
```

```yaml
# OpenAI, or any OpenAI-compatible gateway
llm:
  mode: endpoint
  endpoint:
    provider: openai-compatible     # an OpenAI key under provider: anthropic => HTTP 401
    api_key_env: OPENAI_API_KEY
    # base_url: https://your-gateway/v1   # only for gateways; defaults to api.openai.com
    model_map:
      segment: gpt-4o
```

- `api_key_env` is required whenever `endpoint` is present; if the variable is unset at
  scan time the scan stops before any analysis with a clear message. Storing a key
  value anywhere under `llm.endpoint` is rejected by validation outright, and the value
  is never logged or written to an artifact.
- `model_map.segment` is the fallback tier: `local` and `system` default to it.
- Getting `HTTP Error 401`? The message names the provider and URL that was called —
  almost always the provider does not match the key, or the variable is not exported in
  the shell running `secscan`. Full checklist in
  [Configuration → Troubleshooting](docs/configuration.md#troubleshooting-http-error-401).

#### Endpoint scheduling: batch (default) vs interactive

With an endpoint configured, analysis is submitted through the provider's **batch
API by default**: each escalation round becomes one submission instead of one live
request per segment, which removes the per-minute rate-limit failure mode on large
repositories and is billed at the providers' published 50% batch discount.

```yaml
execution_policy:
  mode: auto                        # auto | interactive | batch | batch-offpeak
  # offpeak_window: "02:00-06:00"   # REQUIRED when mode is batch-offpeak
  batch:
    fallback: interactive           # items the batch cannot answer are re-run live
    window_hours: 24                # batch expiry, measured from submission
```

The scan waits in the foreground and prints `processing c/N` status lines; Ctrl-C is
safe — the batch reference is persisted before waiting and the next run resumes the
same batch. Every answer is stored under `.secscan/analysis/answers/` and reused only
when the request is byte-identical, so nothing is paid for twice. Failed, expired, or
missing items fall back to live requests (with retries on 429/5xx) and are listed in
the report with their reasons. Configurations written before this default contain an
explicit `mode: interactive` and keep that behaviour; `--policy` on `secscan run`
overrides the policy for one scan, and any machine-specific value can come from an env
override in the `SECSCAN_<SECTION>_<KEY>` form (e.g. `SECSCAN_LLM_MODE`,
`SECSCAN_EXECUTION_POLICY_MODE`). Details: [Configuration → Endpoint
scheduling](docs/configuration.md#endpoint-scheduling-batch-default-vs-interactive).

`secscan init` also accepts `--install[=all|tool,tool]`, `--yes`, and
`--no-input`; nothing installs before the exact list is presented and confirmed.

**NVD API key** (spec 009): OWASP Dependency-Check downloads its data from the
National Vulnerability Database, which is heavily rate-limited without an API
key — the first sync can take many times longer. Set `NVD_API_KEY` in your
shell (request one at <https://nvd.nist.gov/developers/request-an-api-key>);
init detects it by variable name only — the value is never prompted for,
stored, or printed. When the key is absent, init reports the tool as
`awaiting-key` / `degraded-no-key` / `skipped-no-key` and, in interactive runs,
offers to skip or proceed anyway. Non-interactive runs skip the tool unless
`--allow-keyless-nvd` is passed explicitly; blanket consent (`--yes`,
`--install=all`) never silently installs it keyless.

Secrets are **never** stored in config — only the name of an environment variable.
Machine-specific values can be overridden with `SECSCAN_<SECTION>_<KEY>`.

### Scan profiles

Profiles control both reporting thresholds **and** analysis depth, so `quick` is
genuinely cheaper rather than just quieter.

| Profile | Reports | Depth |
|---------|---------|-------|
| `quick` | High/Critical only | 4 domains, escalation ≤ 2, no system review |
| `full` (default) | Medium+ with confidence ≥ 0.5 | all domains, escalation ≤ 3 |
| `audit` | everything | all domains, escalation ≤ 4 |

Define your own in `profiles:` (optionally `base:` an existing one), and override
any setting per scan with `--set key=value`.

## Commands

One command, **`secscan`**, covers both setup and scanning:

| Command | Purpose |
|---------|---------|
| `secscan init <dir> [--ai <agent>]` | Scaffold the skill into an agent and/or generate config + check the environment; re-run to upgrade in place |
| `secscan agents` | List supported agents and their skill paths |
| `secscan status <dir>` | Installed skills, stage state, handoff progress, latest report |
| `secscan run [--profile] [--policy] [--set k=v] [--segment id] [--full] [--output quiet\|default\|verbose]` | Run a scan; progress on stderr, summary on stdout |
| `secscan report [--repo name] [--format markdown\|json\|html]` | Re-render from artifacts |
| `secscan data [--refresh-eol]` | Knowledge-base versions and dataset staleness |
| `secscan version` | Tool and schema versions |

Exit codes: `0` ok · `1` error · `2` not ready · `3` agent handoff pending ·
`4` report published with quarantined narrative section(s) · `130` interrupted.

A running scan prints each stage, segment (`i/N`), external tool and coverage note
to stderr as it happens, with a heartbeat during long steps; `-q` silences it, `-v`
adds budget and tool detail, and `.secscan/scan.log` always keeps the full trace.

From an installed skill payload the same surface is
`python -m pipeline.scan_cli <subcommand>` with `<skill>/scripts` on `PYTHONPATH`
— no global install needed.

## Safety properties

These are enforced by tests, not just intent:

- **Secrets never reach a model.** A deterministic layered redactor (rule packs +
  entropy + custom patterns) runs before any context packet is built. Content it
  cannot confidently classify is *blocked*, not passed through. Because the
  redactor must locate every credential anyway, it doubles as the authoritative
  hard-coded-secret detector — so secrets are still *reported* while their values
  appear nowhere. Environment-variable references (`"$VAR"`, `"${VAR}"`, `"%VAR%"`,
  template and CI expressions) are recognised as runtime wiring and never reported
  as hard-coded credentials.
- **No attacks are executed.** Verification is static: a traced source-to-sink
  path decides `verified` / `plausible` / `disproven`.
- **Reproduction steps are benign.** Triggers use non-destructive canary values,
  contain no real credentials, and target a local/test deployment only.
- **Budgets are never exceeded.** Enforced against the *actual serialized request*,
  not an estimate. Oversized segments are subdivided; files are dropped whole and
  reported, never silently truncated.
- **The scanner ignores itself.** Installed skill payloads and tooling directories
  are excluded from scanning.
- **Nothing is claimed that was not established.** Locations are resolved against
  the code model, not taken from model output. A reproduction block states an
  *observation* only for a finding verified end to end; everything else states the
  outcome to check and says the scanner did not observe it. A trail rendered with
  dataflow arrows contains only traced edges.
- **An unknown never buys silence.** Undetermined architecture cannot suppress a
  finding, an unaudited dependency domain is never reported as clean, and
  unverified host ownership never exempts a host. Where the pipeline cannot decide,
  it records a third state and says why.
- **Read-only against the scanned project.** Dependency audits run native
  ecosystem tooling with no install, upgrade, or lockfile write — asserted by
  hashing every manifest before and after.

## Artifacts

```
.secscan/
├── config.yaml                 project configuration
├── workspace.json              members + typed integration points
├── repository/<repo>.manifest.json
├── code-graph.json             nodes/edges, stable ids, security annotations
├── segments/<id>.json          security-boundary segments
├── context-packets/<id>-l<level>.json   post-redaction, budgeted
├── handoff/{requests,responses}/        agent reasoning exchange
├── analysis/answers/             cached endpoint/batch answers (reused when byte-identical)
├── triage/declarations.json      operator answers to triage flag questions
├── findings/{local,correlated}
├── system-review.md
├── reports/<scan-id>.{md,json,html}   one data set, three renderings
├── state.json                  checkpoints, file hashes
├── usage.json                  tokens per stage/tier, savings vs baseline
└── scan.log                    progress trace of the latest run (diagnostic, not an artifact)
```

Gitignored by default; install with `--commit-artifacts` to share scan history.

## Contributing

secscan is open source and contributions are welcome — bug reports, docs, agent
adapters, audit adapters, knowledge-base data, and features. Start with
[**CONTRIBUTING.md**](CONTRIBUTING.md): dev setup, the verification gate
(`pytest -q`, `pytest -q -m slow`, `ruff check src tests`), the spec-first
workflow, and the constitution's six non-negotiable principles every change is
checked against.

Deeper dives for contributors: [Architecture](docs/architecture.md) ·
[Testing](docs/testing.md) · [Extending the knowledge bases](docs/extending-data.md).

## Roadmap

Built and tested:

- ✅ Discovery, multi-language code graph, boundary partitioning, bounded context
- ✅ Redaction, token budgets, evidence escalation, usage/cost accounting
- ✅ Verification + reproduction blocks, correlation/dedup, unified report
- ✅ Installer, 7 agent adapters, init/environment checks, in-place upgrade
- ✅ Agent handoff with cross-session resume

Accuracy hardening (feature 002 — built and tested):

- ✅ Tiered location resolution: symbol-exact where the language is parsed, file-tier
  where it is not, rejection only when the file itself cannot be verified
- ✅ Line-numbered context packets, so a model never counts lines itself
- ✅ Architecture-aware classification with cross-member reachability, so a weakness
  class impossible for the target is remapped rather than misrouted
- ✅ Framework-control evaluation (credited / bypassed / absent / unassessed) and
  verification-aware severity calibration
- ✅ Template and configuration coverage: markup sinks, manifests, deployment and
  datastore config in the code graph
- ✅ Native per-ecosystem dependency audits plus end-of-support reporting
- ✅ Redaction identifier-shape gate — no coverage gap from a long camel-case name
- ✅ Credential-finding precision: identifiers and message strings that merely
  mention credential words are exempted (decisions recorded in packets); heuristic
  matches are graded below format matches and never auto-verified; test-code
  credentials are reported at reduced severity/confidence
- ✅ Report consistency gate: a self-contradicting report is withheld, not warned about
- ✅ Accuracy benchmark asserting per defect class
- ✅ Deterministic misconfiguration rules (CSRF disabled, wildcard CORS, exposed
  consoles, InsecureSkipVerify, …) as versioned data — redaction-independent
- ✅ Compound cross-file findings: whole-repo evidence legs (e.g. unauthenticated
  GraphQL endpoint + cyclic schema + proven-absent depth limits; seeded shared
  passwords + public login), with undetermined legs named, never silenced
- ✅ Offline dependency-vulnerability matching against bundled per-ecosystem
  advisory snapshots (npm/maven/pypi/go); stale snapshots read as
  could-not-check, never clean
- ✅ Structured coverage gaps: every blocked value or budget-dropped file records
  cause, criticality, and impact — security-critical gaps rank first
- ✅ Modern-exploit category (spec 007): direct and indirect prompt injection
  (CWE-1427) traced as flows, sensitive data entering model context (CWE-200),
  model output reaching interpreters unvalidated (CWE-116), over-privileged
  agent/MCP configuration (CWE-250), and supply-chain exposure (dependency
  confusion CWE-829, mutable references CWE-494) — deterministic, offline,
  honest-uncertainty guard states; per-class benchmark assertions (`llm-detection`,
  `supply-chain-detection`) are release-blocking. v1 integration recognition
  covers SDK clients, raw HTTP model endpoints, and local endpoints; indirect
  invocation (agent frameworks, queues) is declared as undetermined posture

Tooling, execution, and reporting (built and tested):

- ✅ Navigable HTML report with redacted code excerpts per finding (feature 005)
  — one data set rendered as Markdown, JSON, and HTML
- ✅ External scanner tooling (spec 008): `init` detects project ecosystems and
  maps applicable tools from the shipped registry (`semgrep`, `gitleaks`,
  `osv-scanner`, `trivy`, `npm audit`, `pip-audit`, `govulncheck`, OWASP
  Dependency-Check); project-provided instances (declared build plugins,
  project-local dependencies, wrapper toolchains) are used directly; missing
  tools install only after the presented list is confirmed — selectively, never
  into the scanned project. Tools run read-only during analysis
  (fingerprint-guarded, timed out, never fatal), their findings merge with
  provenance, and a cross-check suppresses only deterministically disproven
  findings, with every suppression auditable in the report. Tool absence is
  always declared as a coverage limitation — never read as clean.
- ✅ NVD API key handling (spec 009): init detects `NVD_API_KEY` by variable
  name only (the value is never prompted for, stored, or printed); keyless runs
  degrade loudly as `awaiting-key` / `degraded-no-key` / `skipped-no-key`, and
  blanket consent never installs OWASP Dependency-Check keyless
- ✅ Runtime credential references (feature 010): `"$VAR"`, `"${VAR}"`,
  `"%VAR%"`, template and CI expressions are classified structurally as runtime
  wiring and never reported as hard-coded credentials
- ✅ Scan progress output (feature 011): stages, segments (`i/N`), external tools
  and coverage notes stream to stderr with a heartbeat; `-q`/`-v` levels; the
  full trace lives in `.secscan/scan.log`; the three stdout summary lines are a
  frozen interface
- ✅ Endpoint scheduling (feature 012): provider batch API by default (providers'
  published 50% batch discount, no per-minute rate-limit wall on large repos),
  off-peak windows, resumable waits (Ctrl-C safe, the batch reference is
  persisted), interactive fallback with retries on 429/5xx, an answer cache
  reused only for byte-identical requests, and per-level model tiers
  (`local` / `segment` / `system`)
- ✅ Finding triage round (feature 013): after correlation, the reasoning layer
  re-examines each finalized finding — confirm / downgrade / refute-with-citations /
  flag-with-a-question. Refutations and downgrades apply only when the pipeline
  mechanically re-verifies every citation (file, lines, exact pattern) against the
  repo; failed proofs degrade to flags, never suppressions. Verified refutations
  land in the auditable suppression list; flags render in an Awaiting Verification
  report section whose questions operators answer in `.secscan/triage/declarations.json`
  (user-declared provenance, reversible, lapses safely). Credential findings are
  never refutable — the value never reaches reasoning. Same round in every
  execution mode (agent handoff, endpoint, provider batch); `quick` profiles skip
  it, `triage.enabled` overrides
- ✅ Report accuracy hardening (feature 014): dependency findings carry a
  three-state **usage** block (found / none-found / undetermined) so an advisory
  never narrates exploitation for a package nothing imports; misconfiguration
  findings carry a three-state **integration** state so stale rules-config reads
  as removal work; template sinks get deterministic framework-escaping credit
  (a bypass call keeps the finding standing, an unassessed control routes to the
  triage round); currency findings merge per `(member, product, cycle)` instead
  of doubling up; and a narrative section that references a nonexistent finding
  is quarantined at publication — declared in the report, exit code 4

Multi-repo workspaces (Phase 6 / US4 — built and tested):

- ✅ Workspace model with member discovery (declared manifest or auto-inferred
  from directory structure) and declared integration points normalized and
  typed (sync-api, async-messaging, shared-datastore, identity-propagation)
- ✅ Multi-member code graph with cross-repo call edges, segments spanning
  repos, and compound findings whose evidence legs cross members
- ✅ Cross-member applicability and host ownership: a weakness class impossible
  for a lone browser member survives when a reachable sibling issues
  server-side requests; sibling hosts classify as internal
- ✅ Unified workspace report with per-repo derived views and a cross-boundary
  review: a deterministic baseline narrative (cross-boundary observations are
  never silenced — it says so when nothing crossed), enriched by the host agent
  via the final-review prompt in agent-mediated mode

Specified, not yet built:

- ⬜ Deep cross-repo reasoning (US4 remainder) — inference and typing of
  *undeclared* integration points, the richer correlation relationships
  (`related`/`dependent`, conflict reconciliation), and a model-driven
  system-tier cross-boundary review at the endpoint
- ⬜ Incremental rescan (Phase 7 / US5) — per-file change detection (content
  hashes key every stage, so changed files re-run only the stages downstream of
  them), single-segment re-runs (`--segment`), and profile-depth re-analysis
  exist. What does not: selecting a *subset* of segments for re-analysis from
  the changed files, and invalidating dependent segments in other repos across
  a declared integration
- ⬜ Performance/scale validation (Phase 8) — batch/off-peak execution
  (feature 012), determinism regression tests, artifact redaction sweep, the
  `docs/` set, and a scale scan over a repository 10x a single context window
  (`pytest -q -m slow`) are all delivered; the timed large-repository
  performance benchmark is the remaining item

The system-level review currently produces a deterministic narrative from
structured evidence — including cross-boundary observations for findings whose
evidence spans members; in agent-mediated mode the host agent enriches it via
the final-review prompt. A model-driven cross-boundary review at the endpoint
`system` tier is the remaining Phase 6 item.

## Specification

This project is built spec-first with [GitHub Spec Kit](https://github.com/github/spec-kit).
The full specification, plan, contracts, and task list live in
[`specs/001-hierarchical-security-scan/`](specs/001-hierarchical-security-scan/):

| Document | Contents |
|----------|----------|
| `spec.md` | Requirements, user stories, success criteria, 38 recorded clarifications |
| `plan.md` | Technical context and structure |
| `research.md` | Decisions with rationale and alternatives (R1–R6) |
| `data-model.md` | Entities and lifecycles |
| `contracts/` | CLI, config, finding, and artifact schemas |
| `quickstart.md` | Executable validation scenarios mapped to tests |
| `tasks.md` | Dependency-ordered task list with progress |

Follow-on features each have their own spec directory under [`specs/`](specs/) —
002 accuracy hardening, 003–004 secret-precision/missed-detection work, 005 HTML
report excerpts, 006 verification pass, 007 modern-exploit detection, 008
external scanner integration, 009 NVD API key setup, 010 runtime credential
references, 011 scan progress output, 012 provider batch API, 013 finding
triage, 014 report accuracy hardening.
