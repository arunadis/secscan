# Configuration

secscan is configured by one human-editable file, `.secscan/config.yaml`, created
by `secscan init`. The file is **strictly validated** before any scan work begins:
all problems are reported at once, and conflicting settings are rejected rather
than silently resolved.

Two rules to internalize first:

- **Secrets never live in config.** Credentials are referenced by environment
  variable *name* only. Storing a key value anywhere under `llm.endpoint` is
  rejected outright by validation, and the value is never logged or written to an
  artifact.
- **Machine-specific values come from the environment.** Any setting can be
  overridden with `SECSCAN_<SECTION>_<KEY>` (e.g. `SECSCAN_LLM_MODE`,
  `SECSCAN_EXECUTION_POLICY_MODE`), so the committed config stays
  machine-agnostic.

## Full example

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
  batch:
    window_hours: 24              # batch expiry, measured from submission

budgets:
  max_context_tokens: 12000
  max_output_tokens: 3000
  escalation_threshold: 0.75

scanners:
  semgrep: { enabled: auto }      # auto = run when detected

tooling:                          # external security tools (spec 008)
  install: ask                    # never | ask | all — consent default for init
  timeout_s: 120                  # per-tool wall-clock ceiling during analysis

output:                           # progress output of `secscan run` (spec 011)
  level: default                  # quiet | default | verbose
```

## Execution modes: who does the reasoning

`llm.mode` chooses who analyzes. Every scan runs in exactly one of three modes:

| Mode | Who analyzes | Needs a key | Endpoint-only cost features |
|------|--------------|-------------|------------------------------|
| `agent` | The coding agent running the skill, with its own model | No | Unavailable (declared at init) |
| `endpoint` | A provider endpoint you configure | Yes (`api_key_env`) | Provider batch API (the default; providers publish a 50% discount for it), off-peak window scheduling, per-level model tiers |
| `auto` (default) | Endpoint when one is configured, otherwise the agent | Only with an endpoint | As above when an endpoint is configured |

Explicit configuration always wins: setting `llm.endpoint` switches analysis to it
even in `auto`, and `llm.mode: agent` forces agent-mediated reasoning even with an
endpoint present. Agent-mediated mode makes no analysis call leave your machine —
see [Agent integration](agent-integration.md).

### Configuring an endpoint

An endpoint has four settings under `llm.endpoint`:

| Key | Required | Meaning |
|-----|----------|---------|
| `provider` | no (default `anthropic`) | Wire protocol: `anthropic` or `openai-compatible`. **Must match the key you supply** — see the table below. |
| `api_key_env` | **yes** | The *name* of the environment variable holding the key. Never the key itself. |
| `base_url` | no | Host to send requests to. Only needed for gateways/proxies; each provider has a sensible default. |
| `model_map` | no | Model per analysis level (`local` / `segment` / `system`). `segment` is the fallback for the other two. |

`provider` decides the URL, the auth header, and the request/response shape:

| `provider` | Request | Auth header | Default `base_url` | Use for |
|------------|---------|-------------|--------------------|---------|
| `anthropic` | `POST {base_url}/v1/messages` | `x-api-key` | `https://api.anthropic.com` | Anthropic API keys (`sk-ant-...`) |
| `openai-compatible` | `POST {base_url}/chat/completions` | `Authorization: Bearer` | `https://api.openai.com/v1` | OpenAI keys, and any gateway that speaks Chat Completions (Azure OpenAI, OpenRouter, LiteLLM, vLLM, internal proxies) |

#### Example: Anthropic

```yaml
llm:
  mode: endpoint
  endpoint:
    provider: anthropic
    api_key_env: ANTHROPIC_API_KEY
    model_map:
      local: claude-haiku-latest      # cheap tier: per-symbol/secret checks
      segment: claude-sonnet-latest   # segment analysis (fallback tier for the others)
      system: claude-opus-latest      # cross-boundary system review
```

```bash
export ANTHROPIC_API_KEY=...          # in your shell, never in the config file
secscan run --full
```

#### Example: OpenAI

```yaml
llm:
  mode: endpoint
  endpoint:
    provider: openai-compatible       # NOT "anthropic" — an OpenAI key sent to the
    api_key_env: OPENAI_API_KEY       # Anthropic endpoint is rejected with HTTP 401
    model_map:
      local: gpt-4o-mini
      segment: gpt-4o
      system: gpt-4o
```

`base_url` can be omitted: it defaults to `https://api.openai.com/v1`.

#### Example: OpenAI-compatible gateway

Any service exposing the Chat Completions shape works — point `base_url` at it and
name whichever variable holds its key:

```yaml
llm:
  mode: endpoint
  endpoint:
    provider: openai-compatible
    api_key_env: LLM_GATEWAY_KEY
    base_url: https://llm-gateway.internal.example/v1   # secscan appends /chat/completions
    model_map:
      segment: my-gateway-model
```

#### Notes

- `api_key_env` is required whenever `endpoint` is present. If the variable is
  unset at scan time, the scan stops before any analysis with a clear message.
- Storing a key value anywhere under `llm.endpoint` (`api_key`, `token`, `secret`,
  ...) is rejected by validation. The key value is never logged or written to an
  artifact — only the variable name appears in `init` output and scan metadata.
- `model_map` values are passed to the provider verbatim; use the model IDs your
  provider/gateway accepts.
- A trailing `/` on `base_url` is tolerated.

#### Troubleshooting: HTTP Error 401

A failed call surfaces as
`analysis endpoint request failed (<provider> <url>): HTTP Error 401: Unauthorized`.
The message names the provider and the exact URL that was called. Check, in order:

1. **Provider matches the key.** An OpenAI key with `provider: anthropic` (or the
   reverse) always yields 401 — the key is valid, it is just being sent to the wrong
   service. Fix `provider`, not the key.
2. **The variable is exported in the shell running `secscan`**, e.g.
   `echo ${OPENAI_API_KEY:+set}` should print `set`. If it is set in another
   terminal, a `.env` file, or your IDE only, the CLI will not see it.
3. **The key works outside secscan**:
   `curl -s https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"`
   (or the Anthropic equivalent). If this fails, the problem is the key or the
   account, not secscan.
4. **You are running the version you think you are.** If you installed from a source
   checkout and later pulled changes, see
   [Getting started → Upgrading](getting-started.md#upgrading-a-source-install).

### Endpoint scheduling: batch (default) vs interactive

With an endpoint configured, `execution_policy` picks how analysis requests reach
the provider:

```yaml
execution_policy:
  mode: auto                        # auto | interactive | batch | batch-offpeak
  # offpeak_window: "02:00-06:00"   # REQUIRED when mode is batch-offpeak
  batch:
    fallback: interactive           # the only valid value: items the batch could not
                                    # answer are re-run live and recorded as fallbacks
    window_hours: 24                # batch expiry, measured from submission
```

| `mode` | Behaviour |
|--------|-----------|
| `auto` (default) | **Batch** whenever `llm.endpoint` is configured; agent-mediated otherwise. The scan header and report say `endpoint-batch (default policy)` so the choice is never silent. |
| `batch` | Batch, chosen explicitly. |
| `batch-offpeak` | Batch, but each round's submission waits for the `offpeak_window` time-of-day range. Expiry is still `window_hours` from submission. |
| `interactive` | One live request per segment, with retries (below). Faster on small repositories; exposed to per-minute rate limits on large ones. |

`execution_policy.batch.enabled` is accepted for compatibility (`true` forces batch,
`false` forces interactive); it conflicts with an explicit `mode` that says the
opposite and validation reports that.

**Backward compatibility.** Configurations generated before batch became the default
contain an explicit `mode: interactive` and keep interactive behaviour. Only newly
generated configurations (which write `mode: auto`) get batch by default.

**What a batch scan does.** For each escalation round, the requests of every segment
that needs analysis are grouped by model, split only if the provider's per-batch
limits require it, and submitted together — a handful of requests instead of one per
segment, which is what removes the "429 Too Many Requests" failure mode on large
repositories. The scan then waits in the foreground, checking status every 30 s
(backing off to 5 min) and printing a `processing c/N` line each time. The batch
reference is written to `.secscan/state.json` *before* waiting, so **Ctrl-C is safe**:
the next `secscan run` polls the same batch instead of submitting a new one. Every
answer is persisted under `.secscan/analysis/answers/` the moment it is observed and
is reused only if the request (prompt, context, model) is byte-identical — so no
request is ever paid for twice. Items the batch reports as errored, expired, or
missing — and every item of a batch that expired locally, failed validation, or whose
reference the provider no longer knows — are re-run interactively; each such fallback
appears as a warning during the run and in the report's fallback list with its reason.
A gateway that does not implement batching (404/405/501 on the batch endpoint) is
detected on the first submission; the scan then runs interactively with one declared
coverage note and does not try batch again.

**Estimated saving.** The report's usage summary shows
`Estimated saving vs interactive pricing: N% (assumes the provider's published 50%
batch discount)`. It is computed from tokens — `50% × (tokens answered via batch ÷
all analysis tokens)` — not from a price table, and is labelled as an estimate.

### Retries for live requests

Interactive requests — the interactive policy and batch fallbacks — retry transient
provider failures (HTTP 429, 5xx, 529, connection errors) with a growing, jittered
wait, honouring the provider's `Retry-After` as a minimum:

```yaml
llm:
  retry:
    attempts: 5                     # total attempts per request (1 initial + 4 retries)
    max_wait_s: 60                  # ceiling for one wait
```

Waits start at 2 s and double up to `max_wait_s`; the total wait per request is
bounded at about three minutes. Each retry is printed as a warning naming the segment,
attempt number, and wait. Authentication, malformed-request, and unknown-model errors
are never retried. When retries are exhausted the scan stops with one line (no
traceback), keeps every segment analysed so far, and resumes from the failed segment
on the next run. The `--policy` flag on `secscan run` overrides the execution policy
for a single scan.

## Budgets

Budgets control how much context any single analysis invocation may consume and
are enforced against the *actual serialized request*, never an estimate (see
[Security model](security-model.md)):

- `max_context_tokens` — ceiling per context packet.
- `max_output_tokens` — ceiling per model response.
- `escalation_threshold` — fraction of the context budget at which the pipeline
  prefers escalating to the next evidence level over packing more files into the
  current one.

## Finding triage

```yaml
triage:
  enabled: auto            # auto | on | off — auto follows the profile
  min_severity_band: Medium   # lowest band triaged (profile default when omitted:
                              # full Medium, audit Low)
  include_unverified: true    # findings with unverified status are candidates too
```

The triage round (feature 013) re-examines each eligible *finalized* finding once,
before reporting: the reasoning layer may confirm it, downgrade it with cited
limiting facts, refute it with cited controls, or flag it with a concrete question
for the operator. Verdicts that refute or downgrade apply only after the pipeline
mechanically re-verifies every citation against the repository (file, lines, and
exact pattern text); an unverifiable claim degrades to a flag, never a
suppression. Credential findings (CWE-798/CWE-522) are never refutable — neither
by reasoning nor by declaration. Flagged findings appear in the report's
Awaiting Verification section; answer their questions in
`.secscan/triage/declarations.json`:

```json
{
  "schema_version": 1,
  "declarations": [
    {
      "finding_ref": { "repo": "shop", "file": "scripts/dev.sh", "cwe": "CWE-798" },
      "question": "…exactly as asked in the report…",
      "answer": "No — the token is dev-compose only; the gateway rejects it.",
      "resolution": "downgrade"
    }
  ]
}
```

Declarations bind on the finding's identity (repo/file/weakness, optional symbol)
and the question text, tolerate line drift, apply on the next scan with explicit
`user-declared` provenance, lapse (and re-flag) when the question or finding
disappears, and are removed cleanly by deleting the entry — the flag returns.

Profiles gate the round: `quick` skips it; `full` and `audit` run it
(`analysis_depth.finding_triage`). Same round in every execution mode —
agent-mediated handoff, interactive endpoint, or provider batch.

## External tooling

```yaml
tooling:
  install: ask        # never | ask | all — what init may do without asking again
  timeout_s: 120      # per-tool wall-clock ceiling during analysis
```

`--tool-timeout` on `secscan run` overrides `timeout_s` per scan. Tools always run
read-only against the scanned project, fingerprint-guarded and timed out, and a
tool's absence is declared as a coverage limitation — never read as clean.

## Output

```yaml
output:
  level: default      # quiet | default | verbose
```

Controls how much `secscan run` prints to **stderr** while it works. `quiet` prints
nothing until the final summary (identical to releases before progress output
existed); `default` shows every stage, segment `i/N`, external tool, and warning
as it happens, plus a heartbeat every 30 s during long silent steps; `verbose`
adds the escalation level and token count per segment, tool versions and
invocations, and checkpoint keys. The stdout summary is the same at every level.

Precedence, highest first: `secscan run --output <level>` (or `-q` / `-v`) →
`SECSCAN_OUTPUT_LEVEL` → `output.level` → `default`. The level applies whether or
not a terminal is attached; automated callers that want silence pass `-q`.

Independent of the level, every run writes the full trace to `.secscan/scan.log`
(see [Artifacts](artifacts.md#the-scan-log)).

## Environment overrides

Every setting has an environment-variable form: prefix `SECSCAN_`, then the
section and key in upper snake case:

```bash
export SECSCAN_LLM_MODE=agent
export SECSCAN_EXECUTION_POLICY_MODE=interactive
export SECSCAN_EXECUTION_POLICY_BATCH_WINDOW_HOURS=6
export SECSCAN_LLM_RETRY_ATTEMPTS=3
export SECSCAN_LLM_RETRY_MAX_WAIT_S=30
export SECSCAN_OUTPUT_LEVEL=quiet
export SECSCAN_TRIAGE_ENABLED=off
```

Related environment variables that are *inputs*, not config:

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | Un-throttles OWASP Dependency-Check's NVD data sync. Detected by name only; never stored or printed. |
| `<api_key_env>` | Whatever variable your `llm.endpoint.api_key_env` names — the key value itself. |
