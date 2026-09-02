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
  mode: interactive               # interactive | batch-offpeak
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

## Execution modes: who does the reasoning

`llm.mode` chooses who analyzes. Every scan runs in exactly one of three modes:

| Mode | Who analyzes | Needs a key | Endpoint-only cost features |
|------|--------------|-------------|------------------------------|
| `agent` | The coding agent running the skill, with its own model | No | Unavailable (declared at init) |
| `endpoint` | A provider endpoint you configure | Yes (`api_key_env`) | Batch API (~50% cost discount), off-peak window scheduling, per-level model tiers |
| `auto` (default) | Endpoint when one is configured, otherwise the agent | Only with an endpoint | As above when an endpoint is configured |

Explicit configuration always wins: setting `llm.endpoint` switches analysis to it
even in `auto`, and `llm.mode: agent` forces agent-mediated reasoning even with an
endpoint present. Agent-mediated mode makes no analysis call leave your machine —
see [Agent integration](agent-integration.md).

### Configuring an endpoint

```yaml
llm:
  mode: endpoint
  endpoint:
    provider: anthropic             # anthropic | openai-compatible
    api_key_env: ANTHROPIC_API_KEY  # variable NAME — the key itself is never in this file
    # base_url: https://your-gateway # optional, for openai-compatible gateways
    model_map:                      # optional per-analysis-level model tiers
      local: claude-haiku-latest    # cheap tier: per-symbol/secret checks
      segment: claude-sonnet-latest # segment analysis (fallback tier for the others)
      system: claude-opus-latest    # cross-boundary system review
```

- `api_key_env` is required whenever `endpoint` is present. If the variable is
  unset at scan time, the scan stops before any analysis with a clear message.
- `model_map.segment` is the fallback tier: `local` and `system` default to it.
- The bundled HTTP transport speaks the Anthropic Messages API
  (`POST /v1/messages`); `provider: openai-compatible` and `base_url` are accepted
  for provider-agnostic gateway deployments.

### Endpoint scheduling: interactive vs batch

With an endpoint configured, `execution_policy` picks how analysis is submitted:

```yaml
execution_policy:
  mode: interactive                 # interactive | batch-offpeak
  offpeak_window: "02:00-06:00"     # REQUIRED when mode is batch-offpeak
  batch:
    enabled: false                  # true = submit via the provider batch API
    fallback: interactive           # the only valid fallback: failed/expired batch
                                    # items are re-run interactively and recorded
```

`batch-offpeak` defers analysis to the configured window; `batch.enabled` routes
calls through the provider's batch API. Both require an endpoint — strict
validation and `secscan init` reject batch settings in agent-mediated mode rather
than silently ignoring them. The `--policy` flag on `secscan run` overrides the
execution policy for a single scan.

## Budgets

Budgets control how much context any single analysis invocation may consume and
are enforced against the *actual serialized request*, never an estimate (see
[Security model](security-model.md)):

- `max_context_tokens` — ceiling per context packet.
- `max_output_tokens` — ceiling per model response.
- `escalation_threshold` — fraction of the context budget at which the pipeline
  prefers escalating to the next evidence level over packing more files into the
  current one.

## External tooling

```yaml
tooling:
  install: ask        # never | ask | all — what init may do without asking again
  timeout_s: 120      # per-tool wall-clock ceiling during analysis
```

`--tool-timeout` on `secscan run` overrides `timeout_s` per scan. Tools always run
read-only against the scanned project, fingerprint-guarded and timed out, and a
tool's absence is declared as a coverage limitation — never read as clean.

## Environment overrides

Every setting has an environment-variable form: prefix `SECSCAN_`, then the
section and key in upper snake case:

```bash
export SECSCAN_LLM_MODE=agent
export SECSCAN_EXECUTION_POLICY_MODE=interactive
```

Related environment variables that are *inputs*, not config:

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | Un-throttles OWASP Dependency-Check's NVD data sync. Detected by name only; never stored or printed. |
| `<api_key_env>` | Whatever variable your `llm.endpoint.api_key_env` names — the key value itself. |
