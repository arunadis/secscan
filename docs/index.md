# secscan documentation

**secscan** — hierarchical, context-bounded security scanning for large codebases,
installable as a skill into your coding agent. This is the documentation hub; the
[README](../README.md) is the overview and showcase.

## Using secscan

| Page | What it covers |
|------|----------------|
| [Getting started](getting-started.md) | Install the CLI, scaffold the skill into your agent, run your first scan |
| [Configuration](configuration.md) | `config.yaml` reference: LLM modes, endpoints, budgets, execution policy, env overrides |
| [CLI reference](cli-reference.md) | Every command, flag, and exit code |
| [Scan profiles](scan-profiles.md) | `quick` / `full` / `audit`, custom profiles, per-scan overrides |
| [Agent integration](agent-integration.md) | The handoff protocol, cross-session resume, how agents answer scan requests |
| [Artifacts](artifacts.md) | What lands in `.secscan/`, schema versioning, state and resume |

## How it works

| Page | What it covers |
|------|----------------|
| [Architecture](architecture.md) | The pipeline stages, the context-as-a-managed-resource design, module map |
| [Security model](security-model.md) | Redaction, offline/read-only guarantees, honest uncertainty, benign reproduction |
| [Testing](testing.md) | Suite layout, ground-truth fixtures, accuracy benchmarks, verification commands |

## Extending secscan

| Page | What it covers |
|------|----------------|
| [Extending the knowledge bases](extending-data.md) | Adding stacks, weakness-applicability rules, framework controls, audit adapters — as data, not pipeline changes |

## Contributing

| Page | What it covers |
|------|----------------|
| [CONTRIBUTING](../CONTRIBUTING.md) | Dev setup, the verification gate, naming conventions, spec-first workflow, what makes a good contribution |

Deeper source material also lives in the repo:

- The governance document: [`.specify/memory/constitution.md`](../.specify/memory/constitution.md) —
  the six non-negotiable principles every feature is checked against.
- The feature history: [`specs/`](../specs/) — spec-first records (001–014) with
  requirements, plans, contracts, and task lists.
- Agent-facing guidance: [`AGENTS.md`](../AGENTS.md).

## Where to start

- **You want to scan your code** → [Getting started](getting-started.md)
- **You want to tune a scan** → [Configuration](configuration.md), then
  [Scan profiles](scan-profiles.md)
- **You want to understand a finding** → [Security model](security-model.md) and
  [Artifacts](artifacts.md)
- **You want to contribute** → [CONTRIBUTING](../CONTRIBUTING.md), then
  [Architecture](architecture.md) and [Testing](testing.md)
