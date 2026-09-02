# Getting started

This page takes you from zero to a first scan. For the why, see the
[README](../README.md) and [Architecture](architecture.md).

## Requirements

- Python 3.11+
- One of the supported coding agents (optional but typical — see below)
- No API key, unless you choose to configure an external endpoint

## 1. Install the CLI

```bash
uv tool install .          # from the secscan repo checkout
# or
pipx install .
```

This puts `secscan` on your PATH.

> **`command not found: secscan`?** `uv pip install -e .` installs into the
> project's `.venv` **without** putting it on your PATH. Either use
> `uv tool install .` as above, activate the venv first
> (`source .venv/bin/activate`), or prefix commands with `uv run`.

For iterating on secscan itself, `uv tool install --editable .` keeps the
installed command live-linked to your checkout.

## 2. Scaffold your project

From anywhere, point `init` at the project you want to scan:

```bash
secscan agents                                # see the supported agents
secscan init /path/to/your/project --ai claude
```

`init` does three things:

1. **Installs the skill** — copies the `secscan` payload into the agent's skills
   directory inside your project, registering an invocable command. Each project
   pins its own scanner version; re-running `init` upgrades in place, preserving
   config and artifacts.
2. **Generates config** — writes `.secscan/config.yaml` (see
   [Configuration](configuration.md)).
3. **Checks the environment** — detects your project's ecosystems and reports which
   external security tools apply (see step 3 below).

For CI or other unattended setups, useful flags: `--no-init` (skill only, no
config), `--commit-artifacts` (opt scan artifacts *into* git; default is to
gitignore `.secscan/`), and the tool-install flags described next.

## 3. External tools (optional)

secscan can integrate `semgrep`, `gitleaks`, `osv-scanner`, `trivy`, `npm audit`,
`pip-audit`, `govulncheck`, and OWASP Dependency-Check when they apply to your
stacks. Nothing installs without your confirmation:

```bash
secscan init . --install=all                 # confirm everything presented
secscan init . --install=npm-audit,osv-scanner   # a selective list
secscan init . --no-input                    # never prompt; skip with a declared note
```

Tools you already have (declared build plugins, project-local dependencies, wrapper
toolchains) are used directly. Missing tools install only after the exact list is
presented and confirmed — and never into the scanned project.

**NVD API key:** OWASP Dependency-Check downloads its data from the National
Vulnerability Database, which is heavily rate-limited without a key. Set
`NVD_API_KEY` in your shell (request one at
<https://nvd.nist.gov/developers/request-an-api-key>). The value is never prompted
for, stored, or printed — init detects it by variable *name* only. Without the key,
non-interactive runs skip the tool unless you pass `--allow-keyless-nvd`; blanket
consent (`--yes`, `--install=all`) never silently installs it keyless.

## 4. Scan

```bash
cd /path/to/your/project
secscan run --full
```

A scan writes durable artifacts under `.secscan/` as it goes and resumes
automatically if interrupted. When it finishes:

```bash
secscan report                               # re-render the latest report
secscan report --format html                 # ...as navigable HTML
secscan status .                             # stage state, handoff progress
```

Reports land in `.secscan/reports/<scan-id>.{md,json,html}` — one data set, three
renderings.

### When the scan stops with exit code 3

In the default agent-mediated mode, the scanner never calls a model itself. When it
needs reasoning it stops and tells you:

```
→ 6 analysis request(s) await agent reasoning
  .secscan/handoff/requests/<request-id>.json   (prompt + bounded packet)
```

Answer the requests into `.secscan/handoff/responses/` (your agent does this when
you invoke the installed skill — that's the normal flow), then re-run
`secscan run`. Partial answers keep prior work, so one scan can span multiple agent
sessions. Details in [Agent integration](agent-integration.md).

## 5. Tune it

- Pick a profile for depth vs. speed: `secscan run --profile quick` — see
  [Scan profiles](scan-profiles.md).
- Point analysis at your own endpoint for batch/off-peak cost features — see
  [Configuration](configuration.md).
- Override any setting per scan: `secscan run --set budgets.max_context_tokens=8000`.

## What's next

- [Configuration](configuration.md) — the full config reference
- [CLI reference](cli-reference.md) — every command and flag
- [Artifacts](artifacts.md) — understanding what a scan leaves behind
