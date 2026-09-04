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

### Upgrading a source install

`uv tool install .` caches the built wheel by *version number*. Because the version
does not change between commits, re-running `uv tool install . --force` after
`git pull` (or after editing the source) will happily reinstall the **old, cached**
build — and the command will keep behaving exactly as before. Use one of:

```bash
# one-off: rebuild from the current checkout, ignoring the cache
uv tool install . --force --reinstall --no-cache

# for development: live-link the command to your checkout so edits apply immediately
uv tool install --editable . --force
```

To confirm which code is installed, check the path `secscan` resolves to and inspect
the files under it:

```bash
which secscan                       # ~/.local/bin/secscan
ls -la ~/.local/share/uv/tools/secscan/lib/python*/site-packages/pipeline/
```

With an editable install the `pipeline/` entry is a link into your checkout; with a
regular install it is a copy whose timestamps should match your last install.

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

While it runs, the scan reports what it is doing on stderr — each stage as it
starts and finishes, every segment as `i/N`, each external tool, and any coverage
note the moment it is recorded — so a long scan never looks stuck:

```
14:02:11 +00:00 start scan 20260903T140211Z-1a2b3c (full profile, agent-mediated)
14:02:11 +00:00 done  discover_repo (0.4s)
14:02:13 +00:02 done  build_code_graph (1.8s)
14:02:13 +00:02 start segment_analysis segment 1/7 shop:orders
14:02:45 +00:34 wait  still running segment_analysis shop:orders (32s)
```

Pass `-q` for scripts that only want the final summary, `-v` for per-segment budget
and per-tool detail (see [CLI reference](cli-reference.md#progress-output)). The
same trace is always written to `.secscan/scan.log`.

A scan writes durable artifacts under `.secscan/` as it goes and resumes
automatically if interrupted (Ctrl-C exits with status 130; the next run picks up
from the last checkpoint). When it finishes:

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

If a scan stops for any other reason, `.secscan/scan.log` holds the full trace of
that run; its last line names the stage — and segment or tool — that was in
progress.

### Exit code 4: report published with quarantined narrative

Exit code 4 is not a failure and not a stop: the report **was written** to
`.secscan/reports/`, but a narrative section (system review, cross-system
findings, attack paths, or recommendations) referenced a finding identifier that
is not part of the report, so that section was omitted. The report's
*Report Integrity* section declares what was removed and which identifier was
dangling. Re-running with a freshly computed narrative clears it.

### Reading dependency and misconfiguration findings

Dependency findings carry a **usage** state: `found` (with the import/config/
dynamic locations), `none-found` (nothing references the package — the finding
still stands, but the impact is conditional on the package being exercised), or
`undetermined` (with the reason). Misconfiguration findings carry an
**integration** state: `integrated`, `no-integration-found` (no SDK/import/config
integration with the governed technology — remove the configuration rather than
harden it), or `undetermined`.

## 5. Tune it

- Pick a profile for depth vs. speed: `secscan run --profile quick` — see
  [Scan profiles](scan-profiles.md).
- Point analysis at your own endpoint — see [Configuration](configuration.md). With an
  endpoint the scan submits each analysis round as one provider **batch** by default
  (rate-limit-proof, billed at provider batch pricing): you will see
  `batch 1/1 submitted: N items`, then `processing c/N` status lines while it waits in the
  foreground, then `batch 1/1 ended`. Ctrl-C is safe — the next run resumes the same
  batch. For a quick scan of a small repository use `secscan run --policy interactive`.
- Override any setting per scan: `secscan run --set budgets.max_context_tokens=8000`.

## What's next

- [Configuration](configuration.md) — the full config reference
- [CLI reference](cli-reference.md) — every command and flag
- [Artifacts](artifacts.md) — understanding what a scan leaves behind
