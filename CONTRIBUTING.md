# Contributing to secscan

Thanks for your interest in contributing! secscan is a spec-first,
determinism-first project, so the contribution process has a few opinions — this
guide tells you what they are and how to work with them.

**Quick facts**: Python 3.11+ ·
[docs hub](docs/index.md) · [architecture](docs/architecture.md) ·
[testing guide](docs/testing.md)

## Before you write code: the constitution

Every feature is evaluated against the six principles in
[`.specify/memory/constitution.md`](.specify/memory/constitution.md). The short
version — rules your change must not break:

1. **Determinism before intelligence** — identical input + tool version ⇒
   byte-identical artifacts; structural decisions come from shipped data and code
   structure, never model output.
2. **Context is a managed resource** — budgets enforced against the actual
   serialized request; no silent truncation.
3. **Secrets never reach a model** — the layered redactor runs before any context
   packet; recall takes absolute precedence over precision; unclassifiable content
   is blocked, not passed through.
4. **Evidence over assertion** — schema-conforming findings only; locations resolve
   against the code model.
5. **Honest uncertainty** — undetermined states are recorded and can never suppress
   a finding or read as clean.
6. **Observe, never attack** — static verification, benign reproduction,
   read-only tooling.

If your change seems to push against one of these, raise it in the issue/PR —
either the implementation changes or the principle is amended openly, one of the
two.

## Development setup

```bash
uv venv --python 3.11
uv pip install -e ".[dev]"       # editable install into ./.venv
source .venv/bin/activate        # ...or prefix commands with `uv run`
```

Note: `uv pip install -e .` does **not** put `secscan` on your PATH — use the
activated venv, `uv run`, or `uv tool install --editable .`

Full layout and module tour: [docs/architecture.md](docs/architecture.md).

## The verification gate

Run all three before opening or updating a PR — CI expects exactly this to be
green:

```bash
pytest -q                        # full suite (~800 tests)
pytest -q -m slow                # + the large-repository scale scan
ruff check src tests             # line-length 100, py311, rules E/F/I/UP/B
```

Details on how the suite is organized (fixtures with declared ground truth,
contract tests, release-blocking accuracy benchmarks) are in
[docs/testing.md](docs/testing.md). Tests are written **before** implementation and
must fail first — fixture repos declare ground truth, including deliberate false
positives that must not be reported.

## How we work: spec-first

Features are specified before they're implemented using
[GitHub Spec Kit](https://github.com/github/spec-kit) — see the history in
[`specs/`](specs/) (001–009). For non-trivial features:

1. Write/clarify the spec (`spec.md` with stable requirement identifiers).
2. Write the plan — its **Constitution Check** evaluates the feature against all
   six principles.
3. Break it into a dependency-ordered `tasks.md`; every task cites the requirement
   it discharges.
4. Implement test-first.

Bug fixes and small data additions can go straight to a PR with tests. If you're
unsure which route your change needs, open an issue first and ask.

## Conventions worth knowing

- **Naming**: everything is **`secscan`** — skill name, `secscan` console script,
  `.secscan/` artifacts directory, `SECSCAN_*` env prefix,
  `python -m pipeline.scan_cli` in payloads. Do not reintroduce the old
  `security-scan` name. (Historical `specs/00X-*` documents reference old names —
  they are point-in-time records; do not "fix" them.)
- **Schemas are additive.** A breaking artifact-schema change needs a
  `schema_version` bump and a documented upgrade path.
- **Extensibility as data.** Adding a stack, weakness-applicability rule, or
  framework control **must not** require touching a pipeline stage — extend the
  versioned data files under `src/skill_core/data/`. See
  [docs/extending-data.md](docs/extending-data.md), which also covers the
  deliberately high bar for applicability entries (a wrong suppression is a false
  negative — the more damaging error direction).
- **Style**: ruff enforces it (line length 100, py311, rules E/F/I/UP/B). Compact,
  idiomatic Python; don't add comments restating code.
- **Honest documentation**: status claims in `README.md` must match the repository;
  planned work is labelled planned. If your change alters behavior described
  there or in `docs/`, update the docs in the same PR.

## Good first contributions

Entry points that are well-bounded and easy to verify:

- **New agent adapter** — support another coding agent by adding one thin adapter
  in `src/installer/agents/`; the core never changes. See
  [docs/agent-integration.md](docs/agent-integration.md#adding-a-new-agent).
- **New audit adapter** — read-only, never-raises, timeout-bounded; the base class
  supplies the guarantees and contract tests assert them. See
  [docs/extending-data.md](docs/extending-data.md#adding-an-audit-adapter).
- **Knowledge-base extensions** — stacks, template forms, framework controls,
  misconfiguration rules. All data, all validated by loaders and
  `tests/unit/test_data_files.py`.
- **Documentation** — corrections and clarifications to `docs/` and the README are
  always welcome.

## Pull requests

- Fill in the "why", not just the "what".
- Keep PRs focused; spec changes land separately from implementation where
  practical.
- Confirm the verification gate passes.
- Accuracy-benchmark regressions are release-blocking — a regression in any single
  defect class fails the build even if other classes improve, and that's
  intentional.

## Reporting security issues

**Do not open a public issue for a vulnerability in secscan itself.** Report it
privately to the maintainers first so it can be addressed before disclosure. If no
security-contact channel is listed in the repository yet, open a minimal issue
asking for a private contact rather than describing the problem publicly.
