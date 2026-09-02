# Agent integration

secscan's defining integration choice: in the default mode, **the scanner never
calls a model itself**. The coding agent you already use does the reasoning, with
its own model — no API key required, and no analysis content leaves your machine.
An external endpoint can be configured instead (see
[Configuration](configuration.md#execution-modes-who-does-the-reasoning)); this
page covers the default agent-mediated path and how agents are supported.

## The handoff protocol

When the pipeline needs reasoning (segment analysis, system review), it does not
call a model — it writes a request file and stops:

```
secscan run --full
→ 6 analysis request(s) await agent reasoning
  .secscan/handoff/requests/<request-id>.json   (prompt + bounded packet)
  answer into .secscan/handoff/responses/<request-id>.json, then re-run
```

- **Exit code 3** means "handoff pending". This is not an error; it is the normal
  pause point of an agent-mediated scan.
- Each request file carries the rendered prompt plus the bounded, redacted context
  packet — everything the reasoning needs, nothing else. Token budgets were already
  enforced against the serialized request before it was written.
- The answer is JSON conforming to the finding schema, written to the matching
  response file. Free-form output is rejected by the pipeline.
- Re-running `secscan run` picks up answered requests and continues. Because the
  exchange is **files**, one scan can span **multiple agent sessions** — answer
  what you can, re-run, repeat. Partial answers keep prior work.

In practice you don't read or write these files by hand: invoking the installed
`/secscan` skill in your agent drives the loop — the agent runs the pipeline,
reads the pending requests, answers them, re-runs. Progress is visible any time
with `secscan status .` (`Agent handoff: 4/6 request(s) answered`).

## The skill contract

The installed payload is `src/skill_core/SKILL.md` plus prompts, schemas, and the
knowledge bases. Its rules for the reasoning agent are non-negotiable:

1. Never load the repository into context; work only from the packets provided.
2. Prefer references (`file#symbol`) over pasting unrelated code.
3. Every finding must carry evidence — file, symbol, and why it matters.
4. Every finding must carry a CWE id **from the shipped dataset**, a CVSS-style
   severity score, and a numeric confidence.
5. Output **only** JSON conforming to the finding schema — no prose; the pipeline
   rejects free-form output.
6. No duplicate findings; no invented CWE ids.
7. Cross-segment claims must cite findings from more than one segment.
8. Never execute attacks; verification is static.
9. Reproduction steps use benign canary values, no real secrets, local/test scope
   only.

Model output is advice, not authority: locations are re-resolved against the code
model, CWE ids against the shipped dataset, and self-contradicting reports are
withheld entirely. See [Architecture — decision authority](architecture.md#decision-authority).

## Supported agents

Seven agents are supported through thin adapters over one agent-agnostic core
(`src/installer/agents/`):

| Key | Notes |
|-----|-------|
| `claude` | Claude Code |
| `copilot` | GitHub Copilot |
| `cursor` | Cursor |
| `windsurf` | Windsurf |
| `devin` | Devin |
| `agents` | Cross-vendor `AGENTS.md` convention |
| `gemini` | Gemini — its flat TOML command format is translated automatically |

`secscan agents` lists them with the skill path each one expects.

## Adding a new agent

An adapter implements three small surfaces (`src/installer/agents/base.py`):

- `skill_dir(project_root, skill_name)` — where the payload goes for this agent.
- `entrypoint(project_root, skill_name)` — the invocable command/skill file.
- `render_entrypoint(core_text, skill_name)` + `invocation_hint(skill_name)` — how
  the shared `SKILL.md` core becomes a native invocation for this agent.

The core skill text, payload, upgrade logic, and scan pipeline do not change. The
install matrix is covered by integration tests (`tests/integration/`), so a new
adapter gains end-to-end coverage by registering in the existing fixtures.
