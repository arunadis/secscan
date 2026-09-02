# Contract: init NVD Credential Flow

Interfaces this feature adds or extends. Contract tests: `tests/contract/` and
`tests/integration/test_tooling_init.py` must assert these behaviors and texts'
structure (not prose byte-for-byte, except in canonical artifacts).

## 1. CLI contract (additive to existing `init` flags)

```
secscan init [--workdir PATH] [--install[=TOOLS]] [--yes] [--no-input]
             [--allow-keyless-nvd]
```

| Flag | Effect |
|---|---|
| `--allow-keyless-nvd` | Explicit pre-authorization to install/configure NVD-backed tools without an NVD API key in non-interactive contexts (research R5). Without it, non-interactive runs skip those tools with `skipped-no-key`. |

Invariants carried over from feature 008 and extended:

- Nothing installs before the exact install list is presented and confirmed.
- Blanket consent (`--yes`, `--install` with bare `all`, config
  `tooling_install: all`) DOES NOT include a keyless NVD-backed tool: such a
  tool is filtered out of the selection unless `--allow-keyless-nvd` was given.
- Non-interactive contexts (`--no-input`, non-TTY stdin) never prompt for the
  credential decision; absence of the key defaults to `skipped-no-key`.
- The NVD key is never a CLI flag value and never a prompt answer; the
  environment is the only supply route.

## 2. Interactive credential decision protocol (FR-004 / FR-005)

When an NVD-backed tool is in scope and `NVD_API_KEY` is absent (interactive
mode only):

1. Before the tool's installation/configuration begins, print the
   registry-declared `absence_impact` (the rate-limit implication text) plus
   where to obtain a key (registry `obtain_url`).
2. Offer exactly three choices per tool:
   - **provide** — install-and-wire now, report `awaiting-key`, print the shell
     guidance (set `NVD_API_KEY` in the shell environment/profile; the key takes
     effect at scan time; re-run init to upgrade the status),
   - **proceed** — install keyless, report `degraded-no-key`,
   - **skip** — exclude from the install plan, report `skipped-no-key` with how
     to add later (FR-008).
3. The tool's installation must not start before its choice is made.

## 3. Registry entry contract (additive `credential` block)

See data-model.md §1 for fields and validation. Stability rules:

- Adding a `credential` block to an entry is a data change, no
  `registry_version` bump (additive, readers tolerate absence).
- `env_var` values are stable once shipped — the availability artifact records
  the variable NAME, and renaming it would orphan prior artifacts' meaning;
  renaming is a contract change requiring governance review (same bar as
  feature 008's stable `id` rule).

## 4. Availability artifact contract (additive field)

See data-model.md §3. Readers of `.security-scan/tooling/availability.json`
(008 crosscheck, report sections, tests) MUST tolerate records with or without
`credential`. Writers MUST emit it exactly when the entry declares a block.

The `decision` vocabulary gains one value: `skipped-no-key`.

## 5. Scan-time consumption contract

- The scanner adds NOTHING to tool invocations for the key: inheritance only
  (research R1). `runner.py`'s `invocation` string MUST NOT contain the key
  value — asserted by the SC-004 sentinel sweep.
- Credential behavior beyond init (scan-time reporting or re-checks) is OUT OF
  SCOPE for this feature: presence is an environmental property re-derivable by
  re-running init at any time, and init's record is a statement about what init
  observed and the user chose — scan-time annotation of it may be added by a
  later feature if needed.
