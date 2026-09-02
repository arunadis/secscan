# Data Model: NVD API Key Setup During Initialization

Entities introduced or extended. Everything credential-related is presence
state by variable **name** — no secret value is ever represented in any entity.

## 1. `CredentialSpec` (registry entry extension — shipped data)

Extension of feature 008's `ToolEntry` (parsed from
`src/skill_core/data/tools.json`, optional `credential` block per entry).

| Field | Type | Required | Validation |
|---|---|---|---|
| `env_var` | string | yes | non-empty, uppercase `A-Z0-9_` (env-var-name shape) |
| `obtain_url` | string | yes | `https://` URL — where the user requests a key |
| `absence_impact` | string | yes | non-empty plain-language implication text (FR-004) |

Validation rules (strict, aggregated like `RegistryError` today):

- `credential` is optional; when present all three fields are required.
- Only one `credential` block per entry.
- An entry with a `credential` block SHOULD be `dependency-audit` kind; other
  kinds are permitted (validation allows, since the mechanism is generic).
- Entries without `credential` are untouched — the NVD-backed set is exactly
  the entries carrying a block.

## 2. `CredentialState` (enum — closed vocabulary)

The per-tool credential outcome, an attribute of the availability record:

| State | Meaning | When |
|---|---|---|
| `available` | `env_var` present and non-empty in the environment | any source |
| `awaiting-key` | user chose "provide a key"; tool installed/configured wired by name; key not yet present at this init run | interactive, FR-005(c) |
| `degraded-no-key` | user explicitly proceeded keyless (interactive) or a keyless install was explicitly pre-authorized (non-interactive flag) | FR-005(b), FR-009 |
| `skipped-no-key` | tool excluded from installation/configuration because no key — default in every non-prompting context without the opt-in flag | FR-006, FR-009, FR-010 |

State transitions (per init run, re-derived each run — nothing is sticky):

```text
(no record) → skipped-no-key          # non-interactive default, user skip
(no record) → degraded-no-key         # explicit keyless install
(no record) → awaiting-key            # install-and-wire choice, key absent
(no record) → available               # key present
awaiting-key → available              # re-run init with key set (upgrade)
skipped-no-key → any install state    # re-run init with key or opt-in (FR-008)
```

Empty/whitespace-only values count as *not provided* (spec edge case → FR-002).

## 3. Availability record extension (`.security-scan/tooling/availability.json`)

Feature 008's record gains one optional object (additive; readers must tolerate
absence per the existing §2 contract):

```json
{
  "tool_id": "owasp-dependency-check",
  "applicable": true,
  "source": "missing",
  "decision": "skipped-no-key",
  "network": "on-first-use",
  "credential": {"variable": "NVD_API_KEY", "state": "skipped-no-key"}
}
```

Rules:

- `credential` appears **only** on records whose registry entry declares a
  `credential` block — never on other tools.
- When `source == "missing"` and the key is absent without explicit keyless
  consent, `decision` is `skipped-no-key` (new closed value, additive to the
  feature-008 decision vocabulary) and `credential.state` mirrors it.
- When the tool is installed (`source != "missing"`), `decision` keeps its
  feature-008 values (`use` / `installed`); the credential outcome lives in
  `credential.state` only (`available` / `awaiting-key` / `degraded-no-key`).
- `credential.variable` holds the variable NAME from the registry block; the
  value never appears in any artifact (FR-011, SC-004).
- Sensitive-field invariant: `credential.state` and `credential.variable` are
  fixed strings; the record passes through `canonical_json`, preserving the
  byte-identity invariant across identical input+environment.

## 4. Init report rendering additions (derived, not persisted)

`InitReport.render()` gains one informational check line per NVD-backed tool,
one of:

- `tool credential: <tool_id>` — `$NVD_API_KEY is set — <tool> will run at full speed` (available; notes presence-not-validity per FR-003)
- `… awaiting key — installed and ready; set $NVD_API_KEY and it takes effect at scan time` (awaiting-key)
- `… no NVD key — <tool> runs rate-limited (explicit choice)` (degraded-no-key)
- `… skipped — no NVD key; set $NVD_API_KEY and re-run init to add it` (skipped-no-key, includes FR-008's "how to add later")

All `required=False` — a credential outcome never flips `InitReport.ready`.
