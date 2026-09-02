# Research: NVD API Key Setup During Initialization

All Technical Context items resolved — none remained NEEDS CLARIFICATION. The
decisions below are the ones with real alternatives.

## R1 — How the key reaches Dependency-Check at scan time

**Decision**: Nothing is injected into the invocation. The key reaches the tool
by OS environment inheritance: `secscan scan` runs tool subprocesses with the
inherited environment (`runner.py` uses `subprocess.run` without an `env`
override), and OWASP Dependency-Check ≥ 9.0.4 reads the `NVD_API_KEY`
environment variable itself (feature "Allow to pass NVD API key via environment
variable", DependencyCheck #6443/#6454; the core `Settings` lookup maps the
`nvd.api.key` property to the uppercase-underscore env var). ODC additionally
masks `nvd.api.key` in its own logs (GHSA-qqhq-8r2c-c3f5 fix).

**Rationale**: The constitution requires credentials to be supplied only by
environment-variable *name*; environment inheritance is the only mechanism that
never moves the value into scanner code, config, argv, or artifacts. The
alternative delivery mechanisms all violate a rule: `--nvdApiKey <value>` on the
command line exposes the value in the process list and would be captured in the
`invocation` string recorded in `runs.json`; `nvd.api.key` in a properties file
persists the secret to disk; the Maven plugin's `settings.xml`
`nvdApiServerId` route writes the key into a user-level Maven config the scanner
must not create.

**Alternatives considered**: CLI argument `--nvdApiKey` (rejected — leaks into
process listing and recorded invocation strings); ODC properties file (rejected
— persists the secret, and init may not write user-level config);
`mvn -Dnvd.api.key=...` on the project-provided route (rejected — same argv
leak).

## R2 — Does the environment-variable route cover BOTH Dependency-Check routes?

**Decision**: Yes for the provisioned CLI route (`dependency-check.sh`) and the
project-provided Maven route, with one honest caveat. The env-var lookup lives
in ODC *core* `Settings`, which both routes use. The Gradle plugin also passes
through core Settings. If an unknown future ODC version dropped env-var support
for one integration, that surfaces as a keyless (slow) run — declared behavior,
since init reports *presence, not validity* (FR-003) and never claims the tool
has consumed the key.

**Rationale**: Verifying consumption would require a live scan; FR-003 forbids
network validation of the credential.

## R3 — Where the NVD-backing declaration lives

**Decision**: An optional `credential` block on the registry entry in
`src/skill_core/data/tools.json`, parsed and strictly validated in
`registry.py`:

```json
"credential": {
  "env_var": "NVD_API_KEY",
  "obtain_url": "https://nvd.nist.gov/developers/request-an-api-key",
  "absence_impact": "<plain-language rate-limit implication from FR-004>"
}
```

The NVD-backed tool *set* (spec Key Entities) is simply "entries carrying a
`credential` block". `registry_version` stays `1` — the block is optional and
additive; existing readers ignore unknown keys, and the constitution's
additive-schema rule applies.

**Rationale**: Extensibility as data (constitution quality gate): the next
NVD-backed tool is a data edit, not a pipeline change. `absence_impact` being
registry data keeps the user-facing warning with the tool it describes instead
of hardcoding ODC facts in `init_cmd.py`.

**Alternatives considered**: A hardcoded `{tool_id: env_var}` map in
`credentials.py` (rejected — new pipeline edit per tool, against
extensibility-as-data); a separate `credentials.json` data file (rejected — a
second registry to validate and keep in sync; the credential is an attribute of
the tool).

## R4 — Where the credential state is recorded

**Decision**: Additive `credential` object on the affected records in
`.security-scan/tooling/availability.json`:

```json
"credential": {"variable": "NVD_API_KEY", "state": "awaiting-key"}
```

with `state` a closed enum: `available` | `awaiting-key` | `degraded-no-key` |
`skipped-no-key`. Feature-008 contract readers already must tolerate missing
optional fields (`specs/008.../contracts/data-contracts.md` §2), and the
canonical writer in `tooling/state.py` is field-agnostic — no writer change.

**Rationale**: Spec FR-007's four report states must be *derived from a record*,
not recomputed ad hoc, and the availability artifact is where feature 008
already persists per-tool init decisions consumed at scan time (`crosscheck.py`,
crosscheck tests, report sections).

**Alternatives considered**: A separate `credentials.json` artifact (rejected —
splits the tool's outcome across two artifacts; nothing else consumes it);
embedding the state in `decision` (rejected — `decision` describes install
consent in feature 008's contract; overloading it breaks its closed vocabulary
and existing readers).

Precedence note: `skipped-no-key` implies `decision: "skipped-no-key"` on the
*missing* record (new closed value, additive); for an already-present tool the
record's decision stays `use` and only the `credential.state` carries the
credential outcome (`available`, `degraded-no-key`, or — for the
install-and-wire path — `awaiting-key`).

## R5 — Non-interactive explicit opt-in for keyless installation

**Decision**: A dedicated, documented init flag: `--allow-keyless-nvd`
(`run_init(..., allow_keyless_nvd: bool = False)`). Default `False`: in any
non-prompting context (`--no-input`, non-TTY stdin, `--yes`, `--install all`),
keyless NVD-backed tools are removed from the selection and recorded
`skipped-no-key`. The flag is the ONLY way to install them keyless unattended.

**Rationale**: FR-009/FR-010 require that opt-in be explicit and that blanket
consent never silently permits degraded install. Piggy-backing on `--install`'s
value string (e.g. a magic token) would conflate *which tools* with *under what
credential policy* — two decisions in one string, harder to document and audit.

**Alternatives considered**: Config-file preference `tooling.allow_keyless_nvd`
(rejected for v1 — a config flag silently applies forever, weakening FR-010 for
every future run; a per-invocation CLI flag keeps the exception explicit per
run; can be revisited as a follow-up); magic token in `--install` (rejected as
above).

## R6 — Presence check semantics

**Decision**: `environ.get("NVD_API_KEY")` non-empty (after `strip()`) ⇒
available. Empty or whitespace-only ⇒ not provided (spec edge case). No key
format validation, no network validation (FR-002, FR-003). The check takes the
injected `environ` mapping, identical to `run_init`'s existing injection point,
so every flow is testable hermetically.

**Rationale**: Mirrors the existing `mode_mod.credential_status` pattern in
`init_cmd.py` (presence by variable name). Whitespace-only values are
operationally absent and treating them as provided would be a false positive in
the one direction the spec forbids (an "awaiting"/"available" claim that is not
true).

## R7 — Interactive prompt ordering

**Decision**: The credential warning/choice happens when the *install list is
presented* (existing `_tooling_flow` presentation point), before any install
runs — for each NVD-backed tool individually when more than one exists (future),
each with its own skip/provide/proceed choice. Already-present NVD-backed tools
get the presence check + status report without any install-side prompt (they
are not on the install list), surfacing `degraded-no-key` as an informational
check line, never prompting to uninstall.

**Rationale**: FR-004 requires the warning before any installation of the tool
begins; feature 008's contract already guarantees nothing installs before the
list is presented — the credential choice belongs at the same decision point so
the user makes one coherent consent decision.
