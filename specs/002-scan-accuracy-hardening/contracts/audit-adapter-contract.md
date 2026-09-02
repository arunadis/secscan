# Contract: Native Dependency Audit Adapter

One adapter per ecosystem, mirroring the existing external-scanner adapter pattern in
`pipeline/adapters/`. Adapters live in `pipeline/audits/` and are selected per workspace member from
that member's detected ecosystem (FR-030a).

## Interface

```python
class AuditAdapter(Protocol):
    ecosystem: str          # "npm" | "pnpm" | "yarn" | "python" | "go" | "maven" | "gradle"
    capability: str         # "native-advisory" | "coordinates-plus-offline-match"

    def detect(self, root: Path) -> bool:
        """True when this member uses this ecosystem. Manifest presence only — no execution."""

    def available(self) -> Availability:
        """Is the toolchain present and runnable? Never raises; never installs."""

    def audit(self, root: Path, member: str, *, timeout_s: int) -> AuditOutcome:
        """Read-only. Returns advisories | clean | could-not-check. Never raises."""
```

`AuditOutcome` carries `status`, `advisories[]`, `reason`, `remediation_command`, `tool`,
`tool_version` — the Audit Outcome entity in `data-model.md`.

## Hard guarantees

Every adapter must satisfy all of these; each is asserted by a contract test.

1. **Read-only** (FR-031). No install, no upgrade, no manifest or lockfile write. Enforced by
   hashing every manifest and lockfile under the member root before and after `audit()` and failing
   the test on any change. Commands that mutate — `npm audit fix`, `npm install`, anything that
   resolves and downloads a build plugin — are prohibited.
2. **Never raises.** A missing toolchain, a non-zero exit, a timeout, unparseable output, or a
   network error all map to `could-not-check` with a reason (FR-033).
3. **`clean` means audited and clean.** Any uncertainty is `could-not-check`. Conflating the two is
   the single worst failure available to this adapter, since it converts an unknown into a
   reassurance (Edge Cases).
4. **Deterministic output.** Adapter output is a *normalized projection*, never verbatim tool output.
   Volatile fields are discarded and all collections sorted. `npm audit --json` is known to vary
   between runs in `via`, `effects`, and `fixAvailable` (research.md A2), so those fields must not
   reach an artifact.
5. **Runtime vs development is explicit** (FR-032). Where the tool cannot express it, the adapter must
   mark `exposure` from dependency scope, not guess.
6. **Bounded.** A per-member timeout is mandatory; expiry is `could-not-check`, not a hang.
7. **No credential exposure.** Registry tokens may appear in tool output or error text; adapter
   output passes through the redactor before it is written, exactly as reproduction blocks do.

## Commands

Verified in research.md A2. Every command is read-only.

| Adapter | Capability | Command |
|---|---|---|
| `npm` | native-advisory | `npm audit --json --omit=dev --package-lock-only` |
| `pnpm` | native-advisory | `pnpm audit --json --prod` |
| `yarn` (Berry ≥ 2) | native-advisory | `yarn npm audit --json --environment production --all --recursive` — **NDJSON** since 4.0.1 |
| `yarn` (Classic) | native-advisory | `yarn audit --json --groups dependencies` — JSON-lines |
| `python` | native-advisory | `pip-audit --format json` (`--locked` for PEP-751; `poetry export` / `uv export` upstream) |
| `go` | native-advisory | `govulncheck -json ./...` (`-db file://…` when a local DB is present) |
| `maven` | coordinates-plus-offline-match | `mvn -o -q dependency:list` → match against the bundled OSV Maven export |
| `gradle` | coordinates-plus-offline-match | `gradle -q dependencies` → same matcher |

**Why Java differs**: Java has no read-only native audit. OWASP `dependency-check` would make Maven or
Gradle resolve and download a plugin artifact, which guarantee 1 forbids. Rather than break FR-031 or
leave a parsed language uncovered (FR-030d), Java enumerates resolved coordinates in offline mode and
matches them against a bundled advisory export. Same output shape, same guarantees.

## Field mapping

Adapters normalize onto the Dependency Advisory entity. Mapping per tool:

| Target field | npm / pnpm | yarn Berry | pip-audit | govulncheck | maven / gradle |
|---|---|---|---|---|---|
| `package` | `vulnerabilities.<k>.name` | `value` | `name` | `Trace[].Module` | coordinate `groupId:artifactId` |
| `affected_range` | `.range` | `Vulnerable Versions` | derived from `version` + `vulns[].fix_versions` | OSV `ranges` | matched OSV range |
| `fixed_version` | `.fixAvailable` (**normalized**, volatile) | `Patched Versions` | `vulns[].fix_versions` | `FixedVersion` | matched OSV `fixed` |
| `advisory_ids` | `.via[].source`/`url` | `ID` | `vulns[].id` + `aliases` | OSV `id` | OSV `id` |
| `severity` | `.severity` | `Severity` | from advisory | from advisory | from advisory |
| `exposure` | `--omit=dev` ⇒ runtime | `--environment production` | export scope | n/a (no dev split) | scope ≠ `test`/`provided` |

Severity strings (`low`/`moderate`/`high`/`critical`) map to the existing CVSS-style band thresholds in
`pipeline/cwe.py`; the numeric score is taken from the advisory when present, otherwise from the band
midpoint, and which of the two was used is recorded.

CWE assignment: dependency findings map to **CWE-1035 / CWE-1104** (use of vulnerable or unmaintained
third-party components), both already present in the shipped taxonomy.

## Monorepo attribution

Ordered fallback for a hoisted lockfile covering several members (FR-030e/FR-030f):

1. **Native per-member.** `npm audit --workspace=<name> --json` yields per-workspace output even with
   one hoisted lockfile. Preferred whenever the ecosystem supports it.
2. **Manifest mapping.** Map the advisory's package back to the members whose own manifests declare
   it, directly or transitively as far as the lockfile permits.
3. **Workspace-level.** `attribution = "workspace-not-derivable"`, and the report says so.

Guessing and broadening to every member are both prohibited (FR-030f).

## Merging with external scanners

Native audits run only where a dedicated scanner has not already covered the domain for that member.
Where both produce results, findings merge on `(ecosystem, package, affected_range)` — the Dependency
Advisory identity — so a domain is never double-reported (spec Dependencies). The surviving finding
records both sources in `audit_source`.

## Stack currency

Separate from advisories: `stack_currency.py` reads declared language, runtime, and framework versions
from manifests and compares them against `skill_core/data/eol.json`, emitting a finding per
past-support-window component independent of any individual advisory (FR-034). Dataset staleness is
itself reported.

## Test matrix

| Case | Asserts |
|---|---|
| manifest + lockfile, toolchain present, advisories exist | advisories parsed; runtime/dev split correct (FR-032) |
| toolchain absent | `could-not-check` + `remediation_command`; per-member gap (FR-030c) |
| network unreachable | `could-not-check`, never `clean` (FR-033) |
| manifest, no lockfile | `version_ambiguous` set (FR-035) |
| mixed-ecosystem workspace | each member audited against its own ecosystem (FR-030a) |
| shared package across members | one finding, all members attributed (FR-030b) |
| hoisted lockfile | per-member attribution, else `workspace-not-derivable` (FR-030e/f) |
| same advisory twice through different paths | grouped once (Edge Cases) |
| any adapter run | manifest and lockfile hashes unchanged (FR-031) |
| two consecutive runs | byte-identical artifacts (SC-013) |
| tool output containing a registry token | redacted before write |
