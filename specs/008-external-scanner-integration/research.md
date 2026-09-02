# Research: External Scanner Tooling Integration

Phase 0 output for feature 008. Every decision below was resolved against existing codebase patterns (`pipeline/audits/`, `pipeline/ingest_findings.py`, `pipeline/init_cmd.py`, `skill_core/data/`) and documented tool behavior; the Technical Context had no NEEDS CLARIFICATION markers.

## R1 — Tool registry format and location

- **Decision**: A single versioned JSON document, `src/skill_core/data/tools.json`, keyed by tool id, loaded and validated by `pipeline/tooling/registry.py`.
- **Rationale**: Constitution mandates extensibility-as-data and no-on-demand-downloads for the scanner itself; the project already ships `stacks.json`, weakness taxonomies, and `advisories/*.json` this way. Adding npm-audit-style tools or OWASP Dependency-Check entries must be a data edit, not a pipeline change (FR-001).
- **Alternatives considered**: Python module per tool (rejected — pipeline change per tool, violates extensibility-as-data); user-editable config registry (deferred — ship the built-in registry first; user extension is additive later).

## R2 — Read-only execution modes per tool

Each registry entry declares its read-only invocation; analysis: take each candidate tool and pin the mode that never writes into the scanned project, reusing `audits/base.py`'s manifest/lockfile fingerprint guard and timeout discipline.

- **Decision**:
  - **npm audit** — `npm audit --json` against the project directory; read-only, driven by `package-lock.json`. Requires a lockfile and network (or a warm `npm` cache); without a lockfile the tool is reported skipped with that reason rather than attempted.
  - **pip-audit** — `pip-audit -r requirements.txt -f json`; read-only; network or populated cache required; absence of lock pins is the existing offline baseline's job.
  - **govulncheck** — `govulncheck -json ./...`; read-only against the project (build cache lives outside the project); network for vuln db unless cached.
  - **OSV-Scanner** — `osv-scanner --lockfile=<path> --format=json`; read-only; supports lockfile-only scanning without network when an offline DB is provided, else declared network.
  - **Semgrep** — `semgrep scan --json --config <registry ruleset or local config>`; read-only; ruleset fetch declared as network unless vendored.
  - **Gitleaks** — `gitleaks detect --source <path> --no-git --report-format json --report-path <store dir>`; read-only against sources; report file written into the scanner store, never the project.
  - **Trivy** — `trivy fs --format json <path>`; read-only; vulnerability DB cache lives in the user cache dir, outside the project, declared as network on first use.
  - **OWASP Dependency-Check** — two modes: (a) **project-provided**: when the Maven/Gradle plugin is already declared in `pom.xml`/`build.gradle(.kts)`, invoke via `./mvnw`/`./gradlew` (or system `mvn`/`gradle`) `dependency-check:check` / `dependencyCheckAnalyze` with report output redirected into the scanner store; (b) **provisioned**: standalone CLI (`dependency-check.sh|bat`) with `--scan <project> --out <store dir> --data <user cache dir>`; NVD data directory always outside the scanned project. The plugin-download path (`mvn org.owasp:dependency-check-maven:check` on an undeclared project) is **rejected** as a default because it mutates effective build state; it is usable only as the project-provided route.
- **Rationale**: FR-004 requires a byte-identical project before/after; the fingerprint guard turns "read-only" from a promise into a check. Redirecting all report/data/cache directories outside the scanned project also satisfies FR-012 and the scanner-ignores-itself invariant.
- **Alternatives considered**: Running tools with default output locations inside the project and deleting after (rejected — mutation even if transient, and unverifiable); sandboxing via containers (rejected for v1 — adds a runtime dependency the constitution forbids on the default path).

## R3 — Project-local tool discovery (FR-003a)

- **Decision**: Registry entries carry declarative `project_local` discovery rules evaluated read-only against manifests: (a) **Node**: name present in `package.json` `devDependencies`/`dependencies`, or executable under `node_modules/.bin/`; (b) **Maven**: plugin GAV declared in `pom.xml` build/plugins; (c) **Gradle**: plugin id in `build.gradle[.kts]` plugins block or settings; wrapper scripts (`gradlew`/`mvnw`) detected by file presence; (d) **Go**: module in `go.mod` `tool` directives or `go run`-able tool modules; (e) **Python**: tool in project dev-requirements or a project-local virtualenv bin directory. System discovery remains `shutil.which`. Precedence: project-provided over system-installed; compatibility declared undetermined when version constraints cannot be evaluated.
- **Rationale**: Matches the spec clarification directly; manifest inspection is already the ecosystem-detection mechanism (`offline.py` `_iter_manifests`), so discovery composes on existing parsers with no new dependencies.
- **Alternatives considered**: Executing project build files to resolve plugins (rejected — executing arbitrary build logic violates observe-never-attack and determinism); probing well-known tool subdirectories (kept only for `node_modules/.bin`, which is a pure filesystem check).

## R4 — Provisioning channels

- **Decision**: Registry entries declare an ordered list of install channels (e.g., `brew`, `npm -g`, `pipx`, `go install`, release-archive download), each with the exact command template. The provisioner selects the first channel whose package manager exists and installs into that manager's user-level prefix (brew/pipx/go manage their own locations; scanner-managed downloads, caches, and databases live under the scanner's canonical tooling directory, outside both the scanned project and the payload), then verifies with the entry's version probe before marking installed. Determinism of availability records is preserved by scan-time re-probing (R8), not by pinning the install location. Unattended mode: `--install` flag (optionally naming a subset); interactive: present list, accept/deselect per tool, then install confirmed subset.
- **Rationale**: Selective confirmation (spec Q2) requires per-tool granularity; channel ordering gives deterministic, documented behavior across platforms.
- **Alternatives considered**: Package-manager auto-detection scanning every channel (rejected — slower, non-deterministic ordering); single mandated channel per tool (rejected — macs use brew, minimal Linux CI lacks it).

## R5 — Ingestion, dedupe, and native-audit displacement

- **Decision**: Adapters write normalized findings to the existing `findings/external/*.json` store paths; `load_external_findings` + `covered_domains` in `pipeline/ingest_findings.py` stay the single dedupe/displacement seam. `DEPENDENCY_SCANNERS` becomes registry-derived (each entry declares `covers_ecosystems`). The documented trap is preserved: a native audit is skipped only when an external scanner actually produced findings for that domain in this scan. Dedupe across sources keys on advisory identity — `(ecosystem, package, affected_range)` aligned with `Advisory.identity`, intersected with shared advisory ids (CVE/GHSA) where present — and merged findings record every contributing source in provenance.
- **Rationale**: The seam was explicitly designed for this ("Until 001's adapters land…"), the empty-adapters state proves the default behavior is safe by construction, and reusing `Advisory.identity` keeps one definition of "same advisory".
- **Alternatives considered**: New parallel merge stage (rejected — two dedupe owners is exactly the precision failure `ingest_findings.py` was written to prevent).

## R6 — Cross-check and structural disproof (FR-007/008)

- **Decision**: `pipeline/crosscheck.py` evaluates every ingested external finding against: (1) resolved dependency pins from `offline.extract_components` — package absent, or resolved version outside the vulnerable range (existing `_version_parts`/`_version_affected` comparators); (2) tiered location resolution from feature 002 — a cited file/symbol that does not resolve is structural disproof; (3) component presence in the code model. Only these grounds suppress. Anything else — including reachability — retains the finding with the existing `verified`/`plausible`/`undetermined` verification state. Each suppression writes a record `{finding identity, tool, disproof ground, evidence}` to an additive `tooling/suppressions.json` artifact plus a human-visible report section.
- **Rationale**: Direct implementation of clarification Q1 (structural-only); reuses shipped comparators and the location gate instead of building new machinery; suppression-without-audit-trail is the precise failure mode the suppression list exists to prevent.
- **Alternatives considered**: Reachability-based suppression via the call graph (rejected by clarification and Principle V — uncalled ≠ disproven); suppression as a finding flag rather than a separate list (rejected — a suppressed finding in the findings array reads as reported; a separate section keeps the signal unambiguous).

## R7 — Provenance and determinism with evolving advisory data

- **Decision**: Every tool run records `{tool_id, tool_version, db_or_ruleset_version, invocation, started/ended}` in a `tooling/runs.json` artifact; findings carry `sources: [...]` (multi-contributor after dedupe). Byte-identical output is asserted for identical input *plus identical tool/db versions* — the wording Principle I already uses ("identical input plus identical tool version").
- **Rationale**: External advisory content evolves by definition; the honest answer is provenance, not freezing third-party data. Fixtures pin recorded tool output so tests stay deterministic.
- **Alternatives considered**: Vendoring advisory DBs per run (already covered by the bundled offline baseline — external tools exist to go beyond it).

## R8 — Interaction between init availability state and scan runs

- **Decision**: Init persists a `tooling/availability.json` record in `.security-scan/`; the scan reads it but **re-probes cheaply** (`shutil.which`, manifest rules) at run time, because machines change between init and scan. Availability is therefore a per-scan Tool Availability Record, not a cached truth.
- **Rationale**: Honest-uncertainty discipline — a stale availability claim is exactly the kind of silent gap this project's audits layer exists to eliminate.
- **Alternatives considered**: Persist-and-trust (rejected — silent drift).
