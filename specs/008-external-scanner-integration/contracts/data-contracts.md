# Contract: Data Artifacts

Schemas for the artifacts feature 008 introduces or extends. All are JSON in the `.security-scan/` store, byte-identical for identical input+tool versions (Principle I). Field-level detail lives in [data-model.md](../data-model.md); this file is the stability contract tests assert against (`tests/contract/`).

## 1. `src/skill_core/data/tools.json` (shipped, versioned)

```json
{
  "registry_version": 1,
  "tools": [
    {
      "id": "npm-audit",
      "display_name": "npm audit",
      "kind": "dependency-audit",
      "ecosystems": ["npm"],
      "covers_ecosystems": ["npm"],
      "project_local": [{"mechanism": "manifest-dep", "manifest": "package.json", "sections": ["dependencies", "devDependencies"], "names": ["npm-audit"]}],
      "system_executable": "npm",
      "version_probe": ["npm", "--version"],
      "provision_channels": [{"manager": "brew", "argv": ["brew", "install", "node"]}],
      "invoke": {"argv": ["npm", "audit", "--json"], "requires_lockfile": "package-lock.json", "requires_network": true, "report_out": "stdout"},
      "timeout_s": 120,
      "report_format": "json",
      "network": "per-run"
    }
  ]
}
```

**Stability rules**: `registry_version` bumps on breaking entry-shape change; entries are append/update only; `id` values are forever-stable (referenced by provenance and suppression records).

## 2. `.security-scan/tooling/availability.json`

`{scan_id, tool_id, applicable, source, version, invocation, network, decision}` records (see data-model). Readers must tolerate missing optional fields (`version`, `invocation`).

## 3. `.security-scan/tooling/runs.json`

`{tool_id, tool_version, db_version, status, reason, invocation, read_only_guard, finding_count}` records (no `scan_id`: scan correlation comes from store state, and embedding it would break byte-identity across identical runs). `status=failed` ⇒ non-empty `reason`; `read_only_guard=tripped` ⇒ `status=failed`.

## 4. `findings/external/*.json` (existing seam, additive)

Normalized findings gain `sources: string[]`, `raw_provenance`, and `verification`. Pre-008 readers see the existing fields unchanged.

## 5. `.security-scan/tooling/suppressions.json`

`{finding, tool_id, disproof_ground, evidence[]}` records (no `scan_id`, same byte-identity rationale); `disproof_ground ∈ {package-absent, version-outside-range, location-unresolvable, component-absent}` is a closed enum — adding a ground is a contract change requiring governance review against Principle V.

## 6. Report integration

Text/HTML reports gain two sections (additive): **External tooling** (availability + run status per tool) and **Suppressed findings** (count + per-item ground/evidence). Reports on zero-tool projects render the sections with explicit "no external tools available — coverage limitation" content.
