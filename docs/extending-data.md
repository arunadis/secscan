# Extending the knowledge bases

Four data files under `src/skill_core/data/` drive every decision the accuracy
stages make. Adding a stack, a rule, or a framework control is a **data change**
and must never require touching a pipeline stage (FR-013c, FR-022d, FR-025b).

Inspect what is shipped and how stale it is:

```bash
secscan data                 # versions, counts, staleness
secscan data --refresh-eol   # how to refresh the support-window snapshot
```

All four files carry `version` and `dataset_date`, are sorted for determinism, and
are loaded read-only. They ship inside the installed skill payload, so a scan needs
no network access.

---

## `applicability.json` — weakness class × architecture

Decides when a weakness class is **structurally impossible** for a target, so the
finding can be remapped to a defensible class instead of misrouting a reviewer.

```json
{
  "cwe": "CWE-918",
  "requires_any": ["server-request-issuer"],
  "alternatives": ["CWE-20", "CWE-116"],
  "rationale": "why this is impossible by construction, not merely unlikely",
  "evidence": "where the claim came from"
}
```

**The bar for adding an entry is high, and deliberately so.** A wrong suppression
is a false negative, and the review that motivated this work showed that to be the
more damaging error direction. So:

- `requires_any` may only list architectures on which the class is possible **by
  construction**. "Unlikely in practice" is not impossibility.
- `alternatives` must be non-empty. Suppression without a replacement discards a
  real code fact — the loader rejects an entry that tries.
- `undetermined` may never appear in `requires_any`. The loader rejects that too:
  an unknown architecture must never satisfy a structural requirement.

Both fields are validated against the shipped CWE dataset, so a class you name
must exist in `cwe_map.json` first.

## `framework_controls.json` — default protections and their bypasses

```json
{
  "id": "angular",
  "detect": ["@angular/core"],
  "escapes_by_default": true,
  "controls": [{
    "id": "angular-dom-sanitizer",
    "mitigates": ["CWE-79"],
    "residual_impact": "what the control still permits",
    "sinks": ["[innerHTML]"],
    "bypasses": ["bypassSecurityTrustHtml"]
  }]
}
```

- `escapes_by_default` is **required** and must be stated explicitly. The loader
  refuses an entry without it, because defaulting it either way is exactly the
  guess this work exists to remove. Jinja2 and JSP are `false`.
- A control that only applies when configured carries `requires_config`, and is
  then reported as `unassessed` rather than credited until that configuration is
  found.
- `bypasses` must be non-empty: a control with no known bypass could never be
  discredited, so it would be credited unconditionally.
- `residual_impact` is what the report's impact paragraph is rewritten to when the
  control is credited, so a reduced severity never sits beside a narrative
  describing the impact the control prevents.

## `stacks.json` — languages, templates, ecosystems

The single answer to "the languages the code model parses". A **grammar-backed**
language is one with an entry in `pipeline.extract._GRAMMARS`; suffixes that are
merely enumerated (`.sql`, `.tf`) are not, and impose no template or ecosystem
requirement.

Adding a language means:

1. a `languages[]` entry with its suffixes, grammar entry point, template forms
   and package ecosystem;
2. a `template_forms[]` entry per dialect, using `tree_sitter_html:language` for
   markup or `delimiter-pass` for expression-level sinks;
3. an `ecosystems[]` entry naming its audit adapter and capability class.

`tests/unit/test_data_files.py` asserts the descriptor set has not drifted from the
loaded grammars, so forgetting step 1 fails the build rather than silently
narrowing template coverage.

## `eol.json` — end-of-support windows

A pinned snapshot of [`endoflife-date/release-data`](https://github.com/endoflife-date/release-data)
(MIT). `identifier_map` exists because package-manager names and dataset product
ids do not coincide.

Refresh is an **explicit operator action**. An implicit network fetch would break
both the offline guarantee and byte-identical determinism, so `--refresh-eol`
prints instructions rather than doing it. When the snapshot passes
`staleness_threshold_days` (default 90), the report says so — an out-of-date
snapshot is disclosed, never presented as current.

---

## Adding an audit adapter

Adapters live in `src/pipeline/audits/` and subclass `AuditAdapter`. Implement
`_command()` and `_parse()`; the base class supplies the guarantees. Every one is
asserted by `tests/contract/test_audit_adapters.py`:

| Guarantee | Why it is absolute |
|---|---|
| Read-only | A tool that mutates the project cannot be run where it is most needed |
| Never raises | A crashed adapter must degrade to a stated gap, not a failed scan |
| `clean` means audited and clean | Anything else converts an unknown into a reassurance |
| Normalized output | `npm audit --json` varies between runs; artifacts must not |
| Bounded by a timeout | Expiry is `could-not-check`, never a hang |

If an ecosystem has no read-only native audit — Java is the case in point, since
OWASP dependency-check would make Maven download a plugin — use the
`coordinates-plus-offline-match` capability instead of relaxing the read-only rule.
