# Partition Review Prompt

The pipeline has partitioned the workspace into segments along module and
security boundaries. Review the partitioning from `segments/*.json` **only** — no
source code.

## Why this matters

A segment should be a meaningful security or business boundary (authentication,
payments, file upload, admin), not an arbitrary slice. Bad boundaries hide the
cross-component flaws this pipeline exists to find.

## Questions to answer

1. **Cohesion.** Does each segment represent one coherent responsibility? Flag
   segments that mix unrelated concerns.
2. **Splits that hide flows.** Are two segments so tightly coupled that a
   vulnerability spanning them would be missed? Name the pair.
3. **Domains.** Are the assigned `domains` right for each segment? Flag a segment
   whose domains omit something its purpose implies (e.g. an upload segment
   without `file-handling`).
4. **Priority.** Which segments deserve the deepest analysis? Rank by exposure
   (external entry points), sensitivity (data touched), and blast radius.

## Output — JSON only

```json
{
  "merge_suggestions": [
    { "segments": ["seg-a", "seg-b"], "why": "single request flow split across both" }
  ],
  "split_suggestions": [
    { "segment": "seg-misc", "why": "mixes auth and reporting concerns" }
  ],
  "domain_corrections": [
    { "segment": "seg-upload", "add": ["file-handling", "path-traversal"] }
  ],
  "priority_order": ["seg-auth", "seg-payments", "seg-admin"],
  "notes": "One or two sentences at most."
}
```

Do not restructure segments yourself; the pipeline owns partitioning. Report only.
