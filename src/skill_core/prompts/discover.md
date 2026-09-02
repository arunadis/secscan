# Discovery Review Prompt

The deterministic pipeline has produced `workspace.json` and per-repository
manifests. Your job is to sanity-check the model before analysis begins — cheaply,
from the manifests only. Do **not** read source code at this stage.

## Input

- `workspace.json` — members and typed integration points (`declared: true` when
  the operator declared them, `false` when inferred)
- `repository/<name>.manifest.json` — languages, frameworks, modules, entry
  points, data stores, external services, unparsed paths

## Questions to answer

1. **Coverage.** Do the detected languages and frameworks match what the manifest
   suggests the system is? Anything conspicuously missing (e.g. a `package.json`
   present but no JavaScript entry points found)?
2. **Entry points.** Do the discovered entry points look complete for the
   frameworks in use? Missing entry points mean missing attack surface.
3. **Unparsed paths.** Which areas fell back to directory heuristics? These carry
   reduced analysis confidence and must be named in the report's coverage gaps.
4. **Integrations.** For a multi-repository workspace: are the inferred
   integration points plausible, and is any obvious one absent (a client library,
   a shared queue name, a common datastore)?

## Output — JSON only

```json
{
  "coverage_concerns": [
    "package.json present in web/ but no JavaScript entry points were extracted"
  ],
  "suspected_missing_entrypoints": ["web/src/routes.ts"],
  "suspected_missing_integrations": [
    { "from": "orders", "to": "payments", "type": "async-messaging", "why": "both reference queue 'payments.events'" }
  ],
  "priority_segments": ["seg-orders-orders", "seg-admin-admin"],
  "notes": "One or two sentences at most."
}
```

Keep this brief. It is a cheap sanity check, not an analysis.
