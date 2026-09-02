# Scan profiles

Profiles control **both reporting thresholds and analysis depth**, so `quick` is
genuinely cheaper rather than just quieter, and `audit` is genuinely exhaustive.
Profiles are data — the built-ins live in
[`src/profiles/builtin.yaml`](../src/profiles/builtin.yaml) and ship inside the
installed skill payload.

Select one per scan:

```bash
secscan run --profile quick
secscan run                      # default: full
```

## Built-in profiles

| Profile | Reports | Depth |
|---------|---------|-------|
| `quick` | High/Critical severity only | 4 domains (injection, authorization, authentication, secrets), escalation ≤ 2, external scanners ingested, no system review — suited to pre-commit or CI gating |
| `full` (default) | Medium+ with confidence ≥ 0.5 | all domains, escalation ≤ 3, scanners ingested, system review on |
| `audit` | everything, regardless of severity or confidence | all domains, escalation ≤ 4 (cross-segment context), scanners ingested, system review on |

Two dimensions per profile:

- **`analysis_depth`** — which vulnerability domains are analyzed per segment, the
  evidence-escalation ceiling (1–4, see
  [Architecture](architecture.md#evidence-escalation)), whether external scanner
  output is ingested, and whether the cross-boundary system review runs.
- **`report_thresholds`** — the minimum severity band and minimum confidence a
  finding needs to appear in the report. Thresholds filter *reporting only*;
  findings still exist as artifacts, so raising the bar later needs no rescan —
  just re-render (`secscan report`).

## Custom profiles

Define your own in `profiles:` in `config.yaml`, optionally based on an existing
one:

```yaml
profiles:
  ci-gate:
    base: quick                     # inherit, then override
    report_thresholds:
      min_confidence: 0.7           # only reasonably-sure High/Critical findings gate CI
```

Then: `secscan run --profile ci-gate`.

## Per-scan overrides

Any resolved profile setting can be overridden for a single run with `--set`
(repeatable):

```bash
secscan run --set report_thresholds.min_confidence=0.8
secscan run --set analysis_depth.max_escalation_level=2
```

Use `--policy interactive|batch-offpeak` to override the configured execution
policy for one scan (see [Configuration](configuration.md)).

## Choosing a profile

- **Day to day / gating merges** — `quick`: cheap, fast, only the highest-impact
  domains and findings.
- **Regular full scans** — `full` (the default): balanced depth and noise.
- **Periodic deep review** — `audit`: maximal escalation, everything reported. This
  is the profile behind the published token-savings measurement.
