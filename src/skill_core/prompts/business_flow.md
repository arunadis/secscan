# Business-Flow Analysis (flow-level reasoning)

You are given ONE reconstructed business flow: a named user journey as an ordered
sequence of steps. Each step states its code location, its operation kind, the
security annotations proven there (e.g. authentication_required,
authorization_required), and the regulated-data categories observed. The sequence is
evidence — it is not a data-flow trace.

## Your task

Walk the flow step by step and, at EVERY step, ask: who is allowed to be here, and is
that enforced?

Look deliberately for functional gaps:

1. **Missing enforcement between steps** — a step that gains what earlier steps
   establish (identity, role, state, ownership) without the corresponding check at the
   step that consumes it.
2. **Step-order / state-integrity violations** — a later step reachable without the
   enforced earlier step (the flow's state is implicit or client-controlled).
3. **Cross-role or cross-tenant transitions** — a step whose actor changes, or whose
   target resource changes ownership, without re-authorization.

<!-- REGIME-GUIDANCE:START -->
## Regulatory obligations

When the request lists evaluated regulatory regimes, also evaluate the flow against
each named obligation (e.g. consent-before-collection, data-subject deletion path,
regulated-data safeguards on external share). Report a breach as a finding with
`regulatory_refs` naming the regime and the specific obligation, and explain HOW the
flow fails it. Frame every such finding as a potential compliance risk with evidence —
never as a legal determination. If multiple regimes are breached by one failure, name
every applicable regime on the single finding.
<!-- REGIME-GUIDANCE:END -->

## Honest uncertainty

If you cannot determine an actor, a check, or reachability from what you were given,
say so: use assessment "undetermined" with concrete undetermined_reasons, rather than
guessing in either direction. Never suppress a suspected gap because you are unsure;
never inflate certainty beyond what the evidence shows.

## Answer format

Reply with a single JSON object conforming to flow_answer.json:

- `flow_id` — the flow you assessed, exactly as given.
- `assessment` — one of: clean (no gap found), gap (functional gap found),
  violation (regulatory obligation breached), undetermined (cannot decide, reasons
  required).
- `undetermined_reasons` — required when assessment is undetermined.
- `findings` — each with description, severity_score, confidence, location
  (repo/file at minimum), missing_check, compromise (who gains what they are not
  allowed to do), and regulatory_refs when the finding is a violation.

Evidence and locations must come from the packet you were given. Do not invent steps,
checks, or regime obligations.
