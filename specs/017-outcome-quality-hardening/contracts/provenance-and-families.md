# Contract: Provenance and family grouping (feature 017)

## Provenance continuity (FR-003)

`FindingNormalizer.normalize` MUST preserve `detection`, `tool_ref`, and
`code_context` on incoming deterministic-findings records exactly as it does for
secret findings. Deterministic-vs-model finding pairs that agree on
(weakness, repo, file, symbol) but differ in `tool_ref` remain distinct findings
through correlation (rule already in feature 002); when both survive to render,
the deterministic one's block keeps `Detection: format` and its rule id. If one
record absorbs the other, merged evidence MUST name both sources.

## Family grouping (FR-004)

- Identification (deterministic, conservative): findings whose evidence references
  the same identity-bearing channel token (a header/cookie name) where the token is
  shown to be identity-bearing by (a) the reading symbol carrying
  `authentication_required` / pack provenance, or (b) the channel token itself
  appearing as a `user_controlled_input` source on an auth-family path.
  The deterministic pack's evidence names the matched channel token explicitly
  (`reason` suffix "client-controlled channel: <token>") — required for the family
  contract to have anything to key on.
- Exactly one anchor per family: the finding located at the trust-decision symbol
  (pack-originated findings win ties; otherwise the location whose symbol carries
  the auth annotation).
- Dependents carry `{"type": "dependent", "reason": "same client-asserted identity
  channel (<token>)"}` to the anchor via the existing `relationships[]` field.
- Rendering: anchor's block contains a "Related findings" sub-listing of dependents
  (id + location + one-line distinction); dependents render their distinct evidence
  and link back. Both remain countable entries in band totals.

**Never**: generic token merge (channel name without an identity-bearing proof), or
family membership changing severity.
