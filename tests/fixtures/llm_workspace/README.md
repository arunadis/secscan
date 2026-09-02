# LLM fixture workspaces (spec 007)

Seeded fixture repositories for the prompt-injection / modern-exploit category.
Ground truth is declared in `tests/benchmark/cases/llm_scan.json` and
`tests/benchmark/cases/supply_chain.json`; each workspace below is referenced by
those cases.

- `us1_direct/` — direct prompt injection surfaces (vulnerable) and structured
  separation counterparts (must not report)
- `us2_indirect/` — external-content ingestion into model context (bounded vs
  unbounded)
- `us3_agent_config/` — over-privileged vs scoped AI config artifacts
- `us4_supply_chain/` — confusion-vulnerable vs hardened dependency manifests
