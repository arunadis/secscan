# Contract: Presentation dedupe & triage batching (feature 017)

## Coverage notes (FR-006)

- Builder progress warnings keep their level-specific text (per-stage diagnostics).
- Report-visible coverage notes are deduped by `(segment, cause, files)` after
  stripping the escalation-level phrase ("at level N"). The surviving line states:
  the (file, segment, cause) set once, listing levels in a set clause when more
  than one level dropped the same file.
- Same post-processing removes duplicated `SECURITY-CRITICAL` markers.

## Tool limitations (FR-007)

When a tool is skipped for an input it needs (e.g. lockfile), the reported reason
MUST distinguish:

- the file is absent from the project ("this project does not have …"), vs
- the file exists but was excluded from analysis context (budget/test scope):
  "present but outside analysis scope (budget-dropped)".

Deriving membership: the member's enumerated file list (the same list that segments
carried before drop), re-checked at report build.

## Triage question batching (FR-008)

- Report's Awaiting Verification: one entry per question text, with
  `finding_ids` listing every bound finding. Per-finding entries are retained under
  the entry's member list.
- Declarations: file schema unchanged (`finding_ref` + `question` + `answer` binding);
  application maps the answered question across all findings asking exactly that
  text. Drift rules and lapse semantics unchanged (existing FR-018/019/020 of
  feature 013).
