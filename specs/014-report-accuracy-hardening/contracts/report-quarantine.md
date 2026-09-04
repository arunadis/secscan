# Contract: Narrative Reference Resolution + Quarantine (FR-010)

Owner stages: `src/pipeline/generate_report.py` (`resolve_narrative_references` pre-gate in `write()`), `src/pipeline/consistency.py` (residual rule), `src/pipeline/scan_cli.py` (exit status).

## Surface

- **Input**: built report object + system review narrative, before any rendering.
- **Output**: report (possibly with `quarantined_sections`; offending sections removed from the published object path), plus a boolean defect signal that `cmd_run` maps to exit code.

## Reference domain

- Identifier syntax: `SEC-\d{4,}`.
- Stance (deliberate): ANY token matching the identifier syntax in a scanned
  section is treated as a reference and must resolve. Narrative-producing code
  (pipeline or agent prompts) must never emit identifier-shaped tokens except
  as real references. Determinism is chosen over intent-inference — there is no
  "this was just an example" escape hatch, because one cannot be decided
  without a judgment call.
- Sections scanned: system review text, cross-system findings, attack paths, recommendations. Findings' own fields are built from admitted IDs and are out of scope.
- Validation target: identifiers admitted to the report (`findings_by_band`), not all known findings — a reference to a suppressed/filtered finding is dangling for this report.

## Decision rules (clarification Q5: quarantine + publish)

1. Pre-gate resolution: any scanned section containing ≥1 unresolvable reference is REMOVED from the published report and appended to `quarantined_sections` (`{section, dangling_id, reason}`).
2. Residual strict check: after quarantine, `consistency.enforce(strict=True)` gains a rule family asserting zero remaining unresolvable references; survival of one is a pipeline bug and raises `ReportInconsistent` (publication blocked) — this branch must be unreachable from user data.
3. Publication proceeds with the redacted/guaranteed-clean sections; rendered Markdown/HTML state the omission inline ("Narrative section 'System-Level Review' omitted: referenced SEC-0006, which is not part of this report").
4. Exit status: `EXIT_REPORT_DEFECT = 4`. Returned by `cmd_run` iff `quarantined_sections` non-empty. JSON report, `.md`, `.html`, `usage.json` all written normally; `state.json` records stage completion as today.
5. Frozen interface: the three stdout summary lines are unchanged. The defect surfaces via exit code, the report body, and `scan.log` (progress reporter).

## Determinism guarantees

- Reference extraction is a fixed regex over fixed section order; quarantine list sorted by `(section, dangling_id)`.
- Clean reports are byte-identical to pre-014 output (field absent, not empty).

## Failure modes

| Condition | Behavior |
|---|---|
| All narrative sections quarantined | Report still publishes findings; every omission declared; exit 4 |
| Reference admitted in JSON view but filtered in a per-repo view | Per-repo view elides/flags consistently (`report_view` recomputation extended to narrative sections) |
| `ReportInconsistent` from residual rule | Non-zero exit via existing error path; treated as defect in the pipeline, never in user data |
