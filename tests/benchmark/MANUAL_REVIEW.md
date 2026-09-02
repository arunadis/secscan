# Manual validation gate

Two success criteria in `spec.md` cannot be discharged by a test:

- **SC-006** — "0 filed findings have a severity an *expert reviewer* judges overstated"
- **SC-011** — "an *independent reviewer* ... classifies 100% of filed findings as accurate"

Both encode a human judgement. `test_accuracy_benchmark.py` asserts machine-checkable
**proxies** for them — capped confidence on unproven findings, recorded control state,
expected weakness class per benchmark finding — and the proxies are what keep the
suite honest between reviews. They are not the criterion itself.

## The gate

Before a release that claims this feature complete, an engineer **who did not
implement it** re-reviews a fresh scan of the benchmark target by the same method
the original review used: check every claim in the report against the source.

The reviewer, not the fixture, is authoritative. **If the review disputes something
the automated criteria accepted, `cases/reviewed_real.json` is wrong and must be
corrected** — not the other way round. Adjusting the expected outcome to match the
scanner would convert this benchmark into a mirror.

This gate is recommended and non-blocking. It is recorded here because an
unstated manual step is one nobody performs, which is how the original defects
reached a reader in the first place.

## What a reviewer should check

| Defect class | Question |
|---|---|
| evidence-integrity | Does every line number point at the code the finding describes? Is every trail entry actually on the path? Could you run each reproduction step and get the stated result? |
| classification | Is the weakness class possible for this target's architecture? Would it route to the right reviewer? |
| calibration | Would you rate each finding at the severity shown? Is any confidence higher than the evidence supports? |
| coverage | Which files did the scan not look at, and does the report say so? |
| dependency-coverage | Run the ecosystem's own audit. Does the report account for what it finds? |
| redaction-precision | Is every declared coverage gap a real uncertainty? |
| report-consistency | Does any part of the report contradict another part? |
