# crash_tool — ground truth

Ecosystem: **npm**.

Ground truth for resilience (SC-006): the test harness injects a PATH shim for
`npm` that exits 137 with no output. The scan MUST complete; `runs.json` MUST
record `status: failed` with a reason; zero partial findings merge; the report
MUST declare the tool's missing contribution as a coverage limitation.
