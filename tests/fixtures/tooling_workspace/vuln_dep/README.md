# vuln_dep — ground truth

Ecosystem: **npm**.

Ground truth: `rapid-parse@2.0.0` is pinned in the lockfile and carries the
recorded advisory GHSA-AAAA-0000-AAAA (see `recorded/npm_audit.json`). The
package is deliberately **absent from the bundled advisory snapshot**, so the
offline baseline cannot surface it — this is the fixture that proves external
tools extend coverage (SC-003).
