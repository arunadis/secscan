# crosscheck — ground truth

Ecosystem: **npm** (plus arbitrary code for location checks).

The recorded external report (`recorded/osv_crosscheck.json` and
`recorded/semgrep_crosscheck.json`) contains seeded dispositions:

| Seeded finding | Expected disposition | Ground |
|---|---|---|
| Advisory on `ghost-lib` | suppressed | package-absent (not in lockfile) |
| Advisory on `safe-serial` `<3.0.0` | suppressed | version-outside-range (resolved 3.0.0) |
| Advisory on `left-pad-again` `<=1.2.3` | retained (verified) | resolved 1.2.3 is inside the range |
| SAST finding at `src/missing.py` | suppressed | location-unresolvable |
| SAST finding at `src/app.py` (reachable-looking doubt only) | retained, undetermined where reachability is the only doubt | reachability never suppresses |

Zero true findings may be suppressed (SC-004).
