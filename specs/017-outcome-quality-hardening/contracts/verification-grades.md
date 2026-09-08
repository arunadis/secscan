# Contract: Verification grades (feature 017)

## Presence class catalogue

`src/pipeline/verify.py` owns it (code-governed; pack members contribute through
`identity_rules.no_refute_cwes()`).

- `PRESENCE_VALID_CWES`: existing {CWE-798, 259, 256, 522, 532, 352, 942, 306,
  489, 1188, 295, 1004} ∪ pack members (currently CWE-290).
- `_REACHABILITY_SENSITIVE_PRESENCE = {"CWE-306", "CWE-290"}` — under the active
  reachability gap (feature 016 FR-007), these demote to `plausible` with the gap
  named; others hold.
- `basis` semantics unchanged: `traced` | `presence`; written only on `verified`.

## Rendering rule (presence-proven without a traced path)

A finding eligible for presence verification whose status is `plausible` solely for
reachability MUST render: **"Weakness proven at this location; exposure path
unconfirmed"** in place of the generic plausible copy, preserving the verification
badge + gap statement.
