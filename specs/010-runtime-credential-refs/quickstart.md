# Quickstart: Validating Runtime Credential References

**Feature**: 010-runtime-credential-refs

Runnable checks that prove the feature end to end. Contracts are in
[contracts/detection-contracts.md](contracts/detection-contracts.md); entity shapes in
[data-model.md](data-model.md).

## Prerequisites

```bash
uv venv --python 3.11 && uv pip install -e ".[dev]"
source .venv/bin/activate
```

## 1. The reported lines produce no finding (SC-001, contract R2)

```bash
python - <<'EOF'
from pipeline.redact import Redactor
from pipeline.secret_findings import findings_from_hits
r = Redactor()
for line in [
    'export AWS_SECRET_ACCESS_KEY="$AWS_DEVIN_PROD_SECRET_ACCESS_KEY"',
    'AWS_ACCESS_KEY_ID="$OLD_AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$OLD_AWS_SECRET_ACCESS_KEY" aws route53 list-hosted-zones',
    'password: "%DB_PASSWORD%"', 'secret: "{{ vault_secret }}"',
    'token: "${{ secrets.GH_TOKEN }}"', 'api_key = "$(cat /run/secrets/key)"',
    'AUTH_TOKEN="$DB_USER:$DB_PASSWORD"', 'password: "${DB_PASSWORD:?DB_PASSWORD is required}"',
]:
    res = r.redact(line, origin="migration/p0/verify-account.sh")
    assert res.text == line and not res.hits, line
    assert [e.decision for e in res.exempted] == ["exempt-reference"], line
    assert findings_from_hits(res.hits, "repo") == []
print("OK: references are visible, exempted, and produce no finding")
EOF
```

Expected: `OK …`. Before the feature, the first six lines each yield an `assigned-secret` hit.

## 2. Recall is preserved and raised (SC-002, contract R3)

```bash
python - <<'EOF'
from pipeline.redact import Redactor
r = Redactor()
for line in [
    'password = "hunter2hunter2"',
    'password: "${DB_PASSWORD:-hunter2hunter2}"',   # recall GAIN: clean today
    'password = "$PREFIX-hunter2hunter2"', 'password = "pa$$w0rd-really-long"',
    'password = "${NAME"', 'key: "${AKIAIOSFODNN7EXAMPLE}"',
]:
    res = r.redact(line, origin="config/settings.py")
    assert res.redacted >= 1, f"missed: {line}"
print("OK: literals and look-alikes are still redacted")
EOF
pytest -q tests/unit/test_redact.py tests/unit/test_false_positive_corpus.py tests/unit/test_secret_findings.py
```

Expected: `OK …` and a green run.

## 3. Reproduction text keeps its file path (SC-005, contract R4)

```bash
python - <<'EOF'
from pipeline.reproduce import build_reproduction
finding = {
    "cwe": "CWE-798",
    "location": {"repo": "skh",
                 "file": "skillhunt-portal-backend/migration/p0/verify-account.sh",
                 "symbol": "AWS_SECRET_ACCESS_KEY", "line_start": 47, "line_end": 53},
    "verification": {"status": "verified"},
}
block = build_reproduction(finding, flow=None)
assert "skillhunt-portal-backend/migration/p0/verify-account.sh" in block["trigger"], block["trigger"]
assert "[REDACTED" not in block["trigger"]
print("OK:", block["trigger"])
EOF
pytest -q tests/unit/test_reproduce_honesty.py
```

Expected: the trigger reads `Inspect skillhunt-portal-backend/migration/p0/verify-account.sh#AWS_SECRET_ACCESS_KEY in a local checkout …`. Before the feature it reads `Inspect [REDACTED:high-entropy-secret].sh#…`.

## 4. Contracts, schema, and benchmark gates (contracts R5, R6)

```bash
pytest -q tests/contract
pytest -q tests/benchmark/test_accuracy_benchmark.py -k credential_precision
pytest -q                     # full suite must be green
ruff check src tests
```

Expected: all green; `audited_credential_baseline.json` integrity assertion reports 26 entries.

## 5. End-to-end scan over a fixture (SC-001, SC-005)

```bash
pytest -q tests/integration -k "runtime_reference or secret"
```

Expected: the integration fixture containing the three `skh` lines yields no CWE-798 finding for
them, while its seeded literal credential is still reported with a readable file path in its
reproduction block.

## 6. One-off confirmation on the reference repository (SC-003, clarification Q4)

Run manually, outside the build, against the `skh` workspace:

```bash
secscan scan <path-to-skh-workspace>
```

Confirm in the report that SEC-0080 / SEC-0082 / SEC-0084 are absent and that the remaining
CWE-798 findings from the baseline scan are present. Record the scan id and outcome under
**Assumptions → Baseline** in `spec.md`.
