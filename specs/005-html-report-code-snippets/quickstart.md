# Quickstart: Validating HTML Report with Code Snippets

Prerequisites: repo dev environment (`pip install -e ".[dev]"`), Python 3.11+.

## Scenario 1 — Three artifacts from one scan (FR-001, SC-001, SC-007)

```bash
security-scan run --workdir <fixture-repo-with-known-findings>
ls <fixture-repo>/.security-scan/reports/
# Expected: <scan_id>.json, <scan_id>.md, <scan_id>.html
```

Re-run and diff: all three files byte-identical across runs.

## Scenario 2 — Navigation and reference links (FR-003–FR-006, SC-002, SC-006)

Open the `.html` file in a browser with network disabled:

- Index lists every finding grouped by severity band.
- Clicking an index entry jumps to the finding detail; "↑ index" returns.
- Cross-references (evidence, coverage gaps) are clickable and land on existing sections.
- Validation shortcut: `pytest tests/unit/test_render_html.py` asserts every `href="#…"` resolves.

## Scenario 3 — Vulnerable code inline (FR-007–FR-010, FR-013, SC-003, SC-005)

Against the fixture with a known vulnerability at a known `file:line`:

- The finding detail (HTML and Markdown) shows the cited lines ±3 context lines, labeled `repo:file:Lstart-Lend`.
- HTML shows line numbers with cited lines highlighted.
- A fixture whose finding overlaps a planted credential shows the redaction placeholder, never the value; a finding in an unconfirmable file shows "excerpt unavailable: …" instead of a block.
- A minified-file fixture shows a bounded excerpt with an explicit truncation marker.

## Scenario 4 — Cross-format identity (SC-001)

```bash
pytest tests/integration/test_report_artifacts.py
```

Asserts: finding ids equal across `.json`/`.md`/`.html`; JSON `code_excerpt` validates against `finding.json`; redaction sweep passes over all three artifacts.

## Scenario 5 — Repo projection in HTML (report_view)

```bash
security-scan report --workdir <fixture-repo> --repo <member> --format html
```

Expected: filtered HTML whose index contains only findings touching `<member>`; all links still resolve.

## Gates before merge

```bash
pytest                       # all green, incl. new unit/contract/integration tests
ruff check src tests         # clean
```
