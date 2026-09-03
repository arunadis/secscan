# Feature Specification: Runtime Credential References Are Not Hard-Coded Credentials

**Feature Branch**: `010-runtime-credential-refs`

**Created**: 2026-09-02

**Status**: Implemented (2026-09-02) — SC-003 manual confirmation on `skh` pending (see Assumptions → Baseline → Re-scan record)

**Input**: User description: "The scanner reported SEC-0080, SEC-0082 and SEC-0084 — three CWE-798 'Use of Hard-coded Credentials' findings, each 'verified' at 0.95 confidence, in shell migration scripts (`p0/verify-account.sh:47`, `p8/preflight-check.sh:336`, `p9/cost-compare.sh:31`). These are false positives: the credentials are not hard-coded, they are injected at runtime. The flagged lines are of the form `export AWS_SECRET_ACCESS_KEY=\"$AWS_DEVIN_PROD_SECRET_ACCESS_KEY\"` and `AWS_SECRET_ACCESS_KEY=\"$OLD_AWS_SECRET_ACCESS_KEY\" aws ...` — the quoted value is a reference to another environment variable, not a literal. Analyze and specify a remediation."

## Root-Cause Analysis

The deterministic secret detector treats a quoted value assigned to a credential-named key as a literal credential whenever the value is at least six characters long and is not on a small placeholder allow-list. That allow-list recognises the *braced* form of a shell variable reference (`"${NAME}"`) but not the far more common *bare* form (`"$NAME"`), nor any other indirection syntax that a script or configuration file uses to say "take this value from the environment at run time". The redactor therefore redacts `"$AWS_DEVIN_PROD_SECRET_ACCESS_KEY"` as an `assigned-secret`, and the finding stage promotes every such redaction hit into a format-confirmed, 0.95-confidence, verified CWE-798 finding.

Verified against the current detector on representative lines:

| Line | Reported today | Correct outcome |
|------|----------------|-----------------|
| `export AWS_SECRET_ACCESS_KEY="$AWS_DEVIN_PROD_SECRET_ACCESS_KEY"` | finding | no finding (runtime reference) |
| `export AWS_SECRET_ACCESS_KEY="${AWS_DEVIN_PROD_SECRET_ACCESS_KEY}"` | no finding | no finding |
| `AWS_SECRET_ACCESS_KEY="$OLD_AWS_SECRET_ACCESS_KEY" aws sts get-caller-identity` | finding | no finding (runtime reference) |
| `password: "%DB_PASSWORD%"` | finding | no finding (runtime reference) |
| `secret: "{{ vault_secret }}"` | finding | no finding (runtime reference) |
| `token: "${{ secrets.GH_TOKEN }}"` | finding | no finding (runtime reference) |
| `api_key = "$(cat /run/secrets/key)"` | finding | no finding (runtime reference) |
| `password = "hunter2hunter2"` | finding | finding (genuine literal) |

The three reported findings are the same defect, not three defects: the code is doing exactly what the finding's own recommendation asks for ("load the value from environment configuration … at runtime").

A **secondary defect** is visible in the same report: the reproduction "Trigger" text reads `Inspect [REDACTED:high-entropy-secret].sh#AWS_SECRET_ACCESS_KEY …`. The report generator redacts its own generated prose after composing it, and the repository path `skillhunt-portal-backend/migration/p0/verify-account` — a long slash-joined run on a line that also contains the credential-named symbol — is consumed by the entropy heuristic. The reader is told to inspect a file whose name has been removed from the instruction.

## Clarifications

### Session 2026-09-02

- Q: When a credential-named key is assigned from a runtime reference, should the reference text stay visible in the context the model sees, or still be redacted while no longer producing a finding? → A: Leave well-formed references visible in context packets and record an auditable exemption; no finding is produced. A reference exposes only an environment-variable name, which artifacts already permit; anything failing the strict reference test is still redacted.
- Q: When several references are joined by punctuation inside one quoted value (e.g. `"$DB_USER:$DB_PASSWORD"`, `"${HOST}/${TOKEN}"`), should the value still count as a runtime reference? → A: Yes. A value is a runtime reference when every letter and digit lies inside a well-formed reference; punctuation between references is permitted, while any letter or digit outside a reference makes the whole value a literal.
- Q: How should shell parameter-expansion operators with an operand be treated (`${X:?msg}`, `${X:-default}`, `${X:=default}`, `${X:+alt}`)? → A: `:-`, `:=` and `:+` operands can become the value and are evaluated as literals (reported when credential-like); `:?` operands are error diagnostics that never become the value and are exempt.
- Q: How should SC-003 (the three findings disappear from the `skh` scan, genuine findings survive) be verified? → A: Automated corpus in the build (the three reported lines join the in-repo runtime-reference corpus) plus a one-off manual re-scan of `skh` recorded as evidence in the spec; the build never depends on the external repository.
- Q: Is this remediation exclusive to the `skh` repository or a generic solution? → A: Generic. The classification rule applies to every scanned repository, language, and path; no repository-, path-, or variable-name-specific suppression is introduced. `skh` supplies only the seed lines for the regression corpus and the one-off confirmation re-scan.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Runtime credential references are not reported as hard-coded credentials (Priority: P1)

A security engineer reviewing the scan report sees three High-severity, "verified", 0.95-confidence hard-coded-credential findings in migration scripts. They open each file and find that the credential-named variable is assigned *from another variable* — the value is supplied by the operator's environment at run time, and no credential value exists anywhere in the repository. The finding contradicts itself: its "Expected" behaviour ("credentials are supplied from environment … at runtime") is precisely what the code does. The engineer loses trust in the credential findings as a class, and the genuine credential findings sitting next to these are now suspect.

The scanner must distinguish a credential *literal* (a value that is itself the secret) from a credential *reference* (an expression that resolves to the secret only when the program runs). Assigning a credential-named key from a variable reference, template placeholder, or command substitution is the recommended practice, not a vulnerability.

**Why this priority**: This is the defect the user reported. Each occurrence is a High-severity, top-confidence, verified finding with a PCI-DSS compliance mapping and an instruction to rotate the credential and rewrite history — the most expensive possible false alarm. Shell-style `"$VAR"` is the dominant way credentials are wired in scripts, CI definitions, container manifests, and deployment tooling, so this pattern is expected to recur in most real repositories.

**Independent Test**: Run the scanner over a script that assigns credential-named variables exclusively from environment-variable references in every common syntax, alongside one genuine credential literal, and confirm that exactly one credential finding is published — for the literal — while every reference assignment is recorded as an auditable exemption.

**Acceptance Scenarios**:

1. **Given** a shell script containing `export AWS_SECRET_ACCESS_KEY="$AWS_DEVIN_PROD_SECRET_ACCESS_KEY"`, **When** the scan runs, **Then** no hard-coded-credential finding is published for that line.
2. **Given** a shell command with an inline environment prefix such as `AWS_SECRET_ACCESS_KEY="$OLD_AWS_SECRET_ACCESS_KEY" aws route53 list-hosted-zones`, **When** the scan runs, **Then** no hard-coded-credential finding is published for that line.
3. **Given** credential-named keys assigned from other indirection syntaxes — braced shell (`"${NAME}"`), Windows batch (`"%NAME%"`), templating (`"{{ name }}"`), CI expressions (`"${{ secrets.NAME }}"`), command substitution (`"$(…)"`), and punctuation-joined compositions (`"$USER:$PASSWORD"`) — **When** the scan runs, **Then** none of them produce a hard-coded-credential finding.
4. **Given** the same file also contains a genuine credential literal such as `password = "hunter2hunter2"` or a value matching a known credential format, **When** the scan runs, **Then** that literal is still detected and reported — recall is unchanged.
5. **Given** a reference assignment was left unreported, **When** the scan artifacts are inspected, **Then** the decision is recorded with file, line, matched rule, the classification "runtime reference", and a reason — the exemption is auditable, never silent.
6. **Given** the reference repository scan that produced SEC-0080, SEC-0082 and SEC-0084, **When** it is re-run with this feature, **Then** none of those three findings is published and every genuine credential finding from the same scan survives.

---

### User Story 2 - Report text never redacts its own file paths (Priority: P2)

A reviewer follows a finding's reproduction steps and reads "Inspect `[REDACTED:high-entropy-secret].sh#AWS_SECRET_ACCESS_KEY` in a local checkout". The one piece of information they need — which file — has been removed by the report's own redaction pass, because the repository path is long, contains no spaces, and sits on a line that also names a credential-like symbol. The finding is unusable without cross-referencing the Location header.

Report text that the scanner composes from information it already knows to be safe — repository names, file paths, symbol names, line numbers — must remain intact in the published report. Redaction exists to keep credential *values* out of the report; it must never remove the *location* of a finding.

**Why this priority**: This defect is visible in the reported output and directly degrades the actionability of every credential finding whose path is long enough to trip the heuristic. It is independent of US1 (it would still bite a genuine finding) but was surfaced by the same report, and fixing US1 alone would leave genuine findings with unreadable reproduction steps.

**Independent Test**: Generate the report for a credential finding located at a deep, hyphen-and-slash-joined path on a line that also names a credential symbol, and confirm the full path appears verbatim in the reproduction trigger text while a seeded credential value placed in the same text is still redacted.

**Acceptance Scenarios**:

1. **Given** a credential finding whose file path is a long slash-joined string (e.g. `skillhunt-portal-backend/migration/p0/verify-account.sh`), **When** the report is generated, **Then** the reproduction text shows the complete path and symbol unredacted.
2. **Given** report text that embeds a repository path and also, separately, a credential value, **When** the report is generated, **Then** the path is intact and the credential value is redacted.
3. **Given** any published finding, **When** its location fields and reproduction text are compared, **Then** the file named in the reproduction text matches the finding's location.

---

### User Story 3 - Regression guard for runtime-reference precision (Priority: P3)

A maintainer tunes the credential detector and has no way to know whether the change re-introduces the `"$VAR"` false positive, silently widens the exemption to swallow a real credential, or starts eating file paths in report text again. Detection quality must be asserted in the build: a maintained corpus of runtime-reference assignments across all supported syntaxes must produce zero credential findings, and the seeded credential corpus — extended with adversarial cases that *look* like references but are literals — must retain full recall.

**Why this priority**: This makes US1 and US2 durable. The project already maintains a false-positive corpus and treats accuracy-benchmark regressions as release-blocking; this story extends that guarantee to the runtime-reference class and to report-text integrity.

**Independent Test**: Run the detection test suite against the runtime-reference corpus and the extended seeded-credential corpus; the build fails if any reference is reported as a credential, if any seeded credential (including reference-look-alike literals) is missed, or if a file path is redacted from report text.

**Acceptance Scenarios**:

1. **Given** the maintained runtime-reference corpus (covering the SEC-0080/0082/0084 lines and every syntax listed in US1 scenario 3), **When** the test suite runs, **Then** zero credential findings are produced from it.
2. **Given** the seeded credential corpus, including literals that merely begin with, contain, or are wrapped around a `$`, `%`, or `{{` sequence, **When** the test suite runs, **Then** every credential is still detected — 100% recall, asserted in the build.
3. **Given** a future change that re-introduces a runtime-reference false positive, drops a real credential, or redacts a file path in report prose, **When** the build runs, **Then** it fails.

---

### Edge Cases

- **Reference with a literal default**: `"${DB_PASSWORD:-hunter2hunter2}"` embeds a fallback literal inside a reference. The whole value MUST be treated as a literal and reported as a credential; a reference wrapper never exempts literal content it contains. There is no partial exemption — a value is exempted whole or handled exactly as today. Recall wins.
- **Parameter-expansion operators** (clarified 2026-09-02): the operand of `:-`, `:=` and `:+` can become the variable's value and is evaluated exactly as a literal assigned to the same key — reported when credential-like, exempt when it is itself a reference or empty (`"${X:-}"`, `"${X:-$Y}"`). The operand of `:?` is an error diagnostic that never becomes the value; `"${DB_PASSWORD:?DB_PASSWORD is required}"` is a runtime reference and MUST NOT be reported.
- **Literal that merely contains a reference marker**: values such as `"pa$$w0rd-really-long"`, `"abc%20def%20secret"`, `"AKIA…"` followed by `$`, or a URL-encoded token are literals, not references. A value is a runtime reference only when every letter and digit in the quoted content lies inside a well-formed indirection expression; a `$`/`%`/`{{` appearing somewhere inside otherwise literal content does not exempt it.
- **References joined by punctuation**: `"$DB_USER:$DB_PASSWORD"`, `"${HOST}/${TOKEN}"`, `"$A@$B"` are runtime references — punctuation between references is never credential material. `"$PREFIX-hunter2hunter2"` is not, because letters and digits lie outside any reference (clarified 2026-09-02).
- **Reference concatenated with a literal**: `"$PREFIX-hunter2hunter2"` and `"hunter2hunter2$SUFFIX"` contain literal credential material and MUST still be reported.
- **Unbalanced or malformed indirection**: `"${NAME"`, `"%NAME"`, `"{{ name"` are not well-formed references and MUST be treated as literals (reported), never silently exempted.
- **Reference to a name that itself embeds a credential word**: `"$OLD_AWS_SECRET_ACCESS_KEY"` — the *referenced* name containing "SECRET" is not evidence of a hard-coded value; it is the normal way to name the variable that carries the secret. Credential words inside the referenced name MUST NOT convert a reference into a finding.
- **Reference in test code**: a runtime reference is a non-finding regardless of whether the file is test or production code; the test-code severity step-down does not apply because nothing is reported.
- **Known credential format inside a reference-like wrapper**: a value matching a definitive credential format (e.g. an AWS access key id pattern, a private-key block) is reported wherever it appears, including inside `${…}` or `{{…}}` — format match bypasses the reference exemption (consistent with feature 003, FR-007).
- **References remain visible in context**: a well-formed, literal-free reference is exempted at the redaction layer — it stays visible in context packets (it exposes only an environment-variable name, never a value) and is recorded as an exemption rather than redacted. Any value that fails the strict reference test (FR-002, FR-003) is redacted exactly as today (clarified 2026-09-02).
- **Path redaction in report text**: a repository path that happens to satisfy a credential *format* rule (not merely the entropy heuristic) is not something the scanner can safely leave visible; such a path is redacted and the finding's location must still be readable via structured location fields. Only heuristic (entropy) matches are exempt for known-safe scanner-composed fields.

## Requirements *(mandatory)*

### Functional Requirements

**Detection precision — runtime references**

- **FR-000**: The runtime-reference classification MUST be a generic rule applied uniformly to every scanned repository, file type, language, and path; the system MUST NOT introduce repository-, path-, or variable-name-specific suppressions to satisfy this feature (clarified 2026-09-02).
- **FR-001**: The system MUST NOT publish a hard-coded-credential finding when the value assigned to a credential-named key is, in its entirety, a runtime indirection expression: a bare or braced shell variable reference, a Windows batch variable reference, a template placeholder, a CI/CD secret expression, or a command substitution.
- **FR-002**: Classification as a runtime reference MUST require that every letter and digit in the quoted content lies inside a well-formed indirection expression; punctuation and whitespace between expressions are permitted, and any letter or digit outside an expression MUST cause the whole value to be treated as a literal (clarified 2026-09-02).
- **FR-003**: A malformed or unbalanced indirection expression MUST be treated as a literal and reported; the system MUST NOT extend the benefit of the doubt to content it cannot classify as a reference.
- **FR-004**: Credential-related words appearing inside the *referenced* name (e.g. `$OLD_AWS_SECRET_ACCESS_KEY`) MUST NOT be treated as evidence of a hard-coded credential.
- **FR-005**: Every runtime-reference exemption MUST be recorded in the scan artifacts with file, line, matched rule, classification, and reason, consistent with the existing exemption-recording mechanism, so the decision is auditable rather than silent.
- **FR-005a**: A well-formed, literal-free runtime reference MUST be exempted at the redaction layer — left visible in context packets rather than replaced by a redaction marker — so no finding can derive from it and the analysis stage sees the actual credential wiring (clarified 2026-09-02).

**Recall preservation (absolute)**

- **FR-006**: Credential-detection recall MUST NOT regress: every credential detectable before this change, and every seeded credential in the test corpus, MUST still be detected and reported.
- **FR-007**: A literal credential embedded within, adjacent to, or concatenated with a reference expression MUST still be reported. For shell parameter expansion, the operand of `:-`, `:=` and `:+` MUST be evaluated as a literal assigned to the same key; the operand of `:?` MUST be treated as a diagnostic message and exempted (clarified 2026-09-02).
- **FR-008**: A match against a known credential format MUST be reported wherever it occurs, including inside a reference-like wrapper; the reference exemption applies only to the variable-assignment rule and heuristic matches, never to format matches.

**Report integrity**

- **FR-009**: Scanner-composed report text (reproduction steps, evidence reasons, descriptions) MUST preserve repository names, file paths, symbol names, and line references verbatim; the heuristic redaction pass MUST NOT remove these known-safe location tokens.
- **FR-010**: Credential values embedded in report text MUST continue to be redacted; FR-009 protects locations, not values.
- **FR-011**: For every published credential finding, the file named in its reproduction text MUST match the file in its structured location; for all other findings, whenever any reproduction field names a file, that file MUST match the structured location.

**Quality gates**

- **FR-012**: A maintained corpus of runtime-reference assignments — including the exact lines behind SEC-0080, SEC-0082 and SEC-0084 and one sample per supported indirection syntax — MUST be asserted to produce zero credential findings in the build.
- **FR-013**: The seeded credential corpus MUST be extended with reference-look-alike literals (literals containing `$`, `%`, `{{`, credential-like operands of `${…:-…}`, `${…:=…}` and `${…:+…}`, and reference-plus-literal concatenations) and MUST be asserted at 100% recall in the build; the runtime-reference corpus MUST include a `${…:?…}` sample asserted as a non-finding.
- **FR-014**: The accuracy benchmark MUST treat runtime-reference false positives as part of the credential-precision defect class; a regression in that class MUST fail the build even if other classes improve.

### Key Entities

- **Runtime Reference**: a quoted assignment value that resolves to a credential only when the program executes. Attributes: syntax family (bare shell, braced shell, batch, template, CI expression, command substitution), referenced name(s) (when extractable), and whether any letter or digit lies outside the reference(s). A value may comprise several references joined by punctuation. A well-formed, literal-free reference is never a finding.
- **Exemption Decision** (existing entity, extended): gains the classification `runtime-reference` with the syntax family and referenced name as the recorded basis, alongside the existing identifier and message-string classifications.
- **Known-Safe Location Token**: repository name, file path, symbol, or line reference that the scanner itself placed into report text; exempt from heuristic redaction, never from format-rule redaction.
- **Runtime-Reference Corpus Entry**: a source sample assigning a credential-named key from an indirection expression, with the expectation of zero findings and a recorded rationale, versioned alongside the scanner and paired with adversarial look-alike literals that must still be found.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Zero hard-coded-credential findings are produced from the runtime-reference corpus, including the three lines behind SEC-0080, SEC-0082 and SEC-0084.
- **SC-002**: Credential-detection recall remains at 100% on the seeded credential corpus, including the newly added reference-look-alike literals; no credential detectable before this change is lost.
- **SC-003**: On the reference repository scan that produced the reported findings, all three runtime-reference findings disappear and every genuine credential finding from the same scan is retained — asserted automatically via the in-repo corpus entries for the three lines, and confirmed by a one-off manual re-scan of `skh` whose outcome is recorded in this spec (clarified 2026-09-02).
- **SC-004**: 100% of runtime-reference exemptions are recorded in the scan artifacts with location, syntax family, and reason.
- **SC-005**: 100% of published credential findings name a readable, complete file path in their reproduction text that matches their structured location; zero report locations are redacted.
- **SC-006**: A reviewer can confirm from the report alone, without opening the source, that a credential finding refers to a literal value rather than an environment reference — the description and evidence are consistent with the code the reviewer will find.

## Assumptions

- **Scope is precision for one pattern plus report-text integrity**: this feature addresses (a) runtime-reference assignments misclassified as literals and (b) location tokens redacted from scanner-composed report text. Broader credential-detection changes (new formats, entropy tuning, identifier handling) are covered by features 002 and 003 and are not reopened here.
- **Recall precedence is absolute** (constitution Principle III): any value that is not unambiguously a well-formed, literal-free reference is treated as a literal and reported. Over-reporting wins every tie.
- **The reference exemption is a redaction-layer exemption** (clarified 2026-09-02): a reference exposes only an environment-variable name — which the project already permits in artifacts — so it is left visible, and the finding disappears because the redactor never records a hit. This does not weaken redaction of anything that is not provably a reference.
- **Exemptions reuse the existing auditable-decision mechanism** introduced by features 002 (FR-038) and 003 (FR-004); no new artifact surface is required.
- **Supported indirection syntaxes** are the common ones enumerated in FR-001; exotic or language-specific interpolation forms not listed are out of scope for this feature and, by FR-003, continue to be reported as literals.
- **Baseline**: the `skh` workspace scan that produced SEC-0080, SEC-0082 and SEC-0084 is the evaluation baseline for SC-003; the remaining CWE-798 findings in that scan are presumed genuine unless separately audited. The build never depends on `skh`: the three lines are reproduced in the in-repo corpus, and the `skh` re-scan is a one-off manual confirmation whose result is recorded here (clarified 2026-09-02).
  - **Re-scan record (T030, 2026-09-02)**: the `skh` workspace was not available in the implementation environment, so the confirmation re-scan has **not** been run. The three reported lines are asserted verbatim in `tests/fixtures/runtime_reference_corpus.py` and the audit is recorded under `follow_up_scans` in `tests/benchmark/cases/audited_credential_baseline.json` (note: the SEC-0080/0082/0084 labels collide with the 2026-08-31 baseline's labels — they are findings from a later scan, hence the separate block). Owner action: run `secscan scan <skh-workspace>` per quickstart §6, confirm the three findings are absent and the remaining CWE-798 findings survive, and replace this note with the scan id and outcome.
- **Generic, not `skh`-specific** (clarified 2026-09-02): the reported files happen to be shell scripts in a migration directory and are treated as production code, but the fix does not depend on file type, language, path, or repository — the same classification applies wherever a credential-named key is assigned from a reference, in any project the scanner is run against. `skh` contributes only corpus seed lines and a confirmation re-scan.
