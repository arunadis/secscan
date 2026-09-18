# Feature Specification: Plugin Install

**Feature Branch**: `018-plugin-install`

**Created**: 2026-09-18

**Status**: Draft

**Input**: User description: "add the capability of installing as a plugin too" —
following a design discussion on making secscan consumable by any agentic platform,
not only by the agents that have a dedicated skill-directory adapter.

## Background & Problem Statement

Today secscan reaches an agent in exactly one way: the installer copies the skill
payload (instructions, prompts, schemas, data, scripts) into a per-agent directory
inside the scanned project (`.claude/skills/`, `.cursor/skills/`, `.gemini/commands/`,
…). This works for the seven agents with an adapter and has real strengths — each
project pins its own scanner version and nothing runs as a server — but it has limits:

1. **Every new platform needs a bespoke adapter**, and platforms that do not read a
   skills directory at all (or read one in a format we do not emit) cannot use secscan.
2. **Installation is project-scoped only.** An engineer who wants secscan available in
   every workspace must re-install per project; an organisation cannot publish it once
   to a plugin registry/marketplace and let engineers add it by name.
3. **The agent drives the scan by composing shell commands** from prose in `SKILL.md`
   (set an environment variable, invoke a module, interpret exit code 3, read and write
   handoff files by path). Agents that prefer — or only support — structured tool calls
   have no such surface, and command-composition mistakes are a recurring source of
   "the scan didn't run" reports.

The scan engine itself already has the shape a plugin needs: a deterministic command
surface (`init`, `run`, `status`, `report`) and a file-based reasoning handoff
(request packets out, answer files in). This feature adds a **plugin distribution**
of that same engine so that a host platform can install secscan by reference and
drive it through its native plugin/tool mechanism, alongside — never instead of — the
existing skill install.

## Clarifications

### Session 2026-09-18

- Q: When a project already has a per-project skill install and the host also has
  the plugin installed, which one drives the scan? → A: The project skill install
  always wins; the plugin detects it, delegates to the pinned payload, and reports
  the pinned version.
- Q: When a `run` operation reaches its time bound before the scan is settled, does
  the scan keep working in the background or stop at a checkpoint? → A: Stop at the
  next durable checkpoint and return "in progress, re-invoke run"; no background
  work — each `run` call advances the scan.
- Q: What does the installer produce for a host that supports both forms when no
  form is specified? → A: The skill form (today's behaviour); the plugin form only
  with an explicit flag.
- Q: Does one tool-provider instance serve a single scan root fixed at launch, or
  take the root per operation? → A: Every operation takes a required scan-root
  parameter, mirroring the command line's `--workdir`.
- *Planning amendment*: two statements were corrected against the code during
  `/speckit-plan` — agent answers live in `handoff/responses/` (the
  `{request_id, answer_key, content}` shape is the provider answer cache, FR-006), and
  the install form is reported in operation results/`status` rather than in the
  report so FR-020 (byte-identical artifacts) holds (FR-015).
- Q: Where is the host's registration of secscan written when the installer sets up
  the plugin form — project or user level? → A: User-level host settings only; the
  project is untouched apart from `.secscan/`.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Install secscan as a plugin on a supported platform (Priority: P1)

An engineer using a coding agent that has a plugin mechanism installs secscan through
that mechanism — from a published plugin listing or a local/remote plugin source —
and immediately has the `secscan` command available in any workspace they open,
without copying scanner files into each project.

**Why this priority**: this is the capability the user asked for; without it nothing
else in the feature has value. It also unlocks organisation-wide distribution (publish
once, install by name).

**Independent Test**: on a clean machine with a supported host, install the plugin
from a plugin source, open a project that has never seen secscan, invoke `secscan`,
and complete a `quick` scan end to end. The project contains only `.secscan/`
afterwards — no agent skill directory was created by secscan.

**Acceptance Scenarios**:

1. **Given** a supported host with the plugin installed and a project with no secscan
   files, **When** the engineer invokes the secscan command, **Then** the scan
   initialises, runs, and publishes a report under `.secscan/` with content identical
   to what the skill install of the same tool version produces for the same input.
2. **Given** the plugin installed, **When** the engineer lists the host's available
   commands/tools, **Then** secscan appears with its name, description, and version
   (for Windsurf: the tool provider and its tools appear; no skill or command is
   expected).
3. **Given** the plugin installed and the project already containing a skill install
   of secscan, **When** the engineer invokes secscan, **Then** the plugin detects the
   project skill install, delegates the scan to that pinned payload, and reports the
   pinned version as the one driving the scan; the two never both drive the same scan.
4. **Given** a host that is *not* supported by a plugin manifest, **When** the engineer
   asks how to install, **Then** the installer's help names the generic route
   (User Story 2) rather than failing silently.

---

### User Story 2 - Drive the scan through structured tool calls on any host (Priority: P1)

An engineer whose agent platform has no secscan-specific adapter attaches secscan as
a generic tool provider — the same way the platform attaches any other tool provider —
and the agent runs the scan by calling named operations instead of composing shell
commands. The reasoning handoff (context packets out, schema-conformant answers in)
happens through the same operations.

**Why this priority**: this is what makes "any agentic platform" true. Vendor plugin
bundles (Story 1) are packaging around this surface; without it each new platform is
again a bespoke adapter.

**Independent Test**: attach secscan as a tool provider to a host with no secscan
adapter; have the agent initialise, run, receive pending reasoning requests, submit
answers, resume, and fetch the report — entirely through tool calls. Artifacts are
byte-identical to a skill-driven run of the same tool version given the same answers.

**Acceptance Scenarios**:

1. **Given** secscan attached as a tool provider, **When** the agent lists the
   provider's operations, **Then** it sees operations that cover, at minimum: initialise
   a scan root, run (with profile / full / setting overrides), report status, list
   pending reasoning requests, fetch one request's packet, submit one answer, and fetch
   the report — each with a machine-readable description of inputs and outputs.
2. **Given** a `run` that stops because reasoning is required, **When** the agent
   fetches a pending request, **Then** it receives exactly the redacted, budgeted
   context packet the skill path would have written to `.secscan/handoff/requests/` —
   nothing more.
3. **Given** the agent submits an answer, **When** the answer does not conform to the
   applicable answer schema, **Then** the submission is rejected with the validation
   reasons and nothing is written; **When** it conforms, **Then** the answer is stored
   as `.secscan/handoff/responses/<request-id>.json` exactly as the skill path would
   have written it, and the next `run` consumes it.
4. **Given** a long-running `run` (external tools, batch endpoint), **When** the host's
   tool-call time limit is shorter than the scan, **Then** the operation stops at the
   next durable checkpoint before the limit and returns an explicit "in progress,
   re-invoke run" state; no work continues in the background, no work is lost, and
   the next `run` call advances the scan from that checkpoint until it settles.
5. **Given** a `run` in progress, **When** the pipeline emits progress (stage, segment
   `i/N`, tool, coverage note, heartbeat), **Then** the host receives that progress as
   progress notifications — not embedded in the operation's result and not written to
   the terminal.
6. **Given** the operation surface, **When** it is invoked with the project configured
   for an external analysis endpoint, **Then** reasoning is still performed by the
   configured endpoint through the existing provider path; the tool surface never
   substitutes the host agent's reasoning for a configured endpoint or vice versa
   without the operator changing configuration.

---

### User Story 3 - Skill and plugin surfaces stay one product (Priority: P2)

A maintainer changes the scan engine (a new stage, a new exit code, a new setting,
a new schema field). Both surfaces reflect the change without duplicated logic, and
a host that has both a skill install and the plugin sees the same behaviour and
the same guidance text.

**Why this priority**: two surfaces that drift produce two products with one name;
that is a support and correctness liability that compounds with every release.

**Independent Test**: the guidance text and operation descriptions exposed by the
plugin are generated from the same source as `SKILL.md`; a test that mutates the
source sees both surfaces change. The install matrix test exercises every plugin
manifest the same way it exercises every skill adapter.

**Acceptance Scenarios**:

1. **Given** the shipped skill instructions, **When** the plugin exposes its
   guidance/command text, **Then** that text is derived from the same shipped source
   and the two never disagree on stage names, exit codes, or file locations.
2. **Given** the installer's `init --ai <agent>` flow, **When** a plugin manifest
   exists for that agent, **Then** the skill form is produced unless the engineer
   explicitly selects the plugin form; the skill form is recorded in the project's
   install manifest and the plugin form in the user-level install record, and the
   project receives no files from a plugin-form install.
3. **Given** a new tool version, **When** the plugin is upgraded through the host's
   mechanism, **Then** projects with existing `.secscan/` config and artifacts are
   preserved, a configuration-schema change is flagged (not silently applied), and a
   downgrade is refused unless explicitly forced — the same guarantees as the skill
   upgrade path.

---

### Edge Cases

- A host installs the plugin at user level while a project has a *different* pinned
  version installed as a skill: the project's pinned version drives the scan, is named
  in the operation result and in `status`, and the plugin-vs-project version
  difference is reported, not hidden.
- The project skill install the plugin delegates to is corrupt (missing manifest or
  payload files): the plugin MUST NOT silently fall back to its own version; it
  reports the corrupt install and how to repair it (re-run the installer).
- Two hosts (or two sessions) drive the same `.secscan/` root concurrently through
  tool calls: the second `run` MUST refuse with a clear "scan in progress" state rather
  than interleave writes.
- The agent submits an answer for a request id that does not exist or is already
  answered: rejected with the reason; no file is written.
- The agent requests a packet for a request that was already consumed by a resume:
  the response says so; the packet is not regenerated.
- A host has no notion of progress notifications: progress is still written to
  `.secscan/scan.log` as today; nothing is lost, and the operation result stays free
  of timing/level content.
- The plugin is installed but the workspace root passed to `init` is not a git
  repository or contains no recognised repository: same behaviour and same message as
  the existing command line.
- The plugin's tool provider process is killed mid-`run`: on the next `run` the scan
  resumes from the last durable checkpoint, exactly as after an interrupted terminal run.
- The installer cannot locate or write the host's user-level settings (unknown host
  version, unwritable location): it MUST fail with the path it tried and MUST NOT
  fall back to writing host configuration into the project.
- A scan-time tool is missing on the machine: `secscan_init`'s environment check
  reports it by name — never a stack trace. A missing *launcher* (`uv`/Python) is a
  host-side launch failure secscan cannot observe; the agent-integration
  documentation names the provisioning command per host.

## Requirements *(mandatory)*

### Functional Requirements

**Scope**

- **FR-001**: The system MUST offer a **plugin distribution** of the scan engine in
  addition to the existing per-project skill install. The skill install MUST remain
  fully supported and unchanged in behaviour.
- **FR-002**: The plugin distribution MUST comprise: (a) a **tool provider** that
  exposes the scan lifecycle as named, schema-described operations over a widely
  supported agent tool protocol, and (b) **vendor plugin manifests** for every
  existing adapter target that has a native plugin/extension mechanism (Claude Code,
  Gemini CLI, Cursor, GitHub Copilot, Devin) that bundle the tool provider with the
  command registration so the host installs both in one step. Windsurf has no
  installable plugin format: its plugin form is the tool provider registered in the
  host's user-level MCP settings, with guidance reaching the model through tool
  descriptions and the invocable prompt only (no skill surface) — the documentation
  MUST say so and recommend the skill form for Windsurf. The cross-vendor `.agents/`
  target has neither and is served by the generic tool provider.
- **FR-003**: The plugin distribution MUST be installable **by reference** from a
  local path or a git URL, so the engineer never copies scanner files into the scanned
  project. Publication to public registries/marketplaces (plugin marketplaces, a
  package index) is out of scope for this feature and is handled by the release
  process; the manifests produced here MUST nevertheless be valid inputs to such a
  publication without modification.

**Tool provider operations**

- **FR-004**: The tool provider MUST expose operations for: initialise (config +
  environment check), run (profile, force-full, setting overrides), status, list
  pending reasoning requests, fetch a request, submit an answer, and fetch a report
  (optionally per repository). Every operation MUST take a required scan-root
  parameter (the same meaning as the command line's `--workdir`); a provider instance
  holds no fixed root and may serve several roots over its lifetime. Each operation
  MUST carry a machine-readable input and output description.
- **FR-005**: A fetched request MUST be exactly the packet the skill path would write
  to `.secscan/handoff/requests/<id>.json`; the tool provider MUST NOT add source,
  file contents, or any material that did not pass the redactor and the budget check.
- **FR-006**: A submitted answer MUST be validated against the answer schema applicable
  to its request kind (segment finding, flow answer, triage answer) before anything is
  written. Rejected submissions MUST return the validation reasons and MUST leave no
  file. Accepted submissions MUST be stored exactly where and how the skill path
  stores an agent answer today — `.secscan/handoff/responses/<request-id>.json`,
  holding the answer content and nothing else — so a resume consumes it through the
  same code path. The plugin MUST NOT write the endpoint answer cache
  (`.secscan/analysis/answers/`, `{request_id, answer_key, content}`), which belongs
  to provider-backed runs only.
- **FR-007**: `run` MUST never block a host's tool call beyond a bounded time. If the
  scan is not settled within that bound, the operation MUST stop at the next durable
  checkpoint and return an explicit "in progress, re-invoke run" state. No scan work
  MAY continue after the operation returns — the tool provider performs no background
  work. `status` MUST report the checkpointed position, and the next `run` MUST
  resume from that checkpoint, never restart. A single stage that cannot be
  checkpointed mid-way (e.g. one external tool invocation) MAY run to completion
  past the bound; the bound applies between checkpoints, and the report's coverage
  notes MUST never be affected by where a `run` call happened to stop. In
  provider-backed execution modes the checkpoints are stage boundaries and batch-poll
  iterations only, so a paused run's usage summary equals an uninterrupted one.
- **FR-008**: Concurrent `run` invocations against the same scan root MUST be refused
  with an explicit in-progress state keyed on the scan root (whether they come from
  the same provider instance, another instance, or the command line); the refusal
  MUST name the running scan.
- **FR-009**: Pipeline progress MUST reach the host as progress notifications through
  the single existing progress channel, MUST continue to be written to
  `.secscan/scan.log`, and MUST NOT appear inside any operation result or any artifact.
- **FR-010**: Operation results MUST expose the same settled outcomes the command line
  exposes today (success; reasoning required with the pending request ids; endpoint
  refused, re-run to resume; report published with quarantined sections) as
  distinct machine-readable states rather than as exit-code integers alone. The
  existing command-line exit codes and the three frozen stdout summary lines MUST be
  unchanged.
- **FR-011**: The tool provider MUST expose the skill's guidance (the `secscan`
  workflow instructions) as an invocable prompt/command on hosts that support it, so
  `/secscan` (or the host's equivalent) works the same way for plugin users as for
  skill users.
- **FR-012**: When the project configuration names an external analysis endpoint, the
  tool provider MUST route reasoning through the existing provider path exactly as the
  command line does, and MUST NOT hand reasoning to the host agent. When no endpoint is
  configured, reasoning requests MUST be surfaced to the host agent through the
  operations above.

**Installer integration**

- **FR-013**: The installer MUST let the engineer choose the plugin form for a
  supported host through an explicit option. Without that option the installer MUST
  produce the skill form exactly as it does today — the default is unchanged for
  every existing invocation. The plugin form registers secscan in the engineer's
  **user-level** host settings (the host's own per-user plugin/tool registration),
  never in the project. A user-level install record MUST capture which form was
  produced, the tool version, and the host; the project-level install manifest
  remains skill-only.
- **FR-014**: Installing the plugin form MUST NOT write anything into the project —
  no agent skill directory and no project-level host configuration; the only
  project-level writes permitted are those the command line already makes at scan
  time (`.secscan/` and the optional `.gitignore` entry).
- **FR-015**: When both a skill install and a plugin are present for the same host,
  the **project skill install MUST take precedence**: the plugin MUST detect the
  project's install manifest, delegate the scan to that pinned payload, and MUST NOT
  run its own engine version against the project. The active form and the tool
  version actually driving the scan MUST be stated in the operation result and in
  `status`, together with the plugin's own version when they differ. The report
  itself continues to name only the tool version that produced it (as today): the
  install form is an execution detail, and recording it in the report would make
  plugin-form and skill-form artifacts differ (FR-020).
- **FR-016**: Plugin upgrade MUST preserve project configuration and artifacts, flag a
  configuration-schema change instead of applying new defaults, and refuse a downgrade
  unless explicitly forced — identical guarantees to the skill upgrade path.
- **FR-017**: The installer's help output MUST list, per host, which install forms
  (skill, plugin, both) are available and how a host with neither is served by the
  generic tool provider.

**Single source of truth**

- **FR-018**: Guidance text, operation descriptions, and vendor manifest metadata
  (name, description, version) MUST be derived from the shipped skill source and the
  single tool-version constant; no second hand-maintained copy may exist.
- **FR-019**: Every vendor plugin manifest MUST be covered by the install-matrix
  tests in the same way as every skill adapter, including an installed-payload
  subprocess test that drives a scan end to end through the plugin form.
- **FR-020**: Artifacts produced through the plugin form MUST be byte-identical to
  artifacts produced through the skill form for identical input, tool version, and
  answers.

**Safety**

- **FR-021**: The tool provider MUST run locally and MUST NOT open any network
  connection of its own; the only network activity permitted is what the existing
  provider path already performs when an endpoint is configured.
- **FR-022**: The tool provider MUST NOT expose any operation that reads arbitrary
  project files to the host; file access remains governed by the existing
  `consultable_files` mechanism inside request packets.
- **FR-023**: Any runtime dependency the plugin form introduces MUST be optional to
  the skill form, so an existing per-project skill install gains no new dependency.

### Key Entities

- **Install form**: how secscan reaches a host — `skill` (payload copied into the
  project, today's model; recorded in the project install manifest) or `plugin`
  (registered by reference in the engineer's user-level host settings, driven
  through operations; recorded in a user-level install record).
- **Tool provider**: the process that exposes scan operations to a host. Attributes:
  tool version, supported operations. Holds no fixed scan root and no scan state of
  its own between operations — the root arrives with each operation and all state
  lives in that root's `.secscan/`.
- **Operation**: a named, schema-described action (`init`, `run`, `status`,
  `list_requests`, `get_request`, `submit_answer`, `report`) with defined settled
  outcomes.
- **Vendor plugin manifest**: a host-specific bundle description that registers the
  tool provider and the `secscan` command with one host. Attributes: host, name,
  description, version, command registration, tool-provider launch reference.
- **Reasoning request / answer**: unchanged from today — a request packet under
  `.secscan/handoff/requests/<id>.json`, an agent answer under
  `.secscan/handoff/responses/<id>.json` holding the answer content only.
- **Scan state**: the settled/in-progress state reported by `status`; extends the
  existing `state.json` view with "in progress by <provider>" and the active install
  form and version.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An engineer on a supported host installs secscan and completes a first
  `quick` scan of a new project in under 10 minutes with no shell commands beyond the
  host's single install command and no hand-edited files.
- **SC-002**: A host with no secscan-specific adapter completes a full scan lifecycle
  (init → run → answer reasoning requests → resume → report) purely through the tool
  provider, with zero manual shell steps.
- **SC-003**: For the accuracy-benchmark fixtures, artifacts produced via the plugin
  form are byte-identical to those produced via the skill form for 100% of fixtures
  and profiles.
- **SC-004**: 100% of non-conformant answer submissions are rejected before any file
  is written, in the contract-test suite.
- **SC-005**: A `run` operation never holds a host tool call longer than the
  configured bound plus one un-checkpointable stage (default well under typical host
  limits); scans that exceed it return in-progress and reach a settled state through
  repeated `run` calls with no lost work and no process left running between calls,
  verified on the large-repository scale scan.
- **SC-006**: Every vendor plugin manifest and the generic tool provider are covered
  by the install-matrix and end-to-end tests; the full suite and lint gates stay green.
- **SC-007**: A change to the shipped skill guidance is reflected in the plugin's
  exposed guidance with no additional edit — verified by a test that mutates the
  source and asserts both surfaces change.
- **SC-008**: The redaction sweep over every artifact and every packet returned by the
  tool provider finds zero credential values.

## Assumptions

- The existing per-project skill install remains the default for hosts where it works
  today; the plugin form is additive, not a replacement, and the `.agents/`
  cross-vendor adapter continues to serve skill-only hosts.
- "Plugin" is realised as a standard agent tool protocol (the mechanism supported by
  all current adapter targets and most other agent platforms) plus thin host-specific
  plugin/extension manifests around it. The plan will name the concrete protocol,
  manifests, and launch commands.
- The tool provider is launched by the host on demand, communicates over local
  process I/O, and pins its version through the launch reference (so a host-level
  install still pins a version; per-project pinning remains available through the
  skill form).
- The bounded-time `run` uses the pipeline's existing checkpointing; no new
  persistence model is introduced. The bound is configurable with a conservative
  default.
- Asking the user the business-flow question is handled by the guidance text on hosts
  that can relay questions; a non-interactive `run` with the key unset skips flow
  analysis exactly as the command line does today.
- Progress notifications reuse the existing single progress reporter with a new sink;
  no stage gains a second output path.
- Any new runtime dependency ships as an optional extra so the copied skill payload
  stays dependency-free.
- Publication to marketplaces/package indexes is a release-process concern outside
  this feature; publication credentials are never stored in the repository.
- Historical specs 001–017 are not updated; README, docs, AGENTS.md and the installer
  help are reconciled in the same change set (constitution "Honest documentation").
