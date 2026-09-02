# LLM-Efficient Security Scanning for Large Codebases

## Overview

Security scanning over a large codebase is difficult because the entire repository cannot fit into an LLM context window.

A better approach is to build a **hierarchical security-analysis pipeline** rather than trying to make one LLM session understand the entire repository.

The key idea is:

> **Deterministic tooling does the splitting and evidence collection; LLMs reason over small, semantically meaningful units; a final LLM aggregates the findings using structured evidence rather than re-reading the entire codebase.**

This approach is similar in spirit to **GitHub Spec Kit**: establish artifacts and contracts at each stage, keep context bounded, and progressively refine the output.

---

# 1. Proposed Architecture

```text
                         ┌─────────────────────┐
                         │    Repository       │
                         └──────────┬──────────┘
                                    │
                         ┌──────────▼──────────┐
                         │  1. Codebase        │
                         │     Discovery       │
                         │                     │
                         │ files / modules     │
                         │ dependencies        │
                         │ entry points        │
                         │ APIs / data flows   │
                         └──────────┬──────────┘
                                    │
                         ┌──────────▼──────────┐
                         │  2. Logical          │
                         │     Partitioning    │
                         │                     │
                         │ auth module         │
                         │ payment module      │
                         │ REST endpoint group  │
                         │ DB access layer      │
                         │ etc.                │
                         └──────────┬──────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
              ┌──────────┐    ┌──────────┐    ┌──────────┐
              │ Segment 1│    │ Segment 2│    │ Segment N│
              │ Context  │    │ Context  │    │ Context  │
              └────┬─────┘    └────┬─────┘    └────┬─────┘
                   │               │               │
                   ▼               ▼               ▼
              ┌──────────┐    ┌──────────┐    ┌──────────┐
              │ Security │    │ Security │    │ Security │
              │ Analysis │    │ Analysis │    │ Analysis │
              └────┬─────┘    └────┬─────┘    └────┬─────┘
                   │               │               │
                   └───────────────┼───────────────┘
                                   ▼
                         ┌─────────────────────┐
                         │ 3. Finding           │
                         │    Normalization     │
                         └──────────┬──────────┘
                                    │
                         ┌──────────▼──────────┐
                         │ 4. Cross-Segment    │
                         │    Correlation      │
                         └──────────┬──────────┘
                                    │
                         ┌──────────▼──────────┐
                         │ 5. Final Security   │
                         │    Assessment       │
                         └─────────────────────┘
```

The important part is that the repository should **not be split simply by token count**.

The goal is:

> **Logical segmentation + controlled context expansion**

---

# 2. Create a Security-Scan Skill

A top-level security scanning skill could have the following structure:

```text
security-scan/
│
├── SKILL.md
│
├── scripts/
│   ├── discover_repo.py
│   ├── build_code_graph.py
│   ├── partition_repo.py
│   ├── build_context.py
│   ├── run_segment_scan.py
│   ├── normalize_findings.py
│   ├── correlate_findings.py
│   └── generate_report.py
│
├── prompts/
│   ├── discover.md
│   ├── partition.md
│   ├── segment_scan.md
│   ├── correlation.md
│   └── final_review.md
│
├── schemas/
│   ├── segment.json
│   ├── finding.json
│   └── security_report.json
│
└── artifacts/
    ├── repository.json
    ├── architecture.json
    ├── segments/
    ├── findings/
    └── final-report.json
```

The `SKILL.md` acts as the orchestrator's instructions.

Conceptually:

```text
# Security Scan Skill

## Objective

Perform a security assessment of a large repository while
maintaining bounded LLM context.

## Workflow

1. Discover repository structure.
2. Build a lightweight semantic/code dependency graph.
3. Identify security-relevant boundaries.
4. Partition repository into logical analysis segments.
5. Generate bounded context for each segment.
6. Perform independent security analysis.
7. Normalize findings into structured artifacts.
8. Correlate findings across segments.
9. Perform final holistic security review.
10. Generate report.

## Rules

- Never load the entire repository into an LLM context.
- Prefer references to files/functions over copying unrelated code.
- Every finding must contain evidence.
- Findings must have confidence and severity.
- Cross-segment claims must reference findings from
  multiple segments.
- Do not duplicate findings.
```

---

# 3. Create a Repository Manifest

Do not immediately ask the LLM to analyze the code.

First, have a deterministic script generate a lightweight repository manifest.

For example:

```json
{
  "repository": "my-application",
  "languages": [
    "java",
    "typescript",
    "sql"
  ],
  "frameworks": [
    "spring",
    "react"
  ],
  "modules": [
    {
      "name": "payment-service",
      "path": "services/payment",
      "files": 184
    }
  ],
  "entrypoints": [
    "PaymentController.createPayment",
    "AuthController.login"
  ],
  "databases": [
    "payments_db"
  ],
  "external_services": [
    "Stripe",
    "Identity Provider"
  ]
}
```

This artifact is tiny compared with the source code.

The LLM can understand the overall system from this without consuming millions of tokens.

---

# 4. Build a Code / Property Graph

This is where a significant improvement over naive chunking can be achieved.

Instead of simply splitting the repository into token-sized chunks:

```text
repo
 ├── 500 lines
 ├── 500 lines
 ├── 500 lines
 └── ...
```

build relationships such as:

```text
HTTP Endpoint
      │
      ▼
Controller
      │
      ▼
Service
      │
      ▼
Repository
      │
      ▼
Database
```

And:

```text
Controller
   │
   ├── calls Service A
   │       │
   │       └── calls Service B
   │
   └── calls AuthService
```

You don't necessarily need a sophisticated graph database.

A JSON graph is sufficient for an initial implementation:

```json
{
  "nodes": [
    {
      "id": "payment_controller",
      "type": "class",
      "path": "payment/PaymentController.java"
    },
    {
      "id": "payment_service",
      "type": "class",
      "path": "payment/PaymentService.java"
    }
  ],

  "edges": [
    {
      "from": "payment_controller",
      "to": "payment_service",
      "type": "calls"
    }
  ]
}
```

Much of this can be derived deterministically using:

- AST parsing
- Language Server Protocol information
- dependency analysis
- import analysis
- call-graph analysis
- framework-specific metadata

---

# 5. Partition Based on Security Boundaries

This is one of the most important parts.

A segment should represent a meaningful security or business boundary rather than an arbitrary number of lines.

For example:

## Segment A — Authentication

```text
Authentication

Files:
  auth/AuthController.java
  auth/AuthService.java
  auth/JwtService.java
  auth/UserRepository.java

Dependencies:
  User DB
  Identity Provider

Entry points:
  POST /login
  POST /refresh
```

## Segment B — Payment Processing

```text
Payment Processing

Files:
  payment/PaymentController.java
  payment/PaymentService.java
  payment/PaymentRepository.java

Dependencies:
  Payment DB
  Stripe API

Entry points:
  POST /payments
  GET /payments/{id}
```

## Segment C — File Upload

```text
File Upload

Files:
  upload/UploadController.java
  upload/FileService.java
  upload/StorageService.java

Dependencies:
  S3
```

This gives the LLM enough context to reason about security properties without exposing unrelated parts of the repository.

---

# 6. Give Every Segment a Context Packet

Instead of sending dozens or hundreds of files to the LLM:

```text
Here are 70 files...
```

construct a compact **context packet**.

For example:

```json
{
  "segment": "payment-processing",

  "purpose": "Processes customer payments",

  "entrypoints": [
    "POST /payments",
    "GET /payments/{id}"
  ],

  "files": [
    "PaymentController.java",
    "PaymentService.java",
    "PaymentRepository.java"
  ],

  "dependencies": [
    "Stripe",
    "PaymentDB"
  ],

  "call_graph": "...",

  "data_flow": [
    "request.amount -> PaymentController -> PaymentService -> Stripe"
  ],

  "security_relevant_symbols": [
    "PaymentController.createPayment",
    "PaymentService.processPayment",
    "PaymentRepository.findById"
  ],

  "source": {
    "PaymentController.java": "...",
    "PaymentService.java": "..."
  }
}
```

The important distinction is:

> **The LLM receives relevant context, not the repository.**

---

# 7. Use Multiple Levels of Analysis

Do not rely on a single:

```text
segment → LLM → finding
```

pipeline.

Use multiple levels of analysis.

---

## Level 1 — Local Analysis

Analyze individual functions, classes, or small components.

```text
Function / Class / Module
          │
          ▼
  Security Analysis
```

Questions can include:

- SQL injection
- XSS
- command injection
- unsafe deserialization
- authentication bypass
- authorization failures
- secrets exposure
- insecure cryptography
- SSRF
- path traversal
- unsafe file handling
- input validation
- insecure error handling

---

## Level 2 — Segment Analysis

After analyzing individual components, perform a segment-level review.

```text
PaymentController
PaymentService
PaymentRepository
       │
       ▼
Segment Security Review
```

The question becomes:

> Does the combination of these components create a vulnerability that isn't visible when looking at each component individually?

For example:

```text
Controller validates X
       ↓
Service assumes X
       ↓
Repository performs dangerous operation
```

The individual components may look acceptable, but the overall flow may be vulnerable.

---

## Level 3 — System Analysis

Finally, perform cross-segment reasoning.

```text
Segment findings
       +
Architecture
       +
Data flows
       +
External integrations
       │
       ▼
System Security Review
```

This catches vulnerabilities that span multiple security boundaries.

For example:

```text
Authentication segment
       ↓
generates user identity

Order segment
       ↓
trusts user identity

Admin segment
       ↓
uses same identity but different authorization assumptions
```

Individually, these components may appear correct.

Together, they may reveal an authorization vulnerability.

---

# 8. Use Structured Findings

Intermediate LLM outputs should **not** be free-form reports.

Define a strict finding schema.

For example:

```json
{
  "id": "SEC-001",
  "category": "Broken Access Control",
  "severity": "HIGH",
  "confidence": 0.91,

  "location": {
    "file": "PaymentController.java",
    "symbol": "getPayment",
    "line_start": 84,
    "line_end": 96
  },

  "description": "...",

  "evidence": [
    {
      "file": "PaymentController.java",
      "symbol": "getPayment",
      "reason": "..."
    }
  ],

  "attack_scenario": "...",

  "impact": "...",

  "recommendation": "...",

  "related_symbols": [
    "PaymentService.getPayment",
    "PaymentRepository.findById"
  ]
}
```

Now the aggregation stage doesn't need to read the source again.

It can reason over:

```text
Finding 1
Finding 2
Finding 3
...
```

---

# 9. Add a Finding Deduplication Stage

Multiple segments may discover the same underlying vulnerability.

For example:

```text
Segment 3:
Missing authorization check

Segment 4:
Missing authorization check

Segment 7:
Missing authorization check
```

These should not necessarily become three independent vulnerabilities.

Have a correlation step classify findings as:

```text
SAME
RELATED
DEPENDENT
DUPLICATE
INDEPENDENT
```

For example:

```text
SEC-001
 ├── segment-03 finding-12
 ├── segment-04 finding-08
 └── segment-07 finding-03
```

The final report can then describe the issue once and reference all relevant evidence.

---

# 10. Use Evidence Escalation

This is one of the most useful techniques for reducing token usage.

Do not give every LLM invocation maximum context.

Start small.

### Stage 1

```text
Function only
     ↓
Potential vulnerability?
```

If suspicious:

### Stage 2

```text
Function
+
Calling function
+
Called function
```

If still suspicious:

### Stage 3

```text
Entire logical segment
+
Data flow
+
Configuration
```

If still uncertain:

### Stage 4

```text
Cross-segment context
+
Architecture
+
Related findings
```

Conceptually:

```text
80% → 5K tokens
15% → 15K tokens
4%  → 30K tokens
1%  → 60K tokens
```

Instead of:

```text
Every LLM call = 100K tokens
```

This can dramatically reduce both cost and latency.

---

# 11. Separate Deterministic Scanning from LLM Reasoning

Traditional security tools should run first.

For example:

```text
SAST
│
├── Semgrep
├── CodeQL
├── Dependency scanners
├── Secret scanners
├── IaC scanners
└── Container scanners
```

Then feed their findings into the LLM.

For example:

```json
{
  "tool": "semgrep",
  "rule": "java.sql-injection",
  "file": "PaymentRepository.java",
  "line": 71
}
```

The LLM can then answer:

> Is this actually exploitable in this application?

rather than:

> Search 500,000 lines of code and find SQL injection.

That is a much better use of LLM reasoning.

---

# 12. Perform Security Data-Flow Tracing

This can make the system significantly more powerful than a conventional scanner.

For every externally controllable input, construct a compact representation.

For example:

```text
HTTP Request
     ↓
POST /payments
     ↓
body.amount
     ↓
PaymentController
     ↓
PaymentService
     ↓
Validation
     ↓
Transformation
     ↓
Stripe API
```

Represent this as:

```text
SOURCE:
POST /payments
    body.amount

        ↓

TRANSFORM:
PaymentRequest.amount

        ↓

VALIDATION:
@NotNull
(no upper bound)

        ↓

SINK:
Stripe.createPayment(amount)
```

Then ask:

> Is the security boundary adequately enforced between source and sink?

This allows the LLM to reason about data flow without seeing unrelated code.

---

# 13. Create Specialized Security Skills

Rather than having one giant security prompt, create specialized security skills.

For example:

```text
skills/
│
├── security/
│   ├── auth/
│   │   ├── authentication.md
│   │   ├── authorization.md
│   │   ├── session-management.md
│   │   └── jwt.md
│   │
│   ├── injection/
│   │   ├── sql-injection.md
│   │   ├── command-injection.md
│   │   ├── xss.md
│   │   └── ldap-injection.md
│   │
│   ├── data/
│   │   ├── secrets.md
│   │   ├── encryption.md
│   │   └── pii.md
│   │
│   ├── api/
│   │   ├── ssrf.md
│   │   ├── api-security.md
│   │   └── rate-limiting.md
│   │
│   └── infrastructure/
│       ├── docker.md
│       ├── kubernetes.md
│       └── terraform.md
```

The orchestrator determines which skills are relevant to each segment.

For example:

```text
Payment module
       │
       ├── API security
       ├── Authorization
       ├── Injection
       ├── Secrets
       └── Data protection
```

Instead of loading every security rule into every LLM call.

---

# 14. Model the Entire Process as an Artifact Pipeline

This is the part to borrow most heavily from the Spec Kit philosophy.

Have every stage produce a durable artifact.

```text
01-repository.md
        ↓
02-architecture.json
        ↓
03-code-graph.json
        ↓
04-segments/
        ↓
05-context-packets/
        ↓
06-local-findings/
        ↓
07-segment-findings/
        ↓
08-correlated-findings/
        ↓
09-system-security-review.md
        ↓
10-final-report.md
```

This provides two major advantages.

## Reproducibility

You can rerun:

```text
segment 17
```

without rerunning the entire scan.

## Incremental Scanning

If someone changes:

```text
payment/PaymentService.java
```

you can determine:

```text
affected segments
        ↓
affected findings
        ↓
affected system conclusions
```

instead of rescanning the entire repository.

---

# 15. Add a Security Knowledge Graph

Eventually, maintain a compact security graph.

For example:

```text
                 ┌───────────────┐
                 │ External User │
                 └───────┬───────┘
                         │
                         ▼
                  POST /payment
                         │
                         ▼
                 PaymentController
                         │
                         ▼
                  PaymentService
                    │         │
                    │         │
                    ▼         ▼
               PaymentDB    Stripe
                    │
                    ▼
                Customer
```

Annotate nodes and edges with properties such as:

```text
trust_boundary
authentication_required
authorization_required
sensitive_data
external_system
user_controlled_input
security_sink
```

The final LLM can then reason over:

```text
Security Graph
      +
Findings
      +
Architecture
```

rather than the complete source code.

This is significantly cheaper in tokens.

---

# 16. Recommended End-to-End Workflow

The complete orchestrator could look like:

```text
security-scan

    │
    ├── Phase 0: Discover
    │       ├── languages
    │       ├── frameworks
    │       ├── modules
    │       ├── dependencies
    │       └── entry points
    │
    ├── Phase 1: Static Analysis
    │       ├── SAST
    │       ├── secrets
    │       ├── dependencies
    │       └── IaC
    │
    ├── Phase 2: Build Model
    │       ├── AST
    │       ├── call graph
    │       ├── data flow
    │       └── security boundaries
    │
    ├── Phase 3: Partition
    │       └── logical security segments
    │
    ├── Phase 4: Local Analysis
    │       └── suspicious functions/classes
    │
    ├── Phase 5: Segment Analysis
    │       └── segment context
    │
    ├── Phase 6: Correlation
    │       ├── deduplicate
    │       ├── connect
    │       └── prioritize
    │
    ├── Phase 7: System Analysis
    │       └── cross-segment reasoning
    │
    └── Phase 8: Report
            ├── Executive summary
            ├── Critical findings
            ├── High findings
            ├── Medium/Low
            ├── Attack paths
            └── Recommendations
```

---

# 17. Make the Pipeline Token-Budget Aware

Token consumption should be an explicit engineering constraint.

Every LLM invocation can have a budget:

```json
{
  "max_context_tokens": 12000,
  "max_output_tokens": 3000,
  "escalation_threshold": 0.75
}
```

The orchestrator then decides:

```text
Is there enough evidence?
        │
        ├── NO
        │    │
        │    ▼
        │ expand context
        │
        └── YES
             │
             ▼
        perform analysis
```

This makes the system adaptive rather than blindly sending maximum context to every LLM call.

---

# 18. Target Architecture

The final architecture should look something like:

```text
             ┌──────────────────────┐
             │      CODEBASE        │
             └──────────┬───────────┘
                        │
              deterministic analysis
                        │
             ┌──────────▼───────────┐
             │   SECURITY MODEL     │
             │                      │
             │ AST                  │
             │ Call Graph           │
             │ Data Flow             │
             │ Dependencies          │
             │ Entry Points          │
             │ Trust Boundaries      │
             └──────────┬───────────┘
                        │
                 logical partition
                        │
       ┌────────────────┼────────────────┐
       ▼                ▼                ▼
   Segment A        Segment B        Segment C
       │                │                │
   small LLM        small LLM        small LLM
       │                │                │
       └────────────────┼────────────────┘
                        ▼
               STRUCTURED FINDINGS
                        │
                        ▼
                 CORRELATION LLM
                        │
                        ▼
                 SECURITY GRAPH
                        │
                        ▼
                SYSTEM REVIEW LLM
                        │
                        ▼
                 FINAL REPORT
```

---

# 19. Core Design Principle

The most important architectural principle is:

> **Don't make the LLM the repository analyzer. Make the LLM the reasoning engine sitting on top of a deterministic repository model.**

This provides:

- Lower token consumption
- Better scalability
- Parallel analysis
- Better reproducibility
- Incremental scanning
- Better explainability
- Stronger evidence chains
- Easier debugging
- Easier re-analysis
- Better separation between deterministic analysis and probabilistic reasoning

The result is effectively a **compiler-like pipeline for security analysis**:

```text
Source Code
     ↓
Repository Model
     ↓
Security-Relevant Segments
     ↓
Bounded Context
     ↓
LLM Reasoning
     ↓
Structured Findings
     ↓
Cross-Segment Correlation
     ↓
System-Level Reasoning
     ↓
Security Report
```

The key is to treat **context as a managed resource** rather than simply giving the LLM as much code as possible.