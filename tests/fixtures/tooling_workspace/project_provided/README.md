# project_provided — ground truth

Ecosystem: **maven** only.

Ground truth for discovery (FR-003a): `pom.xml` declares the
`org.owasp:dependency-check-maven` plugin and `mvnw` is present, so
`owasp-dependency-check` MUST be discovered as **project-provided** via the
wrapper invocation and MUST NOT appear on any install list. A system-installed
copy, if present, is a noted duplicate only.
