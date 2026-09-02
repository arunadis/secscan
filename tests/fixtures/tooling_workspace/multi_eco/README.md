# multi_eco — ground truth

Ecosystems present: **npm** (`package.json`) and **maven** (`pom.xml`).

Expected applicable registry tools: every entry with `ecosystems` containing
`any`, `npm`, or `maven`; nothing for pypi or go.

No tool is provided project-locally; availability depends on the PATH shims the
test harness injects.
