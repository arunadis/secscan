"""External security-tooling layer (feature 008).

Submodules:

* ``registry``   — load/validate the shipped tool registry (FR-001)
* ``ecosystem``  — detect project ecosystems from manifests/build files (FR-001)
* ``discover``   — project-local + system availability discovery (FR-003a)
* ``provision``  — consent-gated, selective installation (FR-003/FR-004)
* ``runner``     — read-only, timeout-bounded tool execution (FR-004/FR-005)

Shared invariants, each enforced rather than trusted:

* never raise — every failure degrades to a declared status with a reason
* never mutate the scanned project — installs land user-level, tool
  caches/DBs in the scanner's tooling dir, and the fingerprint guard
  discards output from any run that writes
* deterministic — artifact writes use the store's canonical JSON
"""

from __future__ import annotations

import os
from pathlib import Path

#: Canonical install/cache target (research.md R4, spec Assumptions): outside
#: both the scanned project and the payload. Package-manager channels install
#: into the manager's user-level prefix; scanner-managed downloads, caches, and
#: tool databases live here. Overridable for tests.
DEFAULT_TOOL_DIR = Path.home() / ".secscan" / "tools"


def tool_dir() -> Path:
    override = os.environ.get("SECSCAN_TOOL_DIR")
    return Path(override) if override else DEFAULT_TOOL_DIR
