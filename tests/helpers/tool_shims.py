"""PATH-shim harness for external-tool tests (feature 008, T002).

Fake executables stand in for real security tools so provisioning, execution,
and ingestion tests are fully offline and deterministic:

* each shim answers a version probe with a fixed version string
* otherwise it cats a recorded JSON report from the fixtures
* ``SECSCAN_SHIM_CRASH=1`` makes a shim exit 137 with no output (crash_tool
  resilience scenario)

Two usages of the environment differ deliberately:

* ``install_shims`` creates the executables under a caller-chosen directory
* ``shimmed_path`` prepends that directory to ``PATH`` for the with-block

Fixtures are copied into ``tmp_path`` before use — scans write ``.secscan/``
into the project root and fixture trees in the repo must stay pristine.
"""

from __future__ import annotations

import contextlib
import os
import shutil
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent / "fixtures" / "tooling_workspace"
RECORDED_DIR = WORKSPACE / "recorded"

#: Absolute coreutils paths: tests restrict PATH to the shim directory, so a
#: shim must not rely on PATH resolution for its own utilities.
_SCRIPT = """#!/bin/sh
case "$1" in
  --version|-v|version) echo "{version}"; exit 0 ;;
esac
if [ "$SECSCAN_SHIM_CRASH" = "1" ]; then exit 137; fi
prev=""
for a in "$@"; do
  case "$prev" in
    --report-path) /bin/cat "{recorded}" > "$a"; exit 0 ;;
    --out) /bin/mkdir -p "$a"; /bin/cat "{recorded}" > "$a/{report_name}"; exit 0 ;;
  esac
  prev="$a"
done
/bin/cat "{recorded}"
"""

#: File-report name per executable when the tool writes into an --out dir.
_REPORT_NAMES = {"dependency-check.sh": "dependency-check-report.json"}


def _script_for(executable: str, recorded: Path, version: str) -> str:
    return _SCRIPT.format(
        version=version,
        recorded=recorded,
        report_name=_REPORT_NAMES.get(executable, "report.json"),
    )


def fixture_workspace(name: str) -> Path:
    """Path to the checked-in fixture tree (do not scan in place)."""
    return WORKSPACE / name


def copy_fixture(name: str, tmp_path: Path) -> Path:
    """Copy a fixture workspace into tmp_path and return the copy's root."""
    target = tmp_path / name
    shutil.copytree(fixture_workspace(name), target, symlinks=True)
    return target


def install_shims(
    tmp_path: Path,
    tools: dict[str, str],
    *,
    versions: dict[str, str] | None = None,
) -> Path:
    """Write one executable shim per ``executable -> recorded file`` entry.

    Returns the directory to prepend to PATH.
    """
    bin_dir = tmp_path / "shim-bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    versions = versions or {}
    for executable, recorded in sorted(tools.items()):
        script = bin_dir / executable
        script.write_text(
            _script_for(
                executable,
                RECORDED_DIR / recorded,
                versions.get(executable, "0.0.0-fixture"),
            )
        )
        script.chmod(0o755)
    return bin_dir


DEFAULT_FORMULAS = {
    "node": "npm",
    "dependency-check": "dependency-check.sh",
    "semgrep": "semgrep",
    "osv-scanner": "osv-scanner",
    "trivy": "trivy",
    "gitleaks": "gitleaks",
}


def install_brew_shim(
    bin_dir: Path,
    *,
    mapping: dict[str, str],
    formulas: dict[str, str] | None = None,
) -> Path:
    """Fake ``brew``: ``brew install <formula>`` materializes the tool shim.

    The created tool shim serves the recorded output for that tool from
    ``mapping`` (executable name -> recorded file). Honors
    ``SECSCAN_SHIM_BREW_FAIL=1`` by exiting 1 and creating nothing, for the
    failed-installation scenario.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    formulas = formulas or DEFAULT_FORMULAS
    cases = []
    for formula, exe in sorted(formulas.items()):
        if exe not in mapping:
            # materialize only tools the test asked for; others fail honestly (exit 1)
            continue
        inner = _script_for(exe, RECORDED_DIR / mapping[exe], "9.9.9-fixture")
        cases.append(
            f'  {formula})\n'
            f'    /bin/cat > "$dir/{exe}" <<\'SHIM_EOF\'\n'
            f'{inner}'
            f'SHIM_EOF\n'
            f'    /bin/chmod +x "$dir/{exe}" ;;'
        )
    script = (
        "#!/bin/sh\n"
        'if [ "$SECSCAN_SHIM_BREW_FAIL" = "1" ]; then exit 1; fi\n'
        'dir=${0%/*}\n'
        'case "$2" in\n'
        + "\n".join(cases)
        + "\n  *) exit 1 ;;\nesac\n"
    )
    brew = bin_dir / "brew"
    brew.write_text(script)
    brew.chmod(0o755)
    return bin_dir


@contextlib.contextmanager
def shimmed_path(bin_dir: Path, env: dict[str, str] | None = None):
    """Prepend ``bin_dir`` to PATH (and set extra env vars) for the block."""
    saved = {key: os.environ.get(key) for key in ["PATH", *(env or {})]}
    os.environ["PATH"] = f"{bin_dir}{os.pathsep}{saved['PATH'] or ''}"
    for key, value in (env or {}).items():
        os.environ[key] = value
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
