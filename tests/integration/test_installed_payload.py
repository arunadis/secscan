"""T037 (continued): the *installed* payload must run standalone.

These tests execute the copied scripts in a subprocess with only the installed
skill directory on ``sys.path`` — deliberately not importing from the source tree.
Without this, resource paths that only resolve in the development layout look
fine in every other test and break for real users.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from installer import core as installer
from installer.agents import supported
from tests.fixtures.single_repo_shop import build

AGENT_KEYS = sorted(supported())


def run_in_payload(skill_dir: Path, code: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Execute ``code`` with ONLY the installed payload importable."""
    scripts = skill_dir / "scripts"
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=cwd,
        capture_output=True,
        text=True,
        env={
            "PYTHONPATH": str(scripts),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(cwd),
        },
        timeout=300,
    )


@pytest.fixture
def installed_shop(tmp_path: Path) -> tuple[Path, Path]:
    repo = build(tmp_path)
    result = installer.install(repo, "devin")
    return repo, result.skill_dir


@pytest.mark.parametrize("agent", AGENT_KEYS)
def test_installed_payload_resolves_its_resources(tmp_path: Path, agent: str) -> None:
    """Schemas, CWE data, prompts, and profiles must resolve in the installed tree."""
    project = tmp_path / agent
    project.mkdir()
    result = installer.install(project, agent)

    proc = run_in_payload(
        result.skill_dir,
        "\n".join(
            [
                "from pipeline import resources",
                "from pipeline.schemas import SCHEMA_DIR",
                "from pipeline.cwe import CWE_MAP_PATH, known_cwes",
                "from config.profiles import BUILTIN_PATH, resolve",
                "assert SCHEMA_DIR.is_dir(), SCHEMA_DIR",
                "assert (SCHEMA_DIR / 'finding.json').exists()",
                "assert CWE_MAP_PATH.exists(), CWE_MAP_PATH",
                "assert known_cwes()",
                "assert BUILTIN_PATH.exists(), BUILTIN_PATH",
                "assert resources.prompts_dir().is_dir()",
                "assert (resources.prompts_dir() / 'segment_scan.md').exists()",
                "assert resolve('audit').analysis_depth.max_escalation_level == 4",
                "print('payload-ok')",
            ]
        ),
        cwd=project,
    )
    assert proc.returncode == 0, proc.stderr
    assert "payload-ok" in proc.stdout


def test_installed_payload_validates_a_finding(installed_shop: tuple[Path, Path]) -> None:
    repo, skill_dir = installed_shop
    proc = run_in_payload(
        skill_dir,
        "\n".join(
            [
                "from pipeline.schemas import validate, SchemaError",
                "doc = {'id': 'SEC-0001', 'cwe': 'CWE-89'}",
                "try:",
                "    validate('finding', doc)",
                "    raise SystemExit('should have failed')",
                "except SchemaError as exc:",
                "    assert exc.errors",
                "print('schema-enforced')",
            ]
        ),
        cwd=repo,
    )
    assert proc.returncode == 0, proc.stderr
    assert "schema-enforced" in proc.stdout


def test_installed_payload_runs_init(installed_shop: tuple[Path, Path]) -> None:
    """`python -m pipeline.init_cmd` works from the installed skill."""
    repo, skill_dir = installed_shop
    proc = subprocess.run(
        [sys.executable, "-m", "pipeline.init_cmd", "--workdir", str(repo)],
        cwd=repo,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(skill_dir / "scripts"), "PATH": "/usr/bin:/bin", "HOME": str(repo)},
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "Ready to scan." in proc.stdout
    assert (repo / ".secscan" / "config.yaml").exists()


#: Driver executed inside the installed payload. Kept as a file (not an inline
#: string) so the regex escaping is readable and honest.
_SCAN_DRIVER = '''
import json
import re
import sys

from pipeline import run as run_mod
from pipeline.init_cmd import run_init

repo = sys.argv[1]
run_init(repo)

UNSAFE_SQL = re.compile(r"""cursor\\.execute\\(\\s*f["']""")


def responder(request):
    """Minimal analysis stand-in: reports only what the packet actually contains."""
    findings = []
    payload = request.payload
    for path, text in (payload.get("source") or {}).items():
        for match in UNSAFE_SQL.finditer(text):
            line = text[: match.start()].count("\\n") + 1
            findings.append(
                {
                    "cwe": "CWE-89",
                    "severity_score": 9.8,
                    "confidence": 0.9,
                    "location": {
                        "repo": payload["repo"],
                        "file": path,
                        "symbol": "find_by_id",
                        "line_start": line,
                        "line_end": line,
                    },
                    "description": "SQL statement built with an f-string.",
                    "evidence": [
                        {
                            "repo": payload["repo"],
                            "file": path,
                            "reason": "f-string interpolation into cursor.execute",
                        }
                    ],
                }
            )
    return json.dumps({"findings": findings})


result = run_mod.run_scan(repo, responder=responder, full=True)
print("FINDINGS", len(result.reported_findings))
print("MODE", result.report["execution_mode"])
print("REPORT_EXISTS", result.report_path.exists())
print("SAVINGS", result.usage["baseline_comparison"]["savings_factor"])
'''


def test_installed_payload_runs_a_full_scan(installed_shop: tuple[Path, Path]) -> None:
    """The whole point: the installed skill scans without the source tree."""
    repo, skill_dir = installed_shop
    driver = repo / "_driver.py"
    driver.write_text(_SCAN_DRIVER)

    proc = subprocess.run(
        [sys.executable, str(driver), str(repo)],
        cwd=repo,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(skill_dir / "scripts"), "PATH": "/usr/bin:/bin", "HOME": str(repo)},
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "MODE agent-mediated" in proc.stdout
    assert "REPORT_EXISTS True" in proc.stdout
    summary = next(line for line in proc.stdout.splitlines() if line.startswith("FINDINGS"))
    count = int(summary.split()[1])
    assert count >= 2, proc.stdout  # the seeded SQLi plus the hard-coded credential


def test_installed_payload_carries_no_source_tree_dependency(
    installed_shop: tuple[Path, Path],
) -> None:
    """No installed file may import the installer or test packages."""
    _repo, skill_dir = installed_shop
    offenders: list[str] = []
    for path in sorted((skill_dir / "scripts").rglob("*.py")):
        text = path.read_text()
        for forbidden in ("from installer", "import installer", "from tests", "import tests"):
            if forbidden in text:
                offenders.append(f"{path.name}: {forbidden}")
    assert not offenders, offenders


def test_manifest_inventory_matches_installed_files(
    installed_shop: tuple[Path, Path],
) -> None:
    _repo, skill_dir = installed_shop
    manifest = json.loads((skill_dir / installer.MANIFEST_NAME).read_text())
    for relative in manifest["files"]:
        assert (skill_dir / relative).exists(), relative
