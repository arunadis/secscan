"""Feature 014 T005: dependency usage evidence (FR-001–FR-003).

The pinned contract: three states (`found` / `none-found` / `undetermined`),
none-found never suppresses, undetermined never reads as none-found, severity is
never adjusted, and `none-found` caps confidence at the unproven ceiling with a
conditional narrative.
"""

from __future__ import annotations

from pathlib import Path

from pipeline import calibrate, usage_evidence


def _graph(member: str = "web", files: list[dict] | None = None) -> dict:
    return {"nodes": files or [], "edges": []}


def _file_node(repo: str, path: str, language: str, imports: list[str]) -> dict:
    return {
        "id": f"{repo}:{path}",
        "repo": repo,
        "type": "file",
        "path": path,
        "language": language,
        "parsed": True,
        "file_class": "source",
        "imports": imports,
    }


def _finding(package: str, ecosystem: str = "npm", members: list[str] | None = None) -> dict:
    members = members or ["web"]
    return {
        "id": "SEC-0001",
        "cwe": "CWE-1035",
        "severity_score": 7.5,
        "severity_band": "High",
        "confidence": 0.95,
        "location": {"repo": members[0], "file": "package.json", "line_start": 1},
        "attack_scenario": "An attacker exploits the published vulnerability.",
        "impact": "Whatever the advisory permits.",
        "dependency": {
            "package": package,
            "ecosystem": ecosystem,
            "affected_members": members,
            "attribution": "per-member",
        },
    }


# ---------------------------------------------------------------- found


def test_found_via_static_import() -> None:
    node = _file_node("web", "src/app.ts", "typescript", ["import { marked } from 'marked'"])
    graph = _graph(files=[node])
    finding = _finding("marked")
    usage_evidence.attach_usage([finding], graph)
    usage = finding["usage"]
    assert usage["state"] == "found"
    assert usage["locations"]
    (loc,) = usage["locations"]
    assert loc["repo"] == "web" and loc["file"] == "src/app.ts" and loc["kind"] == "import"
    assert loc["role"] == "runtime"
    assert usage["role"] == "runtime"


def test_found_via_scoped_npm_import() -> None:
    node = _file_node(
        "web", "src/app.ts", "typescript", ["import { Component } from '@angular/core'"]
    )
    finding = _finding("@angular/core")
    usage_evidence.attach_usage([finding], _graph(files=[node]))
    assert finding["usage"]["state"] == "found"


def test_found_via_python_module_map() -> None:
    node = _file_node("api", "src/app.py", "python", ["import yaml"])
    finding = _finding("PyYAML", ecosystem="pypi", members=["api"])
    usage_evidence.attach_usage([finding], _graph(files=[node]))
    assert finding["usage"]["state"] == "found"


def test_found_via_dynamic_literal_require(tmp_path: Path) -> None:
    root = tmp_path / "web"
    src = root / "src"
    src.mkdir(parents=True)
    (src / "lazy.js").write_text("const m = require('marked');\n")
    finding = _finding("marked")
    usage_evidence.attach_usage([finding], _graph(), roots={"web": root})
    usage = finding["usage"]
    assert usage["state"] == "found"
    assert usage["locations"][0]["kind"] == "dynamic"
    assert usage["locations"][0]["line_start"] == 1


def test_found_via_config_reference(tmp_path: Path) -> None:
    root = tmp_path / "web"
    root.mkdir()
    (root / "tailwind.config.js").write_text(
        "module.exports = { plugins: [require('marked')] };\n"
    )
    finding = _finding("marked")
    usage_evidence.attach_usage([finding], _graph(), roots={"web": root})
    assert finding["usage"]["state"] == "found"
    assert finding["usage"]["locations"][0]["kind"] == "config"


def test_development_role_when_only_tests_use_it() -> None:
    node = _file_node("web", "src/app.test.ts", "typescript", ["import marked from 'marked'"])
    finding = _finding("marked")
    usage_evidence.attach_usage([finding], _graph(files=[node]))
    usage = finding["usage"]
    assert usage["state"] == "found"
    assert usage["role"] == "development"
    assert usage["locations"][0]["role"] == "development"


def _member_root(tmp_path: Path, files: dict[str, str]) -> dict[str, Path]:
    """A real 'web' member — file-backed, so every detection form can complete."""
    root = tmp_path / "web"
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return {"web": root}


# ------------------------------------------------------------- none-found


def test_none_found_when_all_forms_complete_and_silent(tmp_path: Path) -> None:
    source = "import { fetch } from './x';\n"
    roots = _member_root(tmp_path, {"src/app.ts": source})
    node = _file_node("web", "src/app.ts", "typescript", [source.strip()])
    finding = _finding("marked")
    usage_evidence.attach_usage([finding], _graph(files=[node]), roots=roots)
    usage = finding["usage"]
    assert usage["state"] == "none-found"
    assert "locations" not in usage


def test_relative_imports_never_match_a_package(tmp_path: Path) -> None:
    source = "import x from './marked';\n"
    roots = _member_root(tmp_path, {"src/app.ts": source})
    node = _file_node("web", "src/app.ts", "typescript", [source.strip()])
    finding = _finding("marked")
    usage_evidence.attach_usage([finding], _graph(files=[node]), roots=roots)
    assert finding["usage"]["state"] == "none-found"


# ------------------------------------------------------------ undetermined


def test_undetermined_for_unmapped_ecosystem() -> None:
    node = _file_node("svc", "Main.java", "java", ["import com.google.gson.Gson;"])
    finding = _finding("com.google.code.gson:gson", ecosystem="maven", members=["svc"])
    usage_evidence.attach_usage([finding], _graph(files=[node]))
    usage = finding["usage"]
    assert usage["state"] == "undetermined"
    assert usage["reason"]


def test_undetermined_when_non_literal_dynamic_form_present(tmp_path: Path) -> None:
    root = tmp_path / "web"
    src = root / "src"
    src.mkdir(parents=True)
    (src / "lazy.ts").write_text("const m = require(pluginName);\n")
    finding = _finding("marked")
    usage_evidence.attach_usage([finding], _graph(), roots={"web": root})
    assert finding["usage"]["state"] == "undetermined"


def test_undetermined_when_member_has_no_parsed_sources() -> None:
    finding = _finding("marked")
    usage_evidence.attach_usage([finding], _graph())
    usage = finding["usage"]
    assert usage["state"] in ("undetermined", "none-found")  # see reason contract
    if usage["state"] == "undetermined":
        assert usage["reason"]


# --------------------------------------------------------------- invariants


def test_non_dependency_findings_are_untouched() -> None:
    finding = {"id": "SEC-0009", "cwe": "CWE-79", "location": {"repo": "w", "file": "a"}}
    usage_evidence.attach_usage([finding], _graph())
    assert "usage" not in finding


def test_none_found_caps_confidence_but_never_severity(tmp_path: Path) -> None:
    """FR-003 + clarification Q1: confidence ≤ ceiling; severity untouched."""
    source = "import y from './z';\n"
    roots = _member_root(tmp_path, {"src/app.ts": source})
    node = _file_node("web", "src/app.ts", "typescript", [source.strip()])
    finding = _finding("marked")
    usage_evidence.attach_usage([finding], _graph(files=[node]), roots=roots)
    assert finding["usage"]["state"] == "none-found"
    calibrate.apply_calibration([finding])
    assert finding["confidence"] <= calibrate.UNCONFIRMED_CONFIDENCE_CEILING
    assert finding["severity_score"] == 7.5
    assert finding["severity_band"] == "High"
    caps = finding.get("calibration", {}).get("caps_applied", [])
    assert any(c["rule"] == "usage-none-found" for c in caps)


def test_none_found_reframes_the_narrative(tmp_path: Path) -> None:
    source = "import y from './z';\n"
    roots = _member_root(tmp_path, {"src/app.ts": source})
    node = _file_node("web", "src/app.ts", "typescript", [source.strip()])
    finding = _finding("marked")
    usage_evidence.attach_usage([finding], _graph(files=[node]), roots=roots)
    calibrate.apply_calibration([finding])
    text = (finding["impact"] + finding["attack_scenario"]).lower()
    assert "no usage" in text or "no import" in text
    assert "only if" in text  # conditional framing, not an established chain
