"""Stage 1: workspace assembly and repository manifests (FR-001, FR-001a, FR-001c).

Workspace membership comes from the optional declarative manifest in project
config; when absent the scan root is auto-discovered (repos inferred from
directory structure), with inferred entries flagged at lower confidence.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pipeline.state import ArtifactStore, iter_source_files

#: file suffix -> language
LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    # JSX-capable grammar; see pipeline.extract._GRAMMARS (research.md A1).
    ".tsx": "tsx",
    ".go": "go",
    ".sql": "sql",
    ".graphql": "graphql",
    ".graphqls": "graphql",
    ".tf": "terraform",
    # Markup and view templates — where injection actually lives in front-end
    # frameworks, and absent from the code model before feature 002 (FR-025).
    ".html": "html",
    ".htm": "html",
    ".vue": "html",
    ".jsp": "html",
    ".jspx": "html",
    ".djhtml": "html",
    ".j2": "html",
    ".jinja": "html",
    ".jinja2": "html",
    ".njk": "html",
    ".tmpl": "html",
    ".gohtml": "html",
    ".gotmpl": "html",
    ".hbs": "html",
    ".mustache": "html",
    ".erb": "html",
}

#: Programming-language suffixes the code model does NOT have a grammar for.
#:
#: These are enumerated deliberately (FR-003c). Before feature 002 such files
#: produced no graph node at all — not even a file node — so a finding in a Ruby,
#: PHP, C# or Rust repository could not be resolved and was rejected wholesale.
#: Language coverage must never be a precondition for reporting a finding, so
#: these files are represented at file granularity and findings in them resolve at
#: the *file* tier instead of being dropped.
UNMODELLED_LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".m": "objc",
    ".pl": "perl",
    ".sh": "shell",
    ".bash": "shell",
    ".ps1": "powershell",
    ".lua": "lua",
    ".dart": "dart",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".groovy": "groovy",
    ".r": "r",
}


def any_language_for(suffix: str) -> str | None:
    """Language for ``suffix`` whether or not a grammar exists for it."""
    lowered = suffix.lower()
    return LANGUAGE_BY_SUFFIX.get(lowered) or UNMODELLED_LANGUAGE_BY_SUFFIX.get(lowered)


def file_class_for_path(relative: str) -> str | None:
    """Security-relevant file class for a repository-relative path (FR-029).

    Classification is driven by the shipped stack descriptors, so adding a manifest
    or config filename is a data change (FR-025b). Returns ``None`` for files that
    carry no security-relevant class, which is different from a file that has one
    but could not be parsed — that distinction is what lets the report separate
    coverage from silence (FR-027).
    """
    from pipeline import stacks

    name = relative.rsplit("/", 1)[-1]
    by_name = stacks.file_class_for(name)
    if by_name:
        return by_name
    suffix = ("." + name.rsplit(".", 1)[-1]).lower() if "." in name else ""
    if suffix in stacks.template_suffixes():
        return "template"
    if any_language_for(suffix):
        return "source"
    return None

#: marker file -> framework/ecosystem hint
FRAMEWORK_MARKERS: dict[str, str] = {
    "requirements.txt": "python-pip",
    "pyproject.toml": "python-project",
    "package.json": "node",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "go.mod": "go-modules",
    "Dockerfile": "docker",
}

#: import/dependency token -> framework
FRAMEWORK_TOKENS: dict[str, str] = {
    "flask": "flask",
    "fastapi": "fastapi",
    "django": "django",
    "express": "express",
    "nestjs": "nestjs",
    "springframework": "spring",
    "gin-gonic": "gin",
    "echo": "echo",
    "psycopg2": "postgresql",
    "sqlalchemy": "sqlalchemy",
    "pymongo": "mongodb",
    "boto3": "aws",
    "stripe": "stripe",
    "requests": "http-client",
    "axios": "http-client",
}

#: repository roots are recognised by these markers during auto-discovery
REPO_MARKERS = ("pyproject.toml", "package.json", "pom.xml", "go.mod", "requirements.txt", ".git")


@dataclass
class Member:
    name: str
    path: Path
    declared: bool


def _detect_repo_roots(scan_root: Path) -> list[Member]:
    """Auto-discover workspace members beneath ``scan_root`` (FR-001c fallback)."""
    if _looks_like_repo(scan_root):
        return [Member(name=scan_root.name, path=scan_root, declared=False)]

    members: list[Member] = []
    for child in sorted(scan_root.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        if _looks_like_repo(child):
            members.append(Member(name=child.name, path=child, declared=False))
    if not members:
        members = [Member(name=scan_root.name, path=scan_root, declared=False)]
    return members


def _looks_like_repo(path: Path) -> bool:
    if any((path / marker).exists() for marker in REPO_MARKERS):
        return True
    # A directory containing source files directly is treated as a repo.
    return bool(iter_source_files(path)[:1])


def resolve_members(scan_root: Path, declared: list[dict[str, str]]) -> tuple[list[Member], str]:
    """Return workspace members and whether they came from a manifest."""
    if declared:
        members: list[Member] = []
        for entry in declared:
            path = (scan_root / entry["path"]).resolve()
            members.append(Member(name=str(entry["name"]), path=path, declared=True))
        return members, "manifest"
    return _detect_repo_roots(scan_root), "auto-discovered"


# ------------------------------------------------------------------ manifest


def build_manifest(member: Member) -> dict[str, Any]:
    """Compact per-repository manifest — small regardless of repo size (FR-001)."""
    from pipeline.extract import extract_file

    files = iter_source_files(member.path)
    languages: Counter[str] = Counter()
    frameworks: set[str] = set()
    modules: Counter[str] = Counter()
    entrypoints: list[dict[str, str]] = []
    databases: set[str] = set()
    external: set[str] = set()
    unparsed: list[str] = []
    loc = 0

    for path in files:
        relative = path.relative_to(member.path).as_posix()
        language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
        if language:
            languages[language] += 1
        module = relative.rsplit("/", 1)[0] if "/" in relative else "."
        modules[module] += 1

        if path.name in FRAMEWORK_MARKERS:
            frameworks.add(FRAMEWORK_MARKERS[path.name])

        try:
            text = path.read_text(errors="replace")
        except OSError:
            unparsed.append(relative)
            continue
        loc += text.count("\n") + 1

        lowered = text.lower()
        for token, framework in FRAMEWORK_TOKENS.items():
            if token in lowered:
                frameworks.add(framework)
        databases.update(_detect_databases(lowered))
        external.update(_detect_external(lowered))

        if language:
            facts = extract_file(relative, text, language)
            if facts is None:
                unparsed.append(relative)
                continue
            for endpoint in facts.endpoints:
                entrypoints.append(
                    {
                        "symbol": endpoint.symbol,
                        "kind": endpoint.kind,
                        "route": endpoint.route,
                        "file": relative,
                    }
                )
        else:
            unparsed.append(relative)

    manifest = {
        "repository": member.name,
        "languages": sorted(languages),
        "frameworks": sorted(frameworks),
        "modules": [
            {"name": name, "path": name, "file_count": count}
            for name, count in sorted(modules.items())
        ],
        "entrypoints": sorted(entrypoints, key=lambda e: (e["file"], e["symbol"])),
        "databases": sorted(databases),
        "external_services": sorted(external),
        "unparsed_paths": sorted(set(unparsed)),
        "loc": loc,
    }

    # Execution shape, from the facts just gathered (FR-013). Recorded on the
    # manifest so applicability can read it without re-deriving anything.
    from pipeline.architecture import classify_member

    manifest["architecture"] = classify_member(member.path, manifest).to_dict()
    return manifest


_DB_TOKENS = {
    "psycopg2": "postgresql",
    "postgres": "postgresql",
    "mysql": "mysql",
    "sqlite": "sqlite",
    "mongodb": "mongodb",
    "pymongo": "mongodb",
    "redis": "redis",
    "jdbc": "jdbc",
    "dynamodb": "dynamodb",
}

_EXTERNAL_TOKENS = {
    "stripe": "Stripe",
    "boto3": "AWS",
    "s3.": "AWS S3",
    "sendgrid": "SendGrid",
    "twilio": "Twilio",
    "auth0": "Auth0",
    "okta": "Okta",
    "keycloak": "Keycloak",
}


def _detect_databases(lowered: str) -> set[str]:
    return {label for token, label in _DB_TOKENS.items() if token in lowered}


def _detect_external(lowered: str) -> set[str]:
    return {label for token, label in _EXTERNAL_TOKENS.items() if token in lowered}


# ------------------------------------------------------------------- stage


def run(
    store: ArtifactStore,
    declared_members: list[dict[str, str]],
    declared_integrations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Execute discovery, writing ``workspace.json`` and per-repo manifests."""
    members, source = resolve_members(store.scan_root, declared_members)

    available: list[Member] = []
    unavailable: list[str] = []
    for member in members:
        if member.path.exists():
            available.append(member)
        else:
            unavailable.append(member.name)

    if not available:
        raise RuntimeError(
            "no readable repositories found in the workspace; "
            f"declared but missing: {', '.join(unavailable) or 'none'}"
        )

    for member in available:
        manifest = build_manifest(member)
        store.write(
            f"repository/{member.name}.manifest.json",
            "discover_repo",
            manifest,
            "manifest",
        )

    from pipeline.integrations import normalize_declared

    workspace = {
        "id": store.scan_root.name,
        "root": str(store.scan_root),
        "source": source,
        "members": [
            {"name": m.name, "path": _relative_path(store.scan_root, m.path)} for m in available
        ],
        "integrations": normalize_declared(declared_integrations),
    }
    if unavailable:
        workspace["unavailable_members"] = sorted(unavailable)

    store.write("workspace.json", "discover_repo", workspace, "workspace")
    return workspace


def _relative_path(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix() or "."
    except ValueError:
        return str(path)


def member_paths(store: ArtifactStore, workspace: dict[str, Any]) -> dict[str, Path]:
    """Map member name to absolute path."""
    out: dict[str, Path] = {}
    for member in workspace["members"]:
        candidate = Path(member["path"])
        out[member["name"]] = (
            candidate if candidate.is_absolute() else (store.scan_root / candidate).resolve()
        )
    return out


def main() -> None:  # pragma: no cover - CLI wrapper
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    args = parser.parse_args()
    from config.loader import load

    store = ArtifactStore(args.workdir)
    config = load(store.dir)
    workspace = run(store, config.workspace_members, config.workspace_integrations)
    print(f"discovered {len(workspace['members'])} repository/-ies ({workspace['source']})")


if __name__ == "__main__":  # pragma: no cover
    main()
